"""Console locale : programmes fixes, un essai à la fois, rejeu sans VM.

Le collecteur fournit les contrôles HTTP (loopback, Origin, JSON). Ce module
valide à nouveau chaque paramètre et ne transforme jamais une entrée en shell.
L'arrêt est opérateur, jamais une preuve d'intervention défensive de SAWM.
"""
from __future__ import annotations

import copy
import datetime
import fcntl
import json
import os
import pathlib
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
DUREE_MAX_S = 600
GRACE_ARRET_S = 45
MAX_RAPPORT = 8 * 1024 * 1024
MAX_SORTIE = 16 * 1024 * 1024
SCENARIOS = {'transfert', 'transfert-autorise', 'repetition'}
NOM_RAPPORT = re.compile(r'(?:experience-[A-Za-z0-9][A-Za-z0-9_-]{0,95}|validation-mesures)\.json')
UNITES = {'transfert': ('labo-copie-a.service', 'labo-copie-b.service'),
          'transfert-autorise': ('labo-copie-a.service', 'labo-copie-b.service'),
          'repetition': ('labo-repetition.service',)}


class ValidationErreur(ValueError):
    def __init__(self, message, statut_http=400):
        super().__init__(message)
        self.statut_http = statut_http


def maintenant():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _commande(racine, scenario, volume):
    if scenario == 'repetition':
        return [sys.executable, str(racine / 'controleur/validation_reprise.py')]
    cmd = [sys.executable, str(racine / 'controleur/validation.py'), 'transfert',
           '--bytes', str(volume * 1024**3), '--rate', str(8 * 1024**2)]
    return cmd + (['--authorized'] if scenario == 'transfert-autorise' else [])


def _nettoyage_invite(identifiant, scenario):
    """Secours exact sous le verrou du manifeste, seulement pour CETTE console."""
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from controleur.vm_labo import json_code
    source = '''import fcntl,json,os,pathlib,subprocess
root=pathlib.Path('/opt/sawm-labo')
fd=os.open(root/'.executeur.lock',os.O_RDWR|os.O_NOFOLLOW)
fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
m=json.loads((root/'manifeste.json').read_text())
if m.get('operation_id') != OPERATION:
 print(json.dumps({'confirme':False,'raison':'generation_non_possedee','actions_vm':False}))
else:
 p=subprocess.run(['/usr/bin/systemctl','stop','--',*UNITES],capture_output=True,text=True,timeout=20)
 observations=[]
 for unit in UNITES:
  q=subprocess.run(['/usr/bin/systemctl','show','--property=Id,ActiveState,MainPID','--',unit],capture_output=True,text=True,timeout=3)
  d=dict(l.split('=',1) for l in q.stdout.splitlines() if '=' in l)
  observations.append({'unite':unit,'inactive':q.returncode==0 and d.get('Id')==unit and d.get('ActiveState') in ('inactive','failed') and d.get('MainPID')=='0'})
 print(json.dumps({'confirme':p.returncode==0 and all(x['inactive'] for x in observations),'actions_vm':True,'unites':observations,'origine':'arret_operateur'}))
os.close(fd)
'''.replace('OPERATION', repr(identifiant)).replace('UNITES', repr(UNITES[scenario]))
    return json_code(source, timeout=35)


class ControleOperateur:
    """Interface HTTP : traite(dict) et etat(). Aucun lancement au constructeur."""

    def __init__(self, racine=ROOT):
        self.racine = pathlib.Path(racine).resolve()
        self.dossier = self.racine / 'releves/operateur'
        self._mutex = threading.RLock()
        self._operation = None
        self._processus = None
        self._thread = None
        self._stop = threading.Event()
        self._fd_verrou = None
        self._motif_arret = None

    def etat(self):
        with self._mutex:
            return self._etat()

    def _etat(self):
        actif = self._fd_verrou is not None
        externe = False
        if not actif and self.dossier.exists():
            fd = None
            try:
                fd = self._ouvrir_verrou()
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                externe = True
            except OSError:
                # Un verrou non vérifiable ne doit pas annoncer une disponibilité.
                externe = True
            finally:
                if fd is not None:
                    os.close(fd)
        return {'schema': 'sawm-operateur/v1', 'actif': actif or externe,
                'controle_externe': externe, 'operation': copy.deepcopy(self._operation),
                'bornes': {'duree_max_s': DUREE_MAX_S, 'grace_arret_s': GRACE_ARRET_S,
                           'volumes_gio': [1, 5, 20], 'debit_octets_s': 8 * 1024**2},
                'limite': 'Le verrou couvre les essais de cette console. Les lancements CLI externes restent distincts.'}

    def traite(self, payload):
        if type(payload) is not dict or not isinstance(payload.get('action'), str):
            raise ValidationErreur('Objet JSON avec action requis.')
        action = payload['action']
        permis = {'lancer': {'action', 'scenario', 'volume_gio'},
                  'arreter': {'action', 'operation_id'}, 'rejouer': {'action', 'rapport'}}
        if action not in permis or set(payload) - permis[action]:
            raise ValidationErreur('Action ou paramètre inconnu.')
        if action == 'rejouer':
            contenu, _ = self._lire_rapport(payload.get('rapport'))
            return {'ok': True, 'mode': 'REJEU', 'actions_vm': False,
                    'rapport': {'chemin': payload['rapport'], 'contenu': contenu}}
        with self._mutex:
            if action == 'lancer':
                scenario, volume = payload.get('scenario'), payload.get('volume_gio', 1)
                if not isinstance(scenario, str) or scenario not in SCENARIOS:
                    raise ValidationErreur('Scénario inconnu.')
                if type(volume) is not int or volume not in (1, 5, 20):
                    raise ValidationErreur('volume_gio doit être 1, 5 ou 20 (entier).')
                self._lancer(scenario, volume)
            else:
                identifiant = payload.get('operation_id')
                if (not isinstance(identifiant, str) or self._operation is None
                        or identifiant != self._operation['id']):
                    raise ValidationErreur('Identifiant de cet essai requis.', 409)
                if self._fd_verrou is None:
                    raise ValidationErreur('Cet essai est déjà terminé.', 409)
                if not self._stop.is_set():
                    self._motif_arret = 'demande_operateur'
                    self._operation['statut'] = 'arret_demande'
                    self._stop.set()
                    self._sauver_etat()
            return {'ok': True, **self._etat()}

    def _ouvrir_verrou(self):
        return os.open(self.dossier / 'essai.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)

    def _preparer_dossier(self):
        for partie in (self.racine / 'releves', self.dossier):
            partie.mkdir(mode=0o700, exist_ok=True)
            if partie.is_symlink() or not partie.is_dir():
                raise ValidationErreur('Dossier opérateur non sûr.', 500)

    def _lancer(self, scenario, volume):
        if self._fd_verrou is not None:
            raise ValidationErreur('Un essai est déjà en cours.', 409)
        self._preparer_dossier()
        fd = self._ouvrir_verrou()
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise ValidationErreur('Un essai est déjà en cours dans une autre console.', 409)
        identifiant = 'op-' + uuid.uuid4().hex
        chemin_log = self.dossier / (identifiant + '.log')
        try:
            cmd = _commande(self.racine, scenario, volume)
            script = pathlib.Path(cmd[1])
            if script.is_symlink() or not script.is_file():
                raise ValidationErreur('Programme fixe du laboratoire absent ou symbolique.', 500)
            self._operation = {'id': identifiant, 'scenario': scenario,
                'volume_gio': volume if scenario != 'repetition' else None,
                'statut': 'en_cours', 'debut': maintenant(), 'fin': None,
                'code_sortie': None, 'rapport': None, 'erreur': None,
                'origine_arret': None, 'nettoyage_secours': None}
            self._stop = threading.Event()
            self._motif_arret = None
            self._debut_epoch = time.time()
            self._sauver_etat()
            env = dict(os.environ, SAWM_OPERATEUR_ID=identifiant, PYTHONUNBUFFERED='1')
            with os.fdopen(os.open(chemin_log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                  0o600), 'wb') as log:
                self._processus = subprocess.Popen(cmd, cwd=str(self.racine), env=env,
                    stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                    shell=False, start_new_session=True, close_fds=True, pass_fds=(fd,))
            # Le fils conserve ce fd : un redémarrage du collecteur ne permet
            # pas de lancer un second essai tant que le premier fils vit.
            self._fd_verrou = fd
            self._thread = threading.Thread(target=self._surveiller, args=(chemin_log,), daemon=True)
            self._thread.start()
        except Exception:
            os.close(fd)
            if self._operation and self._operation['id'] == identifiant:
                self._operation.update(statut='erreur', fin=maintenant(), erreur='lancement_impossible')
            raise

    def _sauver_etat(self):
        fd, chemin = tempfile.mkstemp(prefix='.operation-', dir=self.dossier)
        try:
            with os.fdopen(fd, 'w') as out:
                json.dump(self._operation, out, ensure_ascii=False)
                out.flush()
                os.fsync(out.fileno())
            os.replace(chemin, self.dossier / 'operation.json')
        finally:
            pathlib.Path(chemin).unlink(missing_ok=True)

    def _lire_rapport(self, chemin):
        if (not isinstance(chemin, str) or not chemin.startswith('releves/rapports/')
                or not NOM_RAPPORT.fullmatch(chemin.removeprefix('releves/rapports/'))):
            raise ValidationErreur('Chemin de rapport non autorisé.')
        fds = []
        try:
            fd = os.open(self.racine, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            fds.append(fd)
            for partie in ('releves', 'rapports'):
                fd = os.open(partie, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                fds.append(fd)
            fd = os.open(chemin.split('/')[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            fds.append(fd)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_RAPPORT:
                raise ValidationErreur('Rapport non régulier ou trop volumineux.')
            with os.fdopen(os.dup(fd), 'rb') as source:
                brut = source.read(MAX_RAPPORT + 1)
            if len(brut) > MAX_RAPPORT:
                raise ValidationErreur('Rapport trop volumineux.')
            contenu = json.loads(brut)
            if not isinstance(contenu, dict):
                raise ValidationErreur('Rapport JSON objet requis.')
            return contenu, info
        except (OSError, ValueError) as exc:
            if isinstance(exc, ValidationErreur):
                raise
            raise ValidationErreur('Rapport absent, illisible ou non sûr.') from exc
        finally:
            for fd in reversed(fds):
                os.close(fd)

    def _rapport_final(self, chemin_log):
        # Les scripts fixes écrivent le chemin final sur stdout ; rien provenant
        # de ces logs n'est publié directement (notamment erreurs ou secrets).
        with chemin_log.open('rb') as source:
            source.seek(max(0, os.fstat(source.fileno()).st_size - 65536))
            lignes = source.read(65536).decode('utf-8', errors='replace').splitlines()
        for ligne in reversed(lignes):
            try:
                resume = json.loads(ligne)
                if not isinstance(resume, dict) or not isinstance(resume.get('rapport'), str):
                    continue
                chemin = pathlib.Path(resume['rapport'])
                relatif = str(chemin.relative_to(self.racine)) if chemin.is_absolute() else str(chemin)
                rapport, info = self._lire_rapport(relatif)
                if info.st_mtime < self._debut_epoch:
                    continue
                nettoyage = rapport.get('nettoyage_operateur')
                rows = nettoyage if isinstance(nettoyage, list) else [nettoyage]
                return {'chemin': relatif, 'run_id': rapport.get('run_id'),
                        'succes_mesure': rapport.get('succes_mesure') is True,
                        'erreur_presente': bool(rapport.get('erreur')),
                        'nettoyage_confirme': bool(rows) and all(
                            isinstance(row, dict) and row.get('code') == 0 for row in rows)}
            except (ValueError, TypeError):
                continue
        return None

    def _surveiller(self, chemin_log):
        processus = self._processus
        echeance = time.monotonic() + DUREE_MAX_S
        arret_a = None
        force = False
        erreur = None
        try:
            while processus.poll() is None:
                if time.monotonic() >= echeance or chemin_log.stat().st_size > MAX_SORTIE:
                    with self._mutex:
                        if not self._stop.is_set():
                            self._motif_arret = 'limite_console'
                            self._operation['statut'] = 'arret_demande'
                            self._stop.set()
                if self._stop.is_set():
                    if arret_a is None:
                        try:
                            processus.terminate()
                        except ProcessLookupError:
                            pass
                        arret_a = time.monotonic()
                    elif time.monotonic() - arret_a >= GRACE_ARRET_S:
                        os.killpg(processus.pid, signal.SIGKILL)
                        processus.wait(timeout=5)
                        force = True
                        break
                time.sleep(0.1)
            rapport = self._rapport_final(chemin_log)
        except Exception as exc:
            erreur = type(exc).__name__
            rapport = None
            if processus.poll() is None:
                try:
                    os.killpg(processus.pid, signal.SIGKILL)
                    processus.wait(timeout=5)
                    force = True
                except (OSError, subprocess.TimeoutExpired):
                    pass
        secours = None
        if (self._stop.is_set() or force or processus.returncode != 0 or rapport is None
                or not rapport.get('nettoyage_confirme')):
            try:
                secours = _nettoyage_invite(self._operation['id'], self._operation['scenario'])
            except Exception as exc:
                secours = {'confirme': False, 'actions_vm': None, 'erreur': type(exc).__name__}
        with self._mutex:
            statut = 'arrete' if self._stop.is_set() else 'termine'
            if processus.returncode != 0 and not self._stop.is_set():
                statut = 'erreur'
            if erreur or force or rapport is None or (secours and not secours.get('confirme')):
                statut = 'erreur'
            self._operation.update(statut=statut, fin=maintenant(), code_sortie=processus.returncode,
                rapport=rapport, erreur=erreur or ('rapport_non_disponible' if rapport is None else None),
                origine_arret=self._motif_arret, nettoyage_secours=secours,
                arret_force=force, attribution='Fin ou arrêt opérateur distinct de toute décision SAWM.')
            try:
                self._sauver_etat()
            finally:
                # Ne jamais libérer le singleton si un fils est encore vivant.
                if processus.poll() is not None:
                    os.close(self._fd_verrou)
                    self._fd_verrou = None
