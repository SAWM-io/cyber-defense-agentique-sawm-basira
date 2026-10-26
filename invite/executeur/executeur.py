#!/usr/bin/env python3
"""Exécuteur privilégié du labo : autorisation exacte, garde, reçu vérifié.

JSON stdin: decision_id, action, cible, generation, manifest_sha256.
--describe rend génération et SHA256 des octets du manifeste à utiliser.
Les mises à jour du manifeste doivent prendre le même verrou .executeur.lock.
Une fin naturelle de charge ne devient jamais une interruption par SAWM.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import pathlib
import re
import stat
import struct
import subprocess
import sys
import tempfile
import time

RACINE = pathlib.Path('/opt/sawm-labo')
MANIFESTE = RACINE / 'manifeste.json'
RECUS = RACINE / 'recus.jsonl'
GARDES = pathlib.Path('/run/sawm-labo/gardes')
SYSTEMD_RUNTIME = pathlib.Path('/run/systemd/system')
CGROUP = pathlib.Path('/sys/fs/cgroup')
BPF = pathlib.Path('/sys/fs/bpf/sawm')
BOOT_ID = pathlib.Path('/proc/sys/kernel/random/boot_id')
ROOT_UID = 0
BIN = {'systemctl': '/usr/bin/systemctl', 'bpftool': '/usr/sbin/bpftool'}
ENV_FIGE = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C'}
DELAI = 20
UNITE_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,100}\.service$')
ID_RE = re.compile(r'^[A-Za-z0-9._~:+/=-]{1,160}$')
PROTEGEES = {'labo-temoin.service', 'labo-recepteur.service', 'labo-telemetrie.service',
             'labo-lsm.service', 'labo-capteur-exec.service',
             'labo-collecteur.service', 'labo-veille.service'}


class Refus(Exception):
    def __init__(self, motif, detail=''):
        super().__init__(f'{motif}: {detail}')
        self.motif, self.detail = motif, detail


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _canon(objet):
    return json.dumps(objet, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode()


def _protege(st, nom, *, fichier=True):
    attendu = stat.S_ISREG(st.st_mode) if fichier else stat.S_ISDIR(st.st_mode)
    if not attendu or st.st_uid != ROOT_UID or st.st_mode & 0o022:
        raise Refus('permissions_non_fiables', str(nom))
    if fichier and st.st_nlink != 1:
        raise Refus('liens_multiples', str(nom))


def _racine_fiable():
    if RACINE.resolve() != RACINE or RACINE.is_symlink():
        raise Refus('racine_symbolique', str(RACINE))
    _protege(RACINE.stat(), RACINE, fichier=False)


def _lire_fichier_fiable(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        _protege(os.fstat(f.fileno()), path)
        data = f.read(1024*1024 + 1)
    if len(data) > 1024*1024:
        raise Refus('fichier_trop_grand', str(path))
    return data


def manifeste():
    _racine_fiable()
    try:
        data = _lire_fichier_fiable(MANIFESTE)
        m = json.loads(data)
    except (OSError, ValueError) as e:
        raise Refus('manifeste_invalide', str(e)) from None
    if not isinstance(m, dict) or m.get('generation') in (None, ''):
        raise Refus('generation_manifeste_absente')
    if not isinstance(m.get('unites_autorisees'), list):
        raise Refus('unites_manifeste_absentes')
    m['_sha256'] = _sha(data)
    return m


def run(nom, *args, codes_admis=(0,)):
    chemin = BIN.get(nom)
    if not chemin or not pathlib.Path(chemin).is_file():
        raise Refus('binaire_non_fiable', nom)
    try:
        p = subprocess.run([chemin, *args], capture_output=True, text=True,
                           timeout=DELAI, env=ENV_FIGE)
    except subprocess.TimeoutExpired:
        raise Refus('delai_depasse_issue_inconnue', nom) from None
    if p.returncode not in codes_admis:
        raise Refus('code_retour_refuse', f'{nom}: {p.returncode}: {p.stderr[:200]}')
    return p.returncode, p.stdout, p.stderr


def _unite(nom):
    if not isinstance(nom, str):
        raise Refus('unite_absente')
    nom = nom if nom.endswith('.service') else nom + '.service'
    if not UNITE_RE.fullmatch(nom):
        raise Refus('unite_malformee', nom)
    return nom


def _etat_unite(unite):
    champs = ('Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'ControlGroup',
              'Slice', 'InvocationID', 'NRestarts', 'FragmentPath', 'DropInPaths',
              'Restart', 'KillMode', 'ConditionResult')
    _, texte, _ = run('systemctl', 'show', '--property=' + ','.join(champs), '--', unite)
    etat = dict(l.split('=', 1) for l in texte.splitlines() if '=' in l)
    if etat.get('Id') != unite or etat.get('LoadState') != 'loaded':
        raise Refus('unite_non_chargee', unite)
    return etat


def unite_autorisee(cible, m):
    unite = _unite(cible)
    if unite in PROTEGEES or unite in {_unite(u) for u in m.get('unites_protegees', [])}:
        raise Refus('unite_protegee', unite)
    if unite not in {_unite(u) for u in m['unites_autorisees']}:
        raise Refus('unite_hors_manifeste', unite)
    etat = _etat_unite(unite)
    tranches = m.get('tranches_autorisees', [])
    if not tranches or etat.get('Slice') not in tranches:
        raise Refus('unite_hors_tranche', etat.get('Slice', ''))
    cg = etat.get('ControlGroup', '')
    if cg:
        morceaux = pathlib.PurePosixPath(cg).parts
        if not cg.startswith('/') or '..' in morceaux or morceaux[-1] != unite:
            raise Refus('cgroup_non_specifique', cg)
        if etat['Slice'] not in morceaux:
            raise Refus('cgroup_hors_tranche', cg)
    attendu = m.get('identites_unites', {}).get(unite, {})
    for champ in ('InvocationID', 'FragmentPath', 'Slice'):
        if champ in attendu and attendu[champ] != etat.get(champ):
            raise Refus('identite_unite_changee', champ)
    liee = m.get('_identite_attendue')
    if liee is not None:
        if liee.get('cible') != unite:
            raise Refus('identite_attendue_cible_differente')
        for champ in ('InvocationID', 'MainPID', 'ControlGroup'):
            if etat.get(champ) != liee.get(champ):
                raise Refus('identite_attendue_changee', champ)
    return unite, etat


def verifier_identite_attendue(demande, m):
    """Lie la mutation à l'invocation observée, sous le verrou de l'exécuteur.

    Le champ est facultatif pour les anciens essais; la veille le fournit.
    Chaque relecture unite_autorisee de l'action contrôle aussi cette identité.
    Le verrou sérialise nos commandes, pas les changements autonomes de l'OS.
    """
    if 'expected_identity' not in demande:
        return m
    attendu = demande['expected_identity']
    champs = ('cible', 'boot_id', 'InvocationID', 'MainPID', 'ControlGroup')
    if not isinstance(attendu, dict) or set(attendu) != set(champs) \
            or any(not isinstance(attendu.get(k), str) or not attendu[k] for k in champs) \
            or not attendu['MainPID'].isdigit() or int(attendu['MainPID']) <= 0:
        raise Refus('identite_attendue_incomplete')
    if attendu['cible'] != _unite(demande.get('cible')):
        raise Refus('identite_attendue_cible_differente')
    if attendu['boot_id'] != BOOT_ID.read_text().strip():
        raise Refus('identite_attendue_redemarrage')
    lie = {**m, '_identite_attendue': attendu}
    unite_autorisee(demande.get('cible'), lie)
    return lie


def _dossier_fiable(path):
    path.mkdir(mode=0o755, parents=True, exist_ok=True)
    if path.resolve() != path or path.is_symlink():
        raise Refus('dossier_symbolique', str(path))
    _protege(path.stat(), path, fichier=False)


def _ecrire_atomique(path, data):
    _dossier_fiable(path.parent)
    fd, temporaire = tempfile.mkstemp(prefix='.sawm-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporaire, path)
    finally:
        pathlib.Path(temporaire).unlink(missing_ok=True)


def _cgroup_vide(cg):
    if not cg:
        return True
    p = CGROUP / cg.lstrip('/')
    if not p.exists():
        return True
    if p.resolve() != p:
        raise Refus('cgroup_symbolique', cg)
    lignes = (p / 'cgroup.events').read_text().splitlines()
    etat = dict(l.split() for l in lignes)
    if 'populated' not in etat:
        raise Refus('etat_cgroup_inconnu', cg)
    return etat['populated'] == '0'


def _arreter_unite(cible, m, decision_id):
    unite, avant = unite_autorisee(cible, m)
    if avant.get('KillMode') != 'control-group':
        raise Refus('killmode_non_borne', avant.get('KillMode', ''))
    fenetre = float(m.get('fenetre_verification_s', 1.0))
    if not .1 <= fenetre <= 10:
        raise Refus('fenetre_hors_bornes')
    # La garde s'applique à CETTE unité, quelle que soit la source d'activation.
    # Pas d'inférence de familles .timer/.path potentiellement hors manifeste.
    garde = GARDES / (unite + '.stop')
    dropin = SYSTEMD_RUNTIME / (unite + '.d') / '90-sawm-lab-stop.conf'
    _ecrire_atomique(garde, _canon({'decision_id': decision_id, 'unite': unite}))
    _ecrire_atomique(dropin, (f'[Unit]\nConditionPathExists=!{garde}\n'
                             '[Service]\nRestart=no\n').encode())
    run('systemctl', 'daemon-reload')
    # Relire après reload : une modification concurrente d'unité est un refus.
    _, relu = unite_autorisee(cible, m)
    if avant.get('InvocationID') != relu.get('InvocationID'):
        raise Refus('invocation_changee_avant_arret', unite)
    if relu.get('Restart') != 'no' or str(dropin) not in relu.get('DropInPaths', '').split():
        raise Refus('garde_non_chargee', unite)
    run('systemctl', 'stop', '--', unite)
    debut = time.monotonic()
    observations = 0
    while True:
        apres = _etat_unite(unite)
        observations += 1
        if (apres.get('ActiveState') not in ('inactive', 'failed')
                or apres.get('MainPID') != '0'
                or not _cgroup_vide(avant.get('ControlGroup', ''))):
            raise Refus('arret_non_verifie', unite)
        if time.monotonic() - debut >= fenetre:
            break
        time.sleep(min(.2, fenetre))
    return dict(mecanisme='garde_systemd_et_stop_unite_exacte', unite=unite,
                cgroup=avant.get('ControlGroup'), avant=avant, apres=apres,
                garde=str(garde), garde_chargee=True, arret_verifie=True,
                observations=observations, fenetre_s=fenetre,
                unite_active_avant=avant.get('ActiveState') == 'active',
                interruption_transfert='a_verifier_au_recepteur', effet_verifie=True)


def act_geler_transfert(cible, m, decision_id):
    return _arreter_unite(cible, m, decision_id)


def act_arreter_service(cible, m, decision_id):
    return _arreter_unite(cible, m, decision_id)


def act_limiter_cpu(cible, m, decision_id):
    unite, _ = unite_autorisee(cible, m)
    quota = int(m.get('quota_cpu_pct', 20))
    if not 1 <= quota <= 100:
        raise Refus('quota_hors_bornes')
    run('systemctl', 'set-property', '--runtime', '--', unite, f'CPUQuota={quota}%')
    _, texte, _ = run('systemctl', 'show', '--property=CPUQuotaPerSecUSec', '--value', '--', unite)
    return {'unite': unite, 'quota_demande_pct': quota, 'relu': texte.strip(),
            'effet_verifie': False, 'verification_requise': 'cpu.stat sous charge'}


def _base_fixtures(m, cle='bac_fixtures'):
    p = pathlib.Path(m[cle])
    if not p.is_absolute() or p == RACINE or RACINE not in p.parents:
        raise Refus('bac_hors_laboratoire', str(p))
    if p.resolve() != p or not p.is_dir():
        raise Refus('bac_non_fiable', str(p))
    return p


@contextlib.contextmanager
def _fichier(base, relatif, flags=os.O_RDONLY):
    p = pathlib.PurePosixPath(relatif)
    if p.is_absolute() or not p.parts or any(x in ('.', '..') for x in p.parts):
        raise Refus('chemin_hors_bac', relatif)
    fd_dir = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fd = None
    try:
        for composant in p.parts[:-1]:
            suivant = os.open(composant, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd_dir)
            os.close(fd_dir)
            fd_dir = suivant
        fd = os.open(p.name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o644, dir_fd=fd_dir)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise Refus('fixture_non_reguliere', relatif)
        yield fd, fd_dir, p.name, st
    finally:
        if fd is not None:
            os.close(fd)
        os.close(fd_dir)


def chemin_autorise(cible, m):
    base = _base_fixtures(m)
    try:
        relatif = str(pathlib.Path(cible).relative_to(base))
    except (TypeError, ValueError):
        raise Refus('chemin_hors_bac', str(cible)) from None
    with _fichier(base, relatif):
        return base / relatif


def _empreinte_fd(fd):
    h = hashlib.sha256()
    while bloc := os.read(fd, 65536):
        h.update(bloc)
    return h.hexdigest()


def act_refuser_inode(cible, m, decision_id):
    base = _base_fixtures(m)
    p = chemin_autorise(cible, m)
    with _fichier(base, str(p.relative_to(base))) as (fd, dossier, nom, st):
        cle = [f'{b:02x}' for b in struct.pack('<Q', st.st_ino)]
        val = [f'{b:02x}' for b in bytes.fromhex(_sha(decision_id.encode())[:16])]
        run('bpftool', 'map', 'update', 'pinned', str(BPF/'inodes_refusees'),
            'key', 'hex', *cle, 'value', 'hex', *val)
        nouveau = os.stat(nom, dir_fd=dossier, follow_symlinks=False)
        if (st.st_dev, st.st_ino) != (nouveau.st_dev, nouveau.st_ino):
            raise Refus('cible_changee_apres_action')
        refuse = False
        try:
            autre = os.open(nom, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dossier)
        except PermissionError:
            refuse = True
        else:
            os.close(autre)
    return dict(inode=st.st_ino, device=st.st_dev, chemin=str(p),
                refus_constate=refuse, effet_verifie=refuse,
                limite='politique existante indexee par inode seul; descripteurs ouverts non revoques')


def _cible_fixtures(cible, m):
    if cible not in m.get('cibles_fixtures', ['fixtures']):
        raise Refus('cible_fixtures_hors_manifeste', str(cible))


def act_verifier_integrite(cible, m, decision_id):
    _cible_fixtures(cible, m)
    base = _base_fixtures(m)
    attendues = m.get('empreintes_fixtures', {})
    if not attendues:
        raise Refus('empreintes_reference_absentes')
    vus, alteres, disparus = {}, [], []
    for nom, attendu in attendues.items():
        if not re.fullmatch(r'[0-9a-f]{64}', attendu):
            raise Refus('empreinte_reference_non_sha256', nom)
        try:
            with _fichier(base, nom) as (fd, *_):
                vus[nom] = _empreinte_fd(fd)
        except FileNotFoundError:
            disparus.append(nom)
            continue
        if vus[nom] != attendu:
            alteres.append(nom)
    return dict(verifies=len(vus), alteres=alteres, disparus=disparus,
                integre=not alteres and not disparus, effet_verifie=not alteres and not disparus,
                portee='fichiers du manifeste; ne conclut pas absence d autres objets')


def act_restaurer_fixtures(cible, m, decision_id):
    _cible_fixtures(cible, m)
    base, ref = _base_fixtures(m), _base_fixtures(m, 'reference_fixtures')
    if base == ref or base in ref.parents or ref in base.parents:
        raise Refus('reference_et_bac_non_distincts')
    # Le cache local n'est accepté qu'avec les empreintes complètes du manifeste
    # racine. Restaurer des fichiers préexistants, pas supprimer un arbre entier.
    attendues = m.get('empreintes_fixtures', {})
    if not attendues:
        raise Refus('empreintes_reference_absentes')
    for nom, attendu in attendues.items():
        if not re.fullmatch(r'[0-9a-f]{64}', attendu):
            raise Refus('empreinte_reference_non_sha256', nom)
        with _fichier(ref, nom) as (source, *_):
            if _empreinte_fd(source) != attendu:
                raise Refus('reference_alteree', nom)
            os.lseek(source, 0, os.SEEK_SET)
            # Écriture par descripteur épinglé : pas de rsync/delete ni suivi de liens.
            with _fichier(base, nom, os.O_WRONLY | os.O_CREAT) as (dest, *_):
                os.ftruncate(dest, 0)
                while bloc := os.read(source, 65536):
                    vue = memoryview(bloc)
                    while vue:
                        vue = vue[os.write(dest, vue):]
                os.fsync(dest)
    resultat = act_verifier_integrite(cible, m, decision_id)
    resultat['restauration'] = 'fixtures_existantes_depuis_cache_verifie'
    return resultat


def act_revoquer_jeton(cible, m, decision_id):
    config = m.get('jetons', {})
    if cible not in config.get('cibles_autorisees', []):
        raise Refus('jeton_hors_manifeste', str(cible))
    p = pathlib.Path(config['etat'])
    if RACINE not in p.parents or p.resolve() != p:
        raise Refus('etat_jeton_hors_laboratoire')
    donnees = json.loads(_lire_fichier_fiable(p))
    donnees.update(version=int(donnees.get('version', 0))+1,
                   decision_id=decision_id, revoque_le_ms=int(time.time()*1000))
    _ecrire_atomique(p, _canon(donnees))
    return dict(version=donnees['version'], cible=cible, effet_verifie=False,
                verification_requise='refus applicatif du jeton precedent')


def act_observer(cible, m, decision_id):
    return {'note': 'aucune mutation du service', 'effet_verifie': True}


ACTIONS = {'ne-rien-faire': act_observer, 'ouvrir-dossier': act_observer,
           'demander-clarification': act_observer, 'geler-transfert': act_geler_transfert,
           'arreter-service': act_arreter_service, 'limiter-cpu': act_limiter_cpu,
           'refuser-inode': act_refuser_inode, 'restaurer-fixtures': act_restaurer_fixtures,
           'verifier-integrite': act_verifier_integrite, 'revoquer-jeton': act_revoquer_jeton}


@contextlib.contextmanager
def verrou():
    _racine_fiable()
    fd = os.open(RACINE/'.executeur.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        _protege(os.fstat(fd), 'verrou')
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _journal(entree):
    fd = os.open(RECUS, os.O_CREAT | os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'ab') as f:
        _protege(os.fstat(f.fileno()), RECUS)
        f.write(_canon(entree) + b'\n')
        f.flush()
        os.fsync(f.fileno())


def _precedent(decision_id):
    if not RECUS.exists():
        return None
    fd = os.open(RECUS, os.O_RDONLY | os.O_NOFOLLOW)
    precedent = None
    with os.fdopen(fd) as f:
        _protege(os.fstat(f.fileno()), RECUS)
        for ligne in f:
            try:
                r = json.loads(ligne)
            except ValueError:
                raise Refus('journal_corrompu') from None
            if r.get('decision_id') == decision_id:
                precedent = r
    return precedent


_MAINTENANCE_MODULE = None


def _charger_maintenance():
    """Importe le helper voisin par chemin, jamais par un sys.path ambiant.

    Le chemin source de repli existe seulement dans le dépôt, sous invite/.
    Une installation VM incomplète échoue au lieu de charger un homonyme.
    """
    global _MAINTENANCE_MODULE
    if _MAINTENANCE_MODULE is not None:
        return _MAINTENANCE_MODULE
    import importlib.util
    script = pathlib.Path(__file__).resolve()
    helper = script.with_name('maintenance.py')
    if not helper.is_file() and script.parent.parent.name == 'invite':
        helper = script.parents[2] / 'controleur' / 'maintenance.py'
    if not helper.is_file() or helper.is_symlink():
        raise Refus('module_maintenance_absent_ou_symbolique')
    spec = importlib.util.spec_from_file_location('_sawm_executor_maintenance', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _MAINTENANCE_MODULE = module
    return module


def verifier_maintenance(demande, m):
    """Requalifie les opérations depuis Linux ; aucun booléen ni scope du LLM.

    L'exception couvre seulement un arrêt visant une cible de défense fichiers.
    Geler un transfert, limiter CPU ou révoquer un accès ne sont pas autorisés
    par un mandat d'écriture. Une erreur d'inspection est un refus à signaler.
    """
    if demande.get('action') != 'arreter-service' or 'maintenance' not in m:
        return {'checked': False, 'veto': False}
    cible = _unite(demande.get('cible'))
    defense = m.get('defense_fichiers') or {}
    targets = defense.get('targets', []) if defense.get('enabled') is True else []
    if not isinstance(targets, list):
        raise Refus('politique_maintenance_invalide')
    targets = [target for target in targets if isinstance(target, dict) and target.get('unit') == cible]
    legacy = m.get('database_policy') or {}
    if not targets and legacy.get('unit') == cible and legacy.get('path'):
        targets = [{'unit': cible, 'path': legacy['path'], 'kind': 'sqlite',
                    'reference_sha256': legacy.get('reference_sha256')}]
    if not targets:
        return {'checked': False, 'veto': False, 'reason': 'aucune_cible_fichier_locale'}
    try:
        maintenance_module = _charger_maintenance()
        observer_os = maintenance_module.observer_os
        inspecter_operations = maintenance_module.inspecter_operations
        evaluate = maintenance_module.evaluate
        OBS_KEYS = maintenance_module.OBS_KEYS
        scopes = []
        for target in targets:
            before = observer_os(cible, target.get('path'))
            measured = inspecter_operations(target, before)
            after = observer_os(cible, target.get('path'))
            if any(before.get(k) != after.get(k) for k in OBS_KEYS):
                raise ValueError('identite_os_changee_avant_veto')
            for operation in measured['operations']:
                result = evaluate(m, after, unit=cible, operation=operation, object_path=target['path'])
                # Unknown is not an instruction to kill. Absence/expiry/revocation
                # merely means no maintenance exception to the existing mandate.
                if result['reason'] in {'politique_absente_ou_invalide', 'requete_invalide', 'horloge_invalide',
                        'bornes_invalides', 'identite_os_non_verifiee', 'observation_perimee_ou_future',
                        'registre_mandats_invalide', 'registre_mandats_ambigu', 'contrat_malforme'}:
                    raise ValueError(result['reason'])
                scopes.append({'operation': operation, 'object_path': target['path'], **result})
        if not scopes:
            raise ValueError('aucune_operation_fichier_confirmee')
        return {'checked': True, 'veto': all(scope['authorized'] for scope in scopes),
                'scopes': scopes, 'source': 'politique_locale_et_observation_os_fraiche'}
    except Exception as exc:
        raise Refus('maintenance_non_verifiable', str(exc)) from None


def verifier_actions_unite(action, cible, m):
    """Restriction supplémentaire facultative ; n'accorde jamais de droit global."""
    if 'actions_par_unite' not in m:
        return
    rules = m['actions_par_unite']
    if (not isinstance(rules, dict) or any(
            not isinstance(unit, str) or not UNITE_RE.fullmatch(unit)
            or not isinstance(actions, list) or not actions
            or any(not isinstance(value, str) or value not in ACTIONS for value in actions)
            or len(set(actions)) != len(actions)
            for unit, actions in rules.items())):
        raise Refus('actions_par_unite_invalides')
    # Les décisions sans mutation acceptent aussi une cible descriptive. Les
    # fonctions de mutation conservent leur propre validation stricte d'unité.
    unit = cible if isinstance(cible, str) and UNITE_RE.fullmatch(cible) else None
    if unit in rules and action not in rules[unit]:
        raise Refus('action_hors_mandat_unite', action)



_ACTIONS_SANS_MUTATION = frozenset(('ne-rien-faire', 'ouvrir-dossier',
                                  'demander-clarification', 'verifier-integrite'))
_DEFENSE_AUTORISATION_MODULE = None


def verifier_defense_profondeur(demande, m):
    """Toute voie d'exécution rencontre ce contrôle si le profil est installé."""
    if 'defense_profondeur' not in m or demande.get('action') in _ACTIONS_SANS_MUTATION:
        return None
    global _DEFENSE_AUTORISATION_MODULE
    if _DEFENSE_AUTORISATION_MODULE is None:
        try:
            if __package__:
                from . import defense_autorisation
                _DEFENSE_AUTORISATION_MODULE = defense_autorisation
            else:
                import importlib.util
                helper = pathlib.Path(__file__).resolve().with_name('defense_autorisation.py')
                if not helper.is_file() or helper.is_symlink():
                    raise ValueError('module absent ou symbolique')
                _protege(helper.stat(), helper)
                spec = importlib.util.spec_from_file_location('_sawm_executor_depth', helper)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                _DEFENSE_AUTORISATION_MODULE = module
        except Exception:
            raise Refus('defense_profondeur_verificateur_indisponible') from None
    envelope = demande.get('defense_profondeur_autorisation')
    try:
        _DEFENSE_AUTORISATION_MODULE.verify_authorization(
            envelope, demande, m, int(time.time()*1000))
    except Exception:
        raise Refus('defense_profondeur_autorisation_refusee') from None
    return {'valide': True, 'key_id': envelope['key_id'],
            'issued_ms': envelope['payload']['issued_ms'], 'expires_ms': envelope['payload']['expires_ms']}


def appliquer(demande):
    t0 = time.monotonic()
    recu = {'schema': 'sawm-lab-execution/v2', 'applique': False, 'effet_verifie': False,
            'issue': 'non_appliquee', 'demande_ms': int(time.time()*1000)}
    try:
        if not isinstance(demande, dict):
            raise Refus('demande_non_objet')
        decision_id = demande.get('decision_id')
        if not isinstance(decision_id, str) or not ID_RE.fullmatch(decision_id):
            raise Refus('decision_id_invalide')
        recu.update({k: demande.get(k) for k in
                     ('decision_id', 'action', 'cible', 'run_id', 'generation', 'manifest_sha256', 'expected_identity')})
        empreinte = _sha(_canon(demande))
        recu['demande_sha256'] = empreinte
        with verrou():
            m = manifeste()
            if demande.get('generation') is None or str(demande['generation']) != str(m['generation']):
                raise Refus('generation_absente_ou_perimee')
            if demande.get('manifest_sha256') != m['_sha256']:
                raise Refus('manifeste_absent_ou_modifie')
            precedent = _precedent(decision_id)
            if precedent:
                if precedent.get('demande_sha256') != empreinte:
                    raise Refus('rejeu_contradictoire')
                if precedent.get('etat') != 'termine':
                    raise Refus('execution_precedente_issue_inconnue', 'verification operateur requise')
                return {**precedent, 'rejeu': True}
            action = demande.get('action')
            fn = ACTIONS.get(action)
            if fn is None:
                raise Refus('action_inconnue', str(action))
            if action not in m.get('actions_autorisees', list(ACTIONS)):
                raise Refus('action_hors_manifeste', action)
            verifier_actions_unite(action, demande.get('cible'), m)
            m = verifier_identite_attendue(demande, m)
            if manifeste()['_sha256'] != m['_sha256']:
                raise Refus('manifeste_modifie_avant_verification_maintenance')
            recu['maintenance'] = verifier_maintenance(demande, m)
            if recu['maintenance']['veto']:
                _journal({**recu, 'etat': 'refuse_maintenance', 'refus': {'motif': 'maintenance_signee_preservee'}})
                raise Refus('maintenance_signee_preservee', 'opérations observées couvertes par mandats signés actifs')
            autorisation_defense = verifier_defense_profondeur(demande, m)
            if autorisation_defense is not None:
                recu['defense_profondeur'] = autorisation_defense
            # Entrée durable AVANT mutation : un crash n'autorise jamais sa répétition aveugle.
            _journal({**recu, 'etat': 'en_cours'})
            try:
                if manifeste()['_sha256'] != m['_sha256']:
                    raise Refus('manifeste_modifie_avant_action')
                # Le fsync précédent ne prolonge pas la durée d'une autorisation.
                verifier_defense_profondeur(demande, m)
                recu['effet'] = fn(demande.get('cible'), m, decision_id)
                recu['applique'] = True
                recu['effet_verifie'] = recu['effet'].get('effet_verifie') is True
                recu['issue'] = 'appliquee'
            except Exception as e:
                recu['issue'] = 'partielle_ou_inconnue'
                recu['refus'] = {'motif': getattr(e, 'motif', 'erreur_executeur'),
                                 'detail': getattr(e, 'detail', str(e))}
            recu.update(etat='termine', recu_ms=int(time.time()*1000),
                         duree_ms=round((time.monotonic()-t0)*1000, 3))
            _journal(recu)
    except Exception as e:
        recu['refus'] = {'motif': getattr(e, 'motif', 'erreur_executeur'),
                         'detail': getattr(e, 'detail', str(e))}
        recu.update(etat='refuse', recu_ms=int(time.time()*1000),
                     duree_ms=round((time.monotonic()-t0)*1000, 3))
    return recu


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--describe', action='store_true')
    args = p.parse_args()
    if os.geteuid() != 0:
        p.exit(2, 'exécuteur réservé au compte root de la VM laboratoire\n')
    if args.describe:
        m = manifeste()
        print(json.dumps({'generation': m['generation'], 'manifest_sha256': m['_sha256'],
                          'unites_autorisees': m['unites_autorisees']}))
        return 0
    data = sys.stdin.buffer.read(65537)
    if len(data) > 65536:
        p.exit(2, 'demande trop grande\n')
    recu = appliquer(json.loads(data or '{}'))
    print(json.dumps(recu, ensure_ascii=False))
    return 0 if recu['applique'] else 2


if __name__ == '__main__':
    sys.exit(main())
