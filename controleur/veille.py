#!/usr/bin/env python3
"""Veille indépendante des scénarios, bornée et en observation par défaut.

Lit /api/etat et le manifeste; les inspections serveur exigent le drapeau local.
Ne configure ni ne lance de charge.
--cloud autorise au plus quatre analyses SAWM par heure (réservations durables).
--apply exige aussi veille.actions_automatiques dans le manifeste courant.
La surveillance continue pendant l'analyse Cloud. Les angles morts des
inventaires périodiques sont déclarés ; une source inconnue n'est pas un verdict.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import http.client
import json
import os
import pathlib
import queue
import re
import signal
import sys
import threading
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from controleur.motifs_incidents import motif_detection
URL_HOTE = '127.0.0.1'
URL_PORT = int(os.environ.get('LABO_HTTP', '8899'))
MAX_AGE_MS = 3000
ACTIONS_AUTOMATIQUES = {'geler-transfert', 'arreter-service', 'limiter-cpu'}
PROTEGEES = {'labo-temoin.service', 'labo-recepteur.service', 'labo-telemetrie.service',
             'labo-lsm.service', 'labo-capteur-exec.service',
             'labo-collecteur.service', 'labo-veille.service'}


def empreinte(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False).encode()).hexdigest()


def dashboard(route, objet=None):
    # HTTPConnection évite proxy d'environnement et redirection hors loopback.
    connexion = http.client.HTTPConnection(URL_HOTE, URL_PORT, timeout=2)
    try:
        corps = None if objet is None else json.dumps(objet, ensure_ascii=False).encode()
        connexion.request('GET' if objet is None else 'POST', route, body=corps,
                          headers={'Content-Type': 'application/json'} if corps else {})
        r = connexion.getresponse()
        raw = r.read(2*1024*1024+1)
        if r.status != 200 or len(raw) > 2*1024*1024:
            raise RuntimeError(f'dashboard: HTTP {r.status} ou réponse trop grande')
        return json.loads(raw)
    finally:
        connexion.close()


def lire_manifeste_invite():
    from controleur.vm_labo import json_code
    return json_code("import pathlib,json,hashlib\np=pathlib.Path('/opt/sawm-labo/manifeste.json');"
                     "b=p.read_bytes();m=json.loads(b);m['_sha256']=hashlib.sha256(b).hexdigest();"
                     "print(json.dumps(m))")


def _unite(nom):
    if not isinstance(nom, str) or not nom:
        return None
    return nom if nom.endswith('.service') else nom+'.service'


def ressources(m):
    interdites = PROTEGEES | {_unite(x) for x in m.get('unites_protegees', [])}
    return sorted({_unite(x) for x in m.get('unites_autorisees', [])} - interdites - {None})


def frais(etat):
    t = etat.get('telemetrie_invite') or {}
    return (etat.get('mode') == 'DIRECT' and t.get('connectee') is True
            and isinstance(t.get('age_ms'), (int, float)) and 0 <= t['age_ms'] <= MAX_AGE_MS
            and bool(etat.get('invite')))


def unite_socket(s):
    cg = s.get('cgroup')
    if not isinstance(cg, str):
        return None
    lignes = cg.splitlines()
    # L'inventaire publie /proc/PID/cgroup. Aucune extraction depuis la ligne de commande.
    chemins = [l.split(':', 2)[-1] for l in lignes]
    for chemin in chemins:
        for element in reversed(chemin.split('/')):
            if element.endswith('.service') and '..' not in element:
                return element
    return None


def evenement(genre, identite, faits, *, unite=None, analysable=False, canal='incident'):
    cle = [genre, identite] if canal == 'incident' else [genre, identite, canal]
    return {'id': 'veille-'+empreinte(cle)[:24], 'genre': genre, 'canal': canal,
            'faits': faits, 'unite': unite, 'analysable': analysable,
            'survenu_observe_ms': int(time.time()*1000)}


class Detecteur:
    """Détecte écarts techniques ; ne les qualifie jamais automatiquement d'attaque."""
    def analyser(self, etat, m):
        if etat.get('mode') != 'DIRECT':
            return [evenement('mode_non_direct', 'mode', [{'mode': etat.get('mode')}])]
        if not frais(etat):
            return [evenement('telemetrie_indisponible', 'telemetrie',
                              [{'telemetrie': etat.get('telemetrie_invite')}])]
        e = etat['invite'][-1]
        baseline = m.get('veille')
        if not isinstance(baseline, dict) or not isinstance(baseline.get('unites_connues'), list) \
                or not isinstance(baseline.get('sources_connues'), list):
            return [evenement('baseline_absente', 'baseline',
                              [{'limite': 'manifeste sans veille.unites_connues/sources_connues'}])]
        connues = {_unite(x) for x in baseline['unites_connues']}
        sources = set(baseline['sources_connues'])
        out = []
        capteurs = e.get('capteurs') or {}
        for capteur in ('ebpf_exec_actif', 'lsm_attache'):
            if capteurs.get(capteur) is not True:
                out.append(evenement('capteur_indisponible', capteur,
                                     [{'capteur': capteur, 'valeur': capteurs.get(capteur)}]))
        sockets = e.get('connexions')
        if not isinstance(sockets, list):
            out.append(evenement('inventaire_connexions_absent', 'connexions',
                                 [{'limite': 'aucune conclusion de silence réseau'}]))
        else:
            sans_proprietaire = {}
            # Un port n'est qualifié de service que s'il est observé LISTEN.
            def port(adresse):
                valeur = str(adresse or '').rsplit(':', 1)[-1]
                return valeur if valeur.isdigit() else None
            ecoutes = {port(s.get('locale')) for s in sockets
                       if str(s.get('etat', '')).upper() == 'LISTEN'} - {None}
            for s in sockets[:100]:
                u = unite_socket(s)
                if u in connues:
                    continue
                pid = s.get('pid')
                if type(pid) is not int or pid <= 0:
                    # TIME-WAIT après fermeture n'a normalement plus de PID.
                    # SYN/ESTAB non attribués restent une limite de couverture,
                    # pas un incident par port éphémère et jamais une cible.
                    service = next((p for p in (port(s.get('locale')), port(s.get('distante')))
                                    if p in ecoutes), None)
                    cle = (str(s.get('etat', 'inconnu'))[:30], service)
                    sans_proprietaire[cle] = sans_proprietaire.get(cle, 0) + 1
                    continue
                identite = [e.get('boot_id'), pid, s.get('starttime'), u, s.get('cgroup')]
                out.append(evenement('processus_reseau_hors_baseline', identite,
                    [{'unite_observee': u, 'pid_observe': pid, 'cgroup_observe': s.get('cgroup'),
                      'locale': s.get('locale'), 'distante': s.get('distante'),
                      'etat_socket': s.get('etat'), 'source': 'inventaire OS périodique',
                      'identite_processus_complete': bool(e.get('boot_id') and s.get('starttime')),
                      'limite': 'nouveauté ≠ compromission; processus brefs possibles entre échantillons'}],
                    unite=u, analysable=u is not None))
            if sans_proprietaire:
                out.append(evenement('couverture_attribution_sockets', 'inventaire',
                    [{'nombre_echantillonne': sum(sans_proprietaire.values()),
                      'groupes': [{'etat_socket': cle[0], 'port_service_ecoute': cle[1], 'nombre': n}
                                  for cle, n in sans_proprietaire.items()],
                      'limite_inventaire': 100, 'lignes_inventaire': len(sockets),
                      'limite': 'Sockets sans PID regroupées; fermeture TIME-WAIT normale; attribution et intention non établies.'}],
                    canal='observation'))
        recepteur = e.get('recepteur')
        if not isinstance(recepteur, dict):
            out.append(evenement('recepteur_indisponible', 'recepteur', [{'compteur': None}]))
        else:
            for flux_id, flux in list((recepteur.get('flux') or {}).items())[-256:]:
                if flux.get('source_id') in sources:
                    continue
                # Métadonnée de l'émetteur, pas identité OS : observation seule.
                out.append(evenement('source_flux_hors_baseline', flux_id,
                    [{'source_declaree': flux.get('source_id'), 'octets_recus': flux.get('recus'),
                      'etat_reception': flux.get('etat'), 'debut_reception_ms': flux.get('debut_ms'),
                      'limite': 'source déclarative non corrélée à un processus OS'}], canal='observation'))
        fichiers = e.get('fichiers')
        if isinstance(fichiers, dict):
            if fichiers.get('erreur'):
                out.append(evenement('capteur_fichiers_indisponible', 'inotify',
                                     [{'erreur': str(fichiers['erreur'])[:300]}]))
            if isinstance(fichiers.get('pertes_file'), int) and fichiers['pertes_file'] > 0:
                out.append(evenement('pertes_capteur_fichiers', fichiers['pertes_file'],
                                     [{'pertes_file': fichiers['pertes_file']}]))
            connus = set(baseline.get('fichiers_connus', []))
            for f in (fichiers.get('evenements') or [])[-100:]:
                chemin = str(f.get('chemin', ''))[:300]
                operations = [str(x)[:40] for x in (f.get('operations') or [])[:8]]
                if chemin in connus and set(operations) <= {'lecture', 'ouverture', 'fermeture'}:
                    continue
                # Regroupement par objet/opération, pas un incident à chaque octet écrit.
                out.append(evenement('activite_fichier_observee', [chemin, operations],
                    [{'source': 'inotify', 'perimetre': fichiers.get('perimetre'),
                      'chemin_relatif': chemin, 'operations': operations,
                      'mur_evenement_ms': f.get('mur_epoch_ms'), 'pid': f.get('pid'),
                      'attribution_pid': fichiers.get('attribution_pid', False),
                      'limite': 'activité observée; ni nouveauté ni nom caché ne prouvent une attaque'}],
                    canal='observation'))
        return out


class Journal:
    MAX_VUS = 10000

    def __init__(self, dossier, audit=None):
        from collections import deque
        dossier.mkdir(parents=True, exist_ok=True)
        self.path = dossier/'journal.jsonl'
        self.lock = os.open(dossier/'.veille.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(self.lock)
            raise
        self.mutex = threading.RLock()
        self.audit = audit
        self.vus, self.reservations = set(), []
        self._ordre_vus = deque()
        self._migration_vue = False
        try:
            if audit is None:
                for entree in self._entrees_simples():
                    self._retenir(entree)
            else:
                # Seule la preuve vérifiée fait foi. Le journal lisible peut manquer.
                for entree in self._entrees_signees():
                    self._retenir(entree)
                if not self._migration_vue:
                    maintenant = time.time()
                    recentes = sum(x >= maintenant-3600 for x in self.reservations)
                    anciennes = sum(1 for e in self._entrees_simples()
                                    if e.get('type') == 'reservation_cloud'
                                    and self._epoch(e.get('epoch')) >= maintenant-3600)
                    # Conservateur : maximum quatre débits hérités. Ils expirent
                    # une heure après la migration, pas selon une date non prouvée.
                    compteur = min(4, max(0, anciennes-recentes))
                    self.ecrire('migration_budget_non_signe', epoch=maintenant,
                                nombre_reservations_importees=compteur,
                                nature='compteur_declare_non_authentifie',
                                conservation_prudente_secondes=3600,
                                anciennes_observations_retro_signees=False)
            self.reservations = [x for x in self.reservations if x >= time.time()-3600]
        except BaseException:
            os.close(self.lock)
            raise

    @staticmethod
    def _epoch(value):
        import math
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError('Horodatage de réservation invalide : budget fermé')
        return value

    def _entrees_simples(self):
        if not self.path.exists():
            return
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as file:
            for ligne in file:
                entree = json.loads(ligne)  # ancien budget illisible = refus
                if not isinstance(entree, dict) or 'type' not in entree:
                    raise ValueError('Journal de veille invalide')
                yield entree

    def _entrees_signees(self):
        from controleur import audit_signe as preuve
        with preuve._verrou(self.audit.path):
            statut = preuve._verifier(self.audit.path, self.audit.public_key_path)
            seq, precedent = 0, preuve.ZERO
            fd = os.open(self.audit.path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as file:
                while True:
                    ligne = file.readline(preuve.MAX_LINE+1)
                    if not ligne:
                        break
                    if len(ligne) > preuve.MAX_LINE or not ligne.endswith(b'\n'):
                        raise preuve.AuditInvalide('Lecture du journal signé interrompue')
                    objet = json.loads(ligne)
                    entree = preuve._verifier_signature(objet, self.audit.key.public_key())
                    if entree.get('seq') != seq+1 or entree.get('precedent') != precedent \
                            or entree.get('journal_id') != statut['journal_id'] \
                            or entree.get('key_id') != statut['key_id'] or entree.get('type') != 'evenement':
                        raise preuve.AuditInvalide('Chaîne signée modifiée pendant la lecture')
                    seq, precedent = entree['seq'], objet['sha256']
                    yield entree['evenement']
            if seq != statut['seq'] or precedent != statut['dernier_sha256']:
                raise preuve.AuditInvalide('Journal signé changé pendant la récupération')

    def _retenir(self, entree):
        genre = entree['type']
        if genre in ('incident', 'observation'):
            identifiant = entree['incident']['id']
            if not isinstance(identifiant, str) or len(identifiant) > 256:
                raise ValueError('Identifiant de veille invalide')
            if identifiant not in self.vus:
                self.vus.add(identifiant)
                self._ordre_vus.append(identifiant)
                while len(self._ordre_vus) > self.MAX_VUS:
                    self.vus.discard(self._ordre_vus.popleft())
        elif genre == 'reservation_cloud':
            epoch = self._epoch(entree['epoch'])
            if epoch >= time.time()-3600:
                self.reservations.append(epoch)
        elif genre == 'migration_budget_non_signe':
            if self._migration_vue:
                raise ValueError('Migration du budget répétée : refus')
            self._migration_vue = True
            compteur = entree.get('nombre_reservations_importees')
            epoch = self._epoch(entree['epoch'])
            if type(compteur) is not int or not 0 <= compteur <= 4 \
                    or entree.get('nature') != 'compteur_declare_non_authentifie':
                raise ValueError('Migration du budget invalide')
            if epoch >= time.time()-3600:
                self.reservations.extend([epoch]*compteur)

    def ecrire(self, genre, **data):
        with self.mutex:
            entry = {'type': genre, 'epoch': time.time(), **data}
            if self.audit is not None:
                self.audit.append(entry)  # Durable avant toute action dépendante.
                # Même si la copie lisible échoue ensuite, le débit reste acquis.
                self._retenir(entry)
            fd = os.open(self.path, os.O_CREAT | os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'a') as f:
                f.write(json.dumps(entry, ensure_ascii=False)+'\n')
                f.flush()
                os.fsync(f.fileno())

    def nouveau(self, incident):
        with self.mutex:
            if incident['id'] in self.vus:
                return False
            genre = 'observation' if incident.get('canal') == 'observation' else 'incident'
            self.ecrire(genre, incident=incident)
            if self.audit is None:
                self._retenir({'type': genre, 'incident': incident})
            return True

    def reserver(self, incident_id, limite=4, *, maintenant=None):
        with self.mutex:
            maintenant = self._epoch(time.time() if maintenant is None else maintenant)
            self.reservations = [x for x in self.reservations if x >= maintenant-3600]
            if len(self.reservations) >= limite:
                return False
            self.ecrire('reservation_cloud', incident_id=incident_id, epoch=maintenant)
            if self.audit is None:
                self.reservations.append(maintenant)
            return True

    def a_recuperer(self, max_age_s=600):
        """Relire les preuves avant de reprendre une analyse, jamais une action.

        Une décision, un début d'exécution ou un reçu coupe définitivement la
        reprise automatique pour cet incident. Les éventuelles suites manquantes
        figurent dans reprises_bloquees, à vérifier par l'opérateur.
        """
        if not isinstance(max_age_s, (int, float)) or isinstance(max_age_s, bool) \
                or not 0 < max_age_s <= 600:
            raise ValueError('La reprise est limitée aux dix dernières minutes')
        self.reprises_bloquees = []
        if self.audit is None:
            return []  # Aucun ancien journal non signé n'autorise une reprise.
        with self.mutex:
            maintenant = time.time()
            incidents, termines, engages, derniers = {}, set(), set(), {}
            terminaux = {'aucune_action', 'verification_action', 'retour', 'retour_memoire',
                         'retour_memoire_non_effectue_echeance', 'observation_expiree',
                         'analyse_annulee_manifeste_modifie'}
            action_engagee = {'decision', 'avant_execution', 'recu_execution', 'recu'}
            for entry in self._entrees_signees():
                genre = entry['type']
                if genre == 'incident':
                    incident = entry.get('incident') or {}
                    identifiant = incident.get('id')
                    observe_ms = incident.get('survenu_observe_ms')
                    if not isinstance(observe_ms, (int, float)) or isinstance(observe_ms, bool):
                        continue
                    age = maintenant-observe_ms/1000
                    if incident.get('analysable') is True and incident.get('canal') != 'observation' \
                            and isinstance(identifiant, str) and 0 <= age <= max_age_s:
                        incidents[identifiant] = incident
                else:
                    identifiant = entry.get('incident_id')
                if not isinstance(identifiant, str):
                    continue
                derniers[identifiant] = genre
                if genre in terminaux:
                    termines.add(identifiant)
                if genre in action_engagee:
                    engages.add(identifiant)
            # Les verdicts restent monotones, même après une analyse_indisponible
            # tardive ou un nouvel événement portant le même identifiant.
            self.reprises_bloquees = [
                {'incident_id': identifiant, 'motif': 'en_attente_preuves'
                    if derniers.get(identifiant) == 'en_attente_preuves'
                    else 'decision_ou_execution_sans_fin_confirmee',
                 'dernier_evenement': derniers.get(identifiant), 'reprise_action_automatique': False}
                for identifiant in incidents if identifiant in engages and identifiant not in termines
            ][-64:]
            return [incident for identifiant, incident in incidents.items()
                    if identifiant not in termines and identifiant not in engages][-64:]

    def close(self):
        os.close(self.lock)


def autoriser_action(decision, incident, ancien, courant, etat, appliquer, restant,
                     *, observation_ressources=None, observation_fichiers=None, reference_fichiers=None,
                     audit_profondeur=None, budget_cloud=None):
    if not appliquer:
        return 'mode_observation_ou_proposition'
    if restant < 125:
        return 'budget_temps_insuffisant_pour_action_et_retour'
    if not frais(etat):
        return 'telemetrie_non_fiable_au_moment_action'
    if not re.fullmatch(r'[a-f0-9]{64}', str(courant.get('_sha256', ''))) \
            or courant.get('generation') in (None, '') \
            or courant.get('_sha256') != ancien.get('_sha256') \
            or courant.get('generation') != ancien.get('generation'):
        return 'manifeste_modifie_pendant_analyse'
    if not decision.executable or decision.proposition is None:
        return 'proposition_non_executable'
    p = decision.proposition
    autorisees = set((courant.get('veille') or {}).get('actions_automatiques', []))
    if p.action not in ACTIONS_AUTOMATIQUES or p.action not in autorisees:
        return 'action_non_autorisee_pour_veille'
    if p.cible not in ressources(courant) or p.cible != incident.get('unite'):
        return 'cible_absente_ou_non_correllee'
    from controleur.defense_profondeur import refuse
    veto = refuse(courant, etat, audit=audit_profondeur, cloud_budget=budget_cloud)
    if veto:
        return veto
    if incident.get('genre') == 'diagnostic_defense_fichiers':
        if p.action != 'arreter-service':
            return 'action_non_qualifiee_pour_incident_fichier'
        from controleur.inspection_fichiers import refus_action
        paths = {f.get('objet') for f in incident.get('faits', []) if isinstance(f,dict) and isinstance(f.get('objet'),str)}
        if len(paths) != 1:
            return 'objet_fichier_absent_ou_ambigu'
        return refus_action(observation_fichiers, reference_fichiers, courant, p.cible, object_path=next(iter(paths)))
    identite = next((f.get('identite_os') for f in incident.get('faits', []) if f.get('identite_os')), None)
    if incident.get('genre') == 'ressources_a_enqueter':
        observation = observation_ressources or {}
        observe_ms = observation.get('observed_epoch_ms')
        if observation.get('observation_valid') is not True or observation.get('identity_stable') is not True \
                or observation.get('status') != 'observed' \
                or observation.get('action') != 'inspecter-processus' \
                or observation.get('unit') != p.cible \
                or type(observe_ms) not in (int, float) \
                or not 0 <= time.time()*1000-observe_ms <= MAX_AGE_MS \
                or not isinstance(observation.get('before'), dict) \
                or observation['before'] != observation.get('after'):
            return 'inspection_ressources_non_fiable_au_moment_action'
        champs = ('boot_id', 'pid', 'starttime_ticks', 'cgroup', 'invocation_id')
        if not isinstance(identite, dict) or identite.get('unit') != p.cible \
                or any(not identite.get(k) for k in champs):
            return 'identite_processus_incomplete'
        if any(observation['before'].get(k) != identite[k] for k in champs):
            return 'identite_processus_changee'
        return None
    if identite is None or not identite.get('boot_id') or not identite.get('starttime'):
        return 'identite_processus_incomplete'
    dernier = etat['invite'][-1]
    if dernier.get('boot_id') != identite['boot_id'] or not any(
            s.get('pid') == identite.get('pid') and s.get('starttime') == identite['starttime']
            and s.get('cgroup') == identite.get('cgroup') and unite_socket(s) == p.cible
            for s in dernier.get('connexions') or []):
        return 'identite_processus_changee'
    # Un processus ou un service disparu n'est pas interrompu après sa fin naturelle.
    if not any(unite_socket(s) == p.cible for s in etat['invite'][-1].get('connexions') or []):
        return 'activite_unite_plus_observee'
    return None


class Veille:
    def __init__(self, manifeste, journal, *, cloud=False, appliquer=False, limite_cloud=4,
                 poster=dashboard, lire_manifest=lire_manifeste_invite, fin=None):
        self.m, self.journal = manifeste, journal
        self.cloud, self.appliquer = cloud, appliquer
        self.limite_cloud = limite_cloud
        self.poster, self.lire_manifest = poster, lire_manifest
        self.fin = fin if fin is not None else time.monotonic()+300
        self.identifiant = 'veille-'+uuid.uuid4().hex[:16]
        self.detecteur = Detecteur()
        self.attente = queue.Queue(maxsize=64)
        self.indisponible_jusqua = 0.0
        self.echecs_cloud = 0
        self.correlateur = None
        self.dernier_battement = 0.0
        self.derniere_sante = None
        self.worker = None
        self.dispositions = None
        self._dispositions_entity = None
        self._dispositions_mutex = threading.RLock()
        self.perception_serveur = None
        self.posture_defense = None
        self._posture_fingerprint = None
        self._audit_profondeur = None
        self._audit_profondeur_monotone = None
        if (self.m.get('veille') or {}).get('enquete_autonome') is True:
            from controleur.perception_serveur import PerceptionServeur
            self.perception_serveur = PerceptionServeur()

    def publier(self, route, objet):
        try:
            self.poster(route, objet)
        except Exception as e:
            self.journal.ecrire('publication_echouee', route=route,
                                incident_id=objet.get('id'), erreur=type(e).__name__)

    def publier_attention(self, inc, statut, raison, *, decision=None, details=()):
        """Dossier visible pour l'humain, sans verdict ni permission supplémentaire.

        Le collecteur conserve ces mises à jour dans son journal persistant.
        Une mise à jour remplace la carte : reprendre les faits initiaux évite
        de perdre les observations quand l'analyse manque ou reste incertaine.
        """
        faits = [json.dumps(f, ensure_ascii=False)[:2000]
                 for f in inc.get('faits', [])[:20]]
        faits += [str(f)[:2000] for f in details[:8]]
        objet = {'id': inc['id'], 'titre': inc['genre'].replace('_', ' '),
                 'statut': statut, 'gravite': 'attention',
                 'raison_publique': str(raison)[:4000], 'faits': faits,
                 'motif_detection': motif_detection(inc),
                 'run_id': self.identifiant,
                 'origine': 'Revue humaine requise; anomalie ou couverture incomplète, pas un verdict malware'}
        if decision is not None:
            objet['decision_id'] = decision.decision_id
        self.publier('/api/incident', objet)

    def initialiser_dispositions(self, pont):
        """Isoler l'état local par espace et entité, jamais par nom de campagne."""
        from controleur.dispositions_serveur import DispositionsServeur
        scope = [pont.espace, pont.entite]
        if any(not isinstance(value, str) or not value or len(value) > 256 for value in scope):
            raise ValueError('identite_entite_dispositions_invalide')
        entity = 'basira-'+empreinte(scope)
        with self._dispositions_mutex:
            if self._dispositions_entity != entity:
                self.dispositions = DispositionsServeur(self.journal.path.parent/'dispositions', entity)
                self._dispositions_entity = entity
                self.publier_dispositions(self.dispositions.snapshot())

    def publier_dispositions(self, snapshot):
        # Le journal garde tous les motifs; le marqueur a une limite de 4000 caractères.
        self.journal.ecrire('disposition_serveur', dispositions=snapshot)
        public = json.loads(json.dumps(snapshot, ensure_ascii=False))
        texte = json.dumps(public, ensure_ascii=False)
        while len(texte) > 4000 and public.get('motifs'):
            public['motifs'].pop(0)
            texte = json.dumps(public, ensure_ascii=False)
        self.publier('/api/marqueur', {'phase': 'disposition_serveur', 'texte': texte,
            'run_id': self.identifiant,
            'origine': 'État heuristique local; aucun sentiment ni droit d’action supplémentaire'})

    def observer_disposition(self, event_id, signal, source_ref, observed_ms):
        with self._dispositions_mutex:
            if self.dispositions is None:
                return
            avant = self.dispositions.snapshot()
            self.dispositions.observer(event_id, signal, source_ref, observed_ms)
            apres = self.dispositions.snapshot()
            if apres['revision'] != avant['revision']:
                self.publier_dispositions(apres)

    def snapshot_dispositions(self):
        with self._dispositions_mutex:
            return self.dispositions.snapshot() if self.dispositions is not None else None

    def disposition_incident(self, inc):
        if inc.get('genre') == 'ressources_a_enqueter' and inc.get('unite') in ressources(self.m):
            # Un dépassement mesuré est une anomalie technique, jamais une culpabilité.
            self.observer_disposition(inc['id']+':observation', 'anomalie_verifiee',
                {'id': inc['id'], 'unit': inc['unite']}, inc['survenu_observe_ms'])

    def disposition_verification(self, inc, decision, recu, verification):
        """Un effet vérifié n'établit ni violation initiale ni fausse alerte."""
        p = decision.proposition
        if p is None or recu.get('applique') is not True \
                or recu.get('decision_id') != decision.decision_id \
                or recu.get('action') != p.action or recu.get('cible') != p.cible \
                or verification.get('decision_id') != decision.decision_id \
                or verification.get('action') != p.action or verification.get('cible') != p.cible \
                or verification.get('statut') != 'verifie' or verification.get('temoin') != 'disponible' \
                or verification.get('effet') not in ('arret_unite_verifie', 'quota_cgroup_verifie') \
                or len(verification.get('observations') or []) < 2 \
                or type(recu.get('recu_ms')) is not int:
            return
        self.observer_disposition(decision.decision_id+':verification', 'verification_reussie',
            {'id': decision.decision_id, 'unit': p.cible}, recu['recu_ms'])

    def audit_defense(self, *, force=False):
        """Vérification locale, jamais un booléen fourni par SAWM ou un journal OS."""
        if 'defense_profondeur' not in self.m:
            return None
        now = time.monotonic()
        if not force and self._audit_profondeur is not None \
                and 0 <= now - self._audit_profondeur_monotone < 10:
            return self._audit_profondeur
        result = {'valide': None, 'verifie_a_ms': round(time.time()*1000)}
        audit = self.journal.audit
        if audit is not None:
            try:
                from controleur.audit_signe import verifier
                verified = verifier(audit.path, public_key_path=audit.public_key_path)
                result.update({k: verified.get(k) for k in ('valide', 'ancre_externe_verifiee', 'key_id')})
            except Exception:
                result['valide'] = False
        self._audit_profondeur, self._audit_profondeur_monotone = result, now
        return result

    def suivre_defense(self, etat):
        if 'defense_profondeur' not in self.m:
            return
        from controleur.defense_profondeur import evaluate, fingerprint
        report = evaluate(self.m, etat, audit=self.audit_defense(), cloud_budget=self.limite_cloud)
        self.posture_defense = report
        digest = fingerprint(report)
        if digest == self._posture_fingerprint:
            return
        self.journal.ecrire('posture_defense_profondeur', rapport=report)
        self._posture_fingerprint = digest
        counts = report['counts']
        attention = counts.get('ecart', 0) + counts.get('inconnu', 0)
        self.publier('/api/incident', {
            'id': self.identifiant+'-posture', 'titre': 'Défense en profondeur : couverture technique',
            'statut': 'a_verifier' if attention else 'resolu', 'gravite': 'information',
            'run_id': self.identifiant, 'origine': 'Contrôles techniques locaux, sans verdict de conformité',
            'raison_publique': f"{counts.get('satisfait', 0)} contrôles satisfaits, "
                f"{counts.get('ecart', 0)} écarts, {counts.get('inconnu', 0)} inconnus. "
                'Voir le panneau Défense en profondeur pour les sources et dates.'})

    def observer(self, etat):
        self.suivre_defense(etat)
        sante = frais(etat)
        if sante != self.derniere_sante:
            self.journal.ecrire('etat_capteurs', frais=sante, precedent=self.derniere_sante)
            self.derniere_sante = sante
        events = self.detecteur.analyser(etat, self.m)
        from controleur.perception_defense import incidents_defense
        events += incidents_defense(etat, self.m)
        if self.perception_serveur is not None and sante and time.monotonic() < self.fin:
            try:
                events += self.perception_serveur.analyser(self.m, inspecter_fn=self.inspecter_autorise)
            except Exception as e:
                self.journal.ecrire('perception_serveur_indisponible', erreur=type(e).__name__)
        if self.correlateur is not None:
            events += self.correlateur.analyser(etat, self.m)
        for inc in events:
            if self.correlateur is not None and inc['genre'] == 'processus_reseau_hors_baseline':
                inc = {**inc, 'analysable': False, 'canal': 'observation'}
            if not self.journal.nouveau(inc):
                continue
            self.disposition_incident(inc)
            if inc.get('canal') == 'observation':
                self.publier('/api/marqueur', {
                    'phase': inc['genre'], 'run_id': self.identifiant,
                    'origine': 'Observation technique; aucun verdict attaque',
                    'texte': json.dumps(inc['faits'], ensure_ascii=False)[:2000]})
                continue
            self.publier('/api/incident', {
                'id': inc['id'], 'titre': inc['genre'].replace('_', ' '),
                'statut': 'a_verifier', 'gravite': 'information', 'run_id': self.identifiant,
                'origine': 'Veille technique; aucun verdict attaque',
                'motif_detection': motif_detection(inc),
                'faits': [json.dumps(f, ensure_ascii=False)[:2000] for f in inc['faits']]})
            if self.cloud and inc['analysable'] and frais(etat):
                try:
                    self.attente.put_nowait(inc)
                except queue.Full:
                    self.journal.ecrire('file_analyse_pleine', incident_id=inc['id'])
                    self.publier_attention(inc, 'a_revoir',
                        'File d’analyse pleine : dossier conservé pour examen humain, sans analyse Cloud.')
        if self.cloud and frais(etat) and self.indisponible_jusqua <= time.monotonic() < self.fin \
                and (self.worker is None or not self.worker.is_alive()) and not self.attente.empty():
            # ODVL et la réservation portent sur le choix effectif, hors boucle
            # des capteurs. La file reste intacte pendant le classement réseau.
            self.worker = threading.Thread(target=self.traiter_attente, daemon=True)
            self.worker.start()

    def _retirer_attente(self, incident_id):
        """Retirer un seul choix sous mutex; aucun autre incident n'est déplacé."""
        with self.attente.mutex:
            for inc in self.attente.queue:
                if inc['id'] == incident_id:
                    self.attente.queue.remove(inc)
                    self.attente.not_full.notify()
                    return inc
        return None

    def traiter_attente(self):
        """Prioriser au plus 64 dossiers; rang consultatif, repli FIFO explicite."""
        from controleur.priorite_incidents import prioriser_incidents
        if time.monotonic() >= self.fin:
            return
        with self.attente.mutex:
            lot = list(self.attente.queue)[:64]
        now_ms = int(time.time()*1000)
        valides = []
        for inc in lot:
            observed = inc.get('survenu_observe_ms')
            if type(observed) is not int or not 0 <= now_ms-observed <= 600000:
                if self._retirer_attente(inc['id']) is not None:
                    self.journal.ecrire('observation_expiree', incident_id=inc['id'])
                    self.publier_attention(inc, 'observation_expiree',
                        'Observations trop anciennes pour agir : recueillir de nouvelles mesures.')
            else:
                valides.append(inc)
        if not valides:
            return
        pont = None
        try:
            if len(valides) > 1:
                from connecteur.pont_memoire import PontMemoire
                pont = PontMemoire(campagne=self.identifiant)
            resultat = prioriser_incidents(pont, valides, maintenant_ms=now_ms)
        except Exception as exc:
            # Même un échec local/initialisation ne retire aucune preuve.
            resultat = {'incidents': valides, 'trace': {
                'schema': 'sawm-incident-priority/v1', 'statut': 'fifo_repli',
                'odvl_appelle': False, 'ordre_applique': False, 'ordre_modifie': False,
                'ordre_entree': [i['id'] for i in valides],
                'ordre_sortie': [i['id'] for i in valides],
                'raison_repli': 'initialisation_priorite_indisponible',
                'erreur_type': type(exc).__name__,
                'limite': 'FIFO conservé; aucun rang ODVL ni droit supplémentaire.'}}
        finally:
            if pont is not None:
                try: pont.close()
                except Exception: pass
        # Le réseau peut avoir consommé la fin de la fenêtre d'un incident.
        selection_ms = int(time.time()*1000)
        encore_frais, expires = [], []
        for inc in resultat['incidents']:
            if 0 <= selection_ms-inc['survenu_observe_ms'] <= 600000:
                encore_frais.append(inc)
            else:
                expires.append(inc['id'])
                if self._retirer_attente(inc['id']) is not None:
                    self.journal.ecrire('observation_expiree', incident_id=inc['id'])
                    self.publier_attention(inc, 'observation_expiree',
                        'Observations expirées pendant le classement : recueillir de nouvelles mesures.')
        choix = encore_frais[0] if encore_frais else None
        choisi_id = choix['id'] if choix is not None else None
        trace = {**resultat['trace'], 'incident_choisi': choisi_id,
                 'incidents_expires_apres_classement': expires,
                 'budget_sawm_reserve': False}
        if choix is None:
            trace['raison_report'] = 'observations_expirees_apres_classement'
        elif time.monotonic() >= self.fin:
            trace['raison_report'] = 'echeance_veille_atteinte'
        elif not self.journal.reserver(choix['id'], self.limite_cloud):
            self.journal.ecrire('budget_cloud_epuise', incident_id=choix['id'])
            self.publier_attention(choix, 'attente_budget',
                'Budget d’analyse Cloud épuisé : dossier en attente, protections locales conservées.')
            self.indisponible_jusqua = time.monotonic()+60
            trace['raison_report'] = 'budget_cloud_epuise'
        else:
            trace['budget_sawm_reserve'] = True
        self.journal.ecrire('priorite_incidents', incident_id=choisi_id, trace=trace)
        public = {key: value for key, value in trace.items() if key not in ('facteurs', 'candidats', 'classement')}
        list_keys = ('ordre_entree', 'ordre_sortie', 'incidents_expires_apres_classement')
        public['listes_resumees'] = any(len(public.get(key, [])) > 8 for key in list_keys)
        for key in list_keys:
            if key in public:
                public[key] = public[key][:8]
        public['taille_lot'] = len(valides)
        texte = json.dumps(public, ensure_ascii=False, separators=(',', ':'))
        while len(texte) > 4000:
            # Réduire les listes, jamais couper le JSON au milieu d'une preuve.
            key = max(list_keys, key=lambda name: len(public.get(name, [])))
            public[key].pop()
            public['listes_resumees'] = True
            texte = json.dumps(public, ensure_ascii=False, separators=(',', ':'))
        marqueur = {'phase': 'priorite_incidents', 'run_id': self.identifiant,
            'texte': texte,
            'origine': 'Ordre consultatif ODVL; ni probabilité ni permission d’action'}
        if choisi_id is not None:
            marqueur['incident_id'] = choisi_id
        self.publier('/api/marqueur', marqueur)
        if trace['budget_sawm_reserve']:
            selected = self._retirer_attente(choix['id'])
            if selected is not None:
                self.analyser_cloud(selected)

    def inspecter_autorise(self, action, unit, *, contexte=None):
        """Relire l'autorité avant chaque sonde, sans conférer de droit d'action."""
        from controleur.environnement_serveur import inspecter
        if time.monotonic() >= self.fin:
            raise TimeoutError('echeance_veille_atteinte')
        courant = self.lire_manifest()
        if not re.fullmatch(r'[a-f0-9]{64}', str(courant.get('_sha256', ''))) \
                or courant.get('_sha256') != self.m.get('_sha256') \
                or not courant.get('generation') \
                or courant.get('generation') != self.m.get('generation'):
            raise ValueError('manifeste_modifie_avant_inspection')
        if unit not in ressources(courant):
            raise ValueError('cible_non_autorisee_pour_inspection')
        if action == 'inspecter-base':
            from controleur.inspection_fichiers import inspecter_base
            context = contexte if isinstance(contexte,dict) else {}
            return inspecter_base(unit, courant, object_path=context.get('object_path'))
        if action not in ('inspecter-processus', 'inspecter-compte', 'inspecter-connexions'):
            raise ValueError('outil_non_autorise_pour_veille')
        return inspecter(action, unit, contexte=contexte)

    def enqueter(self, pont, inc, policy):
        """Raccorder les lectures bornées; aucune permission d'exécuter ici."""
        from controleur.enquete_autonome import enqueter

        def before_turn(index):
            if time.monotonic() >= self.fin:
                return False
            if index == 0:
                return True  # Réservation durable faite sur le choix effectif du worker.
            reserve = self.journal.reserver(inc['id']+'-tour-'+str(index), self.limite_cloud)
            if not reserve:
                self.journal.ecrire('budget_cloud_epuise', incident_id=inc['id'], tour=index)
            return reserve

        def on_step(step):
            self.journal.ecrire('etape_enquete', incident_id=inc['id'], etape=step)
            resume = {k: step.get(k) for k in ('step', 'action', 'unit', 'status', 'reason')}
            resultat = (step.get('tool_result') or {}).get('result') or {}
            if isinstance(resultat, dict) and resultat:
                resume['observation'] = {k: resultat.get(k) for k in (
                    'status', 'observation_valid', 'identity_stable', 'measurements_complete', 'reason')}
                processus = (resultat.get('evidence') or {}).get('process') or {}
                if isinstance(processus, dict):
                    resume['mesures_processus'] = {k: processus.get(k) for k in (
                        'cpu_percent_one_core', 'sample_elapsed_seconds', 'rss_bytes', 'threads')}
            self.publier('/api/marqueur', {'phase': 'etape_enquete',
                'incident_id': inc['id'], 'run_id': self.identifiant,
                'texte': json.dumps(resume, ensure_ascii=False)[:2000],
                'origine': 'Enquête SAWM; lectures choisies, observations non fiables sans vérification'})

        return enqueter(pont, inc['faits'], self.identifiant, ressources(self.m),
            politique_locale=policy, inspecter_fn=self.inspecter_autorise, max_steps=3,
            on_step=on_step, before_turn=before_turn,
            dispositions=self.snapshot_dispositions())

    def analyser_cloud(self, inc):
        pont = None
        try:
            # Import paresseux : observation seule ne charge pas le coffre Cloud.
            from controleur import validation
            from connecteur.pont_memoire import PontMemoire
            if time.monotonic() >= self.fin:
                return
            courant = self.lire_manifest()
            if not re.fullmatch(r'[a-f0-9]{64}', str(courant.get('_sha256', ''))) \
                    or courant.get('_sha256') != self.m.get('_sha256') \
                    or not courant.get('generation') \
                    or courant.get('generation') != self.m.get('generation'):
                self.journal.ecrire('analyse_annulee_manifeste_modifie', incident_id=inc['id'])
                self.publier_attention(inc, 'a_revoir',
                    'Manifeste modifié : analyse annulée, autorisations actuelles à vérifier.')
                return
            if 'defense_profondeur' in self.m:
                from controleur.defense_profondeur import evaluate
                posture = evaluate(courant, self.poster('/api/etat?n=1'),
                    audit=self.audit_defense(), cloud_budget=self.limite_cloud)
                inc = {**inc, 'faits': [*inc['faits'], {
                    'posture_defense_profondeur_observee': {
                        'observed_ms': posture['observed_ms'],
                        'manifest_sha256': posture['manifest_sha256'],
                        'checks': [{'id': c['id'], 'status': c['status']} for c in posture['checks']]},
                    'limite': 'État technique local, sans droit supplémentaire ni certificat ISO.'}]}
            reference_fichiers = None
            if inc.get('genre') == 'diagnostic_defense_fichiers':
                paths = {f.get('objet') for f in inc.get('faits',[]) if isinstance(f,dict) and isinstance(f.get('objet'),str)}
                if len(paths) != 1:
                    raise ValueError('objet_fichier_absent_ou_ambigu')
                reference_fichiers = self.inspecter_autorise('inspecter-base',inc.get('unite'),
                    contexte={'object_path':next(iter(paths))})
                self.journal.ecrire('inspection_fichiers_initiale',incident_id=inc['id'],inspection=reference_fichiers)
                # A trusted reinspection is recorded alongside the old telemetry;
                # only its local adapter may produce the Cloud policy argument.
                inc = {**inc, 'faits':[*inc['faits'], {'inspection_base_courante':reference_fichiers}]}
            pont = PontMemoire(campagne=self.identifiant)
            self.initialiser_dispositions(pont)
            self.disposition_incident(inc)
            contexte = ('Référence de fonctionnement déclarée par le propriétaire: '+json.dumps({
                'unites_connues': (self.m.get('veille') or {}).get('unites_connues'),
                'sources_connues': (self.m.get('veille') or {}).get('sources_connues'),
                'actions_automatiques': (self.m.get('veille') or {}).get('actions_automatiques', []),
                'politique_autorisations': (self.m.get('veille') or {}).get('politique_autorisations', 'mandats inconnus')}, ensure_ascii=False)
                + '. Une nouveauté ne prouve ni intention hostile ni absence de mandat. '
                  'En cas d’information métier manquante, demander une clarification. '
                  'Les permissions d’action ne constituent pas un verdict sur la cible.')
            policy = None
            baseline = self.m.get('veille') or {}
            if type(baseline.get('reseau_hors_baseline_autorise')) is bool:
                policy = {'generation': str(self.m['generation']), 'manifest_sha256': self.m['_sha256'],
                    'unites_connues': baseline['unites_connues'],
                    'reseau_hors_baseline_autorise': baseline['reseau_hors_baseline_autorise'],
                    'actions_automatiques': baseline.get('actions_automatiques', [])}
            if reference_fichiers is not None and policy is not None:
                from controleur.inspection_fichiers import politique_database
                database_policy = politique_database(reference_fichiers,courant,inc['unite'])
                if database_policy is not None:
                    policy = {**policy,'database_policy':database_policy}
            if baseline.get('enquete_autonome') is True:
                d, trace = self.enqueter(pont, inc, policy)
            else:
                d, trace = validation.decision_cloud(pont, inc['faits'], self.identifiant,
                    ressources(self.m), contexte, politique_locale=policy,
                    dispositions=self.snapshot_dispositions())
            self.journal.ecrire('decision', incident_id=inc['id'], trace=trace)
            self.echecs_cloud = 0
            faits_choix = [json.dumps({'confiance_declaree_non_calibree': d.proposition.confiance,
                'inconnues': list(d.proposition.inconnues)[:8]}, ensure_ascii=False)[:2000]] if d.proposition else []
            self.publier('/api/decision', {
                'id': d.decision_id, 'incident_id': inc['id'],
                'action': d.proposition.action if d.proposition else 'proposition_invalide',
                'statut': 'proposee', 'raison_publique': (d.proposition.justification if d.proposition else d.refus) or 'non fournie',
                'faits': [json.dumps(d.resume(), ensure_ascii=False)[:2000]],
                'run_id': self.identifiant, 'origine': 'SAWM Cloud; décision proposée, non exécutée'})
            if d.proposition and d.proposition.action == 'demander-clarification':
                source = {'id': d.decision_id}
                if inc.get('unite') in ressources(self.m):
                    source['unit'] = inc['unite']
                self.observer_disposition(d.decision_id+':clarification', 'observation_insuffisante',
                    source, inc['survenu_observe_ms'])
                self.journal.ecrire('en_attente_preuves', incident_id=inc['id'],
                    decision_id=d.decision_id, motif=d.proposition.justification)
                self.publier('/api/decision', {'id': d.decision_id, 'incident_id': inc['id'],
                    'action': d.proposition.action, 'statut': 'en_attente_preuves',
                    'faits': faits_choix, 'raison_publique': d.proposition.justification,
                    'run_id': self.identifiant, 'origine': 'Enquête suspendue; preuves ou mandat manquants'})
                self.publier_attention(inc, 'en_attente_preuves',
                    d.proposition.justification + ' · Clarification requise; aucune reprise automatique de cet incident.',
                    decision=d, details=faits_choix)
                return
            etat = self.poster('/api/etat?n=1')
            dernier = self.lire_manifest()
            observation_ressources = None
            observation_fichiers = None
            if inc.get('genre') == 'ressources_a_enqueter' and self.appliquer \
                    and d.executable and d.proposition and d.proposition.action in ACTIONS_AUTOMATIQUES \
                    and d.proposition.cible == inc.get('unite'):
                observation_ressources = self.inspecter_autorise('inspecter-processus', d.proposition.cible)
            if inc.get('genre') == 'diagnostic_defense_fichiers' and self.appliquer \
                    and d.executable and d.proposition and d.proposition.action == 'arreter-service' \
                    and d.proposition.cible == inc.get('unite'):
                observation_fichiers = self.inspecter_autorise('inspecter-base',d.proposition.cible,
                    contexte={'object_path':reference_fichiers.get('object_path') if reference_fichiers else None})
                self.journal.ecrire('inspection_fichiers_avant_action',incident_id=inc['id'],inspection=observation_fichiers)
            autorise_a_ms = round(time.time()*1000)
            refus = autoriser_action(d, inc, self.m, dernier, etat, self.appliquer,
                                     self.fin-time.monotonic(), observation_ressources=observation_ressources,
                                     observation_fichiers=observation_fichiers,reference_fichiers=reference_fichiers,
                                     audit_profondeur=self.audit_defense(force=True), budget_cloud=self.limite_cloud)
            if refus:
                self.journal.ecrire('aucune_action', incident_id=inc['id'], motif=refus)
                self.publier('/api/decision', {'id': d.decision_id, 'incident_id': inc['id'],
                    'action': d.proposition.action if d.proposition else 'proposition_invalide',
                    'statut': 'non_executee',
                    'faits': faits_choix, 'raison_publique': ((d.proposition.justification if d.proposition else d.refus) or '')+' · '+refus,
                    'run_id': self.identifiant, 'origine': 'Frontière locale des autorisations'})
                self.publier_attention(inc, 'a_revoir',
                    'Aucune action exécutée · '+refus+' · '+
                    ((d.proposition.justification if d.proposition else d.refus) or 'Motif non fourni'),
                    decision=d, details=faits_choix)
                return
            from controleur.verification_action import observer_ressource, verifier_action
            avant = observer_ressource(d.proposition.cible)
            if observation_fichiers is not None:
                from controleur.inspection_fichiers import valide
                identity = observation_fichiers['after']; unit_state = avant.get('unite') or {}
                if (not valide(observation_fichiers,dernier,d.proposition.cible)
                        or avant.get('boot_id') != identity['boot_id']
                        or unit_state.get('MainPID') != str(identity['pid'])
                        or unit_state.get('InvocationID') != identity['invocation_id']
                        or unit_state.get('ControlGroup') != identity['cgroup']):
                    raise ValueError('identite_changee_avant_execution_fichiers')
            self.journal.ecrire('avant_execution', incident_id=inc['id'], decision_id=d.decision_id, avant=avant)
            if 'defense_profondeur' in dernier:
                from controleur.defense_profondeur import refuse
                from invite.executeur.defense_autorisation import sign_authorization
                final_audit = self.audit_defense(force=True)
                expired = not 0 <= round(time.time()*1000)-autorise_a_ms < 5000
                veto = 'defense_profondeur_precontrole_expire' if expired else refuse(
                    dernier, etat, audit=final_audit, cloud_budget=self.limite_cloud)
                if veto:
                    self.journal.ecrire('aucune_action', incident_id=inc['id'], motif=veto)
                    self.publier_attention(inc, 'a_revoir',
                        'Intervention suspendue avant signature : '+veto, decision=d, details=faits_choix)
                    return
                authorization = sign_authorization(self.journal.audit.key, {
                    'decision_id': d.decision_id, 'action': d.proposition.action,
                    'cible': d.proposition.cible, 'manifest_sha256': dernier['_sha256'],
                    'expected_identity': validation.identite_execution(avant)}, now_ms=autorise_a_ms)
                recu = validation.execute(d, dernier['generation'], attendu=avant,
                    defense_authorisation=authorization)
            else:
                recu = validation.execute(d, dernier['generation'], attendu=avant)
            self.journal.ecrire('recu_execution', incident_id=inc['id'], recu=recu)
            self.publier('/api/decision', {'id': d.decision_id, 'incident_id': inc['id'],
                'action': d.proposition.action, 'statut': 'appliquee' if recu.get('applique') else 'refusee',
                'raison_publique': d.proposition.justification, 'run_id': self.identifiant,
                'origine': 'SAWM Cloud; effet réseau restant à vérifier indépendamment'})
            verification = verifier_action(d.proposition.action, d.proposition.cible, recu, avant)
            self.journal.ecrire('verification_action', incident_id=inc['id'], decision_id=d.decision_id, verification=verification)
            self.disposition_verification(inc, d, recu, verification)
            self.publier('/api/decision', {'id': d.decision_id, 'incident_id': inc['id'],
                'action': d.proposition.action, 'statut': verification['statut'],
                'raison_publique': d.proposition.justification,
                'faits': faits_choix + [json.dumps({k: verification.get(k) for k in ('statut','effet','temoin','reseau','motif','limites')}, ensure_ascii=False)[:2000]],
                'run_id': self.identifiant, 'origine': 'Exécution puis vérification OS et service témoin; voir audit signé pour preuves complètes'})
            self.publier('/api/incident', {'id': inc['id'], 'titre': inc['genre'].replace('_', ' '),
                'statut': 'resolu' if verification['statut'] == 'verifie' else 'a_revoir',
                'decision_id': d.decision_id,
                'raison_publique': ('Effet vérifié dans la fenêtre mesurée.' if verification['statut'] == 'verifie'
                    else 'Effet non confirmé : contrôler le service et les observations avant de conclure.'),
                'faits': faits_choix + [json.dumps({k: verification.get(k) for k in ('statut','effet','temoin','motif')}, ensure_ascii=False)],
                'run_id': self.identifiant, 'origine': 'Vérification après action; résolution limitée à la fenêtre mesurée'})
            if self.fin-time.monotonic() >= 45:
                retour = pont.deposer([{'id': 'retour-'+d.decision_id,
                    'titre': 'Reçu de réponse défensive en veille',
                    'contenu': json.dumps({'recu': recu, 'verification': verification}, ensure_ascii=False), 'survenu_a': validation.now()}], budget_s=45)
                self.journal.ecrire('retour_memoire', incident_id=inc['id'], recu=retour)
            else:
                self.journal.ecrire('retour_memoire_non_effectue_echeance', incident_id=inc['id'])
        except Exception as e:
            self.echecs_cloud += 1
            self.indisponible_jusqua = time.monotonic()+min(900, 30*2**min(self.echecs_cloud-1, 5))
            self.journal.ecrire('analyse_indisponible', incident_id=inc['id'], erreur=type(e).__name__)
            self.publier_attention(inc, 'analyse_indisponible',
                'Analyse ou vérification indisponible ('+type(e).__name__+
                ') : état à vérifier; aucun succès supposé ni répétition automatique d’une action engagée.')
            # Retry analysis only before a decision; never replay an execution after an uncertain outcome.
            if 'd' not in locals() and time.monotonic() < self.fin:
                try:
                    self.attente.put_nowait(inc)
                except queue.Full:
                    self.journal.ecrire('file_analyse_pleine', incident_id=inc['id'])
        finally:
            if pont:
                pont.close()


def ecrire_etat(dossier, veille, *, mode, erreur=None):
    obj = {'schema': 'sawm-veille/v2', 'pid': os.getpid(), 'mur_epoch_ms': int(time.time()*1000),
           'mode': mode, 'erreur': erreur, 'supervision': 'launchd si installé; état confirmé par battement',
           'budget_analyses_par_heure': veille.limite_cloud if veille else None,
           'analyses_reservees_derniere_heure': sum(x >= time.time()-3600 for x in veille.journal.reservations) if veille else None,
           'analyses_en_attente': veille.attente.qsize() if veille else 0,
           'analyse_en_cours': bool(veille and veille.worker and veille.worker.is_alive()),
           'repli_cloud_secondes': max(0, round(veille.indisponible_jusqua-time.monotonic())) if veille else 0,
           'protections_locales': 'indépendantes du Cloud; état des capteurs dans la télémétrie',
           'journal_signe': bool(veille and veille.journal.audit is not None),
           'defense_profondeur': veille.posture_defense if veille else None}
    tmp = dossier/'etat.tmp'
    tmp.write_text(json.dumps(obj, ensure_ascii=False))
    tmp.chmod(0o600)
    tmp.replace(dossier/'etat.json')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--duration', type=float, default=300)
    p.add_argument('--permanent', action='store_true', help='Veille continue; journal signé obligatoire')
    p.add_argument('--audit', action='store_true', help='Signer les événements sur le contrôleur')
    p.add_argument('--interval', type=float, default=1)
    p.add_argument('--cloud', action='store_true')
    p.add_argument('--apply', action='store_true')
    p.add_argument('--cloud-per-hour', type=int, default=4)
    args = p.parse_args()
    if (not args.permanent and not 1 <= args.duration <= 3600) or not .5 <= args.interval <= 30:
        p.error('durée 1..3600 s ou --permanent; période 0.5..30 s')
    if not 1 <= args.cloud_per_hour <= 4 or (args.apply and not args.cloud):
        p.error('budget 1..4 analyses/h; --apply exige --cloud')
    from controleur.vm_labo import local_vm, verifier_vm_locale
    if local_vm():
        verifier_vm_locale()
    dossier = ROOT/'releves/veille'
    audit = None
    if args.audit or args.permanent:
        from controleur.audit_signe import JournalSigne
        audit = JournalSigne(dossier/'audit.jsonl')
    journal = Journal(dossier, audit=audit)
    arret = threading.Event()
    for s in (signal.SIGTERM, signal.SIGINT):
        signal.signal(s, lambda *_: arret.set())
    fin = float('inf') if args.permanent else time.monotonic()+args.duration
    veille = None
    prochaine_reference = 0.0
    mode = 'protection_autorisee' if args.apply else 'analyse_cloud' if args.cloud else 'observation'
    from controleur.correlation import Correlateur
    journal.ecrire('demarrage', mode=mode, permanent=args.permanent,
                    duree_max_s=None if args.permanent else args.duration,
                    budget_analyses_par_heure=args.cloud_per_hour,
                    couverture='sockets OS échantillonnés; fichiers sans PID non attribués; pas tous les exec')
    try:
        while not arret.is_set() and time.monotonic() < fin:
            if time.monotonic() >= prochaine_reference:
                prochaine_reference = time.monotonic()+30
                try:
                    m = lire_manifeste_invite()
                    if veille is None or m.get('_sha256') != veille.m.get('_sha256') or veille.fin <= time.monotonic():
                        if veille and veille.worker and veille.worker.is_alive():
                            veille.fin = time.monotonic()  # Cancel old authority, await completion.
                            prochaine_reference = time.monotonic()+2
                        else:
                            veille = Veille(m, journal, cloud=args.cloud, appliquer=args.apply,
                                            limite_cloud=args.cloud_per_hour, fin=fin)
                            veille.correlateur = Correlateur()
                            if audit is not None:
                                for incident in journal.a_recuperer():
                                    veille.attente.put_nowait(incident)
                                for bloque in journal.reprises_bloquees:
                                    veille.publier('/api/marqueur', {'phase': 'verification_operateur_requise',
                                        'texte': json.dumps(bloque, ensure_ascii=False)[:2000],
                                        'run_id': veille.identifiant, 'origine': 'Reprise après interruption; aucune réexécution automatique'})
                            journal.ecrire('reference_chargee', baseline_sha256=m.get('_sha256'),
                                            generation=m.get('generation'))
                except Exception as e:
                    ecrire_etat(dossier, veille, mode='attente_manifeste', erreur=type(e).__name__)
                    if veille:
                        veille.fin = time.monotonic()  # No further action with unavailable authority.
            if veille:
                try:
                    etat = dashboard('/api/etat?n=1')
                except Exception:
                    etat = {'mode': 'DIRECT', 'telemetrie_invite': {'connectee': False}, 'invite': []}
                veille.observer(etat)
                ecrire_etat(dossier, veille, mode='attente_manifeste' if veille.fin <= time.monotonic() else mode if frais(etat) else 'telemetrie_indisponible')
            arret.wait(min(args.interval, max(0, fin-time.monotonic())))
    finally:
        if veille:
            veille.fin = time.monotonic()
        journal.ecrire('arret_veille', cause='signal' if arret.is_set() else 'echeance',
                        analyse_en_cours=bool(veille and veille.worker and veille.worker.is_alive()))
        ecrire_etat(dossier, veille, mode='arretee')
        if not veille or not veille.worker or not veille.worker.is_alive():
            journal.close()


if __name__ == '__main__':
    main()
