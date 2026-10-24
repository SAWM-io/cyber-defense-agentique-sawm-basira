"""Corrélation bornée d'observations OS ; jamais une preuve d'intention.

Une connexion dans trois inventaires distincts démontre sa persistance, pas
une exfiltration. Inotify sans identité complète et les identifiants déclarés
par un émetteur ne sont jamais joints au processus. Ce module ne donne aucun
nouveau droit d'action ; l'autorisation reste celle de l'exécuteur local.
"""
from __future__ import annotations

from collections import OrderedDict
import hashlib
import json
import math
import time


def _evenement(genre, identite, faits, *, unite=None, analysable=False, canal='incident'):
    h = hashlib.sha256(json.dumps([genre, identite, canal], sort_keys=True,
                                 ensure_ascii=False).encode()).hexdigest()[:24]
    return {'id': 'veille-' + h, 'genre': genre, 'canal': canal, 'faits': faits,
            'unite': unite, 'analysable': analysable,
            'survenu_observe_ms': int(time.time() * 1000)}


def _unite(cgroup):
    for ligne in cgroup.splitlines():
        chemin = ligne.split(':', 2)[-1]
        for element in reversed(chemin.split('/')):
            if element.endswith('.service') and '..' not in element:
                return element
    return None


def _entier(value):
    # Les booléens sont des int Python, mais pas des identifiants OS.
    return type(value) is int and value > 0


class Correlateur:
    """Trois observations OS concordantes sur >=2 s, mémoire de 120 s/512 PID.

    Aucun apprentissage de baseline silencieux. Unité connue => aucune alerte.
    L'absence d'identité complète produit une limite de couverture uniquement.
    """
    def __init__(self, *, retention_s=120, maximum_processus=512,
                 minimum_echantillons=3, minimum_duree_s=2):
        if not (1 <= retention_s <= 3600 and 1 <= maximum_processus <= 4096
                and 2 <= minimum_echantillons <= 60
                and 0 < minimum_duree_s <= retention_s):
            raise ValueError('Bornes de corrélation invalides')
        self.retention_ns = int(retention_s * 1_000_000_000)
        self.maximum_processus = maximum_processus
        self.minimum_echantillons = minimum_echantillons
        self.minimum_duree_ns = int(minimum_duree_s * 1_000_000_000)
        self.processus = OrderedDict()
        self.boot_id = None
        self.monotone_ns = None
        self.generation = None

    def _effacer(self):
        self.processus.clear()
        self.monotone_ns = None

    def analyser(self, etat, manifeste):
        t = etat.get('telemetrie_invite') or {}
        age = t.get('age_ms')
        if (etat.get('mode') != 'DIRECT' or t.get('connectee') is not True
                or type(age) not in (int, float) or not math.isfinite(age)
                or not 0 <= age <= 3000 or not etat.get('invite')):
            self._effacer()
            return []
        e = etat['invite'][-1]
        baseline = manifeste.get('veille') or {}
        if not isinstance(baseline.get('unites_connues'), list):
            self._effacer()
            return []
        # Une modification des droits ou de la baseline invalide la fenêtre.
        generation = json.dumps([manifeste.get('generation'), manifeste.get('_sha256'),
                                 baseline['unites_connues']], sort_keys=True)
        boot, maintenant = e.get('boot_id'), e.get('monotone_ns')
        if not isinstance(boot, str) or not boot or len(boot) > 128 or not _entier(maintenant):
            self._effacer()
            return [_evenement('couverture_correlation', 'horloge-identite', [{
                'limite': 'boot_id ou horloge monotone absents ; aucune jointure de processus',
                'identite_complete': False}], canal='observation')]
        if boot != self.boot_id or generation != self.generation:
            self._effacer()
            self.boot_id, self.generation = boot, generation
        if self.monotone_ns is not None and maintenant <= self.monotone_ns:
            return []  # Ni relecture du même échantillon ni désordre temporel.
        self.monotone_ns = maintenant
        for identite, observation in list(self.processus.items()):
            if maintenant - observation['dernier_ns'] > self.retention_ns:
                del self.processus[identite]
        connues = {x if x.endswith('.service') else x + '.service'
                   for x in baseline['unites_connues'] if isinstance(x, str)}
        sockets = e.get('connexions')
        if not isinstance(sockets, list):
            self._effacer()
            return []
        # Un processus présent dans plusieurs sockets ne compte qu'une fois.
        courants, incomplets = {}, 0
        for s in sockets[:100]:
            if not isinstance(s, dict) or str(s.get('etat', '')).upper() not in {
                    'ESTAB', 'ESTABLISHED', 'SYN-SENT', 'SYN-RECV'}:
                continue
            pid, debut, cg = s.get('pid'), s.get('starttime'), s.get('cgroup')
            if (not _entier(pid) or not _entier(debut) or not isinstance(cg, str)
                    or not cg or len(cg) > 4096):
                incomplets += 1
                continue
            unite = _unite(cg)
            if unite in connues:
                continue
            identite = (boot, pid, debut, cg)
            entree = courants.setdefault(identite, {'unite': unite, 'destinations': set()})
            destination = s.get('distante')
            if isinstance(destination, str) and len(destination) <= 128:
                entree['destinations'].add(destination)
        out = []
        if incomplets:
            out.append(_evenement('couverture_correlation', [boot, 'socket'], [{
                'sockets_incomplets_echantillon': incomplets,
                'limite': 'PID, starttime et cgroup complets requis ; aucune jointure par PID seul',
                'identite_complete': False}], canal='observation'))
        for identite, courant in courants.items():
            observation = self.processus.get(identite)
            if observation is None:
                observation = {'premier_ns': maintenant, 'dernier_ns': maintenant,
                               'premier_ms': e.get('mur_epoch_ms'), 'nombre': 0,
                               'destinations': set(), 'destinations_initiales': set(courant['destinations']),
                               'changement_destination_ns': None, 'emission_ns': None}
                self.processus[identite] = observation
            observation['dernier_ns'] = maintenant
            observation['nombre'] += 1
            if (courant['destinations'] - observation['destinations_initiales']
                    and observation['changement_destination_ns'] is None):
                observation['changement_destination_ns'] = maintenant
            observation['destinations'].update(courant['destinations'])
            # Les destinations restent bornées même pour un processus très actif.
            observation['destinations'] = set(sorted(observation['destinations'])[:32])
            self.processus.move_to_end(identite)
            while len(self.processus) > self.maximum_processus:
                self.processus.popitem(last=False)
            if ((observation['emission_ns'] is not None and maintenant-observation['emission_ns'] < 300_000_000_000) or observation['nombre'] < self.minimum_echantillons
                    or maintenant - observation['premier_ns'] < self.minimum_duree_ns):
                continue
            observation['emission_ns'] = maintenant
            fichiers = e.get('fichiers') or {}
            recepteur = e.get('recepteur') or {}
            faits = [{
                'identite_os': {'boot_id': boot, 'pid': identite[1],
                                'starttime': identite[2], 'cgroup': identite[3]},
                'sequence': [
                    {'etape': 'premiere_presence_reseau_hors_baseline',
                     'monotone_ns': observation['premier_ns'], 'mur_epoch_ms': observation['premier_ms']},
                    {'etape': 'presence_reseau_reobservee_meme_processus',
                     'monotone_ns': maintenant, 'mur_epoch_ms': e.get('mur_epoch_ms'),
                     'echantillons_distincts': observation['nombre']}],
                'destinations_observees': sorted(observation['destinations']),
                'hypotheses': ['activité légitime absente de la baseline',
                               'activité réseau non autorisée à examiner'],
                'incertitude': 'intention indéterminée ; persistance réseau observée',
                'couverture': {'identite_processus_complete': True,
                               'creation_processus_observee': False,
                               'lecture_fichier_attribuee': False,
                               'octets_flux_attribues': False,
                               'inventaire_periodique_max_sockets': 100},
                'signaux_non_attribues': {
                    'evenements_fichiers_echantillon': min(len(fichiers.get('evenements') or []), 100),
                    'flux_recepteur_echantillon': min(len(recepteur.get('flux') or {}), 256),
                    'limite': 'coexistence temporelle uniquement ; aucune causalité ni attribution au processus'},
                'limite': 'présence réseau répétée ≠ exfiltration ; processus brefs possibles entre échantillons'}]
            if observation['changement_destination_ns'] is not None:
                faits[0]['sequence'].append({
                    'etape': 'destination_supplementaire_meme_processus',
                    'monotone_ns': observation['changement_destination_ns']})
                faits[0]['sequence'].sort(key=lambda x: x['monotone_ns'])
            out.append(_evenement('sequence_reseau_hors_baseline',
                [identite, observation['premier_ns'], maintenant // 300_000_000_000], faits,
                unite=courant['unite'], analysable=courant['unite'] is not None))
        return out
