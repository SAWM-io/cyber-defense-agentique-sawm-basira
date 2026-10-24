"""Perception bornée des ressources : une inspection, aucun verdict ni arrêt.

Le manifeste fourni par l'appelant est la politique root. Les dépassements
CPU/RSS ouvrent une enquête; les variations entre deux mesures sont des faits,
pas une preuve de programme malveillant. Aucun import de veille (pas de cycle).
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time

from controleur.environnement_serveur import inspecter

_UNIT = re.compile(r'labo-[a-z0-9][a-z0-9_.-]{0,55}\.service')
_PROTECTED = frozenset(('labo-temoin.service', 'labo-recepteur.service',
    'labo-telemetrie.service', 'labo-lsm.service', 'labo-capteur-exec.service',
    'labo-capteur-large.service', 'labo-collecteur.service', 'labo-veille.service'))
MAX_TARGETS = 8
MIN_INTERVAL_S = 10.0


def _unit(value):
    if not isinstance(value, str):
        return None
    name = value if value.endswith('.service') else value + '.service'
    return name if _UNIT.fullmatch(name) else None


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


def _event(genre, identity, facts, *, unit=None, analysable=False, observed_ms=None):
    channel = 'incident' if analysable else 'observation'
    digest = hashlib.sha256(json.dumps([genre, identity, channel], sort_keys=True,
                                      separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    return {'id': 'veille-' + digest[:24], 'genre': genre, 'canal': channel,
            'faits': facts, 'unite': unit, 'analysable': analysable,
            'survenu_observe_ms': observed_ms if type(observed_ms) is int and observed_ms > 0
            else int(time.time() * 1000)}


def _identity(observation, unit):
    if not isinstance(observation, dict) or observation.get('observation_valid') is not True \
            or observation.get('identity_stable') is not True:
        raise ValueError('inspection_non_verifiee')
    before, after = observation.get('before'), observation.get('after')
    if not isinstance(before, dict) or before != after:
        raise ValueError('identite_absente_ou_changee')
    u = before.get('systemd') or {}
    pid, start = before.get('pid'), before.get('starttime_ticks')
    boot, cg, invocation = before.get('boot_id'), before.get('cgroup'), before.get('invocation_id')
    if (observation.get('unit') != unit or observation.get('action') != 'inspecter-processus'
            or u.get('Id') != unit or u.get('ActiveState') != 'active'
            or u.get('LoadState') != 'loaded' or str(pid) != u.get('MainPID')
            or u.get('InvocationID') != invocation or u.get('ControlGroup') != cg
            or type(pid) is not int or pid <= 1 or type(start) is not int or start <= 0
            or not isinstance(boot, str) or not re.fullmatch(r'[0-9a-f-]{36}', boot)
            or not isinstance(invocation, str) or not re.fullmatch(r'[0-9a-f]{32}', invocation)
            or not isinstance(cg, str) or not cg.startswith('/sawm.slice/')
            or cg.split('/')[-1] != unit or any(part in ('.', '..') for part in cg.split('/'))):
        raise ValueError('identite_os_incomplete')
    return {'unit': unit, 'boot_id': boot, 'pid': pid, 'starttime_ticks': start,
            'cgroup': cg, 'invocation_id': invocation}


class PerceptionServeur:
    """Déduplique les classes CPU/RAM jusqu'au retour sous leur seuil.

    Une seule inspection est appelée par analyser. Les cibles éligibles sont
    parcourues dans l'ordre de leur dernière inspection, au plus toutes les
    dix secondes par cible. Les états mémorisés restent limités à huit unités.
    """
    def __init__(self):
        self.derniere_observation = None
        self.derniere_unite = None
        self._last = {}
        self._states = {}
        self._notices = {}
        self._sequence = 0

    def _notice(self, reason, *, unit=None, details=None, observed_ms=None):
        key = unit or '_policy'
        signature = json.dumps([reason, details], sort_keys=True, ensure_ascii=False)
        if self._notices.get(key) == signature:
            return []
        self._notices[key] = signature
        self._sequence += 1
        return [_event('ressources_observation_indisponible', [key, reason, self._sequence],
                       [{'motif': reason, **(details or {}),
                         'limite': 'Aucune conclusion de consommation normale ou de compromission.'}],
                       unit=unit, observed_ms=observed_ms)]

    def analyser(self, manifeste, *, inspecter_fn=inspecter, now=time.monotonic):
        policy = manifeste.get('veille') if isinstance(manifeste, dict) else None
        if not isinstance(policy, dict) or policy.get('enquete_autonome') is not True:
            return []
        watched, authorized = policy.get('unites_surveillees'), manifeste.get('unites_autorisees')
        protected = manifeste.get('unites_protegees', [])
        if not isinstance(watched, list) or not isinstance(authorized, list) or not isinstance(protected, list):
            return self._notice('politique_cibles_absente_ou_invalide')
        cpu_threshold = policy.get('cpu_alerte_pct', 80)
        ram_threshold = policy.get('ram_alerte_mio', 256)
        if any(not _number(value) or value <= 0 for value in (cpu_threshold, ram_threshold)):
            return self._notice('seuils_ressources_invalides')
        allowed = {_unit(value) for value in authorized} - {None}
        forbidden = _PROTECTED | {_unit(value) for value in protected}
        targets = list(dict.fromkeys(unit for value in watched if (unit := _unit(value))
                                     and unit in allowed and unit not in forbidden))
        eligible_count = len(targets)
        targets = targets[:MAX_TARGETS]
        for mapping in (self._last, self._states, self._notices):
            for key in list(mapping):
                if key not in targets and key != '_policy':
                    del mapping[key]
        notices = []
        if eligible_count > MAX_TARGETS:
            notices = self._notice('couverture_bornee', details={'cibles_eligibles': eligible_count,
                                                               'cibles_inspectees_max': MAX_TARGETS})
        else:
            self._notices.pop('_policy', None)
        timestamp = now()
        if not _number(timestamp):
            return notices + self._notice('horloge_monotone_invalide')
        due = [unit for unit in targets if unit not in self._last
               or timestamp - self._last[unit] >= MIN_INTERVAL_S]
        if not due:
            return notices
        unit = min(due, key=lambda value: self._last.get(value, -math.inf))
        self._last[unit] = timestamp
        self.derniere_unite = unit
        self.derniere_observation = None
        try:
            observation = inspecter_fn('inspecter-processus', unit)
            self.derniere_observation = observation if isinstance(observation, dict) else None
        except Exception:
            return notices + self._notice('inspection_indisponible', unit=unit)
        observed_ms = observation.get('observed_epoch_ms') if isinstance(observation, dict) else None
        try:
            identity = _identity(observation, unit)
            process = (observation.get('evidence') or {}).get('process') or {}
            cpu, rss = process.get('cpu_percent_one_core'), process.get('rss_bytes')
            elapsed = process.get('sample_elapsed_seconds')
            if (not _number(cpu) or cpu < 0 or type(rss) is not int or rss < 0
                    or not _number(elapsed) or elapsed < .5
                    or type(observed_ms) is not int or observed_ms <= 0):
                raise ValueError('mesures_ressources_absentes')
        except (ValueError, TypeError, AttributeError):
            # Unité inactive, redémarrage ou trou de mesure : observation seulement.
            return notices + self._notice('identite_ou_mesures_non_verifiees', unit=unit,
                                           observed_ms=observed_ms)
        self._notices.pop(unit, None)
        ram = rss / 1024**2
        classes = set()
        if cpu >= cpu_threshold:
            classes.add('cpu')
        if ram >= ram_threshold:
            classes.add('ram')
        state = self._states.get(unit)
        if state is None or state['identity'] != identity:
            state = {'identity': identity, 'classes': set(), 'cpu': None, 'ram': None,
                     'episodes': {}}
        previous_classes = state['classes']
        new_classes = classes - previous_classes
        variations = {'cpu_delta_points': None if state['cpu'] is None else round(cpu - state['cpu'], 3),
                      'rss_delta_mio': None if state['ram'] is None else round(ram - state['ram'], 3)}
        episodes = state['episodes']
        self._states[unit] = {'identity': identity, 'classes': classes, 'cpu': cpu, 'ram': ram,
                              'episodes': episodes}
        if not new_classes:
            return notices
        variant = tuple(sorted(classes))
        episodes[variant] = episodes.get(variant, 0) + 1
        incident = _event('ressources_a_enqueter', [identity, list(variant), episodes[variant]],
            [{'source': 'inspection OS en lecture seule', 'identite_os': identity,
              'identite_processus_complete': True, 'classes': sorted(classes),
              'classes_nouvellement_declenchees': sorted(new_classes),
              'mesures': {'cpu_pct_un_coeur': cpu, 'rss_mio': round(ram, 3),
                          'fenetre_s': elapsed, **variations},
              'seuils': {'cpu_alerte_pct': cpu_threshold, 'ram_alerte_mio': ram_threshold},
              'limite': 'Dépassement de ressources à enquêter; aucune qualification de malware ni arrêt automatique.'}],
            unit=unit, analysable=True, observed_ms=observed_ms)
        incident['identite_os'] = identity
        return notices + [incident]
