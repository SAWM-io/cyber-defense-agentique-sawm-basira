"""Ordonnancement consultatif ODVL; aucun changement de faits ni d'autorité.

Le score d'entrée est la fraîcheur linéaire dans une fenêtre de dix minutes.
L'importance est la moyenne de l'impact technique mesuré et de la présence
d'une identité OS complète. Ce sont des conventions locales documentées,
jamais des probabilités, verdicts ou permissions. Une valeur inconnue garde
son marqueur d'absence même si sa contribution numérique est nulle.
"""
from __future__ import annotations

import json
import math
import re

MAX_BATCH = 64
WINDOW_MS = 600_000
_ID = re.compile(r'[A-Za-z0-9._~:+/=-]{1,160}')
_UNIT = re.compile(r'labo-[a-z0-9][a-z0-9_.-]{0,55}\.service')


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


def _freeze(incidents):
    if type(incidents) not in (list, tuple) or len(incidents) > MAX_BATCH:
        raise ValueError('lot_incidents_invalide')
    raw = json.dumps(incidents, allow_nan=False, ensure_ascii=False, separators=(',', ':'))
    if len(raw.encode()) > 262144:
        raise ValueError('lot_incidents_trop_grand')
    frozen = json.loads(raw)
    ids = set()
    for incident in frozen:
        cid = incident.get('id') if type(incident) is dict else None
        if type(cid) is not str or not _ID.fullmatch(cid) or cid in ids:
            raise ValueError('identifiant_incident_invalide_ou_duplique')
        ids.add(cid)
    return frozen


def _attribution(incident, facts):
    identities = [incident.get('identite_os')] + [fact.get('identite_os') for fact in facts]
    valid = []
    unit = incident.get('unite')
    if type(unit) is not str or not _UNIT.fullmatch(unit):
        return False
    for identity in identities:
        if type(identity) is not dict:
            continue
        pid, start = identity.get('pid'), identity.get('starttime_ticks', identity.get('starttime'))
        boot, group = identity.get('boot_id'), identity.get('cgroup')
        if (type(pid) is not int or pid <= 1 or type(start) is not int or start <= 0
                or type(boot) is not str or not re.fullmatch(r'[0-9a-f-]{36}', boot)
                or type(group) is not str):
            continue
        paths = [line.split(':', 2)[-1] for line in group.splitlines()]
        if not any(path.startswith('/sawm.slice/') and path.split('/')[-1] == unit
                   and all(part not in ('.', '..') for part in path.split('/')) for path in paths):
            continue
        if identity.get('unit', unit) != unit:
            continue
        valid.append((boot, pid, start, group))
    return bool(valid) and len(set(valid)) == 1


def construire_candidats(incidents, *, maintenant_ms):
    """Fonction pure : tuples du PontMemoire et facteurs numériques vérifiables."""
    if type(maintenant_ms) is not int or maintenant_ms <= 0:
        raise ValueError('horodatage_priorite_invalide')
    frozen = _freeze(incidents)
    candidates, factors = [], []
    for incident in frozen:
        observed = incident.get('survenu_observe_ms')
        age = maintenant_ms - observed if type(observed) is int and 0 < observed <= maintenant_ms else None
        freshness = None if age is None else max(0.0, 1.0 - age / WINDOW_MS)
        all_facts = incident.get('faits')
        facts = [fact for fact in all_facts[:32] if type(fact) is dict] if type(all_facts) is list else []
        impacts = []
        evidence = []
        for fact in facts:
            measurements, thresholds = fact.get('mesures'), fact.get('seuils')
            if type(measurements) is dict and type(thresholds) is dict:
                for metric, threshold_key in (('cpu_pct_un_coeur', 'cpu_alerte_pct'), ('rss_mio', 'ram_alerte_mio')):
                    value, threshold = measurements.get(metric), thresholds.get(threshold_key)
                    if _number(value) and value >= 0 and _number(threshold) and threshold > 0:
                        fraction = min(1.0, value / threshold)
                        impacts.append(fraction)
                        evidence.append({'mesure': metric, 'valeur': value, 'seuil': threshold,
                                         'fraction_du_seuil_plafonnee': fraction})
            sqlite = fact.get('sqlite')
            if type(sqlite) is dict:
                for metric in ('read_available', 'write_available', 'reference_matches'):
                    if type(sqlite.get(metric)) is bool:
                        impacts.append(float(not sqlite[metric]))
                        evidence.append({'mesure': 'sqlite.' + metric, 'valeur': sqlite[metric]})
            service = fact.get('service_legitime')
            if type(service) is dict and type(service.get('healthy')) is bool:
                impacts.append(float(not service['healthy']))
                evidence.append({'mesure': 'service_legitime.healthy', 'valeur': service['healthy']})
        impact = max(impacts) if impacts else None
        attributed = _attribution(incident, facts)
        # Le booléen analysable, le texte libre et les dispositions n'entrent
        # jamais dans ces coefficients et restent intacts dans les incidents.
        score = freshness if freshness is not None else 0.0
        importance = ((impact if impact is not None else 0.0) + float(attributed)) / 2
        candidates.append((incident['id'], score, importance))
        factors.append({'candidate_id': incident['id'], 'age_ms': age,
            'actualite': freshness, 'impact_mesure': impact, 'identite_os_complete': attributed,
            'contributions_absentes': [name for name, missing in
                (('actualite', freshness is None), ('impact', impact is None), ('attribution', not attributed)) if missing],
            'mesures_utilisees': evidence,
            'faits_examens_bornes': type(all_facts) is list and len(all_facts) > 32})
    return {'schema': 'sawm-incident-priority-candidates/v1', 'candidats': candidates,
            'facteurs': factors, 'fenetre_actualite_ms': WINDOW_MS,
            'convention': 'score=actualite; importance=(impact_mesure+identite_os_complete)/2; absence contribue 0 explicitement.',
            'limite': 'Ordonnancement heuristique non probabiliste; aucune gravité, culpabilité ou autorité déduite.'}


def appliquer_permutation(incidents, recu):
    """Refuse ajouts, omissions, doublons et rangs ambigus; ignore les scores ODVL."""
    frozen = _freeze(incidents)
    if type(recu) is not dict or recu.get('schema') != 'basira-odvl-ranking/v1' \
            or ('available' in recu and recu['available'] is not True) \
            or type(recu.get('ranking')) is not list:
        raise ValueError('recu_odvl_hors_contrat')
    ranking = recu['ranking']
    if len(ranking) != len(frozen):
        raise ValueError('classement_odvl_non_conservatif')
    ids = []
    for rank, row in enumerate(ranking, 1):
        if type(row) is not dict or type(row.get('rank')) is not int or row['rank'] != rank \
                or type(row.get('candidate_id')) is not str:
            raise ValueError('rang_odvl_invalide')
        ids.append(row['candidate_id'])
    by_id = {incident['id']: incident for incident in frozen}
    if len(set(ids)) != len(ids) or set(ids) != set(by_id):
        raise ValueError('classement_odvl_non_conservatif')
    return [by_id[cid] for cid in ids]


def prioriser_incidents(pont, incidents, *, maintenant_ms):
    """ODVL ne peut que permuter; toute indisponibilité garde le FIFO explicite."""
    frozen = _freeze(incidents)
    plan = construire_candidats(frozen, maintenant_ms=maintenant_ms)
    trace = {'schema': 'sawm-incident-priority/v1', 'statut': 'ordre_trivial',
             'odvl_appelle': False, 'ordre_applique': False, 'ordre_modifie': False,
             'ordre_entree': [i['id'] for i in frozen],
             'ordre_sortie': [i['id'] for i in frozen], 'facteurs': plan['facteurs'],
             'candidats': plan['candidats'], 'convention': plan['convention'],
             'limite': plan['limite'], 'raison_repli': None}
    if len(frozen) < 2:
        return {'incidents': frozen, 'trace': trace}
    trace['odvl_appelle'] = True
    try:
        receipt = pont.hierarchiser(list(plan['candidats']))
        ordered = appliquer_permutation(frozen, receipt)
    except Exception as exc:
        trace.update(statut='fifo_repli', raison_repli='odvl_indisponible_ou_recu_invalide',
                     erreur_type=type(exc).__name__)
        return {'incidents': frozen, 'trace': trace}
    trace.update(statut='ordre_odvl_valide', ordre_applique=True,
                 ordre_sortie=[i['id'] for i in ordered],
                 ordre_modifie=[i['id'] for i in ordered] != trace['ordre_entree'],
                 classement=[{'candidate_id': row['candidate_id'], 'rank': row['rank']}
                             for row in receipt['ranking']])
    if _number(receipt.get('_latence_ms')) and receipt['_latence_ms'] >= 0:
        trace['latence_ms'] = receipt['_latence_ms']
    return {'incidents': ordered, 'trace': trace}
