#!/usr/bin/env python3
"""Six propositions Cloud sur faits figes; aucune commande VM ni action OS.

Compare uniquement le contexte ajoute par le connecteur. La memoire native
SAWM Cloud reste active et memorise les tours : ceci n'est pas une ablation
de Basira ni une estimation statistique d'un gain de memoire.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import json
import math
import pathlib
import re
import sys
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from connecteur.pont_memoire import PontMemoire
from connecteur.tour_sawm import TourSawm

VARIANTES = ('sans_rappels_connecteur', 'rappel_tsst', 'rappel_odvl')
LIMITES = [
    'Le rappel natif SAWM Cloud reste actif dans les trois variantes et ne peut etre desactive par cette API.',
    'Les tours SAWM sont memorises dans la meme entite Cloud; les sessions distinctes n isolent pas cette memoire.',
    'Les faits et les rappels explicites sont figes avant les six tours; la memoire native peut evoluer entre eux.',
    'Deux problemes seulement, une observation par variante : aucun gain statistique ou causal etabli.',
    'Latences observees avec reseau et fournisseur; ni graine ni determinisme du modele imposes.',
    'Aucun actuateur ni acces VM : une proposition restrictive ne signifie pas qu une action a ete appliquee.',
]


def maintenant():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def empreinte(objet):
    raw = json.dumps(objet, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def sauver(path, report):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False))
    temp.replace(path)


def lire_rapport(path):
    if path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError('rapport source trop grand')
    report = json.loads(path.read_text())
    if (not isinstance(report, dict) or report.get('type') != 'transfert'
            or type(report.get('mandat_autorise')) is not bool):
        raise ValueError('rapport de transfert avec mandat explicite requis')
    return report


def selectionner(reports_dir, *, autorise=None, non_autorise=None):
    """Dernier rapport par mandat explicite, sans selectionner selon succes."""
    selected = {}
    for allowed, explicit in ((True, autorise), (False, non_autorise)):
        if explicit is not None:
            path = pathlib.Path(explicit)
            data = lire_rapport(path)
            if data['mandat_autorise'] is not allowed:
                raise ValueError('mandat du rapport explicite incorrect')
            selected[allowed] = (path, data)
            continue
        candidates = []
        for path in reports_dir.glob('experience-vm-*.json'):
            try:
                data = lire_rapport(path)
                stamp = datetime.datetime.fromisoformat(data['debut']).timestamp()
            except (OSError, ValueError, KeyError, TypeError):
                continue
            if data['mandat_autorise'] is allowed:
                candidates.append((stamp, path, data))
        if not candidates:
            raise ValueError('un rapport autorise et un rapport non autorise sont necessaires')
        _, path, data = max(candidates, key=lambda row: (row[0], row[1].name))
        selected[allowed] = (path, data)
    return selected


def figer_faits(path, report):
    """Seulement le snapshot AVANT analyse; aucun resultat futur de la campagne."""
    initial = next((e.get('snapshot') for e in report.get('etapes', [])
                    if e.get('phase') == 'avant_analyse'), None)
    if not isinstance(initial, dict) or not isinstance(initial.get('mur_epoch_ms'), int):
        raise ValueError('snapshot initial horodate absent')
    run = report['run_id']
    flux = (initial.get('recepteur') or {}).get('flux', {})

    def volume(source):
        values = [row.get('recus') for row in flux.values()
                  if row.get('run_id') == run and row.get('source_id') == source]
        if not values:
            return None
        if any(type(value) is not int or value < 0 for value in values):
            raise ValueError('compteur de reception hors contrat')
        return sum(values)

    facts = [
        {'unite': 'labo-copie-b.service', 'source_id': 'source-b',
         'octets_recus': volume('source-b'), 'destination': '127.0.0.1:9009',
         'observation_connexions': initial.get('sockets')},
        {'unite': 'labo-copie-a.service', 'source_id': 'source-a',
         'octets_recus': volume('source-a'), 'role_declare': 'copie autorisee'},
        {'service_documentaire': initial.get('temoin')},
    ]
    context = ('Le proprietaire declare la copie labo-copie-a.service autorisee et protegee. '
               'La copie labo-copie-b.service est ' +
               ('autorisee' if report['mandat_autorise'] else 'non autorisee') +
               '. Preserver le service documentaire et la copie autorisee. '
               'Ce mandat est une information declaree; les compteurs sont des mesures OS archivees.')
    stamp = datetime.datetime.fromtimestamp(initial['mur_epoch_ms'] / 1000,
                                            datetime.timezone.utc).isoformat()
    return {'source': str(path.resolve()), 'source_run_id': run,
            'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'mandat_autorise': report['mandat_autorise'], 'survenu_a': stamp,
            'faits': facts, 'contexte': context,
            'faits_sha256': empreinte({'faits': facts, 'contexte': context, 'survenu_a': stamp})}


def preparer_memoire(pont, case):
    recall = pont.rappeler('labo-copie-b.service transfert service observations systeme', limite=5)
    verified, excluded = [], 0
    for evidence in recall.preuves:
        if not isinstance(evidence, dict):
            raise ValueError('preuve TSST hors contrat')
        if evidence.get('integrity_verified') is False:
            excluded += 1
        else:
            verified.append(dict(evidence))
    by_id, candidates = {}, []
    for evidence in verified:
        cid = evidence.get('candidate_id') or evidence.get('evidence_id')
        score = evidence.get('score')
        if (not isinstance(cid, str) or not re.fullmatch(r'[A-Za-z0-9._~:+/=-]{1,160}', cid)
                or cid in by_id or isinstance(score, bool) or not isinstance(score, (int, float))
                or not 0 <= score <= 1 or not math.isfinite(score)):
            raise ValueError('candidat TSST hors contrat')
        by_id[cid] = evidence
        candidates.append((cid, float(score), 0.0))
    ordered = list(verified)
    odvl = {'available': False, 'reason': 'aucune_preuve'}
    if candidates:
        odvl = pont.hierarchiser(candidates)
        ranking = odvl.get('ranking')
        if (odvl.get('schema') != 'basira-odvl-ranking/v1' or not isinstance(ranking, list)
                or len(ranking) != len(candidates)):
            raise ValueError('classement ODVL hors contrat')
        ids = []
        for rank, row in enumerate(ranking, 1):
            if (not isinstance(row, dict) or not isinstance(row.get('candidate_id'), str)
                    or type(row.get('rank')) is not int or row['rank'] != rank):
                raise ValueError('rang ODVL hors contrat')
            ids.append(row['candidate_id'])
        if len(set(ids)) != len(ids) or set(ids) != set(by_id):
            raise ValueError('classement ODVL non conservatif')
        ordered = [by_id[cid] for cid in ids]
    return {'rappel': dataclasses.asdict(recall), 'preuves_exclues_integrite': excluded,
            'preuves_tsst': verified, 'preuves_odvl': ordered, 'odvl': odvl,
            'prepare_a': maintenant(), 'contexte_explicite_fige': True}


def message(case, evidence):
    facts = [{'survenu_a': case['survenu_a'], 'source': 'mesure OS archivee du laboratoire',
              'resume': json.dumps(row, ensure_ascii=False)} for row in case['faits']]
    text = TourSawm.composer_message(faits=facts, manifeste=['labo-copie-b.service'], rappels=evidence)
    return text + '\nCONTEXTE DECLARE PAR LE PROPRIETAIRE\n' + case['contexte'] + (
        '\nCes faits sont archives. Proposer une decision sur cette photographie, sans supposer '
        'connaitre sa suite. Aucune action OS ne sera executee dans cette comparaison.')


def comparer(*, reports_dir=None, autorise=None, non_autorise=None):
    directory = pathlib.Path(reports_dir or ROOT / 'releves/rapports')
    selected = selectionner(directory, autorise=autorise, non_autorise=non_autorise)
    run = 'ablation-' + time.strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex[:4]
    destination = directory / ('experience-' + run + '.json')
    report = {'schema': 'sawm-context-comparison/v1', 'run_id': run, 'debut': maintenant(),
        'limites': LIMITES, 'nombre_problemes': 2, 'tours_prevus': 6,
        'max_output_tokens_par_tour': 600, 'actions_os_executees': 0,
        'rappel_natif_sawm': 'actif_non_ablate', 'gain_statistique': 'non_estime',
        'ordre_execution': [], 'cas': [], 'comparaisons': [], 'recette_complete': False}
    pont = None
    try:
        pont = PontMemoire(campagne=run, budget_rejeu=2)
        # Figer TOUS les rappels explicites avant le premier tour memorise.
        for index, allowed in enumerate((True, False), 1):
            path, source = selected[allowed]
            case = figer_faits(path, source)
            case.update(id='cas-' + str(index), resultats=[])
            case['memoire'] = preparer_memoire(pont, case)
            report['cas'].append(case)
        sauver(destination, report)
        for case in report['cas']:
            memories = {'sans_rappels_connecteur': [],
                        'rappel_tsst': case['memoire']['preuves_tsst'],
                        'rappel_odvl': case['memoire']['preuves_odvl']}
            # L'ordre est explicite; deux cas ne permettent pas de neutraliser
            # carry-over et alea du modele. Aucune conclusion causale.
            for variant in VARIANTES:
                evidence = memories[variant]
                prompt = message(case, evidence)
                session = run + '-' + case['id'] + '-' + variant
                turn = session + '-tour'
                record = {'variante': variant, 'faits_sha256': case['faits_sha256'],
                    'message_sha256': hashlib.sha256(prompt.encode()).hexdigest(),
                    'nombre_preuves_connecteur': len(evidence), 'execution_os': 'aucune'}
                report['ordre_execution'].append({'cas': case['id'], 'variante': variant})
                try:
                    result = TourSawm(pont, session_id=session).jouer(prompt,
                        cibles_autorisees={'labo-copie-b.service'}, preuves_connecteur=evidence,
                        turn_id=turn, max_tokens=600)
                    record.update(result.resume(), decision=dataclasses.asdict(result),
                                  usage=result.usage, memoire_native=result.memoire_sawm)
                except Exception as exc:
                    record['erreur'] = {'type': type(exc).__name__}
                case['resultats'].append(record)
                report['comparaisons'].append({'cas': case['id'], 'variante': variant,
                    'mandat_autorise': case['mandat_autorise'], 'action': record.get('action'),
                    'cible': record.get('cible'), 'latence_ms': record.get('latence_ms'),
                    'preuves_connecteur': len(evidence), 'preuves_natives': record.get('preuves_sawm'),
                    'refus': record.get('refus'), 'erreur': record.get('erreur')})
                sauver(destination, report)
        report['recette_complete'] = (len(report['comparaisons']) == 6
            and all('decision' in row and 'turn.done' in row['decision']['ordre_evenements']
                    and not row.get('refus') for case in report['cas'] for row in case['resultats']))
    except Exception as exc:
        report['erreur'] = {'type': type(exc).__name__}
    finally:
        if pont is not None:
            pont.close()
        report['fin'] = maintenant()
        sauver(destination, report)
    print(json.dumps({'rapport': str(destination), 'recette_complete': report['recette_complete'],
        'tours_observes': len(report['comparaisons']), 'actions_os_executees': 0,
        'gain_statistique': 'non_estime'}, ensure_ascii=False))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rapport-autorise', type=pathlib.Path)
    parser.add_argument('--rapport-non-autorise', type=pathlib.Path)
    args = parser.parse_args()
    return 0 if comparer(autorise=args.rapport_autorise,
                        non_autorise=args.rapport_non_autorise)['recette_complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
