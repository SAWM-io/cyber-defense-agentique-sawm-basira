"""Pont sans effets de la télémétrie défensive vers les incidents de la veille.

Le diagnostic local, le reçu de maintenance et les effets mesurés sont des
données fournies à SAWM. Ils ne remplacent ni l'inspection actuelle de la cible
ni le contrôle d'autorisation de l'exécuteur. Aucun import de veille, aucun
appel Cloud ou VM. Les campagnes sans unité restent visibles aux humains.
"""
from __future__ import annotations

import hashlib
import json
import math
import re

_UNIT = re.compile(r'labo-[a-z0-9][a-z0-9_.-]{0,55}\.service')
_PRIORITIES = frozenset(('normale', 'moyenne', 'haute', 'critique'))


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


def _clean(value, *, maximum=32768):
    """Copie JSON finie, bornée ; aucune mutation des relevés de la VM."""
    try:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False)
        if len(raw.encode()) > maximum:
            return None
        return json.loads(raw)
    except (ValueError, TypeError, RecursionError):
        return None


def _event(kind, key, facts, now, *, unit=None, analysable=False, observation=False):
    stable = json.dumps([kind, key], ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    return {'id': 'veille-' + hashlib.sha256(stable.encode()).hexdigest()[:24],
            'genre': kind, 'unite': unit, 'faits': facts, 'survenu_observe_ms': now,
            'analysable': analysable, 'canal': 'observation' if observation else 'incident'}


def _unit(value):
    if type(value) is not str:
        return None
    value = value if value.endswith('.service') else value + '.service'
    return value if _UNIT.fullmatch(value) else None


def _target(item, *, boot, generation, observed_ms, known, protected):
    if type(item) is not dict:
        return None
    unit = _unit(item.get('unit'))
    path = item.get('path')
    if unit is None or type(path) is not str or len(path) > 1024:
        return None
    diagnostic = item.get('diagnostic')
    if type(diagnostic) is not dict:
        return None
    recommendation = diagnostic.get('recommandation')
    if recommendation not in ('surveiller', 'signaler', 'contenir_sous_mandat'):
        return None
    authorization = item.get('authorization') if type(item.get('authorization')) is dict else {}
    action = item.get('action') if type(item.get('action')) is dict else None
    # La raison et l'autorisation proviennent du garde. Les textes libres
    # restent des données ; aucun indice lexical n'entraîne d'action.
    priority = diagnostic.get('priorite')
    facts = {'source': 'garde_local_fichiers_télémétrie', 'unite_observee': unit,
             'objet': path, 'operation': item.get('operation'),
             'diagnostic_local': diagnostic, 'maintenance': authorization,
             'integrite': item.get('integrity'), 'sqlite': item.get('availability'),
             'attribution_os': item.get('attribution_os'),
             'action_locale': action, 'effet_observe_apres': item.get('after'),
             'mesures_latence': item.get('metrics'), 'priorite_locale': priority if priority in _PRIORITIES else 'inconnue',
             'auteur_action': 'politique_locale' if action and action.get('applique') is True else 'aucune_action_confirmee',
             'action_sawm_etablie': False, 'synthese_seule_ne_permet_pas_action': True,
             'incertitude': 'Le diagnostic indique les preuves et inconnues ; aucune identité humaine ni malware général établi.',
             'limite': 'Réinspecter la cible et revalider le mandat avant tout acte ; cette synthèse ne donne aucun droit.'}
    facts = _clean(facts)
    if facts is None:
        return None
    action_fingerprint = None if action is None else {
        key: action.get(key) for key in ('applique', 'refus', 'action', 'cible')}
    attribution = item.get('attribution_os')
    incarnation = ({name:attribution.get(name) for name in
                    ('boot_id','pid','process_start_ticks','invocation_id','cgroup','uid')}
                   if type(attribution) is dict else None)
    integrity = item.get('integrity')
    object_identity = ({name:integrity.get(name) for name in ('device','inode')}
                       if type(integrity) is dict else None)
    # Les durées, timestamps d'échantillonnage et compteurs de perf ne créent
    # pas une nouvelle alerte à chaque seconde. Une nouvelle incarnation,
    # un fichier remplacé ou une décision/refus changé constituent un nouvel
    # incident ; un PID réutilisé ne doit pas disparaître dans la déduplication.
    key = [generation, boot, unit, path, item.get('operation'), recommendation,
           diagnostic.get('raison'), authorization.get('authorized'), authorization.get('reason'),
           authorization.get('mandate_id'), action_fingerprint,
           sorted({str(proof.get('fait')) for proof in diagnostic.get('preuves', [])
                   if type(proof) is dict}) if type(diagnostic.get('preuves')) is list else [],
           diagnostic.get('inconnues'), incarnation, object_identity]
    preserved = recommendation == 'surveiller' and action is None
    kind = ('maintenance_defensive_observee' if authorization.get('authorized') is True
            else 'activite_defensive_observee') if preserved else 'diagnostic_defense_fichiers'
    return _event(kind,
                  key, [facts], observed_ms, unit=unit,
                  analysable=not preserved and unit in known and unit not in protected,
                  observation=preserved)


def incidents_defense(etat, manifeste):
    """Consomme uniquement le dernier relevé direct et frais du collecteur."""
    if type(etat) is not dict or type(manifeste) is not dict:
        return []
    telemetry = etat.get('telemetrie_invite')
    samples = etat.get('invite')
    if (type(telemetry) is not dict or etat.get('mode') != 'DIRECT'
            or telemetry.get('connectee') is not True or not _number(telemetry.get('age_ms'))
            or not 0 <= telemetry['age_ms'] <= 3000 or type(samples) is not list or not samples
            or type(samples[-1]) is not dict):
        return []
    sample = samples[-1]
    now, boot = sample.get('mur_epoch_ms'), sample.get('boot_id')
    if type(now) is not int or now <= 0 or type(boot) is not str or not 0 < len(boot) <= 128:
        return []
    generation = manifeste.get('generation')
    known = {_unit(value) for value in manifeste.get('unites_autorisees', [])} - {None} \
        if type(manifeste.get('unites_autorisees')) is list else set()
    protected = {_unit(value) for value in manifeste.get('unites_protegees', [])} - {None} \
        if type(manifeste.get('unites_protegees')) is list else set()
    protected |= {'labo-temoin.service', 'labo-telemetrie.service', 'labo-capteur-exec.service',
                  'labo-lsm.service', 'labo-recepteur.service', 'labo-auth-guard.service',
                  'labo-defense-fichiers.service'}
    output = []
    envelope = sample.get('defense_fichiers')
    snapshot = envelope.get('snapshot') if type(envelope) is dict else None
    state_fresh = (type(envelope) is dict and envelope.get('available') is True
                   and envelope.get('status') == 'etat_recu' and _number(envelope.get('age_ms'))
                   and 0 <= envelope['age_ms'] <= 5000 and type(snapshot) is dict
                   and snapshot.get('schema') == 'sawm-file-defense/v1')
    if not state_fresh or snapshot.get('active') is not True:
        status = envelope.get('status') if type(envelope) is dict else 'etat_absent'
        output.append(_event('couverture_defense_fichiers', [generation, boot, status,
            snapshot.get('active') if type(snapshot) is dict else None],
            [{'etat': status, 'actif': snapshot.get('active') if type(snapshot) is dict else None,
              'limite': 'Garde absent, périmé ou inactif ; aucune conclusion de protection complète.'}], now))
    else:
        targets = snapshot.get('targets') if type(snapshot.get('targets')) is list else []
        history = snapshot.get('alertes') if type(snapshot.get('alertes')) is list else []
        ids = set()
        for item in targets[:8] + history[-32:]:
            if type(item) is not dict:
                continue
            observed = item.get('observed_ms', snapshot.get('observed_ms'))
            # L'historique reste visible mais n'est pas ressuscité comme une
            # décision active après cinq minutes ou un changement d'horloge.
            if type(observed) is not int or not 0 <= now-observed <= 300_000:
                continue
            event = _target(item, boot=boot, generation=generation, observed_ms=observed,
                            known=known, protected=protected)
            if event and event['id'] not in ids:
                ids.add(event['id']); output.append(event)
    auth = sample.get('authentification')
    if type(auth) is dict and auth.get('available') is True and type(auth.get('campagnes')) is list:
        for campaign in auth['campagnes'][:16]:
            if (type(campaign) is not dict or campaign.get('identite_commune_etablie') is not False
                    or campaign.get('blocage_propage') is not False or campaign.get('ip_a_bloquer') != []
                    or campaign.get('recommandation') != 'signaler'):
                continue
            safe = _clean(campaign, maximum=16384)
            if safe is None:
                continue
            output.append(_event('campagne_authentification_possible', [generation, boot, safe.get('id')],
                [{'source': 'journal_root_garde_authentification', 'campagne': safe,
                  'synthese_seule_ne_permet_pas_action': True, 'signaler_humain': True,
                  'incertitude': 'IP et compte visé ne prouvent pas une personne commune ; aucune exclusion propagée.'}], now))
    ssh = sample.get('ssh')
    if type(ssh) is dict and ssh.get('available') is True and ssh.get('block_performed') is False:
        for category in ('alertes','campagnes'):
            rows = ssh.get(category)
            for alert in rows[:16] if type(rows) is list else []:
                safe = _clean(alert,maximum=8192)
                if type(safe) is not dict:
                    continue
                output.append(_event('ssh_comportement_a_examiner',[generation,boot,category,safe],
                    [{'source':'journal_root_sshd','alerte':safe,'signaler_humain':True,
                      'synthese_seule_ne_permet_pas_action':True,'blocage_ssh_effectue':False}],now))
    return output
