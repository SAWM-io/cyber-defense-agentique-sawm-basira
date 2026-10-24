"""Corrélation défensive pure, bornée, sans droit d'exécution ni verdict malware.

Les appels viennent du contrôleur : observations structurées issues de ses
capteurs, reçu d'autorisation issu du vérificateur local et politique vérifiée.
Les textes de journaux, noms de fichiers et sorties LLM ne peuvent construire
ces objets de confiance. Ce module n'authentifie pas un capteur compromis.

Une invocation concerne une unité et un objet : ``mandat`` contient ``unit``,
``object_id``, ``manifest_sha256``, ``verified``, ``protected``,
``authorization_required`` et ``allowed_actions``. ``autorisation`` est le reçu
``evaluate`` du vérificateur de maintenance pour cette même opération/cible.
Une recommandation n'est jamais une permission : l'exécuteur doit revalider
identité, fraîcheur et mandat juste avant tout acte, puis vérifier son effet.

Les observations ont ``id``, ``kind``, ``source``, ``observed_ms`` ; les faits
attribués portent ``identity`` (boot_id, pid, starttime_ticks, cgroup, unit).
``object_id`` est un identifiant opaque déjà vérifié par le collecteur.
Les champs libres et les intentions supposées n'entrent dans aucune règle.
"""
from __future__ import annotations

import json
import math
import re

try:  # Dépôt complet côté contrôleur ; modules plats installés dans la VM.
    from invite.agent_labo.auth_campaigns import campagnes_auth
except ModuleNotFoundError:
    from auth_campaigns import campagnes_auth

MAX_OBSERVATIONS = 128
MAX_AGE_MS = 30_000
_SHA = re.compile(r'[a-f0-9]{64}')
_UUID = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}')
_UNIT = re.compile(r'labo-[a-z0-9][a-z0-9_.-]{0,55}\.service')
_SOURCES = frozenset(('controller_probe', 'procfs', 'auditd', 'fanotify', 'ebpf', 'ss'))
_WRITES = frozenset(('write', 'truncate', 'rename', 'unlink', 'chmod', 'chown'))


def _int(value, minimum=0):
    return type(value) is int and value >= minimum


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


def _label(value, maximum=200):
    return type(value) is str and 0 < len(value) <= maximum and not any(ord(c) < 32 for c in value)


def _identity(value, unit):
    if type(value) is not dict:
        return None
    boot, pid, start, group = (value.get(key) for key in ('boot_id', 'pid', 'starttime_ticks', 'cgroup'))
    if (not _int(pid, 2) or not _int(start, 1) or type(boot) is not str
            or not _UUID.fullmatch(boot) or value.get('unit') != unit
            or type(group) is not str or len(group) > 4096
            or not group.startswith('/sawm.slice/') or group.split('/')[-1] != unit
            or any(part in ('.', '..') for part in group.split('/'))):
        return None
    return (boot, pid, start, group)


def _frozen(observations):
    if type(observations) not in (list, tuple) or len(observations) > MAX_OBSERVATIONS:
        raise ValueError('observation_batch_invalid')
    raw = json.dumps(observations, allow_nan=False, ensure_ascii=False)
    if len(raw.encode()) > 262144:
        raise ValueError('observation_batch_too_large')
    return json.loads(raw)


def diagnostiquer(observations, *, autorisation, mandat, maintenant_ms):
    """Renvoie preuves, inconnues, priorité heuristique et recommandation locale.

    Types et champs :
    - integrity : reference_sha256/current_sha256, reference_verified,
      sample_stable ; tous sur l'objet du mandat.
    - availability : read_available/write_available, read_error/write_error.
    - file : operation, succeeded, identity_stable ; identity + object_id.
    - lock : exclusive_range_verified, holder_verified, identity_stable.
    - resources : cpu_pct/rss_bytes + seuils cpu_threshold/rss_threshold.
    - network : established, outside_baseline ; identité stable obligatoire.
    Les observations malformées/périmées restent des inconnues explicites.
    """
    if not _int(maintenant_ms, 1):
        raise ValueError('diagnostic_clock_invalid')
    rows = _frozen(observations)
    policy = mandat if type(mandat) is dict else {}
    unit, object_id = policy.get('unit'), policy.get('object_id')
    scope_valid = (type(unit) is str and bool(_UNIT.fullmatch(unit)) and _label(object_id)
                   and policy.get('verified') is True
                   and type(policy.get('manifest_sha256')) is str
                   and bool(_SHA.fullmatch(policy['manifest_sha256'])))
    unknown = set()
    if not scope_valid:
        unknown.add('mandat_local_non_verifie')
    proofs, usable, seen = [], [], set()
    identities = set()
    for row in rows:
        if type(row) is not dict or not _label(row.get('id'), 160) or row.get('id') in seen:
            unknown.add('observation_invalide_ou_dupliquee')
            continue
        seen.add(row['id'])
        observed = row.get('observed_ms')
        if not _int(observed, 1) or not 0 <= maintenant_ms-observed <= MAX_AGE_MS:
            unknown.add('observation_perimee_ou_horloge_invalide')
            continue
        if row.get('source') not in _SOURCES:
            unknown.add('source_non_admise')
            continue
        kind = row.get('kind')
        if kind not in ('integrity', 'availability', 'file', 'lock', 'resources', 'network'):
            unknown.add('type_observation_non_pris_en_charge')
            continue
        if kind in ('integrity', 'availability', 'file', 'lock') and row.get('object_id') != object_id:
            unknown.add('objet_hors_perimetre')
            continue
        identity = None
        if kind in ('file', 'lock', 'resources', 'network'):
            identity = _identity(row.get('identity'), unit)
            if identity is None or row.get('identity_stable') is not True:
                unknown.add('attribution_processus_absente_ou_instable')
                continue
            identities.add(identity)
        usable.append((row, identity))
    # Une unité ayant redémarré ne permet pas de joindre deux incarnations PID.
    if len(identities) > 1:
        unknown.add('plusieurs_incarnations_processus_non_jointes')
        usable = [(row, identity) for row, identity in usable if identity is None]

    changed_hash = busy = written = locked = resources = network = False
    file_operations = set()
    for row, identity in usable:
        kind = row['kind']
        reason = None
        if kind == 'integrity':
            reference, current = row.get('reference_sha256'), row.get('current_sha256')
            if (row.get('reference_verified') is True and row.get('sample_stable') is True
                    and type(reference) is str and _SHA.fullmatch(reference)
                    and type(current) is str and _SHA.fullmatch(current)):
                if reference != current:
                    changed_hash = True
                    reason = 'empreinte_differente_reference_verifiee'
            else:
                unknown.add('reference_hash_ou_mesure_non_verifiee')
        elif kind == 'availability':
            if (row.get('read_available') is False and row.get('write_available') is False
                    and row.get('read_error') == 'SQLITE_BUSY' and row.get('write_error') == 'SQLITE_BUSY'):
                busy = True
                reason = 'lectures_et_ecritures_sqlite_occupees'
            elif any(type(row.get(k)) is not bool for k in ('read_available', 'write_available')):
                unknown.add('disponibilite_non_mesuree')
        elif kind == 'file':
            if row.get('operation') in _WRITES and row.get('succeeded') is True:
                written = True
                file_operations.add(row['operation'])
                reason = 'operation_fichier_attribuee_reussie'
        elif kind == 'lock':
            if row.get('exclusive_range_verified') is True and row.get('holder_verified') is True:
                locked = True
                reason = 'detenteur_verrou_exclusif_attribue'
        elif kind == 'resources':
            exceeded = False
            for metric, threshold in (('cpu_pct', 'cpu_threshold'), ('rss_bytes', 'rss_threshold')):
                value, limit = row.get(metric), row.get(threshold)
                if _number(value) and value >= 0 and _number(limit) and limit > 0 and value >= limit:
                    exceeded = True
            if exceeded:
                resources = True
                reason = 'ressources_au_dessus_seuil_local'
        elif kind == 'network':
            if row.get('established') is True and row.get('outside_baseline') is True:
                network = True
                reason = 'connexion_attribuee_hors_baseline'
        if reason:
            proofs.append({'observation_id': row['id'], 'kind': kind, 'source': row['source'],
                           'observed_ms': row['observed_ms'], 'fait': reason,
                           'attribution_complete': identity is not None})

    receipt = autorisation if type(autorisation) is dict else {}
    # Le reçu doit sortir du vérificateur de maintenance, pas d'un événement.
    authorized = (receipt.get('authorized') is True and receipt.get('reason') == 'mandat_signe_valide'
                  and _label(receipt.get('mandate_id'))
                  and _label(receipt.get('principal')))
    absent = (receipt.get('authorized') is False and receipt.get('reason') in {
        'aucun_mandat_pour_operation', 'mandat_expire_ou_futur', 'mandat_revoque'})
    if not authorized and not absent:
        unknown.add('autorisation_non_etablie')
    locked_violation = busy and locked
    integrity_violation = changed_hash and written
    violation = locked_violation or integrity_violation
    if busy and not locked:
        unknown.add('detenteur_verrou_non_attribue')
    if changed_hash and not written:
        unknown.add('auteur_modification_non_attribue')
    if integrity_violation:
        unknown.add('causalite_octets_du_hash_non_prouvee')
    # Un même UID ou un même nom de compte ne constitue jamais une personne.
    unknown.add('identite_humaine_non_etablie')
    containment_allowed = (scope_valid and policy.get('protected') is False
                           and policy.get('authorization_required') is True
                           and type(policy.get('allowed_actions')) is list
                           and 'arreter-service' in policy['allowed_actions'] and absent)
    recommendation, reason, priority = 'surveiller', 'aucune_infraction_etablie', 'normale'
    if proofs:
        recommendation, reason, priority = 'signaler', 'indices_a_examiner', 'moyenne'
    if busy or changed_hash:
        priority = 'haute'
    if resources and network and written:
        priority = 'haute'
        reason = 'activites_fichier_ressources_reseau_correlees'
    if authorized:
        recommendation, reason = 'surveiller', 'operation_couverte_par_mandat_authentifie'
        # La couverture d'une opération n'efface pas ses effets observés.
        priority = 'moyenne' if proofs else 'normale'
    elif violation:
        if containment_allowed:
            recommendation, reason, priority = 'contenir_sous_mandat', 'infraction_locale_attribuee', 'critique'
        else:
            recommendation, reason, priority = 'signaler', 'infraction_possible_sans_autorite_de_confinement', 'haute'
    mappings = []
    if integrity_violation and ('rename' in file_operations or 'write' in file_operations):
        mappings.append({'id': 'T1486', 'usage': 'piste_investigation_integrite', 'technique_confirmee': False})
    return {'schema': 'sawm-defense-diagnostic/v1', 'unit': unit if scope_valid else None,
            'preuves': proofs, 'inconnues': sorted(unknown), 'priorite': priority,
            'recommandation': recommendation, 'raison': reason, 'action_executee': False,
            'autorisation_etablie': authorized, 'identite_humaine_etablie': False,
            'malware_confirme': False, 'mappings_attack': mappings,
            'fenetre_max_ms': MAX_AGE_MS, 'manifest_sha256': policy.get('manifest_sha256') if scope_valid else None,
            'limites': ['Règles explicites non apprises ; la priorité n’est pas une probabilité.',
                       'Une empreinte modifiée ne prouve ni chiffrement ni auteur des octets.',
                       'Revalider mandat et identité avant exécution, puis mesurer son effet.',
                       'La fraîcheur des preuves ne mesure pas la latence de détection de bout en bout.']}
