"""Évaluation technique et veto additif ; ne confère jamais de droits.

Les correspondances ISO/CIS sont documentaires, pas une certification.
Les données OS et le journal sont contrôlés séparément de la proposition LLM.
"""
from __future__ import annotations

from collections import Counter
import copy
import hashlib
import json
import math
import re
import time

SCHEMA = 'sawm-defense-profondeur/v1'
PROFILE = 'industriel-prudent-v1'
STATUSES = {'satisfait', 'ecart', 'inconnu', 'non_applicable'}
BASE_REQUIRED = {'politique_chargee', 'delegation_limitee', 'telemetrie_fraiche', 'journal_signe', 'autorite_controleur'}
OS_TITLES = {
    'os_aslr': 'Randomisation mémoire',
    'os_kptr_restrict': 'Restriction des adresses noyau',
    'os_dmesg_restrict': 'Restriction du journal noyau',
    'os_ptrace_scope': 'Restriction du débogage interprocessus',
    'os_protected_hardlinks': 'Protection des liens physiques',
    'os_protected_symlinks': 'Protection des liens symboliques',
    'os_ssh_root_login': 'Connexion SSH directe de root désactivée',
    'os_ssh_password_auth': 'Authentification SSH par mot de passe désactivée',
    'os_ssh_empty_passwords': 'Mots de passe SSH vides interdits',
    'os_ssh_max_authtries': 'Essais SSH bornés',
    'os_auditd_active': 'Service auditd actif',
    'os_ntp_synchronized': 'Horloge synchronisée',
}
TITLES = {
    'politique_chargee': 'Politique locale identifiée',
    'delegation_limitee': 'Interventions explicitement bornées',
    'telemetrie_fraiche': 'Observations récentes',
    'journal_signe': 'Intégrité du journal signée et vérifiée',
    'autorite_controleur': 'Clé du contrôleur enrôlée par l’administrateur',
    'ancre_exterieure': 'Ancre extérieure vérifiée',
    'capteur_exec': 'Sonde d’exécution opérationnelle',
    'capteur_lsm': 'Attachement LSM démontré',
    'service_temoin': 'Disponibilité du service témoin',
    'budget_cloud': 'Budget des analyses borné',
    **OS_TITLES,
}


def fresh(timestamp, now, maximum):
    return type(timestamp) in (int, float) and math.isfinite(timestamp) and 0 <= now - timestamp <= maximum


def _timestamp(value):
    return int(value) if type(value) in (int, float) and math.isfinite(value) and value >= 0 else None


def _counts(checks):
    counts = Counter(c['status'] for c in checks)
    return {status: counts[status] for status in sorted(STATUSES)}


def policy(manifest):
    """Un profil malformé ne peut désactiver le veto par défaut."""
    if 'defense_profondeur' not in manifest:
        return False, set(), None
    value = manifest['defense_profondeur']
    if not isinstance(value, dict) or set(value) not in ({'profil', 'controles_bloquants'}, {'profil', 'controles_bloquants', 'cles_controleur'}) \
            or value.get('profil') != PROFILE:
        return True, BASE_REQUIRED, 'profil_defense_profondeur_invalide'
    required = value['controles_bloquants']
    if not isinstance(required, list) or len(required) > len(TITLES) \
            or any(not isinstance(x, str) or x not in TITLES for x in required) \
            or len(set(required)) != len(required):
        return True, BASE_REQUIRED, 'controles_defense_profondeur_invalides'
    keys = value.get('cles_controleur', [])
    if not isinstance(keys, list) or len(keys) > 16 or any(
            not isinstance(k, str) or not re.fullmatch('[a-f0-9]{64}', k) for k in keys) \
            or len(keys) != len(set(keys)):
        return True, BASE_REQUIRED, 'cles_controleur_invalides'
    return True, BASE_REQUIRED | set(required), None


def _boolean(value):
    return 'satisfait' if value is True else 'ecart' if value is False else 'inconnu'


def evaluate(manifest, state, *, audit=None, cloud_budget=None, now_ms=None):
    now = round(time.time()*1000) if now_ms is None else now_ms
    enabled, required, invalid = policy(manifest)
    digest = manifest.get('_sha256')
    checks = []
    def add(key, status, source, reason, measured=None):
        checks.append({'id': key, 'title': TITLES[key], 'status': status,
                       'source': source, 'reason': reason,
                       'observed_ms': _timestamp(measured) if fresh(measured, now, float('inf')) else None})
    valid_policy = isinstance(manifest.get('generation'), str) and bool(manifest['generation']) \
        and isinstance(digest, str) and re.fullmatch('[a-f0-9]{64}', digest) is not None
    add('politique_chargee', _boolean(valid_policy and invalid is None), 'manifeste local',
        invalid or 'Empreinte et génération identifiées ; ne prouve pas une certification.', now)
    baseline = manifest.get('veille')
    actions = baseline.get('actions_automatiques') if isinstance(baseline, dict) else None
    allowed = manifest.get('unites_autorisees')
    protected = manifest.get('unites_protegees')
    bounded = isinstance(actions, list) and isinstance(allowed, list) and isinstance(protected, list)
    bounded = bounded and all(isinstance(x, str) for x in allowed + protected + actions)
    if bounded:
        def unit(x):
            name = x if x.endswith('.service') else x+'.service'
            return name if re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,100}\.service', name) else None
        allowed, protected = [unit(x) for x in allowed], [unit(x) for x in protected]
        bounded = set(actions) <= {'geler-transfert', 'arreter-service', 'limiter-cpu'} \
            and None not in allowed + protected and not (set(allowed) & set(protected))
    add('delegation_limitee', _boolean(bounded), 'manifeste local',
        'Délégation bornée ; les droits par cible et la maintenance restent contrôlés par l’exécuteur.', now)
    samples = state.get('invite')
    sample = samples[-1] if isinstance(samples, list) and samples and isinstance(samples[-1], dict) else {}
    telemetry = state.get('telemetrie_invite') if isinstance(state.get('telemetrie_invite'), dict) else {}
    recent = state.get('mode') == 'DIRECT' and telemetry.get('connectee') is True \
        and type(telemetry.get('age_ms')) in (int, float) and 0 <= telemetry['age_ms'] <= 3000 \
        and fresh(sample.get('mur_epoch_ms'), now, 5000)
    add('telemetrie_fraiche', 'satisfait' if recent else 'inconnu', 'télémétrie OS',
        'Horodatage du relevé et âge de réception vérifiés ; transport à sécuriser séparément.', sample.get('mur_epoch_ms'))
    audit = audit if isinstance(audit, dict) else {}
    audit_recent = fresh(audit.get('verifie_a_ms'), now, 15000)
    add('journal_signe', _boolean(audit.get('valide')) if audit_recent else 'inconnu',
        'vérificateur Ed25519 local', 'Vérification complète de chaîne ; la présence d’un fichier ne suffit pas.', audit.get('verifie_a_ms'))
    key_ids = set()
    if enabled and invalid is None:
        key_ids = {hashlib.sha256(bytes.fromhex(k)).hexdigest()
                   for k in manifest['defense_profondeur'].get('cles_controleur', [])}
    add('autorite_controleur', _boolean(isinstance(audit.get('key_id'), str) and audit['key_id'] in key_ids)
        if audit_recent and audit.get('valide') is True else 'inconnu', 'manifeste et clé Ed25519',
        'La clé publique doit être enrôlée hors du modèle avant une intervention.', audit.get('verifie_a_ms'))
    add('ancre_exterieure', 'satisfait' if audit_recent and audit.get('valide') is True
        and audit.get('ancre_externe_verifiee') is True else 'inconnu',
        'vérificateur d’ancre', 'Une copie ou une déclaration d’envoi ne prouve pas une ancre indépendante.', audit.get('verifie_a_ms'))
    capteurs = sample.get('capteurs') if isinstance(sample.get('capteurs'), dict) else {}
    add('capteur_exec', _boolean(capteurs.get('ebpf_exec_actif')) if recent else 'inconnu',
        'sonde d’exécution OS', 'Identité et état déclarés par la sonde ; couverture bornée.', sample.get('mur_epoch_ms'))
    add('capteur_lsm', 'inconnu', 'sonde LSM',
        'Le fichier BPF épinglé seul ne démontre pas l’attachement effectif.', sample.get('mur_epoch_ms'))
    witness = sample.get('service_temoin') if isinstance(sample.get('service_temoin'), dict) else {}
    add('service_temoin', _boolean(witness.get('disponible')) if recent else 'inconnu',
        'sonde HTTP du service témoin', 'Cette mesure ne garantit pas la disponibilité de tous les services.', sample.get('mur_epoch_ms'))
    add('budget_cloud', 'inconnu' if cloud_budget is None else _boolean(type(cloud_budget) is int and 1 <= cloud_budget <= 4),
        'contrôleur local', 'Plafond d’analyses par heure ; aucune requête supplémentaire créée par ce contrôle.', now)
    os_probe = sample.get('posture_securite')
    os_valid = recent and isinstance(os_probe, dict) and os_probe.get('schema') == 'sawm-posture-os/v1' \
        and fresh(os_probe.get('observed_ms'), now, 65000)
    rows = os_probe.get('controls') if os_valid else None
    rows = rows if isinstance(rows, list) and len(rows) <= 32 else []
    for key in OS_TITLES:
        matches = [r for r in rows if isinstance(r, dict) and r.get('id') == key]
        row = matches[0] if len(matches) == 1 else {}
        from invite.agent_labo.posture_securite import status_for
        measured_status = status_for(key, row.get('observed_value'))
        # Inconsistent or synthetic success labels cannot satisfy a local gate.
        status = measured_status if row.get('status') == measured_status else 'inconnu'
        add(key, status, 'sonde locale en lecture seule',
            'Seuil technique du profil ; adaptation à approuver selon le rôle du serveur.'
            if status != 'inconnu' else 'Mesure absente, expirée ou non exploitable.',
            os_probe.get('observed_ms') if os_valid else None)
    return {'schema': SCHEMA, 'observed_ms': now, 'profile': PROFILE if enabled else 'observation',
            'enabled': enabled, 'manifest_sha256': digest if valid_policy else None,
            'certification': False, 'stale': False, 'checks': checks,
            'counts': _counts(checks),
            'required': sorted(required), 'policy_error': invalid}


def refuse(manifest, state, *, audit=None, cloud_budget=None, now_ms=None):
    enabled, required, error = policy(manifest)
    if not enabled:
        return None
    if error:
        return error
    report = evaluate(manifest, state, audit=audit, cloud_budget=cloud_budget, now_ms=now_ms)
    missing = sorted(c['id'] for c in report['checks'] if c['id'] in required and c['status'] != 'satisfait')
    return 'defense_profondeur_preuve_manquante:' + ','.join(missing) if missing else None


def fingerprint(report):
    """Les changements de date seuls n’engendrent pas un nouvel incident."""
    stable = [report['manifest_sha256'], report['enabled'], report['required'], report['policy_error'],
              [(c['id'], c['status'], c['reason']) for c in report['checks']]]
    return hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()


def project(report, *, now_ms):
    """Projection bornée du battement privé ; une ancienne preuve ne devient pas actuelle."""
    if not isinstance(report, dict) or report.get('schema') != SCHEMA \
            or report.get('certification') is not False or type(report.get('enabled')) is not bool:
        return None
    rows = report.get('checks')
    if not isinstance(rows, list) or len(rows) != len(TITLES) \
            or {c.get('id') for c in rows if isinstance(c, dict)} != set(TITLES):
        return None
    out = copy.deepcopy(report)
    stale = not fresh(report.get('observed_ms'), now_ms, 15000)
    for row in out['checks']:
        if row.get('status') not in STATUSES or any(not isinstance(row.get(k), str) or len(row[k]) > 400
                                                  for k in ('title', 'source', 'reason')):
            return None
        if stale:
            row['status'] = 'inconnu'
            row['reason'] = 'Rapport historique : le contrôleur doit confirmer un nouvel état.'
        else:
            ttl = 65000 if row['id'].startswith('os_') else 15000
            if row['id'] in {'telemetrie_fraiche', 'capteur_exec', 'capteur_lsm', 'service_temoin'}:
                ttl = 5000
            if not fresh(row.get('observed_ms'), now_ms, ttl):
                row['status'] = 'inconnu'
                row['reason'] = 'Mesure individuelle périmée, future ou non datée.'
    out['stale'] = stale
    out['counts'] = _counts(out['checks'])
    return out
