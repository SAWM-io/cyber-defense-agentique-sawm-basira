"""Pure evidence checks retained from the laboratory report; no report or OS side effects."""
import math

def finite(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def strict_success(case):
    """Recontrôle les critères essentiels, sans transformer un libellé en preuve."""
    if case.get('status') != 'passed' or case.get('witness', {}).get('healthy') is not True:
        return False
    result = case.get('result') or {}
    decision = result.get('diagnostic') or {}
    unit = case.get('unit_after') or {}
    if case.get('permit') == 'valid':
        veto = case.get('veto_attempt') or {}
        expected_pid = (veto.get('expected_identity') or {}).get('MainPID')
        return (result.get('authorization', {}).get('authorized') is True
                and decision.get('recommandation') in ('surveiller', 'signaler')
                and not result.get('action') and unit.get('ActiveState') == 'active'
                and veto.get('applique') is False
                and (veto.get('refus') or {}).get('motif') == 'maintenance_signee_preservee'
                and type(expected_pid) is str and expected_pid.isdecimal()
                and int(expected_pid) > 1 and unit.get('MainPID') == expected_pid)
    if case.get('permit') == 'forged':
        return (result.get('authorization', {}).get('authorized') is False
                and decision.get('recommandation') == 'signaler'
                and not result.get('action') and unit.get('ActiveState') == 'active')
    action = result.get('action') or case.get('cloud_receipt') or {}
    if action.get('applique') is not True or action.get('effet_verifie') is not True \
            or unit.get('ActiveState') != 'inactive':
        return False
    if case.get('origin') == 'SAWM':
        verification = case.get('cloud_verification') or {}
        if not (verification.get('statut') == 'verifie' and verification.get('effet') == 'arret_unite_verifie'
                and verification.get('temoin') == 'disponible'):
            return False
    return case.get('mode') != 'lock' or all(case.get('after', {}).get(k) is True
                                          for k in ('read_available', 'write_available'))


def title(case):
    situation = 'Verrou SQLite' if case.get('mode') == 'lock' else 'Écriture / intégrité'
    permit = {'absent': 'sans mandat', 'valid': 'mandat valide', 'expired': 'mandat expiré',
              'revoked': 'mandat révoqué', 'forged': 'signature falsifiée'}.get(case.get('permit'), 'mandat inconnu')
    return situation + ' / ' + permit + (' / analyse SAWM' if case.get('cloud_requested') is True else '')


def outcome(case):
    if not strict_success(case):
        if case.get('status') == 'passed' and case.get('permit') == 'valid' and not case.get('veto_attempt'):
            return 'Préservation observée ; veto non testé'
        return 'Non confirmé' if case.get('status') == 'passed' else {
            'running': 'En cours', 'failed': 'Écart conservé', 'error': 'Erreur conservée'}.get(case.get('status'), 'Inconnu')
    if case.get('permit') == 'valid':
        return 'Maintenance préservée ; alerte conservée' if \
            (case.get('result') or {}).get('diagnostic', {}).get('recommandation') == 'signaler' else 'Maintenance préservée'
    if case.get('permit') == 'forged':
        return 'Autorisation rejetée ; alerte'
    return 'Arrêt vérifié ; lectures rétablies' if case.get('mode') == 'lock' else 'Écrivain arrêté ; effet vérifié'


def capture_values(capture):
    return [value for case in capture.get('cases', []) if case.get('passed') is True
            for value in case.get('captured_latency_ms', []) if finite(value)]


def ssh_success(ssh):
    attempts, observations, alerts = (ssh.get(key) for key in ('attempts','observations','alerts'))
    return (ssh.get('status') == 'passed' and ssh.get('available') is True
        and type(attempts) is list and len(attempts) == 3
        and all(row.get('authentication_rejected') is True and row.get('exit_code') == 255 for row in attempts)
        and type(observations) is list and len(observations) >= 3
        and len({row.get('id') for row in observations}) == len(observations)
        and all(row.get('source') == 'journald_root_sshd' and row.get('destination_port') == 22
                and row.get('outcome') == 'invalid_account' for row in observations)
        and type(alerts) is list and bool(alerts)
        and all(row.get('recommandation') == 'signaler' and row.get('block_performed') is False for row in alerts)
        and ssh.get('witness_http') == 200 and ssh.get('existing_key_ssh_still_works') is True)
