"""Relecture indépendante sans VM ni commande exécutée."""
import copy
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from controleur.verification_action import observer_ressource, verifier_action

TARGET = 'labo-copie-b.service'
CG = '/sawm.slice/sawm-charge.slice/' + TARGET


def before():
    return {'cible': TARGET, 'cgroup': CG, 'boot_id': 'boot-1', 'monotonic_s': 100,
            'mur_epoch_ms': 100_000, 'pids': [42], 'populated': 1,
            'unite': {'Id': TARGET, 'ActiveState': 'active', 'MainPID': '42', 'InvocationID': 'inv-1'},
            'cpu_max': 'max 100000', 'cpu_usage_usec': 50000, 'temoin': {'code': 200}}


def receipt(action='geler-transfert'):
    return {'applique': True, 'action': action, 'cible': TARGET, 'decision_id': 'dec-test',
            'recu_ms': 101_000, 'effet': {'quota_demande_pct': 20}}


def samples(cpu=False):
    rows = []
    for i in range(3):
        s = before()
        s.update(monotonic_s=102+i, mur_epoch_ms=102_000+i*1000,
                 pids=[42] if cpu else [], populated=1 if cpu else 0,
                 cpu_usage_usec=50000+150_000*i, cpu_max='20000 100000')
        if not cpu:
            s['unite'].update(ActiveState='inactive', MainPID='0', InvocationID='')
        rows.append(s)
    return rows


class VerificationActionTests(unittest.TestCase):
    def run_check(self, *, action='geler-transfert', rows=None, pre=None, rec=None):
        rows = iter(samples(action == 'limiter-cpu') if rows is None else rows)
        def observe(target, group):
            self.assertEqual((target, group), (TARGET, CG))
            return next(rows)
        return verifier_action(action, TARGET, receipt(action) if rec is None else rec,
                               before() if pre is None else pre, observer=observe, attendre=lambda _: None)

    def test_stop_uses_fresh_os_evidence_not_receipt_boolean(self):
        rec = receipt(); rec['effet_verifie'] = False
        r = self.run_check(rec=rec)
        self.assertEqual(r['statut'], 'verifie')
        self.assertEqual(r['effet'], 'arret_unite_verifie')
        self.assertEqual(r['temoin'], 'disponible')
        self.assertEqual(r['reseau'], 'non_attribue')
        self.assertEqual(r['fenetre_observee_s'], 2)

    def test_restart_after_success_receipt_is_failure(self):
        rows = samples(); rows[-1]['pids'] = [83]; rows[-1]['populated'] = 1
        r = self.run_check(rows=rows)
        self.assertEqual(r['statut'], 'echec')
        self.assertEqual(r['motif'], 'activite_apres_arret')

    def test_no_witness_not_success(self):
        rows = samples(); rows[1]['temoin'] = {'code': None}
        self.assertEqual(self.run_check(rows=rows)['statut'], 'inconclusif')
        rows[1]['temoin'] = {'code': 503}
        self.assertEqual(self.run_check(rows=rows)['statut'], 'echec')

    def test_cpu_reads_actual_quota_and_separates_consumption(self):
        r = self.run_check(action='limiter-cpu')
        self.assertEqual(r['effet'], 'quota_cgroup_verifie')
        self.assertEqual(r['cpu_observe_pct_un_coeur'], 15)
        self.assertIn('non démontrée', r['limites'][-1])
        rows = samples(True); rows[-1]['cpu_max'] = 'max 100000'
        self.assertEqual(self.run_check(action='limiter-cpu', rows=rows)['statut'], 'inconclusif')
        rows[-1]['cpu_max'] = '50000 100000'
        self.assertEqual(self.run_check(action='limiter-cpu', rows=rows)['statut'], 'echec')

    def test_stale_boot_changed_wrong_target_and_missing_measurement_are_inconclusive(self):
        for key, value in [('boot_id', 'boot-2'), ('cible', 'labo-other.service'),
                           ('cgroup', '/different'), ('monotonic_s', 99),
                           ('mur_epoch_ms', 100_500), ('pids', None)]:
            with self.subTest(key=key):
                rows = samples(); rows[-1][key] = value
                self.assertEqual(self.run_check(rows=rows)['statut'], 'inconclusif')
        rows = samples(); rows[1] = {'erreur': 'TimeoutError'}
        self.assertEqual(self.run_check(rows=rows)['statut'], 'inconclusif')

    def test_cpu_invocation_restart_invalidates_measurement(self):
        rows = samples(True); rows[-1]['unite']['InvocationID'] = 'inv-2'
        self.assertEqual(self.run_check(action='limiter-cpu', rows=rows)['motif'], 'invocation_changee_cpu')

    def test_before_inactive_missing_or_wrong_receipt_cannot_be_confirmed(self):
        pre = before(); pre['pids'] = []
        self.assertEqual(self.run_check(pre=pre)['statut'], 'inconclusif')
        self.assertEqual(self.run_check(pre={})['statut'], 'inconclusif')
        rec = receipt(); rec['cible'] = 'labo-other.service'
        self.assertEqual(self.run_check(rec=rec)['motif'], 'recu_non_correlle')
        rec['applique'] = False
        self.assertEqual(self.run_check(rec=rec)['statut'], 'non_appliquee')

    def test_observer_rejects_shell_and_foreign_groups_before_transport(self):
        for value in ('sshd.service', 'labo-a;id.service', 'labo-../a.service'):
            with self.assertRaises(ValueError):
                observer_ressource(value)
        for group in ('/sawm.slice/../'+TARGET, '/system.slice/'+TARGET,
                      '/sawm.slice/labo-other.service'):
            with self.assertRaises(ValueError):
                observer_ressource(TARGET, group)

    def test_observation_transport_error_has_no_exception_text(self):
        def fail(*_): raise RuntimeError('confidential-token')
        r = verifier_action('geler-transfert', TARGET, receipt(), before(),
                            observer=fail, attendre=lambda _: None)
        self.assertEqual(r['statut'], 'inconclusif')
        self.assertNotIn('confidential-token', str(r))


if __name__ == '__main__': unittest.main()
