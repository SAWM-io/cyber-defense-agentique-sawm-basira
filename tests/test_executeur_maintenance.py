"""Point privilégié : mandats réévalués avant la vraie fonction d'action."""
import contextlib
import copy
import hashlib
import importlib.util
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from controleur import maintenance as m
from test_maintenance import fixture, NOW, UNIT, OBJECT

path = Path(__file__).resolve().parents[1]/'invite/executeur/executeur.py'
spec = importlib.util.spec_from_file_location('executeur_maintenance_test', path)
ex = importlib.util.module_from_spec(spec); spec.loader.exec_module(ex)


class ExecutorMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.key, self.payload, self.obs, self.manifest = fixture()
        self.manifest.update(_sha256='a'*64, unites_autorisees=[UNIT],
            defense_fichiers={'enabled': True, 'targets': [{'unit': UNIT, 'path': OBJECT['path'],
                             'kind': 'sqlite', 'reference_sha256': 'a'*64}]})
        self.request = {'decision_id': 'decision-test', 'action': 'arreter-service', 'cible': UNIT,
                        'generation': self.manifest['generation'], 'manifest_sha256': 'a'*64}
        self.calls = []
        self.action = Mock(return_value={'effet_verifie': True})
        self.inspection = {'operations': ['sqlite-exclusive-lock']}
        self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        for obj, name, value in [(ex, 'verrou', contextlib.nullcontext), (ex, 'manifeste', lambda: self.manifest),
            (ex, '_journal', self.calls.append), (ex, '_precedent', lambda _: None),
            (ex, '_charger_maintenance', lambda: m),
            (m, 'observer_os', lambda *a: self.obs.copy()),
            (m, 'inspecter_operations', lambda *a: self.inspection), (m.time, 'time', lambda: NOW/1000)]:
            self.stack.enter_context(patch.object(obj, name, value))
        self.stack.enter_context(patch.dict(ex.ACTIONS, {'arreter-service': self.action, 'geler-transfert': self.action}))

    def test_signed_current_maintenance_is_preserved_before_action_and_receipted(self):
        r = ex.appliquer(self.request)
        self.assertFalse(r['applique'])
        self.assertEqual(r['refus']['motif'], 'maintenance_signee_preservee')
        self.assertEqual(r['maintenance']['scopes'][0]['principal'], 'institution:cto')
        self.assertEqual(self.calls[0]['etat'], 'refuse_maintenance')
        self.action.assert_not_called()

    def test_maintenance_becoming_active_during_fsync_is_preserved(self):
        clock = [NOW]
        future = {**self.payload, 'not_before_ms': NOW+100}
        self.manifest['maintenance']['mandates'] = [m.signer(future, self.key)]
        def journal(row):
            self.calls.append(row)
            if row['etat'] == 'en_cours':
                clock[0] = NOW+150
        with patch.object(m.time, 'time', side_effect=lambda: clock[0]/1000), \
                patch.object(ex, '_journal', side_effect=journal):
            receipt = ex.appliquer(self.request)
        self.assertFalse(receipt['applique'])
        self.assertEqual(receipt['issue'], 'non_appliquee')
        self.assertEqual(receipt['refus']['motif'], 'maintenance_signee_preservee')
        self.assertTrue(receipt['maintenance']['veto'])
        self.assertEqual(self.calls[-1]['etat'], 'termine')
        self.action.assert_not_called()

    def test_identity_is_rechecked_after_durable_receipt(self):
        self.manifest['maintenance']['revoked_mandates'] = [self.payload['mandate_id']]
        after_fsync = [False]
        def journal(row):
            self.calls.append(row)
            if row['etat'] == 'en_cours':
                after_fsync[0] = True
        def identity(request, manifest):
            if after_fsync[0]:
                raise ex.Refus('identite_attendue_changee', 'MainPID')
            return manifest
        with patch.object(ex, '_journal', side_effect=journal), \
                patch.object(ex, 'verifier_identite_attendue', side_effect=identity) as check:
            receipt = ex.appliquer(self.request)
        self.assertEqual(check.call_count, 2)
        self.assertFalse(receipt['applique'])
        self.assertEqual(receipt['issue'], 'non_appliquee')
        self.assertEqual(receipt['refus']['motif'], 'identite_attendue_changee')
        self.action.assert_not_called()

    def test_revoked_expired_or_forged_mandate_does_not_override_existing_action_right(self):
        for case in ('revoked', 'expired', 'forged'):
            original = copy.deepcopy(self.manifest)
            if case == 'revoked':
                self.manifest['maintenance']['revoked_mandates'] = [self.payload['mandate_id']]
            elif case == 'expired':
                payload = {**self.payload, 'expires_at_ms': NOW}
                self.manifest['maintenance']['mandates'] = [m.signer(payload, self.key)]
            else:
                self.manifest['maintenance']['mandates'][0]['payload']['uid'] = 0
            with self.subTest(case=case):
                r = ex.appliquer(self.request)
                self.assertTrue(r['applique'], r)
                self.assertFalse(r['maintenance']['veto'])
            self.manifest = original
        self.assertEqual(self.action.call_count, 3)

    def test_inspection_error_or_no_current_violation_refuses_and_never_runs_action(self):
        with patch.object(m, 'observer_os', side_effect=OSError('proc denied')):
            r = ex.appliquer(self.request)
            self.assertFalse(r['applique'])
            self.assertEqual(r['refus']['motif'], 'maintenance_non_verifiable')
        self.inspection = {'operations': []}
        self.assertFalse(ex.appliquer(self.request)['applique'])
        self.action.assert_not_called()

    def test_identity_change_between_local_probes_refuses(self):
        with patch.object(m, 'observer_os', side_effect=[self.obs, {**self.obs, 'process_start_ticks': 999}]):
            r = ex.appliquer(self.request)
        self.assertFalse(r['applique'])
        self.assertIn('identite_os_changee', r['refus']['detail'])
        self.action.assert_not_called()

    def test_write_permission_does_not_preserve_unapproved_lock(self):
        p = {**self.payload, 'operation': 'file-write'}
        self.manifest['maintenance']['mandates'] = [m.signer(p, self.key)]
        self.inspection = {'operations': ['file-write', 'sqlite-exclusive-lock']}
        r = ex.appliquer(self.request)
        self.assertTrue(r['applique'], r)
        self.assertEqual([v['authorized'] for v in r['maintenance']['scopes']], [True, False])

    def test_both_observed_operations_require_two_distinct_exact_mandates(self):
        p = {**self.payload, 'operation': 'file-write', 'mandate_id': 'maintenance-write-002'}
        self.manifest['maintenance']['mandates'].append(m.signer(p, self.key))
        self.inspection = {'operations': ['file-write', 'sqlite-exclusive-lock']}
        r = ex.appliquer(self.request)
        self.assertFalse(r['applique'])
        self.assertEqual(len(r['maintenance']['scopes']), 2)
        self.action.assert_not_called()

    def test_llm_supplied_scope_is_ignored_and_other_action_not_covered(self):
        p = {**self.payload, 'operation': 'file-write'}
        self.manifest['maintenance']['mandates'] = [m.signer(p, self.key)]
        r = ex.appliquer({**self.request, 'operation': 'file-write', 'authorized': True})
        self.assertTrue(r['applique'], r)  # trusted inspection says lock, not claimed write
        self.manifest['maintenance']['mandates'] = [m.signer(self.payload, self.key)]
        r = ex.appliquer({**self.request, 'action': 'geler-transfert'})
        self.assertTrue(r['applique'], r)  # no maintenance exemption for transfer
        self.assertFalse(r['maintenance']['checked'])


class DeterministicImportTests(unittest.TestCase):
    def test_ambient_homonym_is_not_imported_or_executed(self):
        poison = Mock()
        with patch.dict(sys.modules, {'maintenance': poison}), patch.object(ex, '_MAINTENANCE_MODULE', None):
            module = ex._charger_maintenance()
            self.assertEqual(Path(module.__file__).resolve(), path.parents[2]/'controleur/maintenance.py')
            self.assertIsNot(module, poison)
            self.assertEqual(module.SCHEMA, m.SCHEMA)
            self.assertIs(ex._charger_maintenance(), module)
            poison.assert_not_called()


class PerUnitActionPolicyTests(unittest.TestCase):
    def test_descriptive_non_mutating_target_remains_supported(self):
        manifest = {'actions_par_unite': {UNIT: ['arreter-service','ne-rien-faire']}}
        for action in ('ouvrir-dossier', 'demander-clarification', 'ne-rien-faire'):
            ex.verifier_actions_unite(action, 'incident général', manifest)

    def test_restriction_preserves_other_units_and_never_grants_other_mutations(self):
        manifest = {'actions_par_unite': {UNIT: ['arreter-service','ne-rien-faire']}}
        ex.verifier_actions_unite('arreter-service',UNIT,manifest)
        ex.verifier_actions_unite('limiter-cpu','labo-other.service',manifest)
        ex.verifier_actions_unite('ne-rien-faire','',manifest)
        for action in ('geler-transfert','limiter-cpu','restaurer-fixtures'):
            with self.assertRaisesRegex(ex.Refus,'action_hors_mandat_unite'):
                ex.verifier_actions_unite(action,UNIT,manifest)

    def test_malformed_scope_is_always_rejected(self):
        for value in (None, [], {UNIT: None}, {UNIT: []}, {UNIT: 'arreter-service'},
                      {UNIT: ['arreter-service',True]}, {UNIT:['arreter-service','arreter-service']},
                      {'*':['arreter-service']}):
            with self.subTest(value=value), self.assertRaisesRegex(ex.Refus,'actions_par_unite_invalides'):
                ex.verifier_actions_unite('arreter-service',UNIT,{'actions_par_unite':value})


class LocalOperationInspectionTests(unittest.TestCase):
    def test_real_sqlite_healthy_then_exclusive_lock_and_hash_change_are_separate(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder).resolve()/'test.sqlite'
            db = sqlite3.connect(path)
            db.execute('CREATE TABLE witness (x INTEGER)'); db.execute('INSERT INTO witness VALUES (1)'); db.commit()
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            s = path.stat()
            observation = {'object': {'path': str(path), 'device': s.st_dev, 'inode': s.st_ino},
                'pid': 142, 'fd_on_object': True, 'kernel_locks': ['3: POSIX ADVISORY WRITE 142 fe:00:7214 1073741824 1073742335']}
            target = {'path': str(path), 'reference_sha256': digest, 'kind': 'sqlite'}
            self.assertEqual(m.inspecter_operations(target, observation)['operations'], [])
            db.execute('BEGIN EXCLUSIVE')
            result = m.inspecter_operations(target, observation)
            self.assertEqual(result['operations'], ['sqlite-exclusive-lock'])
            self.assertTrue(result['reference_matches'])
            db.rollback()
            db.execute('UPDATE witness SET x=2'); db.commit()
            self.assertEqual(m.inspecter_operations(target, observation)['operations'], ['file-write'])
            db.close()

    def test_python310_busy_without_error_attributes_or_sqlite_constant(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder).resolve()/'fixture.sqlite'; path.write_bytes(b'fixture')
            stat = path.stat()
            observation = {'object': {'path': str(path), 'device': stat.st_dev, 'inode': stat.st_ino},
                'pid': 142, 'fd_on_object': True, 'kernel_locks': ['3: POSIX ADVISORY WRITE 142 fe:00:7214 1073741824 1073742335']}
            target = {'path': str(path), 'reference_sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'kind': 'sqlite'}
            error = sqlite3.OperationalError('database is locked')
            self.assertFalse(hasattr(error, 'sqlite_errorcode'))
            self.assertFalse(hasattr(error, 'sqlite_errorname'))
            with patch.dict(sqlite3.__dict__), patch.object(sqlite3, 'connect', side_effect=error):
                sqlite3.__dict__.pop('SQLITE_BUSY', None)
                result = m.inspecter_operations(target, observation)
            self.assertEqual(result['operations'], ['sqlite-exclusive-lock'])
            self.assertEqual(result['sqlite_busy'], [True, True])

    def test_busy_fallback_never_accepts_locked_tables_corruption_or_partial_text(self):
        for message in ('database table is locked', 'database schema is locked',
                        'database disk image is malformed', 'prefix database is locked',
                        'database is locked suffix', 'DATABASE IS LOCKED'):
            self.assertFalse(m._sqlite_busy(sqlite3.OperationalError(message)), message)
        error = sqlite3.OperationalError('database is locked')
        error.sqlite_errorcode = 11  # explicit SQLITE_CORRUPT wins over misleading text
        self.assertFalse(m._sqlite_busy(error))
        error.sqlite_errorcode = 5
        self.assertTrue(m._sqlite_busy(error))
        del error.sqlite_errorcode
        error.sqlite_errorname = 'SQLITE_LOCKED'
        self.assertFalse(m._sqlite_busy(error))

    def test_hash_change_without_attribution_or_oversized_object_is_uncertain(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder).resolve()/'file'; path.write_bytes(b'changed')
            s = path.stat()
            observation = {'object': {'path': str(path), 'device': s.st_dev, 'inode': s.st_ino}, 'fd_on_object': False}
            target = {'path': str(path), 'reference_sha256': '0'*64, 'kind': 'file'}
            with self.assertRaisesRegex(m.MandatInvalide, 'sans_processus'):
                m.inspecter_operations(target, observation)
            with self.assertRaisesRegex(m.MandatInvalide, 'budget'):
                m.inspecter_operations({**target, 'max_integrity_bytes': 2}, observation)


if __name__ == '__main__': unittest.main()
