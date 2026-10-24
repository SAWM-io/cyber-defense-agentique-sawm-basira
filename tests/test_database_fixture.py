"""Vraie SQLite locale : verrou interprocessus, preuves et limites fixture."""
import contextlib
import importlib
import io
import json
import os
import pathlib
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

DOSSIER = pathlib.Path(__file__).resolve().parents[1] / 'invite/charges_test'
sys.path.insert(0, str(DOSSIER))
database = importlib.import_module('database')


class DatabaseFixtureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.tmp.name).resolve()
        self.run_id = 'test-01'
        self.directory = self.base / 'fixtures/database-defense' / f'run-{self.run_id}'
        self.ledger = self.directory / 'ledger.sqlite'
        self.prepared = database.prepare(self.run_id, racine=self.base)

    def tearDown(self):
        self.tmp.cleanup()

    def _actor(self, command='lock', duration=2):
        script = ('import pathlib,sys;sys.path.insert(0,sys.argv[1]);import database;'
                  'getattr(database,sys.argv[2])(sys.argv[3],float(sys.argv[4]),'
                  'racine=pathlib.Path(sys.argv[5]))')
        return subprocess.Popen([sys.executable, '-u', '-c', script, str(DOSSIER), command,
                                 self.run_id, str(duration), str(self.base)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def _rows(self):
        with contextlib.closing(sqlite3.connect(self.ledger)) as conn:
            return conn.execute('SELECT * FROM ledger ORDER BY entry_id').fetchall()

    def test_prepare_has_exactly_100_synthetic_rows_and_immutable_reference(self):
        self.assertEqual(len(self._rows()), 100)
        self.assertTrue(all(row[3] == 'synthetic-fixture' for row in self._rows()))
        self.assertEqual((self.directory / database.REFERENCE).stat().st_mode & 0o777, 0o400)
        self.assertEqual(self.ledger.read_bytes(), (self.directory / database.REFERENCE).read_bytes())
        self.assertLess(self.ledger.stat().st_size, database.MAX_DATABASE_BYTES)
        with self.assertRaises(FileExistsError):
            database.prepare(self.run_id, racine=self.base)

    def test_status_probes_real_read_and_write_without_changing_hash(self):
        result = database.status(self.run_id, racine=self.base)
        self.assertTrue(result['read_available'])
        self.assertTrue(result['write_available'])
        self.assertTrue(result['reference_matches'])
        self.assertTrue(result['hash_stable_during_probe'])
        self.assertEqual(result['integrity_check'], 'ok')
        self.assertEqual(result['errors'], {})
        self.assertNotIn('synthetic-account', json.dumps(result))

    def test_real_exclusive_lock_blocks_independent_reader_and_writer_then_expires(self):
        proc = self._actor(duration=1)
        try:
            started = json.loads(proc.stdout.readline())
            self.assertTrue(started['locked'])
            self.assertEqual(started['pid'], proc.pid)
            began = time.monotonic()
            result = database.status(self.run_id, racine=self.base)
            self.assertFalse(result['read_available'])
            self.assertFalse(result['write_available'])
            self.assertIsNone(result['integrity_check'])
            self.assertEqual(result['errors'], {'read': 'SQLITE_BUSY', 'write': 'SQLITE_BUSY'})
            self.assertLess(time.monotonic() - began, 0.8)
            self.assertTrue(result['reference_matches'])
            _, stderr = proc.communicate(timeout=3)
            self.assertEqual(proc.returncode, 0, stderr)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        restored = database.status(self.run_id, racine=self.base)
        self.assertTrue(restored['read_available'])
        self.assertTrue(restored['write_available'])
        receipt = json.loads((self.directory / 'lock.json').read_text())
        self.assertEqual(receipt['cause_fin'], 'fin_naturelle_duree')
        self.assertEqual(receipt['attribution_arret'], 'non_etablie')
        self.assertLess(receipt['ecoule_s'], 2)

    def test_signal_releases_lock_without_claiming_sawm_attribution(self):
        proc = self._actor(duration=10)
        try:
            self.assertTrue(json.loads(proc.stdout.readline())['locked'])
            proc.send_signal(signal.SIGTERM)
            _, stderr = proc.communicate(timeout=3)
            self.assertEqual(proc.returncode, 0, stderr)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        receipt = json.loads((self.directory / 'lock.json').read_text())
        self.assertEqual(receipt['cause_fin'], 'signal_recu')
        self.assertEqual(receipt['signal_recu'], signal.SIGTERM)
        self.assertFalse(receipt['locked'])
        self.assertEqual(receipt['attribution_arret'], 'non_etablie')
        self.assertTrue(database.status(self.run_id, racine=self.base)['write_available'])

    def test_killed_process_stale_receipt_is_not_an_availability_measurement(self):
        proc = self._actor(duration=10)
        try:
            self.assertTrue(json.loads(proc.stdout.readline())['locked'])
            proc.kill()
            proc.communicate(timeout=3)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        self.assertTrue(json.loads((self.directory / 'lock.json').read_text())['locked'])
        self.assertTrue(database.status(self.run_id, racine=self.base)['write_available'])

    def test_tamper_one_row_restore_preserves_evidence_and_hash(self):
        before = self._rows()
        with contextlib.redirect_stdout(io.StringIO()):
            altered = database.tamper(self.run_id, racine=self.base)
        after = self._rows()
        self.assertEqual(sum(a != b for a, b in zip(before, after)), 1)
        self.assertEqual(after[0][2], before[0][2] + 1)
        self.assertEqual(altered['changed_rows'], 1)
        self.assertEqual(altered['mutations'], 1)
        self.assertNotEqual(altered['sha256'], altered['reference_sha256'])
        self.assertFalse(database.status(self.run_id, racine=self.base)['reference_matches'])
        altered_bytes = self.ledger.read_bytes()
        restored = database.restore(self.run_id, racine=self.base)
        self.assertTrue(restored['restored'])
        self.assertEqual(self._rows(), before)
        self.assertEqual((self.directory / database.BEFORE_RESTORE).read_bytes(), altered_bytes)
        self.assertTrue(database.status(self.run_id, racine=self.base)['reference_matches'])
        self.assertTrue((self.directory / 'tamper.json').exists())
        with self.assertRaises(FileExistsError):
            database.restore(self.run_id, racine=self.base)
        with self.assertRaises(FileExistsError):
            database.tamper(self.run_id, racine=self.base)

    def test_tamper_actor_alive_after_commit_and_stops_on_signal(self):
        proc = self._actor(command='tamper', duration=10)
        try:
            first = json.loads(proc.stdout.readline())
            self.assertEqual(first['mutations'], 1)
            self.assertFalse(first['termine'])
            self.assertIsNone(proc.poll())
            result = database.status(self.run_id, racine=self.base)
            self.assertTrue(result['read_available'])
            self.assertTrue(result['write_available'])
            self.assertFalse(result['reference_matches'])
            with self.assertRaises(BlockingIOError):
                database.restore(self.run_id, racine=self.base)
            proc.send_signal(signal.SIGTERM)
            _, stderr = proc.communicate(timeout=3)
            self.assertEqual(proc.returncode, 0, stderr)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        result = json.loads((self.directory / 'tamper.json').read_text())
        self.assertEqual(result['cause_fin'], 'signal_recu')
        self.assertEqual(result['mutations'], 1)

    def test_tamper_never_exceeds_20_mutations_or_one_row(self):
        now = [0.0]

        def sleep(seconds):
            now[0] += seconds

        before = self._rows()
        with patch.object(database.time, 'monotonic', side_effect=lambda: now[0]), \
             patch.object(database.time, 'sleep', side_effect=sleep), \
             contextlib.redirect_stdout(io.StringIO()):
            result = database.tamper(self.run_id, 180, racine=self.base)
        after = self._rows()
        self.assertEqual(result['mutations'], 20)
        self.assertEqual(sum(a != b for a, b in zip(before, after)), 1)
        self.assertEqual(after[0][2], before[0][2] + 20)
        self.assertLessEqual(len(list(self.directory.iterdir())), 6)

    def test_duration_and_identifier_limits_before_filesystem_access(self):
        for duration in (0, 0.9, 181, float('inf'), float('nan')):
            with self.subTest(duration=duration):
                with self.assertRaises(ValueError):
                    database.lock('x', duration, racine=self.base / 'missing')
                with self.assertRaises(ValueError):
                    database.tamper('x', duration, racine=self.base / 'missing')
        for run_id in ('../escape', '/opt/real-db', '.', '', 'x' * 65, 'a/b'):
            with self.subTest(run_id=run_id), self.assertRaises(ValueError):
                database.prepare(run_id, racine=self.base)

    def test_symlink_leaf_reference_sidecar_and_hardlink_refused(self):
        outside = self.base / 'outside.sqlite'
        outside.write_bytes(self.ledger.read_bytes())
        original = self.ledger.read_bytes()
        for name in (database.LEDGER, database.REFERENCE, database.LEDGER + '-journal'):
            with self.subTest(name=name):
                target = self.directory / name
                saved = target.read_bytes() if target.exists() else None
                target.unlink(missing_ok=True)
                target.symlink_to(outside)
                try:
                    if name.endswith('-journal'):
                        result = database.status(self.run_id, racine=self.base)
                        self.assertFalse(result['read_available'])
                        self.assertFalse(result['write_available'])
                    else:
                        with self.assertRaises((ValueError, OSError)):
                            database.status(self.run_id, racine=self.base)
                finally:
                    target.unlink()
                    if saved is not None:
                        target.write_bytes(saved)
                self.assertEqual(outside.read_bytes(), original)
        self.ledger.unlink()
        os.link(outside, self.ledger)
        with self.assertRaises(ValueError):
            database.status(self.run_id, racine=self.base)

    def test_symlink_in_any_parent_component_refused(self):
        alias = self.base / 'alias'
        alias.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(OSError):
            database.status(self.run_id, racine=alias)
        real = self.directory.with_name('saved-run')
        self.directory.rename(real)
        self.directory.symlink_to(real, target_is_directory=True)
        with self.assertRaises(OSError):
            database.status(self.run_id, racine=self.base)

    def test_modified_reference_and_oversized_file_refused(self):
        reference = self.directory / database.REFERENCE
        os.chmod(reference, 0o600)
        reference.write_bytes(b'not the original fixture')
        with self.assertRaises(ValueError):
            database.restore(self.run_id, racine=self.base)
        reference.write_bytes(self.ledger.read_bytes())
        with self.ledger.open('ab') as stream:
            stream.truncate(database.MAX_DATABASE_BYTES + 1)
        with self.assertRaises(ValueError):
            database.status(self.run_id, racine=self.base)

    def test_sqlite_corruption_not_reported_as_success_or_leaked(self):
        self.ledger.write_bytes(b'private sentinel, deliberately invalid SQLite file')
        result = database.status(self.run_id, racine=self.base)
        self.assertFalse(result['read_available'])
        self.assertFalse(result['write_available'])
        self.assertIsNone(result['integrity_check'])
        self.assertFalse(result['reference_matches'])
        self.assertNotIn('sentinel', json.dumps(result))

    def test_python310_error_codes_distinguish_lock_and_corruption(self):
        # Exceptions construites sans sqlite_errorname, comme sous Python 3.10.
        cases = {'database is locked': 'SQLITE_BUSY',
                 'database table is locked': 'SQLITE_LOCKED',
                 'file is not a database': 'SQLITE_NOTADB',
                 'database disk image is malformed': 'SQLITE_CORRUPT',
                 'private sentinel in unknown error': 'OperationalError'}
        for message, expected in cases.items():
            with self.subTest(message=message):
                self.assertEqual(database._error(sqlite3.OperationalError(message)), expected)

    def test_cli_has_no_path_argument_and_errors_nonzero(self):
        proc = subprocess.run([sys.executable, str(DOSSIER / 'database.py'), 'status',
                               '--run-id', self.run_id, '--path', str(self.ledger)],
                              capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('unrecognized arguments', proc.stderr)
        with patch.object(database, 'RACINE', self.base), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(database.main(['lock', '--run-id', self.run_id, '--duration', '999']), 1)
        self.assertFalse(json.loads(out.getvalue())['ok'])


if __name__ == '__main__':
    unittest.main()
