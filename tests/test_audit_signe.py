"""Preuves indépendantes : corruption, troncature, crash, concurrence, secrets."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from controleur.audit_signe import AuditInvalide, JournalSigne, verifier


class AuditSigneTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root/'proof/evenements.jsonl'
        self.key = self.root/'private/ed25519.key'
        self.journal = JournalSigne(self.path, key_path=self.key)

    def two(self):
        self.journal.append({'type': 'observation', 'value': 1})
        self.journal.append({'type': 'decision', 'value': 2})

    def test_signed_roundtrip_without_private_key_for_verification(self):
        self.two()
        self.key.unlink()
        result = verifier(self.path, public_key_path=self.journal.public_key_path)
        self.assertTrue(result['valide'])
        self.assertEqual(result['seq'], 2)
        self.assertEqual(result['algorithme'], 'Ed25519')

    def test_private_key_permissions_and_reuse(self):
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)
        self.two()
        restarted = JournalSigne(self.path, key_path=self.key)
        self.assertEqual(restarted.append({'restart': True})['seq'], 3)
        self.assertEqual(restarted.key_id, self.journal.key_id)

    def test_key_bad_mode_refused(self):
        self.key.chmod(0o644)
        with self.assertRaises(AuditInvalide):
            JournalSigne(self.path, key_path=self.key)

    def test_missing_key_not_recreated(self):
        self.key.unlink()
        with self.assertRaises(AuditInvalide):
            JournalSigne(self.path, key_path=self.key)
        self.assertFalse(self.key.exists())

    def test_modified_event_refused_before_new_append(self):
        self.two()
        raw = self.path.read_text().replace('"value":1', '"value":9')
        self.path.write_text(raw)
        with self.assertRaises(AuditInvalide):
            self.journal.append({'unsafe': True})
        self.assertEqual(self.path.read_text(), raw)

    def test_modified_checkpoint_refused(self):
        self.two()
        cp = self.journal.checkpoint_path
        cp.write_text(cp.read_text().replace('"seq":2', '"seq":1'))
        with self.assertRaises(AuditInvalide):
            self.journal.verify()

    def test_remove_last_complete_line_detected(self):
        self.two()
        self.path.write_bytes(self.path.read_bytes().splitlines(keepends=True)[0])
        with self.assertRaises(AuditInvalide):
            self.journal.verify()

    def test_remove_all_lines_detected(self):
        self.two()
        self.path.write_bytes(b'')
        with self.assertRaises(AuditInvalide):
            self.journal.verify()

    def test_reordered_valid_signatures_detected(self):
        self.two()
        self.path.write_bytes(b''.join(reversed(self.path.read_bytes().splitlines(keepends=True))))
        with self.assertRaises(AuditInvalide):
            self.journal.verify()

    def test_missing_checkpoint_never_rebuilt(self):
        self.two()
        self.journal.checkpoint_path.unlink()
        with self.assertRaises(AuditInvalide):
            JournalSigne(self.path, key_path=self.key)
        self.assertFalse(self.journal.checkpoint_path.exists())

    def test_torn_write_refuses_continuation(self):
        self.two()
        with self.path.open('ab') as file:
            file.write(b'{"version":')
        before = self.path.read_bytes()
        with self.assertRaises(AuditInvalide):
            self.journal.append({'new': True})
        self.assertEqual(self.path.read_bytes(), before)

    def test_crash_between_journal_and_checkpoint_fails_closed(self):
        with patch.object(self.journal, '_checkpoint', side_effect=OSError('disk error')):
            with self.assertRaises(OSError):
                self.journal.append({'first': 1})
        with self.assertRaises(AuditInvalide):
            self.journal.verify()
        with self.assertRaises(AuditInvalide):
            self.journal.append({'second': 2})

    def test_rollback_both_files_requires_external_anchor(self):
        self.journal.append({'old': True})
        old_log = self.path.read_bytes()
        old_cp = self.journal.checkpoint_path.read_bytes()
        self.journal.append({'new': True})
        anchor = self.journal.verify()
        self.path.write_bytes(old_log)
        self.journal.checkpoint_path.write_bytes(old_cp)
        # Honest limitation: no external anchor means a historically valid prefix.
        self.assertTrue(self.journal.verify()['valide'])
        with self.assertRaises(AuditInvalide):
            self.journal.verify(ancre=anchor)

    def test_external_anchor_survives_future_appends(self):
        self.journal.append({'old': True})
        anchor = self.journal.verify()
        self.journal.append({'new': True})
        self.assertTrue(self.journal.verify(ancre=anchor)['ancre_externe_verifiee'])

    def test_concurrent_writers_do_not_duplicate_sequence(self):
        errors = []
        def write(n):
            try:
                other = JournalSigne(self.path, key_path=self.key)
                for step in range(5):
                    other.append({'writer': n, 'step': step})
            except Exception as exc:
                errors.append(exc)
        threads = [threading.Thread(target=write, args=(n,)) for n in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(self.journal.verify()['seq'], 20)

    def test_redacts_named_secrets_and_bounds_untrusted_text(self):
        self.journal.append({'api_key': 'never publish me', 'path': 'ignore rules\n<script>'+('x'*3000),
                             'nested': {'authorization': 'Bearer private'}})
        raw = self.path.read_text()
        self.assertNotIn('never publish me', raw)
        self.assertNotIn('Bearer private', raw)
        event = json.loads(raw)['evenement']
        self.assertTrue(event['path'].endswith('[tronqué]'))
        self.assertEqual(event['api_key'], '[expurgé]')
        self.assertTrue(self.journal.verify()['valide'])

    def test_rejects_non_finite_and_oversized_event(self):
        for event in ({'nan': float('nan')}, {str(i): 'x'*2048 for i in range(64)}):
            with self.assertRaises(ValueError):
                self.journal.append(event)
        self.assertEqual(self.journal.verify()['seq'], 0)

    def test_no_symlink_journal(self):
        other = self.root/'victim'
        other.write_text('untouched')
        self.path.unlink()
        self.path.symlink_to(other)
        with self.assertRaises(AuditInvalide):
            self.journal.append({'x': 1})
        self.assertEqual(other.read_text(), 'untouched')

    def test_checkpoint_is_not_accepted_as_event(self):
        self.path.write_bytes(self.journal.checkpoint_path.read_bytes())
        with self.assertRaises(AuditInvalide):
            self.journal.verify()

    def test_reject_wrong_public_key(self):
        other = JournalSigne(self.root/'other/events', key_path=self.root/'other/key')
        with self.assertRaises(AuditInvalide):
            verifier(self.path, public_key_path=other.public_key_path)


if __name__ == '__main__':
    unittest.main()
