"""Raccordement télémétrie réel : JSON root borné, absence, campagnes, fraîcheur."""
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

AGENT = pathlib.Path(__file__).resolve().parents[1] / 'invite/agent_labo'
sys.path.insert(0, str(AGENT))
spec = importlib.util.spec_from_file_location('telemetrie_defense', AGENT / 'telemetrie.py')
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
NOW = 1_800_000_000_000


def event(ip, *, when=NOW-100):
    return {'schema': 'sawm-auth-observation/v1', 'observed_ms': when, 'source_ip': ip,
            'username_label': 'demo-cto', 'endpoint': '/login', 'outcome': 'rejected',
            'geography': 'non_applicable', 'failures_in_window': 3, 'block_receipt': None,
            'campaign_hint': {'possible': True, 'distinct_failed_ips': 2,
                              'window_s': 120, 'identity_established': False}}


def encoded(rows):
    return ('\n'.join(json.dumps(row) for row in rows)+'\n').encode()


class DefenseTelemetryTests(unittest.TestCase):
    def test_real_guard_events_reach_telemetry_and_campaigns(self):
        with patch.object(t, '_lire_prive', return_value=(encoded([event('192.0.2.1'), event('10.203.0.2')]), False)):
            result = t.authentification(now_ms=NOW)
        self.assertTrue(result['available'])
        self.assertEqual(len(result['events']), 2)
        self.assertEqual(len(result['campagnes']), 1)
        self.assertEqual(result['campagnes'][0]['ip_a_bloquer'], [])
        self.assertEqual(result['age_ms'], 100)
        self.assertFalse(result['human_identity_established'])

    def test_unknown_fields_or_forged_claims_are_rejected_before_emission(self):
        data = event('192.0.2.1'); data['password'] = 'must-not-be-exported'
        with patch.object(t, '_lire_prive', return_value=(encoded([data]), False)):
            result = t.authentification(now_ms=NOW)
        self.assertEqual(result['invalid_events'], 1)
        self.assertNotIn('must-not-be-exported', str(result))
        self.assertEqual(result['events'], [])

    def test_missing_log_differs_from_empty_recent_window(self):
        with patch.object(t, '_lire_prive', side_effect=FileNotFoundError):
            missing = t.authentification(now_ms=NOW)
        with patch.object(t, '_lire_prive', return_value=(encoded([event('192.0.2.1', when=NOW-300001)]), False)):
            expired = t.authentification(now_ms=NOW)
        self.assertFalse(missing['available'])
        self.assertEqual(missing['status'], 'journal_absent')
        self.assertTrue(expired['available'])
        self.assertEqual(expired['status'], 'aucun_evenement_recent')

    def test_only_32_valid_recent_events_are_returned(self):
        rows = [event('192.0.2.1', when=NOW-i) for i in range(150)]
        with patch.object(t, '_lire_prive', return_value=(encoded(rows), False)):
            result = t.authentification(now_ms=NOW)
        self.assertEqual(len(result['events']), 32)
        self.assertTrue(result['truncated'])

    def test_defense_snapshot_fresh_stale_and_absent_are_distinct(self):
        snapshot = {'schema': 'sawm-file-defense/v1', 'observed_ms': NOW-20, 'active': True,
                    'targets': [], 'alertes': []}
        with patch.object(t, '_lire_prive', return_value=(json.dumps(snapshot).encode(), False)):
            fresh = t.defense_fichiers(now_ms=NOW)
        self.assertEqual(fresh['status'], 'etat_recu')
        self.assertEqual(fresh['snapshot'], snapshot)
        snapshot['observed_ms'] = NOW-5001
        with patch.object(t, '_lire_prive', return_value=(json.dumps(snapshot).encode(), False)):
            stale = t.defense_fichiers(now_ms=NOW)
        self.assertEqual(stale['status'], 'fraicheur_non_etablie')
        with patch.object(t, '_lire_prive', side_effect=FileNotFoundError):
            absent = t.defense_fichiers(now_ms=NOW)
        self.assertEqual(absent['status'], 'etat_absent')
        self.assertFalse(absent['available'])

    def test_bad_schema_duplicate_or_nonfinite_json_not_relayed(self):
        for raw in (b'{"schema":"sawm-anything/v1"}', b'{"schema":"sawm-file-defense/v1","x":NaN}',
                    b'{"schema":"sawm-file-defense/v1","active":true,"active":false}'):
            with self.subTest(raw=raw), patch.object(t, '_lire_prive', return_value=(raw, False)):
                result = t.defense_fichiers(now_ms=NOW)
                self.assertEqual(result['status'], 'etat_non_verifiable')
                self.assertIsNone(result['snapshot'])

    def test_private_file_symlink_permissions_and_size_are_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'state.json'
            path.write_bytes(b'{"ok":true}')
            path.chmod(0o600)
            # Le test vérifie le descripteur ; les parents temporaires macOS
            # sont hors périmètre root du lecteur de production.
            with patch.object(t.auth_guard, '_safe_parent'):
                raw, truncated = t._lire_prive(path, owner_uid=os.getuid())
                self.assertEqual(raw, b'{"ok":true}')
                self.assertFalse(truncated)
                path.chmod(0o644)
                with self.assertRaises(ValueError):
                    t._lire_prive(path, owner_uid=os.getuid())
                path.chmod(0o600)
                path.write_bytes(b'x'*65537)
                with self.assertRaises(ValueError):
                    t._lire_prive(path, owner_uid=os.getuid())
                link = pathlib.Path(directory) / 'link'
                link.symlink_to(path)
                with self.assertRaises(OSError):
                    t._lire_prive(link, owner_uid=os.getuid())

    def test_tail_is_bounded_and_discards_first_partial_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'events.jsonl'
            path.write_bytes(b'first-line\nsecond-line\nlast-line\n'); path.chmod(0o600)
            with patch.object(t.auth_guard, '_safe_parent'):
                data, cut = t._lire_prive(path, maximum=18, tail=True, owner_uid=os.getuid())
            self.assertTrue(cut)
            self.assertEqual(data, b'last-line\n')


if __name__ == '__main__':
    unittest.main()
