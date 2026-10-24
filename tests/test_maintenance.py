"""Mandats : signature, portée, temps, révocation, identité OS et compatibilité.

Clés éphémères exclusivement ; aucune VM, aucun fournisseur ni vraie mémoire.
"""
import base64
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from controleur import maintenance as m
from controleur import maintenance_cli as cli
from controleur.garde_database import preservation_explicitement_autorisee, proposer

UNIT = 'labo-db-test.service'
OBJECT = {'path': '/opt/sawm-labo/fixtures/comptabilite.sqlite', 'device': 254, 'inode': 7214}
NOW = 1900000000000


def fixture():
    key = Ed25519PrivateKey.generate()
    record = m.public_key_record(key, 'institution:cto', units=[UNIT], operations=['sqlite-exclusive-lock', 'file-write'], objects=[OBJECT['path']])
    p = {'schema': m.SCHEMA, 'mandate_id': 'maintenance-demo-001', 'principal': record['principal'], 'key_id': record['key_id'],
         'generation': 'test-v3', 'machine_id': 'vm-test-1', 'boot_id': 'boot-test-1', 'unit': UNIT,
         'invocation_id': 'invocation-1', 'pid': 142, 'process_start_ticks': 778292, 'uid': 1000,
         'cgroup': '/sawm-labo.slice/'+UNIT, 'object': dict(OBJECT), 'operation': 'sqlite-exclusive-lock',
         'issued_at_ms': NOW-1000, 'not_before_ms': NOW-500, 'expires_at_ms': NOW+60000}
    obs = {k: copy.deepcopy(p[k]) for k in m.OBS_KEYS}
    obs.update(identity_stable=True, observed_at_ms=NOW)
    manifest = {'generation': 'test-v3', 'maintenance': {'schema': m.POLICY_SCHEMA, 'machine_id': 'vm-test-1',
        'keys': [record], 'mandates': [m.signer(p, key)], 'revoked_mandates': [],
        'max_observation_age_ms': 1500, 'max_duration_ms': 3600000}}
    return key, p, obs, manifest


def evaluate(manifest, obs, **changes):
    args = {'unit': UNIT, 'operation': 'sqlite-exclusive-lock', 'object_path': OBJECT['path'], 'now_ms': NOW}
    return m.evaluate(manifest, obs, **{**args, **changes})


class MaintenanceContractTest(unittest.TestCase):
    def setUp(self):
        self.key, self.payload, self.obs, self.manifest = fixture()

    def test_valid_signature_exact_scope_and_fresh_identity(self):
        result = evaluate(self.manifest, self.obs)
        self.assertTrue(result['authorized'])
        self.assertEqual(result['principal'], 'institution:cto')
        self.assertTrue(result['signature_verified'])

    def test_altered_payload_or_signature_rejected(self):
        for field, value in [('uid', 0), ('pid', 999), ('principal', 'institution:other'), ('expires_at_ms', NOW+120000)]:
            manifest = copy.deepcopy(self.manifest)
            manifest['maintenance']['mandates'][0]['payload'][field] = value
            with self.subTest(field=field):
                self.assertFalse(evaluate(manifest, self.obs)['authorized'])
        self.manifest['maintenance']['mandates'][0]['signature'] = base64.b64encode(b'x'*64).decode()
        self.assertEqual(evaluate(self.manifest, self.obs)['reason'], 'signature_invalide')

    def test_self_issued_key_cannot_register_itself(self):
        other = Ed25519PrivateKey.generate()
        record = m.public_key_record(other, self.payload['principal'], units=[UNIT], operations=['sqlite-exclusive-lock'], objects=[OBJECT['path']])
        p = {**self.payload, 'key_id': record['key_id']}
        self.manifest['maintenance']['mandates'] = [m.signer(p, other)]
        self.assertEqual(evaluate(self.manifest, self.obs)['reason'], 'cle_absente_ou_ambigue')

    def test_key_disabled_and_principal_binding(self):
        for changes in ({'enabled': False}, {'enabled': 1}, {'principal': 'institution:other'}):
            manifest = copy.deepcopy(self.manifest)
            manifest['maintenance']['keys'][0].update(changes)
            self.assertFalse(evaluate(manifest, self.obs)['authorized'])

    def test_expiry_start_and_clock_boundaries(self):
        for now, allowed in [(NOW-501, False), (NOW-500, True), (NOW+59999, True), (NOW+60000, False)]:
            obs = {**self.obs, 'observed_at_ms': now}
            with self.subTest(now=now):
                self.assertEqual(evaluate(self.manifest, obs, now_ms=now)['authorized'], allowed)

    def test_old_future_missing_or_unstable_observation_rejected(self):
        for changes in ({'observed_at_ms': NOW-1501}, {'observed_at_ms': NOW+1}, {'observed_at_ms': None},
                        {'observed_at_ms': True}, {'identity_stable': False}, {'identity_stable': 1}):
            self.assertFalse(evaluate(self.manifest, {**self.obs, **changes})['authorized'])

    def test_os_identity_is_not_uid_alone_replay_rejected(self):
        for field, value in [('boot_id', 'other'), ('invocation_id', 'other'), ('pid', 143),
                             ('process_start_ticks', 778293), ('uid', 0), ('cgroup', '/other/'+UNIT),
                             ('machine_id', 'other'), ('object', {**OBJECT, 'inode': OBJECT['inode']+1}),
                             ('object', {**OBJECT, 'device': True})]:
            with self.subTest(field=field, value=value):
                self.assertFalse(evaluate(self.manifest, {**self.obs, field: value})['authorized'])

    def test_write_permission_is_not_lock_or_transfer_permission(self):
        self.payload['operation'] = 'file-write'
        self.manifest['maintenance']['mandates'] = [m.signer(self.payload, self.key)]
        self.assertFalse(evaluate(self.manifest, self.obs)['authorized'])
        self.assertTrue(evaluate(self.manifest, self.obs, operation='file-write')['authorized'])
        self.assertFalse(evaluate(self.manifest, self.obs, operation='exfiltrate')['authorized'])

    def test_exact_path_action_and_key_delegation(self):
        for changes in ({'object_path': OBJECT['path']+'-wal'}, {'object_path': '/opt/sawm-labo/fixtures'},
                        {'unit': 'labo-other.service'}, {'operation': 'file-delete'}):
            self.assertFalse(evaluate(self.manifest, self.obs, **changes)['authorized'])
        for field in ('units', 'operations', 'objects'):
            manifest = copy.deepcopy(self.manifest)
            manifest['maintenance']['keys'][0][field] = ['*']
            self.assertEqual(evaluate(manifest, self.obs)['reason'], 'portee_non_deleguee')

    def test_revoked_mandate_never_resurrects(self):
        self.manifest['maintenance']['revoked_mandates'] = [self.payload['mandate_id']]
        self.assertEqual(evaluate(self.manifest, self.obs)['reason'], 'mandat_revoque')

    def test_generation_and_duplicate_ids_fail_closed(self):
        self.manifest['generation'] = 'test-v4'
        self.assertFalse(evaluate(self.manifest, self.obs)['authorized'])
        self.manifest['generation'] = 'test-v3'
        self.manifest['maintenance']['mandates'] *= 2
        self.assertEqual(evaluate(self.manifest, self.obs)['reason'], 'registre_mandats_ambigu')

    def test_no_authorization_from_missing_data_or_llm_boolean(self):
        for manifest in ({}, {'maintenance': {}}, {'maintenance': {'authorized': True}},
                         {'maintenance': None}, {'maintenance': True}):
            self.assertFalse(evaluate(manifest, self.obs)['authorized'])
        self.manifest['maintenance']['mandates'] = []
        self.assertEqual(evaluate(self.manifest, self.obs)['reason'], 'aucun_mandat_pour_operation')

    def test_malformed_contracts_never_escape_as_success(self):
        for field, value in [('pid', True), ('uid', True), ('object', []), ('generation', '*'),
                             ('cgroup', '/a/../'+UNIT), ('expires_at_ms', NOW-1001), ('operation', '*')]:
            with self.subTest(field=field):
                with self.assertRaises(m.MandatInvalide):
                    m.signer({**self.payload, field: value}, self.key)
        for malformed in (None, [], {'payload': []}, {'payload': {'mandate_id': []}}):
            manifest = copy.deepcopy(self.manifest)
            manifest['maintenance']['mandates'] = [malformed]
            self.assertFalse(evaluate(manifest, self.obs)['authorized'])

    def test_duration_and_observation_budget_cannot_expand_unbounded(self):
        for field, value in [('max_duration_ms', 86400001), ('max_observation_age_ms', 5001),
                             ('max_duration_ms', True), ('max_observation_age_ms', 0)]:
            manifest = copy.deepcopy(self.manifest)
            manifest['maintenance'][field] = value
            self.assertFalse(evaluate(manifest, self.obs)['authorized'])
        self.manifest['maintenance']['max_duration_ms'] = 1000
        self.assertEqual(evaluate(self.manifest, self.obs)['reason'], 'duree_non_deleguee')

    def test_veto_only_restrictive_action_for_covered_operation(self):
        args = dict(unit=UNIT, operation='sqlite-exclusive-lock', object_path=OBJECT['path'], now_ms=NOW)
        self.assertTrue(m.guard_proposition(self.manifest, self.obs, action='arreter-service', **args)['veto'])
        self.assertFalse(m.guard_proposition(self.manifest, self.obs, action='ouvrir-dossier', **args)['veto'])
        args['operation'] = 'file-write'
        self.assertFalse(m.guard_proposition(self.manifest, self.obs, action='arreter-service', **args)['veto'])

    def test_legacy_manifest_never_overrides_configured_signed_policy(self):
        current = {'reference_matches': True, 'reference_sha256': 'a'*64,
                   'hash_stable_during_probe': True, 'errors': {'read': 'SQLITE_BUSY'}}
        legacy = {'database_policy': {'unit': UNIT, 'exclusive_lock_authorized': True,
                  'availability_required': False, 'reference_sha256': 'a'*64}}
        self.assertTrue(preservation_explicitement_autorisee(legacy, UNIT, current))
        self.assertFalse(preservation_explicitement_autorisee({**legacy, 'maintenance': {}}, UNIT, current))
        self.assertTrue(preservation_explicitement_autorisee({**legacy, **self.manifest}, UNIT, current,
                        maintenance_observation=self.obs, now_ms=NOW))

    def test_local_guard_preserves_signed_maintenance_over_default_lock_prohibition(self):
        from test_garde_database import mesures
        manifest, baseline, current, attribution = mesures()
        manifest['database_policy']['unit'] = UNIT
        manifest['unites_autorisees'] = [UNIT]
        attribution['unit'] = UNIT
        manifest.update(self.manifest)
        self.assertIsNone(proposer(manifest, baseline, current, attribution, maintenance_observation=self.obs, now_ms=NOW))
        self.assertIsNone(proposer(manifest, baseline, current, attribution, now_ms=NOW))
        manifest['maintenance']['revoked_mandates'] = [self.payload['mandate_id']]
        self.assertIsNotNone(proposer(manifest, baseline, current, attribution, maintenance_observation=self.obs, now_ms=NOW))


class MaintenanceCLITest(unittest.TestCase):
    def test_keygen_no_overwrite_private_key_or_automatic_authority(self):
        with tempfile.TemporaryDirectory() as folder:
            key = Path(folder)/'key'
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(cli.main(['keygen', '--key', str(key)]), 0)
            self.assertFalse(json.loads(output.getvalue())['authority_registered'])
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)
            before = key.read_bytes()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(['keygen', '--key', str(key)]), 2)
            self.assertEqual(key.read_bytes(), before)
            key.chmod(0o644)
            with self.assertRaises(m.MandatInvalide):
                cli._read(key, private=True)

    def test_install_cannot_add_trust_or_reuse_revoked_identifier(self):
        key, payload, obs, manifest = fixture()
        envelope = manifest['maintenance']['mandates'].pop()
        @contextlib.contextmanager
        def locked(_): yield manifest, manifest['maintenance']
        with patch.object(cli, '_locked_manifest', locked):
            result = cli.install('unused', envelope, now_ms=NOW)
            self.assertTrue(result['installed'])
            self.assertTrue(result['requires_fresh_os_verification'])
            with self.assertRaises(m.MandatInvalide):
                cli.install('unused', envelope, now_ms=NOW)
            cli.revoke('unused', payload['mandate_id'], key, payload['principal'], now_ms=NOW)
            self.assertFalse(evaluate(manifest, obs)['authorized'])
            self.assertEqual(len(manifest['maintenance']['revocation_receipts']), 1)
            cli.revoke('unused', payload['mandate_id'], key, payload['principal'], now_ms=NOW)
            self.assertEqual(len(manifest['maintenance']['revocation_receipts']), 1)
            with self.assertRaises(m.MandatInvalide):
                cli.revoke('unused', payload['mandate_id'], Ed25519PrivateKey.generate(), payload['principal'], now_ms=NOW)

    def test_install_reserved_root(self):
        with patch.object(cli.os, 'geteuid', return_value=1000):
            with self.assertRaisesRegex(m.MandatInvalide, 'root'):
                with cli._locked_manifest('/opt/sawm-labo/manifeste.json'): pass


if __name__ == '__main__': unittest.main()
