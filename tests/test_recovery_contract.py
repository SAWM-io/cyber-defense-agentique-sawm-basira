"""Reconstruction : autorité hors invité, cible exacte et aucune étape sautée."""
import copy
from dataclasses import replace
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from controleur.recovery_contract import (
    ControllerEvidence, Ed25519PrivateKey, MAX_MANIFEST_BYTES, RecoveryBinding,
    RecoveryContractError, RecoveryState, STATES, key_fingerprint, sign_manifest,
    verify_manifest,
)


class RecoveryContractTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.binding = RecoveryBinding('recovery-20260922', '1336e226-8aa3-4c3e-9252-6a327c6990ad',
            '/private/tmp/sawm-lab/overlay.qcow2', 'a' * 64,
            key_fingerprint(self.key.public_key()))
        self.proof = self.evidence('proof')
        self.manifest = sign_manifest(self.binding, private_key=self.key, proof=self.proof)

    def evidence(self, stage):
        return ControllerEvidence(stage, self.binding.run_id, self.binding.vm_id,
                                  self.binding.target, 'b' * 64, 'host-controller', True)

    def verify(self, manifest, **kwargs):
        return verify_manifest(manifest, public_key=kwargs.get('public_key', self.key.public_key()),
            expected=kwargs.get('expected', self.binding), proof_sha256=kwargs.get('proof_sha256', self.proof.sha256))

    def test_signed_roundtrip_uses_only_public_key_and_expected_bindings(self):
        raw = json.dumps(self.manifest).encode()
        self.assertEqual(self.verify(raw)['vm_id'], self.binding.vm_id)
        self.assertTrue(self.verify(raw)['lab_only'])
        self.assertEqual(self.verify(raw)['purpose'], 'lab-vm-recovery')

    def test_tamper_all_bound_fields_and_signature_fails(self):
        for field in self.manifest['payload']:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.manifest)
                changed['payload'][field] = 'tampered'
                with self.assertRaises(RecoveryContractError):
                    self.verify(changed)
        for field in ('signature', 'sha256'):
            changed = copy.deepcopy(self.manifest)
            changed[field] = ('d' if changed[field][0] == 'c' else 'c') + changed[field][1:]
            with self.assertRaises(RecoveryContractError):
                self.verify(changed)

    def test_valid_signature_cannot_authorize_other_vm_run_target_image_or_key(self):
        for field, value in (
            ('vm_id', 'e9ea4efe-eedc-4ae5-8950-dc6c5b191f0f'), ('run_id', 'other-run'),
            ('target', '/private/tmp/other.qcow2'), ('clean_image_sha256', 'c' * 64),
            ('institutional_key_fingerprint', 'd' * 64),
        ):
            with self.subTest(field=field), self.assertRaises(RecoveryContractError):
                self.verify(self.manifest, expected=replace(self.binding, **{field: value}))
        with self.assertRaises(RecoveryContractError):
            self.verify(self.manifest, proof_sha256='d' * 64)
        with self.assertRaises(RecoveryContractError):
            self.verify(self.manifest, public_key=Ed25519PrivateKey.generate().public_key())
        with self.assertRaises(RecoveryContractError):
            sign_manifest(self.binding, private_key=Ed25519PrivateKey.generate(), proof=self.proof)

    def test_guest_claim_failed_observation_and_mismatched_proof_refused(self):
        for changes in ({'origin': 'guest'}, {'passed': False}, {'passed': 1}):
            with self.assertRaises(RecoveryContractError):
                replace(self.proof, **changes)
        for proof in (replace(self.proof, run_id='other-run'), replace(self.proof, stage='verified')):
            with self.assertRaises(RecoveryContractError):
                sign_manifest(self.binding, private_key=self.key, proof=proof)

    def test_exact_bounded_canonical_inputs(self):
        for field, value in (
            ('target', 'relative.qcow2'), ('target', '/tmp/../disk'), ('target', '//tmp/disk'),
            ('target', '/tmp//disk'), ('target', '/tmp/./disk'), ('target', '/tmp/disk\n'),
            ('target', '/' + 'x' * 1024), ('run_id', 'x' * 129), ('vm_id', 'named-vm'),
            ('clean_image_sha256', 'A' * 64),
        ):
            with self.subTest(field=field, value=value[:40]), self.assertRaises(RecoveryContractError):
                replace(self.binding, **{field: value})
        for manifest in (
            {**self.manifest, 'extra': True},
            {**self.manifest, 'payload': {**self.manifest['payload'], 'extra': True}},
            {**self.manifest, 'payload': {**self.manifest['payload'], 'version': True}},
            b' ' * (MAX_MANIFEST_BYTES + 1),
            json.dumps(self.manifest).replace('"version": 1', '"version": 1, "version": 1'),
        ):
            with self.assertRaises(RecoveryContractError):
                self.verify(manifest)

    def test_full_sequence_requires_manifest_and_keeps_failed_attempt_atomic(self):
        state = RecoveryState(self.binding, self.proof)
        self.assertEqual(state.state, 'proof')
        state.advance('isolated', evidence=self.evidence('isolated'))
        before = state.history
        with self.assertRaises(RecoveryContractError):
            state.advance('recovery_verified', evidence=self.evidence('recovery_verified'))
        self.assertEqual(state.history, before)
        altered = copy.deepcopy(self.manifest)
        altered['signature'] = 'x' * 88
        with self.assertRaises(RecoveryContractError):
            state.advance('recovery_verified', manifest=altered, public_key=self.key.public_key())
        self.assertEqual(state.history, before)
        state.advance('recovery_verified', manifest=self.manifest, public_key=self.key.public_key())
        state.require_state('recovery_verified')
        for step in ('rebuilt', 'verified', 'released'):
            state.advance(step, evidence=self.evidence(step))
        self.assertEqual(tuple(step for step, _ in state.history), STATES)
        with self.assertRaises(RecoveryContractError):
            state.advance('released', evidence=self.evidence('released'))

    def test_cannot_skip_repeat_rewind_or_use_other_targets_evidence(self):
        state = RecoveryState(self.binding, self.proof)
        for step in ('proof', 'recovery_verified', 'rebuilt', 'verified', 'released'):
            with self.subTest(step=step), self.assertRaises(RecoveryContractError):
                state.advance(step, evidence=self.evidence(step))
        with self.assertRaises(RecoveryContractError):
            state.require_state('recovery_verified')
        with self.assertRaises(RecoveryContractError):
            state.advance('isolated', evidence=replace(self.evidence('isolated'), target='/tmp/other'))
        self.assertEqual(state.state, 'proof')


if __name__ == '__main__':
    unittest.main()
