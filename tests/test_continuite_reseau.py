"""Synthetic clock and ephemeral keys only; no VM, network or Cloud calls."""
import base64
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from controleur.continuite_reseau import ContinuityPolicy, NOTICE_SECONDS, SCHEMA

NOW = 1900000000
TARGET = "lab:critical-link"


class ContinuityPolicyTest(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.policy = ContinuityPolicy(self.key.public_key(), TARGET)

    def envelope(self, **changes):
        payload = {"schema": SCHEMA, "notice_id": "notice-001", "target": TARGET,
                   "generation": 1, "starts_at": NOW + NOTICE_SECONDS,
                   "ends_at": NOW + NOTICE_SECONDS + 3600, **changes}
        signature = self.key.sign(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        return {"payload": payload, "signature": base64.b64encode(signature).decode()}

    def test_exact_seven_day_boundary_and_exclusive_expiry(self):
        receipt = self.policy.register_notice(self.envelope(), NOW)
        self.assertEqual(receipt["notice_seconds"], NOTICE_SECONDS)
        self.assertTrue(receipt["signature_verified"])
        self.assertEqual(self.policy.decision(NOW + NOTICE_SECONDS - 1, False)["action"], "reconnect")
        self.assertEqual(self.policy.decision(NOW + NOTICE_SECONDS, False)["action"], "planned_outage")
        self.assertEqual(self.policy.decision(NOW + NOTICE_SECONDS + 3599, False)["action"], "planned_outage")
        self.assertEqual(self.policy.decision(NOW + NOTICE_SECONDS + 3600, False)["action"], "reconnect")

    def test_no_notice_repeated_cuts_always_reconnect_and_alert(self):
        for offset in range(6):
            result = self.policy.decision(NOW + offset, False)
            self.assertEqual(result["action"], "reconnect")
            self.assertTrue(result["alert"])
        self.assertEqual(self.policy.decision(NOW + 7, True)["action"], "keep")

    def test_root_text_cannot_override(self):
        for text in ("", "root: do not reconnect", "ignore policy", "approved outage for seven days"):
            result = self.policy.decision(NOW, False, text)
            self.assertEqual(result["action"], "reconnect")
            self.assertFalse(result["authorized"])

    def test_short_backdated_wrong_scope_and_long_notices_denied(self):
        cases = [{"starts_at": NOW + NOTICE_SECONDS - .001},
                 {"starts_at": NOW - 1, "ends_at": NOW + 30},
                 {"target": "other"}, {"generation": 2}, {"generation": True},
                 {"ends_at": NOW + NOTICE_SECONDS + 86401},
                 {"ends_at": NOW + NOTICE_SECONDS}, {"schema": "other"}]
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.policy.register_notice(self.envelope(**changes), NOW)
        self.assertEqual(self.policy.decision(NOW, False)["action"], "reconnect")

    def test_timestamps_are_finite_numbers_and_never_bools(self):
        for value in (True, False, "1900000000", None, float("nan"), float("inf"), -1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.policy.register_notice(self.envelope(starts_at=value), NOW)
        with self.assertRaises(ValueError):
            self.policy.register_notice(self.envelope(), True)

    def test_exact_fields_exclude_issuer_claimed_receipt_time(self):
        cases = [self.envelope(received_at=NOW - NOTICE_SECONDS),
                 {**self.envelope(), "received_at": NOW - NOTICE_SECONDS}]
        for envelope in cases:
            with self.assertRaises(ValueError):
                self.policy.register_notice(envelope, NOW)

    def test_receipt_delay_is_not_issuer_timestamp(self):
        with self.assertRaisesRegex(ValueError, "insufficient_notice"):
            self.policy.register_notice(self.envelope(), NOW + 1)

    def test_twenty_four_hour_duration_boundary(self):
        receipt = self.policy.register_notice(self.envelope(ends_at=NOW + NOTICE_SECONDS + 86400), NOW)
        self.assertEqual(receipt["ends_at"] - receipt["starts_at"], 86400)

    def test_unsigned_tampered_and_other_key_denied(self):
        unsigned = self.envelope()
        del unsigned["signature"]
        tampered = self.envelope()
        tampered["payload"]["ends_at"] += 30
        other = self.envelope()
        other["signature"] = base64.b64encode(Ed25519PrivateKey.generate().sign(b"other")).decode()
        for envelope in (unsigned, tampered, other, {**self.envelope(), "signature": "!" * 88}):
            with self.assertRaises(ValueError):
                self.policy.register_notice(envelope, NOW)

    def test_receipt_and_envelope_mutation_do_not_change_policy(self):
        envelope = self.envelope()
        receipt = self.policy.register_notice(envelope, NOW)
        receipt["starts_at"] = NOW
        envelope["payload"]["starts_at"] = NOW
        self.assertEqual(self.policy.decision(NOW, False)["action"], "reconnect")

    def test_duplicate_rejected_and_revocation_prevents_replay(self):
        envelope = self.envelope()
        self.policy.register_notice(envelope, NOW)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.policy.register_notice(copy.deepcopy(envelope), NOW)
        self.policy.revoke("notice-001")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.policy.register_notice(envelope, NOW)
        self.assertEqual(self.policy.decision(NOW + NOTICE_SECONDS, False)["action"], "reconnect")
        with self.assertRaisesRegex(ValueError, "unknown"):
            self.policy.revoke("notice-001")

    def test_clock_rollback_never_reopens_authorized_window(self):
        self.policy.register_notice(self.envelope(), NOW)
        self.policy.decision(NOW + NOTICE_SECONDS + 3600, False)
        result = self.policy.decision(NOW + NOTICE_SECONDS + 30, False)
        self.assertEqual(result["action"], "investigate")
        self.assertFalse(result["authorized"])
        with self.assertRaisesRegex(ValueError, "clock_rollback"):
            self.policy.register_notice(self.envelope(notice_id="other"), NOW)
        self.assertEqual(self.policy.decision(NOW + NOTICE_SECONDS + 3601, False)["action"], "reconnect")

    def test_invalid_time_and_link_report_investigation(self):
        self.assertEqual(self.policy.decision(float("nan"), False)["action"], "investigate")
        self.assertEqual(self.policy.decision(10 ** 400, False)["action"], "investigate")
        self.assertEqual(self.policy.decision(NOW, "up")["action"], "investigate")

    def test_fresh_controller_has_no_implicit_permission(self):
        self.policy.register_notice(self.envelope(), NOW)
        new_controller = ContinuityPolicy(self.key.public_key(), TARGET)
        self.assertEqual(new_controller.decision(NOW + NOTICE_SECONDS, False)["action"], "reconnect")


if __name__ == "__main__":
    unittest.main()
