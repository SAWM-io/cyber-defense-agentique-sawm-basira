"""Bounded continuity policy; it never executes a command or changes a network.

The trusted controller clock, institutional key and receipt store belong outside
the guest VM (the Mac in this lab). Guest root cannot legitimately authorize a
notice. A compromised guest can still lie about its observations: this policy
does not establish guest integrity or guarantee physical network availability.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import json
import math

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA = "sawm-network-notice/v1"
NOTICE_SECONDS = 7 * 86400
MAX_OUTAGE_SECONDS = 86400
PAYLOAD_KEYS = {"schema", "notice_id", "target", "generation", "starts_at", "ends_at"}


def _timestamp(value: object) -> float:
    if type(value) not in (int, float):
        raise ValueError("invalid_timestamp")
    try:
        converted = float(value)
    except (OverflowError, ValueError) as exc:
        raise ValueError("invalid_timestamp") from exc
    if not math.isfinite(converted) or converted < 0:
        raise ValueError("invalid_timestamp")
    return converted


@dataclass(frozen=True)
class _AcceptedNotice:
    notice_id: str
    starts_at: float
    ends_at: float
    received_at: float


class ContinuityPolicy:
    """One explicitly scoped network target and one trusted policy generation.

    Persist accepted receipts and the clock high-water mark in trusted storage
    before relying on this class across controller restarts. Recreating an empty
    instance deliberately grants no maintenance permission.
    """

    def __init__(self, public_key: Ed25519PublicKey, target: str, generation: int = 1):
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("invalid_public_key")
        if not isinstance(target, str) or not target.strip() or len(target) > 256:
            raise ValueError("invalid_target")
        if type(generation) is not int or generation < 1:
            raise ValueError("invalid_generation")
        self.public_key = public_key
        self.target = target
        self.generation = generation
        self._notices: dict[str, _AcceptedNotice] = {}
        self._seen_ids: set[str] = set()
        self._last_observed: float | None = None

    def _clock(self, now: float) -> bool:
        if self._last_observed is not None and now < self._last_observed:
            return False
        self._last_observed = now
        return True

    def register_notice(self, envelope: dict, received_at: float) -> dict:
        """Verify an institutional notice against controller-captured receipt time.

        ``received_at`` must come from the trusted controller, never a request
        field. Invalid notices raise ValueError and grant no outage permission.
        """
        received_at = _timestamp(received_at)
        if not self._clock(received_at):
            raise ValueError("controller_clock_rollback")
        if type(envelope) is not dict or set(envelope) != {"payload", "signature"}:
            raise ValueError("invalid_envelope")
        payload = envelope["payload"]
        if type(payload) is not dict or set(payload) != PAYLOAD_KEYS:
            raise ValueError("invalid_payload")
        if payload["schema"] != SCHEMA:
            raise ValueError("invalid_schema")
        if payload["target"] != self.target:
            raise ValueError("wrong_target")
        if type(payload["generation"]) is not int or payload["generation"] != self.generation:
            raise ValueError("wrong_generation")
        notice_id = payload["notice_id"]
        if not isinstance(notice_id, str) or not notice_id.strip() or len(notice_id) > 128:
            raise ValueError("invalid_notice_id")
        if notice_id in self._seen_ids:
            raise ValueError("duplicate_notice")
        starts_at = _timestamp(payload["starts_at"])
        ends_at = _timestamp(payload["ends_at"])
        if not 0 < ends_at - starts_at <= MAX_OUTAGE_SECONDS:
            raise ValueError("invalid_outage_duration")
        if starts_at < received_at + NOTICE_SECONDS:
            raise ValueError("insufficient_notice")
        signature = envelope["signature"]
        if not isinstance(signature, str) or len(signature) != 88:
            raise ValueError("invalid_signature")
        try:
            decoded = base64.b64decode(signature, validate=True)
            if len(decoded) != 64:
                raise ValueError("invalid_signature")
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            self.public_key.verify(decoded, canonical)
        except (InvalidSignature, binascii.Error, TypeError) as exc:
            raise ValueError("invalid_signature") from exc
        notice = _AcceptedNotice(notice_id, starts_at, ends_at, received_at)
        self._notices[notice_id] = notice
        self._seen_ids.add(notice_id)
        return {"accepted": True, "schema": SCHEMA, "notice_id": notice_id,
                "target": self.target, "generation": self.generation,
                "received_at": received_at, "starts_at": starts_at, "ends_at": ends_at,
                "notice_seconds": starts_at - received_at, "signature_verified": True}

    def revoke(self, notice_id: str) -> dict:
        """Trusted controller operation; callers must authenticate before this call."""
        if notice_id not in self._notices:
            raise ValueError("unknown_notice")
        del self._notices[notice_id]
        # Keep the identifier tombstone: the signed envelope cannot be replayed.
        return {"revoked": True, "notice_id": notice_id, "target": self.target}

    def decision(self, now: float, link_up: bool, untrusted_request: str = "") -> dict:
        """Return a bounded intention; untrusted guest text cannot alter policy."""
        # Do not parse or reproduce untrusted_request, including root counter-orders.
        try:
            now = _timestamp(now)
        except ValueError:
            return {"action": "investigate", "reason": "invalid_controller_time",
                    "authorized": False, "alert": True, "target": self.target}
        if not self._clock(now):
            return {"action": "investigate", "reason": "controller_clock_rollback",
                    "authorized": False, "alert": True, "target": self.target}
        if type(link_up) is not bool:
            return {"action": "investigate", "reason": "invalid_link_observation",
                    "authorized": False, "alert": True, "target": self.target}
        active = sorted((n for n in self._notices.values() if n.starts_at <= now < n.ends_at),
                        key=lambda n: (n.starts_at, n.notice_id))
        if active:
            return {"action": "planned_outage", "reason": "signed_notice_window",
                    "authorized": True, "alert": False, "target": self.target,
                    "notice_id": active[0].notice_id}
        return {"action": "keep" if link_up else "reconnect",
                "reason": "link_available" if link_up else "unapproved_disconnection",
                "authorized": False, "alert": not link_up, "target": self.target}
