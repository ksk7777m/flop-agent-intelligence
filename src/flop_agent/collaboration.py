"""Fail-closed, transport-neutral collaboration readiness primitives.

This module deliberately has no HTTP client, publisher, wallet integration, or
official-protocol assumptions.  It prepares and validates local evidence that a
future adapter may consume only after a separate human-approved integration.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict, dataclass, replace
from enum import Enum
from typing import Any, Dict, Iterable, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .identity import public_key_from_did


SCHEMA = "flop-collaboration-readiness-v1"
EVIDENCE_DOMAIN = b"FLOP-COLLABORATION-EVIDENCE-V1|"


class TrustClass(str, Enum):
    CONFIRMED = "CONFIRMED"
    OFFICIAL_DRAFT = "OFFICIAL_DRAFT"
    COMMUNITY = "COMMUNITY"
    INFERENCE = "INFERENCE"


class Phase(str, Enum):
    DISCOVERED = "DISCOVERED"
    CLAIM_APPROVED = "CLAIM_APPROVED"
    CLAIMED = "CLAIMED"
    HANDOFF_APPROVED = "HANDOFF_APPROVED"
    HANDED_OFF = "HANDED_OFF"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    COMPLETION_APPROVED = "COMPLETION_APPROVED"
    COMPLETED = "COMPLETED"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"


class EventKind(str, Enum):
    DISCOVER = "DISCOVER"
    APPROVE_CLAIM = "APPROVE_CLAIM"
    RECORD_CLAIM = "RECORD_CLAIM"
    APPROVE_HANDOFF = "APPROVE_HANDOFF"
    RECORD_HANDOFF = "RECORD_HANDOFF"
    RECORD_ACK = "RECORD_ACK"
    APPROVE_COMPLETION = "APPROVE_COMPLETION"
    RECORD_COMPLETION = "RECORD_COMPLETION"
    REQUIRE_RECOVERY = "REQUIRE_RECOVERY"


TRANSITIONS = {
    (None, EventKind.DISCOVER): Phase.DISCOVERED,
    (Phase.DISCOVERED, EventKind.APPROVE_CLAIM): Phase.CLAIM_APPROVED,
    (Phase.CLAIM_APPROVED, EventKind.RECORD_CLAIM): Phase.CLAIMED,
    (Phase.CLAIMED, EventKind.APPROVE_HANDOFF): Phase.HANDOFF_APPROVED,
    (Phase.HANDOFF_APPROVED, EventKind.RECORD_HANDOFF): Phase.HANDED_OFF,
    (Phase.HANDED_OFF, EventKind.RECORD_ACK): Phase.ACKNOWLEDGED,
    (Phase.ACKNOWLEDGED, EventKind.APPROVE_COMPLETION): Phase.COMPLETION_APPROVED,
    (Phase.COMPLETION_APPROVED, EventKind.RECORD_COMPLETION): Phase.COMPLETED,
}

APPROVAL_EVENTS = {
    EventKind.APPROVE_CLAIM,
    EventKind.APPROVE_HANDOFF,
    EventKind.APPROVE_COMPLETION,
}
SIGNED_EVENTS = {
    EventKind.RECORD_CLAIM,
    EventKind.RECORD_HANDOFF,
    EventKind.RECORD_ACK,
    EventKind.RECORD_COMPLETION,
}


def canonical_json(value: Dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class Provenance:
    source_id: str
    source_locator: str
    observed_at: str
    content_sha256: str
    classification: str

    def validate(self) -> None:
        if self.classification not in {item.value for item in TrustClass}:
            raise ValueError("unknown provenance classification")
        if len(self.content_sha256) != 64 or any(c not in "0123456789abcdef" for c in self.content_sha256):
            raise ValueError("content_sha256 must be lowercase SHA-256")
        if not all((self.source_id.strip(), self.source_locator.strip(), self.observed_at.strip())):
            raise ValueError("complete provenance is required")


@dataclass(frozen=True)
class HumanApproval:
    reviewer: str
    approved_at: str
    purpose: str
    subject_sha256: str

    def validate(self, purpose: str, subject_sha256: str) -> None:
        if not self.reviewer.strip() or not self.approved_at.strip():
            raise PermissionError("identified, timestamped human approval is required")
        if self.purpose != purpose or self.subject_sha256 != subject_sha256:
            raise PermissionError("human approval is not bound to this exact purpose and subject")


@dataclass(frozen=True)
class SignedEvidence:
    signer_did: str
    payload: Dict[str, Any]
    signature: str

    def verify(self) -> None:
        encoded = canonical_json(self.payload)
        raw = base64.urlsafe_b64decode(self.signature + "=" * (-len(self.signature) % 4))
        Ed25519PublicKey.from_public_bytes(public_key_from_did(self.signer_did)).verify(
            raw, EVIDENCE_DOMAIN + encoded,
        )


@dataclass(frozen=True)
class CollaborationEvent:
    case_id: str
    sequence: int
    kind: str
    occurred_at: str
    subject: Dict[str, Any]
    provenance: Provenance
    previous_event_sha256: Optional[str]
    approval: Optional[HumanApproval] = None
    evidence: Optional[SignedEvidence] = None
    idempotency_key: Optional[str] = None
    schema: str = SCHEMA

    def unsigned_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        return {key: item for key, item in value.items() if item is not None}

    @property
    def event_sha256(self) -> str:
        return digest(self.unsigned_dict())


@dataclass(frozen=True)
class CollaborationState:
    case_id: str
    phase: Optional[Phase] = None
    last_event_sha256: Optional[str] = None
    next_sequence: int = 1
    task_sha256: Optional[str] = None
    seen_idempotency_keys: Tuple[str, ...] = ()


def evidence_payload(case_id: str, kind: EventKind, subject: Dict[str, Any], idempotency_key: str) -> Dict[str, Any]:
    """The exact payload a separate signer must sign; this function never signs."""
    return {
        "schema": SCHEMA,
        "case_id": case_id,
        "event_kind": kind.value,
        "idempotency_key": idempotency_key,
        "subject_sha256": digest(subject),
    }


def apply_event(state: CollaborationState, event: CollaborationEvent) -> CollaborationState:
    """Validate and reduce one event. Any ambiguity raises and leaves state unchanged."""
    event.provenance.validate()
    if event.schema != SCHEMA or event.case_id != state.case_id:
        raise ValueError("schema or case mismatch")
    if event.sequence != state.next_sequence or event.previous_event_sha256 != state.last_event_sha256:
        raise ValueError("event chain is incomplete or out of order")
    try:
        kind = EventKind(event.kind)
    except ValueError as exc:
        raise ValueError("unknown collaboration event") from exc

    subject_hash = digest(event.subject)
    if kind in APPROVAL_EVENTS:
        if event.approval is None:
            raise PermissionError("transition requires human approval")
        event.approval.validate(kind.value, subject_hash)

    if kind in SIGNED_EVENTS:
        if not event.idempotency_key or event.idempotency_key in state.seen_idempotency_keys:
            raise ValueError("a fresh idempotency key is required")
        if event.evidence is None:
            raise PermissionError("transition requires signed evidence")
        expected = evidence_payload(event.case_id, kind, event.subject, event.idempotency_key)
        if event.evidence.payload != expected:
            raise ValueError("signed evidence is not bound to this exact transition")
        event.evidence.verify()

    if kind is EventKind.REQUIRE_RECOVERY:
        if state.phase in (None, Phase.COMPLETED):
            raise ValueError("recovery is not valid before discovery or after completion")
        next_phase = Phase.RECOVERY_REQUIRED
    else:
        next_phase = TRANSITIONS.get((state.phase, kind))
        if next_phase is None:
            raise ValueError(f"transition {state.phase!s} -> {kind.value} is not allowed")

    task_hash = state.task_sha256
    if kind is EventKind.DISCOVER:
        task_hash = subject_hash
    elif task_hash is None or event.subject.get("task_sha256") != task_hash:
        raise ValueError("transition subject is not bound to the discovered task")

    seen = state.seen_idempotency_keys
    if event.idempotency_key:
        seen += (event.idempotency_key,)
    return replace(
        state, phase=next_phase, last_event_sha256=event.event_sha256,
        next_sequence=state.next_sequence + 1, task_sha256=task_hash,
        seen_idempotency_keys=seen,
    )


def replay(case_id: str, events: Iterable[CollaborationEvent]) -> CollaborationState:
    state = CollaborationState(case_id=case_id)
    for event in events:
        state = apply_event(state, event)
    return state


def readiness_manifest() -> Dict[str, Any]:
    """Static capability declaration: useful to adapters, incapable of acting."""
    return {
        "schema": SCHEMA,
        "mode": "READINESS_ONLY",
        "external_writes_supported": False,
        "wallet_operations_supported": False,
        "phases": [phase.value for phase in Phase],
        "trust_classes": [item.value for item in TrustClass],
        "required_controls": [
            "append_only_hash_chain", "exact_subject_human_approval", "signed_outcome_evidence",
            "idempotency", "task_binding", "explicit_partial_failure_recovery",
        ],
    }
