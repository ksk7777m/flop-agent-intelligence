"""Human-gated signal workflow. This module has no network or publishing code."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Optional

from .classifier import classify
from .source_policy import assess_source
from .remote_content_policy import ReviewedSourceId


class WorkflowState(str, Enum):
    DETECTED = "DETECTED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    APPROVED = "APPROVED"
    PUBLISHED = "PUBLISHED"
    REJECTED = "REJECTED"


@dataclass(frozen=True)
class SignalEnvelope:
    version: str
    state: str
    classification: str
    source_id: str
    source_tier: int
    source_evidence: str
    summary: str
    safety_result: str
    recommended_text: str
    detected_at: str
    approval_status: str
    approved_at: Optional[str] = None
    approved_by: Optional[str] = None
    rejection_reason: Optional[str] = None

    def as_dict(self) -> Dict[str, object]:
        return {key: value for key, value in asdict(self).items() if value is not None}


def prepare_signal(
    *, source_id: ReviewedSourceId | str, source_evidence: str, text: str, summary: str,
    recommended_text: str, directly_linked_by_tier1: bool = False,
    detected_at: Optional[str] = None,
) -> SignalEnvelope:
    source = assess_source(source_id, directly_linked_by_tier1)
    result = classify(text, source_id=source_id if isinstance(source_id, ReviewedSourceId) else None)
    safety = "QUARANTINED" if result.security_review_required or result.category == "IGNORE" else "PASS"
    return SignalEnvelope(
        version="1", state=WorkflowState.REVIEW_REQUIRED.value,
        classification=result.category, source_id=source.source_id, source_tier=source.tier,
        source_evidence=source_evidence, summary=summary, safety_result=safety,
        recommended_text=recommended_text,
        detected_at=detected_at or datetime.now(timezone.utc).isoformat(),
        approval_status=WorkflowState.REVIEW_REQUIRED.value,
    )


def approve_signal(signal: SignalEnvelope, reviewer: str, approved_at: Optional[str] = None) -> SignalEnvelope:
    if signal.state != WorkflowState.REVIEW_REQUIRED.value:
        raise ValueError("only REVIEW_REQUIRED signals can be approved")
    if signal.safety_result != "PASS":
        raise ValueError("quarantined or ignored signals cannot be approved")
    if not reviewer.strip():
        raise ValueError("a human reviewer identifier is required")
    return replace(
        signal, state=WorkflowState.APPROVED.value,
        approval_status=WorkflowState.APPROVED.value,
        approved_at=approved_at or datetime.now(timezone.utc).isoformat(),
        approved_by=reviewer.strip(),
    )


def reject_signal(signal: SignalEnvelope, reason: str) -> SignalEnvelope:
    if signal.state != WorkflowState.REVIEW_REQUIRED.value:
        raise ValueError("only REVIEW_REQUIRED signals can be rejected")
    if not reason.strip():
        raise ValueError("rejection reason is required")
    return replace(
        signal, state=WorkflowState.REJECTED.value,
        approval_status=WorkflowState.REJECTED.value,
        rejection_reason=reason.strip(),
    )


def signer_handoff(signal: SignalEnvelope) -> Dict[str, object]:
    """Local Claude/signer boundary. Produces data only; never signs or publishes."""
    if signal.state != WorkflowState.APPROVED.value:
        raise PermissionError("signer handoff requires an APPROVED signal")
    return {
        "version": signal.version,
        "classification": signal.classification,
        "source": signal.source_evidence,
        "summary": signal.summary,
        "recommended_text": signal.recommended_text,
        "approval": {
            "status": signal.approval_status,
            "approved_at": signal.approved_at,
            "approved_by": signal.approved_by,
        },
    }


def signal_from_dict(value: Dict[str, object]) -> SignalEnvelope:
    return SignalEnvelope(**value)


def validate_publish_approval(signal: SignalEnvelope, text: str) -> None:
    signer_handoff(signal)
    if signal.safety_result != "PASS":
        raise PermissionError("publish requires a safety PASS")
    if signal.recommended_text != text:
        raise PermissionError("publish text must exactly match the human-approved recommended_text")
