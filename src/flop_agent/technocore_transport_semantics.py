"""Offline Technocore 0.13.0 transport-semantics reconciliation.

This module accepts bounded fixture evidence only.  It has no HTTP/MCP client,
writer, signer, retry loop, capability issuer, wallet, or filesystem sink.
Remote bodies are reduced to length and SHA-256 before public projection.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from .wire_evidence import parse_nonce

SCHEMA_VERSION = "technocore-transport-semantics-v1"
POLICY_VERSION = "technocore-0130-transport-policy-v1"
DOCUMENTED_VERSION = "0.13.0"
MAX_BODY_BYTES = 2 * 1024 * 1024
NOTES_LIMIT_DEFAULT = 50
NOTES_LIMIT_MAX = 200
_TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


class TransportSemanticError(ValueError):
    def __init__(self, code: str, field: str, value: Any = None):
        super().__init__(f"{code}: {field}")
        self.code = code
        self.metadata = MappingProxyType({"field": field, "type": type(value).__name__,
                                          "length": _safe_len(value)})


def _safe_len(value: Any) -> int | None:
    try:
        return len(value)
    except (TypeError, OverflowError):
        return None


class Operation(str, Enum):
    MCP_LIST_NOTES = "MCP_LIST_NOTES"
    POST_UPLOAD = "POST_UPLOAD"
    CONDITIONAL_NOTE_WRITE = "CONDITIONAL_NOTE_WRITE"
    NOTE_READ = "NOTE_READ"


class RequestCompletion(str, Enum):
    COMPLETED = "COMPLETED"
    UNKNOWN = "UNKNOWN"


class SchemaValidation(str, Enum):
    VALIDATED = "VALIDATED"
    NOT_VALIDATED = "NOT_VALIDATED"


class ContentCompleteness(str, Enum):
    COMPLETE_BODY_ONLY = "COMPLETE_BODY_ONLY"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


class Freshness(str, Enum):
    UNKNOWN = "UNKNOWN"
    STALE = "STALE"


class RetryDisposition(str, Enum):
    DO_NOT_RETRY = "DO_NOT_RETRY"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    ELIGIBLE_AFTER_NEW_AUTHORIZATION = "ELIGIBLE_AFTER_NEW_AUTHORIZATION"


class SideEffectCertainty(str, Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_PROVEN = "NOT_PROVEN"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"


class NonceOutcome(str, Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class TransportEvidence:
    operation: Operation
    request_completion: RequestCompletion
    http_status: int | None
    response_schema: SchemaValidation
    content_completeness: ContentCompleteness
    content_truncated: bool | None
    dropped_count: int | None
    effective_limit: int | None
    freshness: Freshness
    response_metadata_observed: bool
    cache_evidence_observed: bool
    age_seconds: int | None
    retry_disposition: RetryDisposition
    new_connection_required: bool
    reconciliation_required: bool
    new_authorization_required: bool
    replay_journal_required: bool
    side_effect_certainty: SideEffectCertainty
    nonce_outcome: NonceOutcome
    body_sha256: str
    body_bytes: int
    observed_at: str

    def public_projection(self) -> Mapping[str, Any]:
        return MappingProxyType({
            "schema": SCHEMA_VERSION, "status": "DESCRIPTIVE_ONLY",
            "content_label": "UNTRUSTED_CONTENT", "operation": self.operation.value,
            "request_completion": self.request_completion.value,
            "http_status": self.http_status, "response_schema": self.response_schema.value,
            "content_completeness": self.content_completeness.value,
            "content_truncated": self.content_truncated,
            "dropped_count": self.dropped_count, "effective_limit": self.effective_limit,
            "freshness": self.freshness.value,
            "response_metadata_observed": self.response_metadata_observed,
            "cache_evidence_observed": self.cache_evidence_observed,
            "age_seconds": self.age_seconds,
            "retry_disposition": self.retry_disposition.value,
            "new_connection_required": self.new_connection_required,
            "reconciliation_required": self.reconciliation_required,
            "new_authorization_required": self.new_authorization_required,
            "replay_journal_required": self.replay_journal_required,
            "side_effect_certainty": self.side_effect_certainty.value,
            "nonce_outcome": self.nonce_outcome.value,
            "body_sha256": self.body_sha256, "body_bytes": self.body_bytes,
            "observed_at": self.observed_at, "documented_version": DOCUMENTED_VERSION,
            "runtime_compatibility": "COMPATIBILITY_REVIEW_REQUIRED",
            "ready_to_act": False, "authorized_to_act": False,
            "live_action_enabled": False, "policy_version": POLICY_VERSION,
        })


def _bounded_body(raw: bytes) -> tuple[str, int]:
    if not isinstance(raw, bytes) or len(raw) > MAX_BODY_BYTES:
        raise TransportSemanticError("BODY_INVALID", "body", raw)
    return hashlib.sha256(raw).hexdigest(), len(raw)


def _observed_at(value: Any) -> str:
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        raise TransportSemanticError("OBSERVATION_TIME_INVALID", "observed_at", value)
    return value


def _limit(value: Any) -> int:
    if value is None or (isinstance(value, int) and not isinstance(value, bool) and value < 0):
        return NOTES_LIMIT_DEFAULT
    if isinstance(value, bool) or not isinstance(value, int):
        raise TransportSemanticError("NOTES_LIMIT_INVALID", "limit", value)
    return min(value or 1, NOTES_LIMIT_MAX)


def assess_list_notes(*, raw_output: bytes, requested_limit: int | None,
                      truncated: bool | None, dropped_count: int | None,
                      observed_at: str) -> TransportEvidence:
    """Reduce one MCP result without treating text or omitted keys as authority."""
    digest, length = _bounded_body(raw_output)
    effective = _limit(requested_limit)
    if truncated is not None and not isinstance(truncated, bool):
        raise TransportSemanticError("TRUNCATION_INVALID", "truncated", truncated)
    if dropped_count is not None and (isinstance(dropped_count, bool)
            or not isinstance(dropped_count, int) or dropped_count < 0):
        raise TransportSemanticError("DROPPED_COUNT_INVALID", "dropped_count", dropped_count)
    if truncated is True and (dropped_count is None or dropped_count < 1):
        raise TransportSemanticError("TRUNCATION_EVIDENCE_INCONSISTENT", "dropped_count")
    if truncated is False and dropped_count not in (None, 0):
        raise TransportSemanticError("TRUNCATION_EVIDENCE_INCONSISTENT", "dropped_count")
    completeness = (ContentCompleteness.PARTIAL if truncated is True
                    else ContentCompleteness.UNKNOWN)
    return TransportEvidence(Operation.MCP_LIST_NOTES, RequestCompletion.COMPLETED, None,
        SchemaValidation.NOT_VALIDATED, completeness, truncated, dropped_count, effective,
        Freshness.UNKNOWN, False, False, None, RetryDisposition.DO_NOT_RETRY, False,
        False, False, False, SideEffectCertainty.NOT_APPLICABLE,
        NonceOutcome.NOT_APPLICABLE, digest, length, _observed_at(observed_at))


def note_absence_assessment(evidence: TransportEvidence) -> str:
    if not isinstance(evidence, TransportEvidence) or evidence.operation is not Operation.MCP_LIST_NOTES:
        raise TransportSemanticError("LIST_NOTES_EVIDENCE_REQUIRED", "evidence")
    return "ABSENCE_NOT_PROVEN"


def assess_http(*, operation: Operation, status: int, raw_body: bytes,
                schema_validated: bool, observed_at: str,
                response_metadata_observed: bool = False,
                cache_evidence_observed: bool = False,
                age_seconds: int | None = None,
                nonce: str | None = None,
                runtime_version_verified: bool = False) -> TransportEvidence:
    """Classify fixture HTTP evidence; never performs or schedules a request."""
    if operation not in {Operation.POST_UPLOAD, Operation.CONDITIONAL_NOTE_WRITE,
                         Operation.NOTE_READ}:
        raise TransportSemanticError("HTTP_OPERATION_INVALID", "operation", operation)
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        raise TransportSemanticError("HTTP_STATUS_INVALID", "status", status)
    if not isinstance(schema_validated, bool):
        raise TransportSemanticError("SCHEMA_STATUS_INVALID", "schema_validated", schema_validated)
    if not isinstance(response_metadata_observed, bool) or not isinstance(cache_evidence_observed, bool):
        raise TransportSemanticError("RESPONSE_METADATA_INVALID", "response_metadata")
    if age_seconds is not None and (isinstance(age_seconds, bool)
            or not isinstance(age_seconds, int) or age_seconds < 0):
        raise TransportSemanticError("CACHE_AGE_INVALID", "age_seconds", age_seconds)
    if age_seconds is not None and not cache_evidence_observed:
        raise TransportSemanticError("CACHE_EVIDENCE_REQUIRED", "age_seconds")
    if not isinstance(runtime_version_verified, bool):
        raise TransportSemanticError("RUNTIME_COMPATIBILITY_INVALID", "runtime_version_verified")
    if nonce is not None:
        parse_nonce(nonce)
    digest, length = _bounded_body(raw_body)
    timed_out = status == 408 and operation is Operation.POST_UPLOAD
    conflict = status == 409 and operation is Operation.CONDITIONAL_NOTE_WRITE
    write = operation in {Operation.POST_UPLOAD, Operation.CONDITIONAL_NOTE_WRITE}
    uncertain_write = write and (timed_out or conflict or status >= 400)
    completion = RequestCompletion.UNKNOWN if timed_out else RequestCompletion.COMPLETED
    retry = RetryDisposition.RECONCILIATION_REQUIRED if uncertain_write else RetryDisposition.DO_NOT_RETRY
    return TransportEvidence(operation, completion, status,
        SchemaValidation.VALIDATED if schema_validated else SchemaValidation.NOT_VALIDATED,
        ContentCompleteness.COMPLETE_BODY_ONLY if schema_validated else ContentCompleteness.UNKNOWN,
        None, None, None, Freshness.UNKNOWN, response_metadata_observed,
        cache_evidence_observed, age_seconds, retry, timed_out, uncertain_write,
        uncertain_write, uncertain_write,
        SideEffectCertainty.OUTCOME_UNKNOWN if uncertain_write else
            (SideEffectCertainty.NOT_APPLICABLE if not write else SideEffectCertainty.NOT_PROVEN),
        NonceOutcome.UNKNOWN if nonce is not None else NonceOutcome.NOT_APPLICABLE,
        digest, length, _observed_at(observed_at))


def validate_transport_projection(value: Mapping[str, Any]) -> tuple[str, ...]:
    """Reject authority promotion and cross-field contradictions without echoing values."""
    if not isinstance(value, Mapping):
        return ("PROJECTION_OBJECT_REQUIRED",)
    expected = set(TransportEvidence.__dataclass_fields__) | {"schema", "status",
        "content_label", "documented_version", "runtime_compatibility", "ready_to_act",
        "authorized_to_act", "live_action_enabled", "policy_version"}
    errors: list[str] = []
    if set(value) != expected: errors.append("CLOSED_FIELDS_REQUIRED")
    if value.get("status") != "DESCRIPTIVE_ONLY": errors.append("DESCRIPTIVE_ONLY_REQUIRED")
    if value.get("runtime_compatibility") != "COMPATIBILITY_REVIEW_REQUIRED":
        errors.append("RUNTIME_COMPATIBILITY_UNPROVEN")
    for field in ("ready_to_act", "authorized_to_act", "live_action_enabled"):
        if value.get(field) is not False: errors.append("LIVE_ACTION_PROHIBITED")
    if value.get("http_status") == 408:
        if value.get("request_completion") != "UNKNOWN": errors.append("HTTP_408_OUTCOME_UNKNOWN")
        if value.get("retry_disposition") != "RECONCILIATION_REQUIRED":
            errors.append("HTTP_408_RECONCILIATION_REQUIRED")
    if value.get("content_truncated") is True and value.get("content_completeness") != "PARTIAL":
        errors.append("TRUNCATED_CONTENT_IS_PARTIAL")
    if value.get("operation") == "MCP_LIST_NOTES" and value.get("content_completeness") == "COMPLETE_BODY_ONLY":
        errors.append("MCP_LISTING_COMPLETENESS_UNPROVEN")
    if value.get("freshness") == "UNKNOWN" and value.get("authorized_to_act") is not False:
        errors.append("UNKNOWN_FRESHNESS_CANNOT_AUTHORIZE")
    return tuple(sorted(set(errors)))


__all__ = ("ContentCompleteness", "Freshness", "NonceOutcome", "Operation",
    "RequestCompletion", "RetryDisposition", "SchemaValidation", "SideEffectCertainty",
    "TransportEvidence", "TransportSemanticError", "assess_http", "assess_list_notes",
    "note_absence_assessment", "validate_transport_projection")
