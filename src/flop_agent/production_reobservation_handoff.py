"""Descriptive-only production reobservation handoff specification.

This module exposes immutable public projections and validators.  It has no
permit issuer, execution API, network client, CLI, scheduler, or live action.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import weakref
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from .durable_observation_journal import IDENTITY_DOMAIN as JOURNAL_IDENTITY_DOMAIN
from .durable_observation_journal import JOURNAL_ID, SCHEMA_VERSION as JOURNAL_SCHEMA
from .manual_reobservation_runner import PLAN_ID, SCHEMA_VERSION as RUNNER_SCHEMA
from .observation_retention import (CANONICAL_ENCODING, HASH_ALGORITHM,
    OBSERVATION_POLICY, PREDICATE_POLICY_HASHES, PredicatePolicy,
    SOURCE_ORDER_HASH, SOURCE_SET_ID)
from .remote_content_policy import DEFAULT_HTTP_TIMEOUT_SECONDS, DEFAULT_RESPONSE_LIMIT

SCHEMA_VERSION = "production-reobservation-handoff-v1"
IDENTITY_DOMAIN = "FLOP_PRODUCTION_REOBSERVATION_HANDOFF_V1"
REVIEWED_MAIN_SHA = "fc7df45d032b2a39a652e176581e392ae6c455a0"
REVIEWED_AT = "2026-09-09T00:00:00Z"
CHECKLIST_REVISION = "production-reobservation-activation-checklist-v1"


class HandoffError(RuntimeError):
    def __init__(self, code: str, field: str = "handoff"):
        super().__init__(f"{code}: {field}"); self.code = code


class HandoffState(str, Enum):
    DRAFT = "DRAFT"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    REVIEWED_DESCRIPTIVE_ONLY = "REVIEWED_DESCRIPTIVE_ONLY"
    POLICY_BLOCKED = "POLICY_BLOCKED"
    ACTIVATION_REVIEW_REQUIRED = "ACTIVATION_REVIEW_REQUIRED"
    SUPERSEDED = "SUPERSEDED"
    REVOKED = "REVOKED"
    EXPIRED_OR_CURRENTNESS_UNKNOWN = "EXPIRED_OR_CURRENTNESS_UNKNOWN"
    HANDOFF_INCOMPLETE = "HANDOFF_INCOMPLETE"


def _hash(value: Mapping[str, Any], domain: str) -> str:
    def check(item: Any) -> None:
        if item is None or type(item) in {str, bool, int}: return
        if type(item) is list:
            for child in item: check(child)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for child in item.values(): check(child)
            return
        raise HandoffError("CANONICAL_TYPE_INVALID")
    envelope = {"canonical_encoding": CANONICAL_ENCODING, "domain": IDENTITY_DOMAIN,
        "hash_algorithm": HASH_ALGORITHM, "record_domain": domain, "value": dict(value)}
    check(envelope)
    return hashlib.sha256(json.dumps(envelope, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()


_TIMEOUT_POLICY_ID = _hash({"timeout_seconds": DEFAULT_HTTP_TIMEOUT_SECONDS,
    "body_cap_bytes": DEFAULT_RESPONSE_LIMIT, "redirects_allowed": False}, "TIMEOUT_POLICY")
_RUNNER_IMPLEMENTATION_ID = _hash({"runner_schema": RUNNER_SCHEMA, "plan_id": PLAN_ID,
    "reviewed_main_sha": REVIEWED_MAIN_SHA}, "RUNNER_IMPLEMENTATION")

_REVIEW_MATERIAL = {
    "schema": SCHEMA_VERSION, "record_type": "AUTHORIZATION_REVIEW",
    "status": HandoffState.SUPERSEDED.value, "artifact_scope": "BASELINE_TEST_FIXTURE",
    "currentness": "STALE_REVIEW_REQUIRED", "merged_main_review": "REQUIRED",
    "human_review_proven": False, "cryptographic_attestation": False,
    "durable_authorization": False,
    "reviewed_at": REVIEWED_AT, "reviewed_main_sha": REVIEWED_MAIN_SHA,
    "runner_implementation_id": _RUNNER_IMPLEMENTATION_ID, "plan_id": PLAN_ID,
    "predicate_policy": PredicatePolicy.V2.value,
    "predicate_policy_hash": PREDICATE_POLICY_HASHES[PredicatePolicy.V2],
    "observation_policy": OBSERVATION_POLICY, "source_set_id": SOURCE_SET_ID,
    "source_order_hash": SOURCE_ORDER_HASH, "expected_generation": 0,
    "generation_scope": "TEST_FIXTURE_ONLY", "production_generation": "NOT_OBSERVED",
    "journal_inspection": "NOT_PERFORMED",
    "journal_id": JOURNAL_ID, "journal_identity_domain": JOURNAL_IDENTITY_DOMAIN,
    "journal_schema": JOURNAL_SCHEMA, "checklist_revision": CHECKLIST_REVISION,
    "operation": "READ_ONLY_REOBSERVATION", "method": "GET", "retry_count": 0,
    "redirects_allowed": False, "fallback_enabled": False,
    "alternate_url_enabled": False, "timeout_policy_id": _TIMEOUT_POLICY_ID,
    "production_permit_issuer": "ABSENT", "production_evidence_issuer": "ABSENT",
    "production_execute_api": "ABSENT", "production_execution": "UNREACHABLE",
    "compatibility": "COMPATIBILITY_REVIEW_REQUIRED",
    "retention_policy": "POLICY_REQUIRED", "review_window_policy": "POLICY_REQUIRED",
    "rollback_anchor_policy": "POLICY_REQUIRED", "operator_identity_policy": "POLICY_REQUIRED",
    "separation_of_duties_policy": "POLICY_REQUIRED", "ready_to_act": False,
    "authorized_to_act": False, "executable": False, "live_get_count": 0,
}
_REVIEW_ID = _hash(_REVIEW_MATERIAL, "AUTHORIZATION_REVIEW")

_CHECKS = (
    ("EXACT_REVIEWED_COMMIT", "VERIFICATION_REQUIRED", False, "MERGED_MAIN_EVIDENCE_REQUIRED"),
    ("CLEAN_WORKTREE", "VERIFICATION_REQUIRED", False, "RUNTIME_EVIDENCE_REQUIRED"),
    ("FULL_SUITE_PASS", "VERIFICATION_REQUIRED", False, "RUNTIME_EVIDENCE_REQUIRED"),
    ("SCHEMA_INDEX_PASS", "VERIFICATION_REQUIRED", False, "RUNTIME_EVIDENCE_REQUIRED"),
    ("PRODUCTION_API_UNSAFE_ZERO", "VERIFICATION_REQUIRED", False, "RUNTIME_EVIDENCE_REQUIRED"),
    ("SECRET_SENSITIVE_TRACKING_PASS", "VERIFICATION_REQUIRED", False, "RUNTIME_EVIDENCE_REQUIRED"),
    ("FIXED_SOURCE_PREDICATE_IDENTITIES", "PASS", True, "REPOSITORY_STATIC_INVARIANT"),
    ("DURABLE_JOURNAL_INSPECTION_PASS", "VERIFICATION_REQUIRED", False, "RUNTIME_EVIDENCE_REQUIRED"),
    ("NO_OUTCOME_UNKNOWN", "VERIFICATION_REQUIRED", False, "RUNTIME_EVIDENCE_REQUIRED"),
    ("DURABILITY_UNKNOWN_ABSENT", "VERIFICATION_REQUIRED", False, "RUNTIME_EVIDENCE_REQUIRED"),
    ("RETENTION_REVIEW_WINDOW_DECIDED", "POLICY_REQUIRED", False, "HUMAN_POLICY_DECISION_REQUIRED"),
    ("ROLLBACK_ANCHOR_DECIDED", "POLICY_REQUIRED", False, "HUMAN_POLICY_DECISION_REQUIRED"),
    ("OPERATOR_IDENTITY_AUTHENTICATION_DECIDED", "POLICY_REQUIRED", False, "HUMAN_POLICY_DECISION_REQUIRED"),
    ("PERMIT_EXPIRY_REVOCATION_DECIDED", "POLICY_REQUIRED", False, "HUMAN_POLICY_DECISION_REQUIRED"),
    ("EXPLICIT_LIVE_GET_AUTHORIZATION", "AUTHORIZATION_REQUIRED", False, "EXPLICIT_HUMAN_AUTHORIZATION_REQUIRED"),
    ("INCIDENT_RECONCILIATION_PROCEDURE", "POLICY_REQUIRED", False, "HUMAN_POLICY_DECISION_REQUIRED"),
    ("RAW_CONTENT_NON_RETENTION", "PASS", True, "REPOSITORY_STATIC_INVARIANT"),
    ("RETRY_RESUME_DISABLED", "PASS", True, "REPOSITORY_STATIC_INVARIANT"),
)


def _build_production_projection_service():
    review_material = copy.deepcopy(_REVIEW_MATERIAL); review_id = _REVIEW_ID
    checks = tuple(_CHECKS); timeout_id = _TIMEOUT_POLICY_ID; hash_record = _hash
    schema = SCHEMA_VERSION; checklist_revision = CHECKLIST_REVISION
    reviewed_sha = REVIEWED_MAIN_SHA; plan_id = PLAN_ID

    def review_record() -> Mapping[str, Any]:
        value = copy.deepcopy(review_material); value["record_id"] = review_id
        if validate_review_record(value): raise HandoffError("REVIEW_PROJECTION_INVALID")
        return MappingProxyType(value)

    def activation_checklist() -> Mapping[str, Any]:
        items = [{"ordinal": ordinal, "check_id": check_id, "status": status,
                  "satisfied": satisfied, "provenance": provenance}
            for ordinal, (check_id, status, satisfied, provenance) in enumerate(checks)]
        material = {"schema": schema, "record_type": "ACTIVATION_CHECKLIST",
            "review_record_id": review_id, "checklist_revision": checklist_revision,
            "reviewed_main_sha": reviewed_sha, "plan_id": plan_id,
            "timeout_policy_id": timeout_id, "items": items,
            "activation_status": "BLOCKED", "unsatisfied_count": sum(
                item["satisfied"] is False for item in items),
            "production_permit_issuer": "ABSENT", "production_execution": "UNREACHABLE",
            "ready_to_act": False, "authorized_to_act": False, "live_get_count": 0}
        value = dict(material); value["checklist_id"] = hash_record(material, "ACTIVATION_CHECKLIST")
        if validate_activation_checklist(value): raise HandoffError("CHECKLIST_PROJECTION_INVALID")
        return MappingProxyType(value)

    def handoff_status() -> Mapping[str, Any]:
        value = {"schema": schema, "record_type": "HANDOFF_STATUS",
            "handoff_state": HandoffState.SUPERSEDED.value,
            "review_record_id": review_id, "review_currentness": "STALE_REVIEW_REQUIRED",
            "merged_main_review": "REQUIRED",
            "activation_status": "BLOCKED", "production_permit_issuer": "ABSENT",
            "production_evidence_issuer": "ABSENT", "production_execute_api": "ABSENT",
            "cli_entry_point": "ABSENT", "scheduler": "ABSENT",
            "live_execution": "UNREACHABLE", "compatibility": "COMPATIBILITY_REVIEW_REQUIRED",
            "automatic_retry_allowed": False, "automatic_resume_allowed": False,
            "ready_to_act": False, "authorized_to_act": False,
            "live_action_enabled": False, "live_get_count": 0}
        if validate_handoff_status(value): raise HandoffError("STATUS_PROJECTION_INVALID")
        return MappingProxyType(value)
    return review_record, activation_checklist, handoff_status


def validate_review_record(value: Mapping[str, Any]) -> tuple[str, ...]:
    expected = dict(_REVIEW_MATERIAL); expected["record_id"] = _REVIEW_ID
    if not isinstance(value, Mapping) or set(value) != set(expected): return ("CLOSED_FIELDS_REQUIRED",)
    errors = []
    for key, item in expected.items():
        if value.get(key) != item or type(value.get(key)) is not type(item):
            errors.append("REVIEW_BINDING_INVALID"); break
    return tuple(errors)


def validate_activation_checklist(value: Mapping[str, Any]) -> tuple[str, ...]:
    fields = {"schema", "record_type", "checklist_id", "review_record_id",
        "checklist_revision", "reviewed_main_sha", "plan_id", "timeout_policy_id", "items",
        "activation_status", "unsatisfied_count", "production_permit_issuer",
        "production_execution", "ready_to_act", "authorized_to_act", "live_get_count"}
    if not isinstance(value, Mapping) or set(value) != fields: return ("CLOSED_FIELDS_REQUIRED",)
    errors = []
    items = value.get("items")
    expected_items = [{"ordinal": ordinal, "check_id": check_id, "status": status,
                       "satisfied": satisfied, "provenance": provenance}
        for ordinal, (check_id, status, satisfied, provenance) in enumerate(_CHECKS)]
    if (type(items) is not list or items != expected_items
            or any(type(item) is not dict or set(item) != {"ordinal", "check_id", "status", "satisfied", "provenance"}
                   or type(item["ordinal"]) is not int or type(item["satisfied"]) is not bool
                   for item in items)):
        errors.append("CHECKLIST_ITEMS_INVALID")
    expected = {"schema": SCHEMA_VERSION, "record_type": "ACTIVATION_CHECKLIST",
        "review_record_id": _REVIEW_ID, "checklist_revision": CHECKLIST_REVISION,
        "reviewed_main_sha": REVIEWED_MAIN_SHA, "plan_id": PLAN_ID,
        "timeout_policy_id": _TIMEOUT_POLICY_ID, "activation_status": "BLOCKED",
        "unsatisfied_count": sum(not item[2] for item in _CHECKS),
        "production_permit_issuer": "ABSENT", "production_execution": "UNREACHABLE",
        "ready_to_act": False, "authorized_to_act": False, "live_get_count": 0}
    if any(value.get(key) != item or type(value.get(key)) is not type(item)
           for key, item in expected.items()): errors.append("CHECKLIST_BOUNDARY_INVALID")
    if type(items) is list:
        material = {key: value[key] for key in fields if key != "checklist_id"}
        if value.get("checklist_id") != _hash(material, "ACTIVATION_CHECKLIST"):
            errors.append("CHECKLIST_ID_INVALID")
    return tuple(sorted(set(errors)))


def validate_handoff_status(value: Mapping[str, Any]) -> tuple[str, ...]:
    expected = {
        "schema": SCHEMA_VERSION, "record_type": "HANDOFF_STATUS",
        "handoff_state": HandoffState.SUPERSEDED.value,
        "review_record_id": _REVIEW_ID, "review_currentness": "STALE_REVIEW_REQUIRED",
        "merged_main_review": "REQUIRED",
        "activation_status": "BLOCKED", "production_permit_issuer": "ABSENT",
        "production_evidence_issuer": "ABSENT", "production_execute_api": "ABSENT",
        "cli_entry_point": "ABSENT", "scheduler": "ABSENT", "live_execution": "UNREACHABLE",
        "compatibility": "COMPATIBILITY_REVIEW_REQUIRED", "automatic_retry_allowed": False,
        "automatic_resume_allowed": False, "ready_to_act": False, "authorized_to_act": False,
        "live_action_enabled": False, "live_get_count": 0}
    if not isinstance(value, Mapping) or set(value) != set(expected): return ("CLOSED_FIELDS_REQUIRED",)
    return (("HANDOFF_BOUNDARY_INVALID",) if any(
        value.get(key) != item or type(value.get(key)) is not type(item)
        for key, item in expected.items()) else ())


review_record, activation_checklist, handoff_status = _build_production_projection_service()


class _FixtureReviewToken:
    __slots__ = ("__weakref__",)
    def __new__(cls, *_args: Any, **_kwargs: Any):
        raise PermissionError("fixture review token required")
    def __reduce__(self): raise TypeError("review tokens cannot be serialized")
    def __copy__(self): raise TypeError("review tokens cannot be copied")
    def __deepcopy__(self, _memo): raise TypeError("review tokens cannot be copied")


def _build_fixture_handoff_service(*, pid=os.getpid):
    """Private state-model seam; it issues no permit and invokes no network."""
    registry: weakref.WeakKeyDictionary[_FixtureReviewToken, dict[str, Any]] = weakref.WeakKeyDictionary()
    seen: set[str] = set(); service_id = _hash({"fixture_service": id(registry)}, "FIXTURE_SERVICE")

    def issue() -> _FixtureReviewToken:
        token = object.__new__(_FixtureReviewToken)
        registry[token] = {"record_id": _REVIEW_ID, "service_id": service_id,
            "pid": pid(), "state": HandoffState.DRAFT, "used": False}
        return token

    def transition(token: _FixtureReviewToken, state: HandoffState) -> Mapping[str, Any]:
        if type(token) is not _FixtureReviewToken or token not in registry:
            raise HandoffError("SEALED_FIXTURE_REVIEW_REQUIRED")
        entry = registry[token]
        if entry["service_id"] != service_id or entry["pid"] != pid():
            raise HandoffError("FOREIGN_REVIEW_TOKEN")
        if type(state) is not HandoffState: raise HandoffError("STATE_INVALID")
        if entry["used"] or entry["record_id"] in seen: raise HandoffError("REVIEW_REPLAYED")
        allowed = {
            HandoffState.DRAFT: {HandoffState.REVIEW_REQUIRED, HandoffState.REVOKED},
            HandoffState.REVIEW_REQUIRED: {HandoffState.REVIEWED_DESCRIPTIVE_ONLY,
                HandoffState.POLICY_BLOCKED, HandoffState.REVOKED,
                HandoffState.EXPIRED_OR_CURRENTNESS_UNKNOWN},
            HandoffState.REVIEWED_DESCRIPTIVE_ONLY: {HandoffState.ACTIVATION_REVIEW_REQUIRED,
                HandoffState.HANDOFF_INCOMPLETE, HandoffState.SUPERSEDED, HandoffState.REVOKED},
        }
        if state not in allowed.get(entry["state"], set()): raise HandoffError("TRANSITION_INVALID")
        entry["state"] = state
        if state in {HandoffState.ACTIVATION_REVIEW_REQUIRED, HandoffState.HANDOFF_INCOMPLETE,
                     HandoffState.SUPERSEDED, HandoffState.REVOKED,
                     HandoffState.EXPIRED_OR_CURRENTNESS_UNKNOWN, HandoffState.POLICY_BLOCKED}:
            entry["used"] = True; seen.add(entry["record_id"])
        return MappingProxyType({"state": state.value, "review_record_id": entry["record_id"],
            "activation_status": "BLOCKED", "permit_issued": False,
            "network_invocations": 0, "ready_to_act": False, "authorized_to_act": False})
    return issue, transition


__all__ = ("CHECKLIST_REVISION", "HandoffError", "HandoffState", "SCHEMA_VERSION",
    "activation_checklist", "handoff_status", "review_record",
    "validate_activation_checklist", "validate_handoff_status", "validate_review_record")
