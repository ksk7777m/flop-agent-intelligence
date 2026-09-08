"""Implemented-disabled manual one-shot read-only reobservation boundary.

Production exposes status and a descriptive fixed plan only.  There is no
permit issuer, execute function, CLI, scheduler, or environment/config switch.
"""
from __future__ import annotations

import hashlib
import json
import os
import weakref
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Mapping

from . import technocore_runtime_observation as runtime
from .durable_observation_journal import (FIXED_REOBSERVATION_PLAN_ID,
    SCHEMA_VERSION as JOURNAL_SCHEMA)
from .observation_retention import (CANONICAL_ENCODING, FIXED_SOURCES, HASH_ALGORITHM,
    OBSERVATION_POLICY, PREDICATE_POLICY_HASHES, PredicatePolicy, SOURCE_ORDER_HASH,
    SOURCE_SET_ID)
from .remote_content_policy import DEFAULT_HTTP_TIMEOUT_SECONDS, DEFAULT_RESPONSE_LIMIT

SCHEMA_VERSION = "manual-readonly-reobservation-runner-v1"
EVIDENCE_SCHEMA = "manual-reobservation-evidence-v1"
IDENTITY_DOMAIN = "FLOP_MANUAL_READONLY_REOBSERVATION_RUNNER_V1"
SERVICE_ID = hashlib.sha256((IDENTITY_DOMAIN + ":sealed-runner").encode()).hexdigest()
_OBSERVED_AT = "2026-09-08T07:00:00Z"
_SOURCE_FIELDS = {"source_id", "source_class", "request_attempted", "request_completed",
    "http_status", "final_url_matched", "redirect_detected", "response_size_accepted",
    "content_type_accepted", "schema_validation", "capability_state", "version_evidence",
    "cache_policy_observed", "age_state", "cache_control_class", "validator_present",
    "freshness", "body_sha256", "body_bytes", "observed_at",
    "predicate_policy_revision"}


class RunnerError(RuntimeError):
    def __init__(self, code: str, field: str = "runner"):
        super().__init__(f"{code}: {field}"); self.code = code


class RunnerState(str, Enum):
    DISABLED_NO_PERMIT_ISSUER = "DISABLED_NO_PERMIT_ISSUER"
    PLAN_VALIDATED = "PLAN_VALIDATED"
    PERMIT_VALIDATED = "PERMIT_VALIDATED"
    PERMIT_CONSUMED_DURABLE = "PERMIT_CONSUMED_DURABLE"
    ATTEMPT_INTENT_DURABLE = "ATTEMPT_INTENT_DURABLE"
    SOURCE_INTENT_DURABLE = "SOURCE_INTENT_DURABLE"
    SOURCE_REQUEST_IN_FLIGHT = "SOURCE_REQUEST_IN_FLIGHT"
    SOURCE_RESULT_DURABLE = "SOURCE_RESULT_DURABLE"
    RESULTS_COMPLETE = "RESULTS_COMPLETE"
    EVIDENCE_COMMITTED = "EVIDENCE_COMMITTED"
    FINALIZED = "FINALIZED"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    BLOCKED = "BLOCKED"


class _Permit:
    __slots__ = ("__weakref__",)
    def __new__(cls, *_args: Any, **_kwargs: Any) -> "_Permit":
        raise PermissionError("sealed execution permit required")
    def __reduce__(self) -> Any: raise TypeError("execution permits cannot be serialized")
    def __copy__(self) -> Any: raise TypeError("execution permits cannot be copied")
    def __deepcopy__(self, _memo: Any) -> Any: raise TypeError("execution permits cannot be copied")


def _hash(value: Mapping[str, Any], domain: str) -> str:
    def check(item: Any) -> None:
        if item is None or type(item) in {str, bool, int}: return
        if type(item) is list:
            for child in item: check(child)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for child in item.values(): check(child)
            return
        raise RunnerError("CANONICAL_TYPE_INVALID")
    envelope = {"canonical_encoding": CANONICAL_ENCODING, "domain": IDENTITY_DOMAIN,
        "hash_algorithm": HASH_ALGORITHM, "record_domain": domain, "value": dict(value)}
    check(envelope)
    return hashlib.sha256(json.dumps(envelope, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode()).hexdigest()


_PLAN_MATERIAL = {"schema": SCHEMA_VERSION, "operation": "READ_ONLY_REOBSERVATION",
    "observation_policy": OBSERVATION_POLICY, "predicate_policy": PredicatePolicy.V2.value,
    "predicate_policy_hash": PREDICATE_POLICY_HASHES[PredicatePolicy.V2],
    "source_set_id": SOURCE_SET_ID, "source_order_hash": SOURCE_ORDER_HASH,
    "sources": [source.value for source in FIXED_SOURCES], "method": "GET",
    "request_count_per_source": 1, "retry_count": 0,
    "timeout_policy": {"seconds": DEFAULT_HTTP_TIMEOUT_SECONDS,
                       "body_bytes": DEFAULT_RESPONSE_LIMIT},
    "redirects_allowed": False, "alternate_url": None, "fallback": None,
    "remote_mcp_enabled": False, "signing_enabled": False, "external_write_enabled": False,
    "scheduler_enabled": False, "automatic_resume_allowed": False,
    "evidence_schema": EVIDENCE_SCHEMA, "journal_schema": JOURNAL_SCHEMA, "generation": 0}
PLAN_ID = _hash(_PLAN_MATERIAL, "FIXED_PLAN")
if PLAN_ID != FIXED_REOBSERVATION_PLAN_ID:
    raise RuntimeError("fixed runner/journal plan identity mismatch")


def fixed_plan_projection() -> Mapping[str, Any]:
    value = {"schema": SCHEMA_VERSION, "record_type": "FIXED_PLAN",
        "plan_id": PLAN_ID, "operation": "READ_ONLY_REOBSERVATION",
        "predicate_policy": PredicatePolicy.V2.value,
        "predicate_policy_hash": PREDICATE_POLICY_HASHES[PredicatePolicy.V2],
        "source_set_id": SOURCE_SET_ID, "source_order_hash": SOURCE_ORDER_HASH,
        "source_count": 4, "method": "GET", "request_count_per_source": 1,
        "retry_count": 0, "redirects_allowed": False, "fallback_enabled": False,
        "automatic_resume_allowed": False, "execution_enabled": False,
        "ready_to_act": False, "authorized_to_act": False}
    if validate_plan(value): raise RunnerError("PLAN_INVALID")
    return MappingProxyType(value)


def validate_plan(value: Mapping[str, Any]) -> tuple[str, ...]:
    expected = {"schema": SCHEMA_VERSION, "record_type": "FIXED_PLAN",
        "plan_id": PLAN_ID, "operation": "READ_ONLY_REOBSERVATION",
        "predicate_policy": PredicatePolicy.V2.value,
        "predicate_policy_hash": PREDICATE_POLICY_HASHES[PredicatePolicy.V2],
        "source_set_id": SOURCE_SET_ID, "source_order_hash": SOURCE_ORDER_HASH,
        "source_count": 4, "method": "GET", "request_count_per_source": 1,
        "retry_count": 0, "redirects_allowed": False, "fallback_enabled": False,
        "automatic_resume_allowed": False, "execution_enabled": False,
        "ready_to_act": False, "authorized_to_act": False}
    if not isinstance(value, Mapping) or set(value) != set(expected):
        return ("CLOSED_FIELDS_REQUIRED",)
    return (("FIXED_PLAN_INVALID",) if any(
        value.get(key) != item or type(value.get(key)) is not type(item)
        for key, item in expected.items()) else ())


def runner_status() -> Mapping[str, Any]:
    value = {"schema": SCHEMA_VERSION, "status": "IMPLEMENTED_DISABLED",
        "runner_state": RunnerState.DISABLED_NO_PERMIT_ISSUER.value,
        "plan_id": PLAN_ID, "predicate_policy": PredicatePolicy.V2.value,
        "source_set_id": SOURCE_SET_ID, "source_order_hash": SOURCE_ORDER_HASH,
        "source_count": 4, "production_permit_issuer": "ABSENT", "cli_command": "ABSENT",
        "scheduler": "ABSENT", "live_execution_path": "UNREACHABLE",
        "retry_count": 0, "automatic_resume_allowed": False,
        "automatic_retry_allowed": False, "live_get_count": 0,
        "currentness": "CURRENTNESS_UNKNOWN", "freshness": "FRESHNESS_NOT_CONFIRMED",
        "compatibility": "COMPATIBILITY_REVIEW_REQUIRED", "runtime_nonce_status": "BLOCKED_BY_LIVE_SIGNED_WRITE",
        "ready_to_act": False, "authorized_to_act": False, "live_action_enabled": False}
    if validate_status(value): raise RunnerError("STATUS_INVALID")
    return MappingProxyType(value)


def validate_status(value: Mapping[str, Any]) -> tuple[str, ...]:
    fields = {"schema", "status", "runner_state", "plan_id", "predicate_policy",
        "source_set_id", "source_order_hash", "source_count", "production_permit_issuer",
        "cli_command", "scheduler", "live_execution_path", "retry_count",
        "automatic_resume_allowed", "automatic_retry_allowed", "live_get_count",
        "currentness", "freshness", "compatibility", "runtime_nonce_status",
        "ready_to_act", "authorized_to_act", "live_action_enabled"}; errors = []
    if not isinstance(value, Mapping) or set(value) != fields: return ("CLOSED_FIELDS_REQUIRED",)
    expected = {"schema": SCHEMA_VERSION, "status": "IMPLEMENTED_DISABLED",
        "runner_state": RunnerState.DISABLED_NO_PERMIT_ISSUER.value,
        "predicate_policy": PredicatePolicy.V2.value, "source_set_id": SOURCE_SET_ID,
        "source_order_hash": SOURCE_ORDER_HASH, "source_count": 4,
        "production_permit_issuer": "ABSENT", "cli_command": "ABSENT", "scheduler": "ABSENT",
        "live_execution_path": "UNREACHABLE", "retry_count": 0,
        "automatic_resume_allowed": False, "automatic_retry_allowed": False,
        "live_get_count": 0, "currentness": "CURRENTNESS_UNKNOWN",
        "freshness": "FRESHNESS_NOT_CONFIRMED", "compatibility": "COMPATIBILITY_REVIEW_REQUIRED",
        "runtime_nonce_status": "BLOCKED_BY_LIVE_SIGNED_WRITE", "ready_to_act": False,
        "authorized_to_act": False, "live_action_enabled": False}
    if any(value.get(key) != item or type(value.get(key)) is not type(item)
           for key, item in expected.items()): errors.append("DISABLED_BOUNDARY_INVALID")
    plan = value.get("plan_id")
    if type(plan) is not str or plan != PLAN_ID: errors.append("PLAN_ID_INVALID")
    return tuple(errors)


def _build_fixture_runner(journal_api: tuple[Callable[..., Any], ...],
                          observer: Callable[[Any, str], Any],
                          *, pid: Callable[[], int] = os.getpid
                          ) -> tuple[Callable[..., Any], ...]:
    """Private offline seam. The production module never constructs this service."""
    if len(journal_api) != 11: raise RunnerError("FIXTURE_JOURNAL_REQUIRED")
    (prepare, attempt_intent, source_intent, request_boundary, result_durable,
     commit, finalize, inspect, permit_durable, issue_result, issue_evidence) = journal_api
    permits: weakref.WeakKeyDictionary[_Permit, dict[str, Any]] = weakref.WeakKeyDictionary()
    service_id = _hash({"service": SERVICE_ID, "fixture_instance": id(permits)}, "SERVICE")

    def issue_permit() -> _Permit:
        token = object.__new__(_Permit)
        permits[token] = {"plan_id": PLAN_ID, "predicate": PredicatePolicy.V2.value,
            "source_order_hash": SOURCE_ORDER_HASH, "operation": "READ_ONLY_REOBSERVATION",
            "generation": 0, "retry_count": 0, "service_id": service_id,
            "pid": pid(), "consumed": False}
        return token

    def execute(permit: _Permit) -> Mapping[str, Any]:
        if validate_plan(fixed_plan_projection()): raise RunnerError("PLAN_INVALID")
        existing = inspect()
        if existing["durable_state_found"]: raise RunnerError("EXISTING_ATTEMPT_BLOCKS_EXECUTION")
        if type(permit) is not _Permit or permit not in permits: raise RunnerError("SEALED_PERMIT_REQUIRED")
        binding = permits[permit]
        if binding["pid"] != pid(): raise RunnerError("FOREIGN_PROCESS_PERMIT")
        if binding["service_id"] != service_id or binding["plan_id"] != PLAN_ID:
            raise RunnerError("FOREIGN_PERMIT")
        if binding["consumed"]: raise RunnerError("PERMIT_ALREADY_CONSUMED")
        try: attempt = prepare()
        except Exception: raise RunnerError("JOURNAL_PREPARE_BLOCKED") from None
        binding["consumed"] = True
        try: permit_durable(attempt)
        except Exception: raise RunnerError("RECONCILIATION_REQUIRED") from None
        try: attempt_intent(attempt)
        except Exception: raise RunnerError("RECONCILIATION_REQUIRED") from None
        minimized = []
        for source in FIXED_SOURCES:
            try: source_intent(attempt, source)
            except Exception: raise RunnerError("RECONCILIATION_REQUIRED") from None
            try: request_boundary(attempt, source)
            except Exception: raise RunnerError("RECONCILIATION_REQUIRED") from None
            try: observed = observer(source, _OBSERVED_AT)
            except Exception: raise RunnerError("SOURCE_OUTCOME_UNKNOWN") from None
            if type(observed) is not runtime._SourceObservation:
                raise RunnerError("SEALED_OBSERVER_RESULT_REQUIRED")
            projection = observed.public_projection()
            required = {"source_id", "request_completed", "capability_state", "version_evidence",
                        "freshness", "body_sha256", "body_bytes", "predicate_policy_revision"}
            if (not isinstance(projection, Mapping)
                    or set(projection) != _SOURCE_FIELDS
                    or projection.get("source_id") != source.value
                    or projection.get("predicate_policy_revision") != PredicatePolicy.V2.value):
                raise RunnerError("OBSERVER_RESULT_INVALID")
            result = {key: projection[key] for key in sorted(required)}
            result_id = _hash(result, "MINIMIZED_SOURCE_RESULT")
            try: result_durable(attempt, source, issue_result(source, result_id))
            except Exception: raise RunnerError("SOURCE_OUTCOME_UNKNOWN") from None
            minimized.append({"source_id": source.value, "result_id": result_id,
                "semantic": projection.get("capability_state"),
                "version": projection.get("version_evidence"),
                "freshness": projection.get("freshness")})
            if (projection.get("request_completed") is not True
                    or projection.get("capability_state") != "OBSERVED_IN_LIVE_DOCUMENT"):
                raise RunnerError("SEMANTIC_OR_TRANSPORT_GAP")
        evidence_material = {"schema": EVIDENCE_SCHEMA, "plan_id": PLAN_ID,
            "predicate_policy": PredicatePolicy.V2.value,
            "predicate_policy_hash": PREDICATE_POLICY_HASHES[PredicatePolicy.V2],
            "source_set_id": SOURCE_SET_ID, "source_order_hash": SOURCE_ORDER_HASH,
            "generation": 0, "observed_at": _OBSERVED_AT, "sources": minimized,
            "source_set_complete": True, "version_evidence": "VERSION_EXPLICITLY_OBSERVED_ONE_SHOT",
            "freshness": "FRESHNESS_NOT_CONFIRMED", "currentness": "CURRENTNESS_UNKNOWN",
            "compatibility": "COMPATIBILITY_REVIEW_REQUIRED", "ready_to_act": False,
            "authorized_to_act": False}
        evidence_id = _hash(evidence_material, "SEALED_V2_EVIDENCE")
        try: commit(attempt, issue_evidence(evidence_id))
        except Exception: raise RunnerError("RECONCILIATION_REQUIRED") from None
        try: finalize(attempt)
        except Exception: raise RunnerError("RECONCILIATION_REQUIRED") from None
        return MappingProxyType({"state": RunnerState.FINALIZED.value,
            "plan_id": PLAN_ID, "evidence_id": evidence_id, "source_count": 4,
            "retry_count": 0, "raw_content_retained": False, "live_action_enabled": False,
            "ready_to_act": False, "authorized_to_act": False})

    def recover() -> Mapping[str, Any]:
        value = dict(inspect()); value["network_invocations"] = 0
        value["permit_issued"] = False; return MappingProxyType(value)

    return issue_permit, execute, recover


__all__ = ("RunnerError", "RunnerState", "fixed_plan_projection", "runner_status",
           "validate_plan", "validate_status")
