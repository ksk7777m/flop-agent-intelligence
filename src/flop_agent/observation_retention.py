"""Offline retention, predicate migration, and reobservation ceremony.

All records are immutable, process-local, descriptive tokens.  There is no
network, filesystem, scheduler, retry, writer, signer, wallet, or action sink.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import weakref
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from .remote_content_policy import (DEFAULT_HTTP_TIMEOUT_SECONDS,
                                    DEFAULT_RESPONSE_LIMIT, ReviewedSourceId)

SCHEMA_VERSION = "observation-retention-ceremony-v1"
POLICY_VERSION = "local-observation-retention-policy-v1"
OBSERVATION_POLICY = "technocore-runtime-readonly-observation-v1"
SOURCE_SET_ID = "technocore-runtime-fixed-source-set-v1"
MIGRATION_REASON = "LLMS_PREDICATE_ALIGNED_TO_PINNED_REVISION"
EVENT_TIME = "2026-09-08T05:00:00Z"
IDENTITY_DOMAIN = "FLOP_OBSERVATION_RETENTION_RECORD_ID_V1"
CANONICAL_ENCODING = "STRICT_TYPED_UTF8_JSON_V1"
HASH_ALGORITHM = "SHA-256"
FIXED_SOURCES = (ReviewedSourceId.TECHNOCORE_LLMS, ReviewedSourceId.TECHNOCORE_OPENAPI,
                 ReviewedSourceId.TECHNOCORE_AGENT_MANIFEST, ReviewedSourceId.TECHNOCORE_CONFIG)
SOURCE_ORDER_HASH = hashlib.sha256(json.dumps(
    [source.value for source in FIXED_SOURCES], separators=(",", ":"),
    ensure_ascii=True).encode("utf-8")).hexdigest()
_TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


class RetentionError(ValueError):
    def __init__(self, code: str, field: str):
        super().__init__(f"{code}: {field}")
        self.code = code


class PredicatePolicy(str, Enum):
    V1 = "technocore-runtime-predicates-v1"
    V2 = "technocore-runtime-predicates-v2"


PREDICATE_POLICY_HASHES = MappingProxyType({policy: hashlib.sha256(
    ("FLOP_PREDICATE_POLICY_ID_V1:" + policy.value).encode("utf-8")).hexdigest()
    for policy in PredicatePolicy})


class SourceAttemptState(str, Enum):
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    INTERRUPTED = "INTERRUPTED"


class AttemptStatus(str, Enum):
    STARTED = "STARTED"
    PARTIAL = "PARTIAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    INTERRUPTED = "INTERRUPTED"


class _Token:
    __slots__ = ("__weakref__",)
    def __new__(cls, *_args: Any, **_kwargs: Any) -> "_Token":
        raise PermissionError("ceremony records are issued only by the sealed authority")
    def __reduce__(self) -> Any:
        raise TypeError("ceremony records cannot be serialized")
    def __copy__(self) -> Any:
        raise TypeError("ceremony records cannot be copied")
    def __deepcopy__(self, _memo: Any) -> Any:
        raise TypeError("ceremony records cannot be copied")


class ObservationEvidence(_Token): pass
class PredicateMigration(_Token): pass
class ReobservationPlan(_Token): pass
class HumanReviewRecord(_Token): pass
class ObservationAttempt(_Token): pass


@dataclass(frozen=True)
class _Evidence:
    evidence_id: str
    source_set_id: str
    observed_at: str
    predicate_policy: PredicatePolicy
    observation_policy: str
    minimized_evidence_hash: str
    previous_evidence_id: str | None
    transport_result: str
    semantic_result: str
    source_set_complete: bool
    source_results: tuple[tuple[ReviewedSourceId, str, str], ...]


@dataclass(frozen=True)
class _Migration:
    migration_id: str
    evidence_id: str
    from_policy: PredicatePolicy
    to_policy: PredicatePolicy
    affected_sources: tuple[ReviewedSourceId, ...]
    migrated_at: str


@dataclass(frozen=True)
class _Plan:
    plan_id: str
    migration_id: str
    predicate_policy: PredicatePolicy
    source_set_id: str


@dataclass(frozen=True)
class _Review:
    review_id: str
    plan_id: str
    recorded_at: str


@dataclass(frozen=True)
class _Attempt:
    attempt_id: str
    plan_id: str
    generation: int
    status: AttemptStatus
    sources: tuple[tuple[ReviewedSourceId, SourceAttemptState], ...]
    previous_record_id: str | None
    record_id: str
    reconciliation_required: bool
    result_evidence_id: str | None


def _canonical_hash(value: Mapping[str, Any], record_domain: str) -> str:
    """Hash an internally-built, strict typed JSON tree with domain separation."""
    def check(item: Any) -> None:
        if item is None or type(item) in {str, bool, int}:
            return
        if type(item) is list:
            for child in item:
                check(child)
            return
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise RetentionError("CANONICAL_KEY_INVALID", "identity")
            for child in item.values():
                check(child)
            return
        raise RetentionError("CANONICAL_TYPE_INVALID", "identity")

    envelope = {"canonical_encoding": CANONICAL_ENCODING, "domain": IDENTITY_DOMAIN,
                "hash_algorithm": HASH_ALGORITHM, "record_domain": record_domain,
                "value": dict(value)}
    check(envelope)
    raw = json.dumps(envelope, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _build_authority() -> tuple[Any, ...]:
    lock = threading.Lock()
    evidence_registry: weakref.WeakKeyDictionary[ObservationEvidence, _Evidence] = weakref.WeakKeyDictionary()
    migration_registry: weakref.WeakKeyDictionary[PredicateMigration, _Migration] = weakref.WeakKeyDictionary()
    plan_registry: weakref.WeakKeyDictionary[ReobservationPlan, _Plan] = weakref.WeakKeyDictionary()
    review_registry: weakref.WeakKeyDictionary[HumanReviewRecord, _Review] = weakref.WeakKeyDictionary()
    attempt_registry: weakref.WeakKeyDictionary[ObservationAttempt, _Attempt] = weakref.WeakKeyDictionary()
    migrated_evidence: set[str] = set()
    planned_migrations: set[str] = set()
    reviewed_plans: set[str] = set()
    attempted_plans: set[str] = set()
    active_attempt_record: dict[str, str] = {}

    source_results = ((ReviewedSourceId.TECHNOCORE_LLMS, "COMPLETED", "SEMANTIC_GAP"),
        (ReviewedSourceId.TECHNOCORE_OPENAPI, "COMPLETED", "OBSERVED"),
        (ReviewedSourceId.TECHNOCORE_AGENT_MANIFEST, "COMPLETED", "OBSERVED"),
        (ReviewedSourceId.TECHNOCORE_CONFIG, "COMPLETED", "OBSERVED"))
    identity_sources = [{"source_id": source.value, "source_ordinal": ordinal,
        "transport_result": transport, "semantic_result": semantic,
        "version_evidence": ("VERSION_EXPLICITLY_OBSERVED" if source in {
            ReviewedSourceId.TECHNOCORE_AGENT_MANIFEST, ReviewedSourceId.TECHNOCORE_CONFIG}
            else "VERSION_NOT_EXPOSED"),
        "cache_classification": "POTENTIALLY_STALE",
        "body_sha256": None, "body_bytes": None,
        "body_evidence": "NOT_RETAINED", "response_size_accepted": True,
        "body_byte_limit": DEFAULT_RESPONSE_LIMIT}
        for ordinal, (source, transport, semantic) in enumerate(source_results)]
    material = {"schema": SCHEMA_VERSION, "record_generation": 0,
                "source_set_id": SOURCE_SET_ID, "source_order_hash": SOURCE_ORDER_HASH,
                "observed_at": "2026-09-08T04:34:36Z",
                "predicate_policy": PredicatePolicy.V1.value,
                "predicate_policy_hash": PREDICATE_POLICY_HASHES[PredicatePolicy.V1],
                "observation_policy": OBSERVATION_POLICY,
                "transport_result": "FOUR_OF_FOUR_COMPLETED",
                "semantic_result": "LLMS_SEMANTIC_GAP",
                "source_set_complete": False,
                "deployment_version_evidence": "VERSION_EXPLICITLY_OBSERVED_ONE_SHOT",
                "freshness": "FRESHNESS_NOT_CONFIRMED",
                "retention": "RETAINED", "supersession": "SUPERSEDED",
                "currentness": "CURRENTNESS_UNKNOWN",
                "compatibility": "COMPATIBILITY_REVIEW_REQUIRED",
                "previous_evidence_id": None, "source_results": identity_sources}
    evidence_id = _canonical_hash(material, "EVIDENCE")
    fixed_evidence = _Evidence(evidence_id, SOURCE_SET_ID, material["observed_at"],
        PredicatePolicy.V1, OBSERVATION_POLICY,
        _canonical_hash({"evidence": material}, "MINIMIZED_EVIDENCE"), None,
        "FOUR_OF_FOUR_COMPLETED", "LLMS_SEMANTIC_GAP", False, source_results)

    def issue(token_type: type[_Token], registry: Any, record: Any) -> Any:
        token = object.__new__(token_type)
        registry[token] = record
        return token

    def resolve(token: Any, token_type: type[_Token], registry: Any, field: str) -> Any:
        if type(token) is not token_type:
            raise RetentionError("SEALED_RECORD_REQUIRED", field)
        with lock:
            record = registry.get(token)
        if record is None:
            raise RetentionError("CROSS_AUTHORITY_RECORD", field)
        return record

    def historical() -> ObservationEvidence:
        with lock:
            return issue(ObservationEvidence, evidence_registry, fixed_evidence)

    def migrate(evidence: ObservationEvidence, to_policy: PredicatePolicy) -> PredicateMigration:
        record = resolve(evidence, ObservationEvidence, evidence_registry, "evidence")
        if type(to_policy) is not PredicatePolicy:
            raise RetentionError("PREDICATE_POLICY_UNKNOWN", "to_policy")
        if to_policy is record.predicate_policy:
            raise RetentionError("MIGRATION_SAME_REVISION", "to_policy")
        if record.predicate_policy is not PredicatePolicy.V1 or to_policy is not PredicatePolicy.V2:
            raise RetentionError("MIGRATION_DOWNGRADE_OR_CYCLE", "to_policy")
        with lock:
            if record.evidence_id in migrated_evidence:
                raise RetentionError("MIGRATION_ALREADY_RECORDED", "evidence")
            material = {"evidence_id": record.evidence_id, "from": record.predicate_policy.value,
                        "from_hash": PREDICATE_POLICY_HASHES[record.predicate_policy],
                        "to": to_policy.value, "to_hash": PREDICATE_POLICY_HASHES[to_policy],
                        "reason": MIGRATION_REASON,
                        "affected": [ReviewedSourceId.TECHNOCORE_LLMS.value],
                        "source_set_id": SOURCE_SET_ID, "raw_evidence_available": False,
                        "reevaluation_permitted": False,
                        "reobservation": "REOBSERVATION_REQUIRED", "at": EVENT_TIME}
            migration = _Migration(_canonical_hash(material, "PREDICATE_MIGRATION"), record.evidence_id,
                record.predicate_policy, to_policy, (ReviewedSourceId.TECHNOCORE_LLMS,), EVENT_TIME)
            migrated_evidence.add(record.evidence_id)
            return issue(PredicateMigration, migration_registry, migration)

    def prepare(migration: PredicateMigration) -> ReobservationPlan:
        record = resolve(migration, PredicateMigration, migration_registry, "migration")
        with lock:
            if record.migration_id in planned_migrations:
                raise RetentionError("PLAN_ALREADY_PREPARED", "migration")
            material = {"migration_id": record.migration_id, "policy": record.to_policy.value,
                        "predicate_policy_hash": PREDICATE_POLICY_HASHES[record.to_policy],
                        "source_set_id": SOURCE_SET_ID, "source_order_hash": SOURCE_ORDER_HASH,
                        "method": "GET", "retry_count": 0,
                        "timeout_seconds": DEFAULT_HTTP_TIMEOUT_SECONDS,
                        "body_byte_limit": DEFAULT_RESPONSE_LIMIT, "redirects_allowed": False,
                        "alternate_url_allowed": False, "fallback_allowed": False,
                        "remote_mcp_enabled": False, "signing_enabled": False,
                        "write_enabled": False, "scheduler_enabled": False,
                        "action_authorization": False}
            plan = _Plan(_canonical_hash(material, "REOBSERVATION_PLAN"), record.migration_id, record.to_policy, SOURCE_SET_ID)
            planned_migrations.add(record.migration_id)
            return issue(ReobservationPlan, plan_registry, plan)

    def review(plan: ReobservationPlan) -> HumanReviewRecord:
        record = resolve(plan, ReobservationPlan, plan_registry, "plan")
        with lock:
            if record.plan_id in reviewed_plans:
                raise RetentionError("HUMAN_REVIEW_ALREADY_RECORDED", "plan")
            reviewed_plans.add(record.plan_id)
            item = _Review(_canonical_hash({"plan_id": record.plan_id, "at": EVENT_TIME}, "HUMAN_REVIEW"),
                           record.plan_id, EVENT_TIME)
            return issue(HumanReviewRecord, review_registry, item)

    def begin(review_token: HumanReviewRecord) -> ObservationAttempt:
        review_record = resolve(review_token, HumanReviewRecord, review_registry, "review")
        with lock:
            if review_record.plan_id in attempted_plans:
                raise RetentionError("DUPLICATE_ATTEMPT", "plan")
            attempted_plans.add(review_record.plan_id)
            attempt_id = _canonical_hash({"plan_id": review_record.plan_id,
                "predicate_policy": PredicatePolicy.V2.value, "source_set_id": SOURCE_SET_ID,
                "source_order_hash": SOURCE_ORDER_HASH, "retry_count": 0, "ordinal": 1},
                "OBSERVATION_ATTEMPT")
            sources = tuple((source, SourceAttemptState.NOT_ATTEMPTED) for source in FIXED_SOURCES)
            record_id = _canonical_hash({"attempt_id": attempt_id, "generation": 0,
                "previous_record_id": None, "status": AttemptStatus.STARTED.value,
                "sources": [[source.value, state.value] for source, state in sources]},
                "ATTEMPT_GENERATION")
            item = _Attempt(attempt_id, review_record.plan_id, 0, AttemptStatus.STARTED,
                            sources, None, record_id, False, None)
            active_attempt_record[attempt_id] = record_id
            return issue(ObservationAttempt, attempt_registry, item)

    def record_source(attempt: ObservationAttempt, source_id: ReviewedSourceId,
                      state: SourceAttemptState) -> ObservationAttempt:
        record = resolve(attempt, ObservationAttempt, attempt_registry, "attempt")
        if type(source_id) is not ReviewedSourceId or source_id not in FIXED_SOURCES:
            raise RetentionError("SOURCE_NOT_IN_FIXED_SET", "source_id")
        if type(state) is not SourceAttemptState or state is SourceAttemptState.NOT_ATTEMPTED:
            raise RetentionError("SOURCE_ATTEMPT_STATE_INVALID", "state")
        with lock:
            if active_attempt_record.get(record.attempt_id) != record.record_id:
                raise RetentionError("ATTEMPT_RECORD_SUPERSEDED", "attempt")
            if record.status in {AttemptStatus.COMPLETED, AttemptStatus.FAILED,
                                 AttemptStatus.INTERRUPTED}:
                raise RetentionError("ATTEMPT_TERMINAL", "attempt")
            current = dict(record.sources)
            if current[source_id] is not SourceAttemptState.NOT_ATTEMPTED:
                raise RetentionError("SOURCE_ALREADY_ATTEMPTED", "source_id")
            current[source_id] = state
            values = tuple((source, current[source]) for source in FIXED_SOURCES)
            terminal = state in {SourceAttemptState.FAILED, SourceAttemptState.INTERRUPTED}
            status = (AttemptStatus.FAILED if state is SourceAttemptState.FAILED else
                      AttemptStatus.INTERRUPTED if state is SourceAttemptState.INTERRUPTED else
                      AttemptStatus.COMPLETED if all(v is SourceAttemptState.COMPLETED for _, v in values)
                      else AttemptStatus.PARTIAL)
            generation = record.generation + 1
            record_id = _canonical_hash({"attempt_id": record.attempt_id, "generation": generation,
                "previous_record_id": record.record_id, "status": status.value,
                "sources": [[s.value, v.value] for s, v in values]}, "ATTEMPT_GENERATION")
            item = _Attempt(record.attempt_id, record.plan_id, generation, status, values,
                record.record_id, record_id, terminal, None)
            active_attempt_record[record.attempt_id] = record_id
            return issue(ObservationAttempt, attempt_registry, item)

    def commit_result(attempt: ObservationAttempt, evidence: ObservationEvidence) -> str:
        attempt_record = resolve(attempt, ObservationAttempt, attempt_registry, "attempt")
        evidence_record = resolve(evidence, ObservationEvidence, evidence_registry, "evidence")
        if (attempt_record.status is not AttemptStatus.COMPLETED
                or evidence_record.predicate_policy is not PredicatePolicy.V2
                or evidence_record.previous_evidence_id != fixed_evidence.evidence_id):
            raise RetentionError("JOURNALED_CURRENT_RESULT_REQUIRED", "result")
        return evidence_record.evidence_id

    def project(token: Any) -> Mapping[str, Any]:
        if type(token) is ObservationEvidence:
            record = resolve(token, ObservationEvidence, evidence_registry, "record")
            value = {"record_type": "EVIDENCE", "record_id": record.evidence_id,
                "previous_record_id": record.previous_evidence_id,
                "predicate_policy": record.predicate_policy.value,
                "source_set_id": record.source_set_id, "observed_at": record.observed_at,
                "retention": "RETAINED", "supersession": "SUPERSEDED",
                "currentness": "CURRENTNESS_UNKNOWN", "freshness": "FRESHNESS_NOT_CONFIRMED",
                "completeness": "INCOMPLETE", "semantic_result": record.semantic_result,
                "reobservation": "REOBSERVATION_REQUIRED", "minimized_evidence_hash": record.minimized_evidence_hash}
        elif type(token) is PredicateMigration:
            record = resolve(token, PredicateMigration, migration_registry, "record")
            value = {"record_type": "MIGRATION", "record_id": record.migration_id,
                "previous_record_id": record.evidence_id, "predicate_policy": record.to_policy.value,
                "source_set_id": SOURCE_SET_ID, "observed_at": record.migrated_at,
                "retention": "RETAINED", "supersession": "SUPERSEDED",
                "currentness": "CURRENTNESS_UNKNOWN", "freshness": "FRESHNESS_NOT_CONFIRMED",
                "completeness": "INCOMPLETE", "semantic_result": "RE_EVALUATION_PROHIBITED",
                "reobservation": "REOBSERVATION_REQUIRED", "minimized_evidence_hash": record.migration_id}
        elif type(token) is ReobservationPlan:
            record = resolve(token, ReobservationPlan, plan_registry, "record")
            value = {"record_type": "PLAN", "record_id": record.plan_id,
                "previous_record_id": record.migration_id, "predicate_policy": record.predicate_policy.value,
                "source_set_id": record.source_set_id, "observed_at": EVENT_TIME,
                "retention": "RETAINED", "supersession": "NOT_SUPERSEDED",
                "currentness": "CURRENTNESS_UNKNOWN", "freshness": "FRESHNESS_NOT_CONFIRMED",
                "completeness": "INCOMPLETE", "semantic_result": "MANUAL_EXECUTION_PENDING",
                "reobservation": "PLAN_PREPARED", "minimized_evidence_hash": record.plan_id}
        elif type(token) is HumanReviewRecord:
            record = resolve(token, HumanReviewRecord, review_registry, "record")
            value = {"record_type": "REVIEW", "record_id": record.review_id,
                "previous_record_id": record.plan_id, "predicate_policy": PredicatePolicy.V2.value,
                "source_set_id": SOURCE_SET_ID, "observed_at": record.recorded_at,
                "retention": "RETAINED", "supersession": "NOT_SUPERSEDED",
                "currentness": "CURRENTNESS_UNKNOWN", "freshness": "FRESHNESS_NOT_CONFIRMED",
                "completeness": "INCOMPLETE", "semantic_result": "HUMAN_REVIEW_RECORDED",
                "reobservation": "HUMAN_REVIEW_RECORDED", "minimized_evidence_hash": record.review_id}
        elif type(token) is ObservationAttempt:
            record = resolve(token, ObservationAttempt, attempt_registry, "record")
            with lock:
                attempt_superseded = active_attempt_record.get(record.attempt_id) != record.record_id
            value = {"record_type": "ATTEMPT", "record_id": record.record_id,
                "previous_record_id": record.previous_record_id, "predicate_policy": PredicatePolicy.V2.value,
                "source_set_id": SOURCE_SET_ID, "observed_at": EVENT_TIME,
                "retention": "RETAINED", "supersession": "SUPERSEDED" if attempt_superseded else "NOT_SUPERSEDED",
                "currentness": "CURRENTNESS_UNKNOWN", "freshness": "FRESHNESS_NOT_CONFIRMED",
                "completeness": "COMPLETE" if record.status is AttemptStatus.COMPLETED else "INCOMPLETE",
                "semantic_result": record.status.value, "reobservation": "ATTEMPT_RECORDED",
                "minimized_evidence_hash": record.record_id}
        else:
            raise RetentionError("SEALED_RECORD_REQUIRED", "record")
        migration_fields = ({"from_predicate_policy": PredicatePolicy.V1.value,
            "migration_reason": MIGRATION_REASON,
            "affected_source_id": ReviewedSourceId.TECHNOCORE_LLMS.value}
            if value["record_type"] == "MIGRATION" else
            {"from_predicate_policy": None, "migration_reason": None,
             "affected_source_id": None})
        attempt_fields = ({"attempt_id": record.attempt_id, "observation_plan_id": record.plan_id,
            "attempt_generation": record.generation,
            "source_attempts_hash": _canonical_hash({"sources": [[source.value, state.value]
                for source, state in record.sources]}, "SOURCE_ATTEMPT_STATES"),
            "reconciliation_required": record.reconciliation_required,
            "result_evidence_id": record.result_evidence_id}
            if value["record_type"] == "ATTEMPT" else
            {"attempt_id": None, "observation_plan_id": None, "attempt_generation": None,
             "source_attempts_hash": None, "reconciliation_required": False,
             "result_evidence_id": None})
        projection = {"schema": SCHEMA_VERSION, "status": "DESCRIPTIVE_ONLY", **value,
            "observation_policy": OBSERVATION_POLICY,
            "predicate_policy_hash": PREDICATE_POLICY_HASHES[PredicatePolicy(value["predicate_policy"])],
            **migration_fields,
            **attempt_fields,
            "raw_evidence_available": False, "reevaluation_permitted": False,
            "planned_operation": "GET_ONLY_MANUAL_FUTURE", "execution_enabled": False,
            "retention_policy": "RETENTION_POLICY_REQUIRED", "compatibility": "COMPATIBILITY_REVIEW_REQUIRED",
            "retry_count": 0, "ready_to_act": False, "authorized_to_act": False,
            "live_action_enabled": False, "runtime_nonce_status": "BLOCKED_BY_LIVE_SIGNED_WRITE",
            "policy_version": POLICY_VERSION, "identity_domain": IDENTITY_DOMAIN,
            "canonical_encoding": CANONICAL_ENCODING, "hash_algorithm": HASH_ALGORITHM,
            "record_generation": record.generation if value["record_type"] == "ATTEMPT" else 0,
            "source_count": len(FIXED_SOURCES), "source_order_hash": SOURCE_ORDER_HASH,
            "deployment_version_evidence": "VERSION_EXPLICITLY_OBSERVED_ONE_SHOT",
            "body_evidence": "NOT_RETAINED"}
        if validate_projection(projection):
            raise RetentionError("PROJECTION_INVALID", "record")
        return MappingProxyType(projection)

    return historical, migrate, prepare, review, begin, record_source, commit_result, project


def validate_projection(value: Mapping[str, Any]) -> tuple[str, ...]:
    fields = {"schema", "status", "record_type", "record_id", "previous_record_id",
        "predicate_policy", "source_set_id", "observed_at", "retention", "supersession",
        "currentness", "freshness", "completeness", "semantic_result", "reobservation",
        "minimized_evidence_hash", "observation_policy", "predicate_policy_hash",
        "from_predicate_policy",
        "migration_reason", "affected_source_id", "raw_evidence_available",
        "reevaluation_permitted", "planned_operation", "execution_enabled",
        "attempt_id", "observation_plan_id", "attempt_generation",
        "source_attempts_hash", "reconciliation_required", "result_evidence_id",
        "retention_policy", "compatibility", "retry_count",
        "ready_to_act", "authorized_to_act", "live_action_enabled", "runtime_nonce_status",
        "policy_version", "identity_domain", "canonical_encoding", "hash_algorithm",
        "record_generation", "source_count", "source_order_hash",
        "deployment_version_evidence", "body_evidence"}
    errors = []
    if not isinstance(value, Mapping) or set(value) != fields:
        return ("CLOSED_FIELDS_REQUIRED",)
    for name in ("record_id", "minimized_evidence_hash"):
        item = value.get(name)
        if not isinstance(item, str) or len(item) != 64 or any(c not in "0123456789abcdef" for c in item):
            errors.append("HASH_ID_INVALID")
    previous = value.get("previous_record_id")
    if previous is not None and (not isinstance(previous, str) or re.fullmatch(r"[0-9a-f]{64}", previous) is None):
        errors.append("PREVIOUS_ID_INVALID")
    observed_at = value.get("observed_at")
    if not isinstance(observed_at, str) or _TIME.fullmatch(observed_at) is None:
        errors.append("OBSERVATION_TIME_INVALID")
    if value.get("record_type") not in {"EVIDENCE", "MIGRATION", "PLAN", "REVIEW", "ATTEMPT"}:
        errors.append("RECORD_TYPE_INVALID")
    if value.get("schema") != SCHEMA_VERSION or value.get("status") != "DESCRIPTIVE_ONLY":
        errors.append("SCHEMA_STATUS_INVALID")
    if value.get("predicate_policy") not in {item.value for item in PredicatePolicy}:
        errors.append("PREDICATE_POLICY_INVALID")
    else:
        policy = PredicatePolicy(value["predicate_policy"])
        if value.get("predicate_policy_hash") != PREDICATE_POLICY_HASHES[policy]:
            errors.append("PREDICATE_POLICY_HASH_INVALID")
    if value.get("source_set_id") != SOURCE_SET_ID:
        errors.append("SOURCE_SET_INVALID")
    if value.get("observation_policy") != OBSERVATION_POLICY:
        errors.append("OBSERVATION_POLICY_INVALID")
    if (value.get("identity_domain") != IDENTITY_DOMAIN
            or value.get("canonical_encoding") != CANONICAL_ENCODING
            or value.get("hash_algorithm") != HASH_ALGORITHM):
        errors.append("IDENTITY_ENCODING_INVALID")
    if (type(value.get("record_generation")) is not int
            or not 0 <= value.get("record_generation") <= 4):
        errors.append("RECORD_GENERATION_INVALID")
    if (type(value.get("source_count")) is not int or value.get("source_count") != len(FIXED_SOURCES)
            or value.get("source_order_hash") != SOURCE_ORDER_HASH):
        errors.append("SOURCE_ORDER_INVALID")
    if value.get("deployment_version_evidence") != "VERSION_EXPLICITLY_OBSERVED_ONE_SHOT":
        errors.append("VERSION_EVIDENCE_INVALID")
    if value.get("body_evidence") != "NOT_RETAINED":
        errors.append("BODY_EVIDENCE_INVALID")
    if value.get("raw_evidence_available") is not False or value.get("reevaluation_permitted") is not False:
        errors.append("RAW_REEVALUATION_PROHIBITED")
    if value.get("planned_operation") != "GET_ONLY_MANUAL_FUTURE" or value.get("execution_enabled") is not False:
        errors.append("EXECUTION_PROHIBITED")
    if value.get("retention") != "RETAINED": errors.append("RETENTION_INVALID")
    if value.get("supersession") not in {"SUPERSEDED", "NOT_SUPERSEDED"}:
        errors.append("SUPERSESSION_INVALID")
    if value.get("completeness") not in {"INCOMPLETE", "COMPLETE"}:
        errors.append("COMPLETENESS_INVALID")
    migration_values = (value.get("from_predicate_policy"), value.get("migration_reason"),
                        value.get("affected_source_id"))
    if value.get("record_type") == "MIGRATION":
        if migration_values != (PredicatePolicy.V1.value, MIGRATION_REASON,
                                ReviewedSourceId.TECHNOCORE_LLMS.value):
            errors.append("MIGRATION_BINDING_INVALID")
    elif migration_values != (None, None, None):
        errors.append("MIGRATION_FIELDS_PROHIBITED")
    attempt_values = (value.get("attempt_id"), value.get("observation_plan_id"),
                      value.get("attempt_generation"), value.get("source_attempts_hash"))
    if value.get("record_type") == "ATTEMPT":
        if (any(not isinstance(item, str) or re.fullmatch(r"[0-9a-f]{64}", item) is None
                for item in (attempt_values[0], attempt_values[1], attempt_values[3]))
                or type(attempt_values[2]) is not int or not 0 <= attempt_values[2] <= 4
                or type(value.get("reconciliation_required")) is not bool):
            errors.append("ATTEMPT_BINDING_INVALID")
    elif attempt_values != (None, None, None, None) or value.get("reconciliation_required") is not False:
        errors.append("ATTEMPT_FIELDS_PROHIBITED")
    result_id = value.get("result_evidence_id")
    if result_id is not None and (not isinstance(result_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", result_id) is None):
        errors.append("RESULT_EVIDENCE_ID_INVALID")
    record_type = value.get("record_type")
    expected = {
        "EVIDENCE": (PredicatePolicy.V1.value, "SUPERSEDED", "INCOMPLETE",
                     "LLMS_SEMANTIC_GAP", "REOBSERVATION_REQUIRED"),
        "MIGRATION": (PredicatePolicy.V2.value, "SUPERSEDED", "INCOMPLETE",
                      "RE_EVALUATION_PROHIBITED", "REOBSERVATION_REQUIRED"),
        "PLAN": (PredicatePolicy.V2.value, "NOT_SUPERSEDED", "INCOMPLETE",
                 "MANUAL_EXECUTION_PENDING", "PLAN_PREPARED"),
        "REVIEW": (PredicatePolicy.V2.value, "NOT_SUPERSEDED", "INCOMPLETE",
                   "HUMAN_REVIEW_RECORDED", "HUMAN_REVIEW_RECORDED")}
    if record_type in expected:
        actual = (value.get("predicate_policy"), value.get("supersession"),
                  value.get("completeness"), value.get("semantic_result"),
                  value.get("reobservation"))
        if actual != expected[record_type] or value.get("record_generation") != 0:
            errors.append("RECORD_STATE_CONTRADICTION")
        if (record_type == "EVIDENCE") != (value.get("previous_record_id") is None):
            errors.append("PREVIOUS_ID_CONTRADICTION")
        expected_time = "2026-09-08T04:34:36Z" if record_type == "EVIDENCE" else EVENT_TIME
        if value.get("observed_at") != expected_time:
            errors.append("RECORD_TIME_CONTRADICTION")
    elif record_type == "ATTEMPT":
        semantic = value.get("semantic_result")
        if (value.get("predicate_policy") != PredicatePolicy.V2.value
                or value.get("reobservation") != "ATTEMPT_RECORDED"
                or semantic not in {item.value for item in AttemptStatus}
                or value.get("record_generation") != value.get("attempt_generation")
                or (value.get("completeness") == "COMPLETE") != (semantic == "COMPLETED")
                or ((value.get("previous_record_id") is None)
                    != (value.get("attempt_generation") == 0))
                or (semantic == "STARTED") != (value.get("attempt_generation") == 0)
                or value.get("reconciliation_required")
                    != (semantic in {"FAILED", "INTERRUPTED"})
                or value.get("observed_at") != EVENT_TIME
                or result_id is not None):
            errors.append("ATTEMPT_STATE_CONTRADICTION")
    if value.get("currentness") != "CURRENTNESS_UNKNOWN": errors.append("CURRENTNESS_UNKNOWN_REQUIRED")
    if value.get("freshness") != "FRESHNESS_NOT_CONFIRMED": errors.append("FRESHNESS_UNPROVEN")
    if value.get("retention_policy") != "RETENTION_POLICY_REQUIRED": errors.append("RETENTION_POLICY_REQUIRED")
    if value.get("compatibility") != "COMPATIBILITY_REVIEW_REQUIRED": errors.append("COMPATIBILITY_REVIEW_REQUIRED")
    if value.get("retry_count") != 0: errors.append("RETRY_PROHIBITED")
    if value.get("policy_version") != POLICY_VERSION:
        errors.append("POLICY_VERSION_INVALID")
    if value.get("runtime_nonce_status") != "BLOCKED_BY_LIVE_SIGNED_WRITE":
        errors.append("RUNTIME_NONCE_STATUS_INVALID")
    for name in ("ready_to_act", "authorized_to_act", "live_action_enabled"):
        if type(value.get(name)) is not bool or value.get(name) is not False:
            errors.append("LIVE_ACTION_PROHIBITED")
    return tuple(sorted(set(errors)))


(historical_llms_evidence, record_predicate_migration, prepare_reobservation_plan,
 record_human_review, begin_observation_attempt, record_source_attempt,
 commit_observation_result, public_projection) = _build_authority()

__all__ = ("AttemptStatus", "ObservationAttempt", "ObservationEvidence", "PredicateMigration",
    "PredicatePolicy", "ReobservationPlan", "RetentionError", "SourceAttemptState",
    "begin_observation_attempt", "commit_observation_result", "historical_llms_evidence",
    "prepare_reobservation_plan", "public_projection", "record_human_review",
    "record_predicate_migration", "record_source_attempt", "validate_projection")
