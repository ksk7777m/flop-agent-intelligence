"""Fail-closed testnet readiness and runtime capability assessment.

Runtime observations are opaque, process-local evidence issued by a sealed
verifier.  Public dictionaries and serialized evidence are descriptive only.
This module performs no network, signing, wallet, claim, inference, or write
operation.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import threading
import weakref
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .remote_content_policy import POLICY_VERSION, ReviewedSourceId


VERIFIER_REVISION = "runtime-capability-verifier-v1"
MANIFEST_SCHEMA = "flop-runtime-capability-manifest-v1"
DEFAULT_OBSERVATION_TTL = timedelta(hours=6)


class Domain(str, Enum):
    IDENTITY = "IDENTITY"
    TECHNOCORE = "TECHNOCORE"
    EXPORT_EVIDENCE = "EXPORT_EVIDENCE"
    FAUCET = "FAUCET"
    TESTNET_NETWORK = "TESTNET_NETWORK"
    INFERENCE = "INFERENCE"
    SETTLEMENT_RAIL = "SETTLEMENT_RAIL"
    EVIDENCE_DURABILITY = "EVIDENCE_DURABILITY"


class CapabilityState(str, Enum):
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    IMPLEMENTED_OFFLINE = "IMPLEMENTED_OFFLINE"
    DOCUMENTED_ONLY = "DOCUMENTED_ONLY"
    RUNTIME_NOT_OBSERVED = "RUNTIME_NOT_OBSERVED"
    RUNTIME_OBSERVED = "RUNTIME_OBSERVED"
    RUNTIME_UNAVAILABLE = "RUNTIME_UNAVAILABLE"
    STALE_RUNTIME_OBSERVATION = "STALE_RUNTIME_OBSERVATION"
    CONFLICTING_CAPABILITY_EVIDENCE = "CONFLICTING_CAPABILITY_EVIDENCE"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    READY_FOR_HUMAN_APPROVAL = "READY_FOR_HUMAN_APPROVAL"
    AUTHORIZED = "AUTHORIZED"
    BLOCKED = "BLOCKED"


class Provenance(str, Enum):
    DOCUMENTATION = "DOCUMENTATION"
    SIGNED_OFFICIAL_SOURCE = "SIGNED_OFFICIAL_SOURCE"
    REVIEWED_REPOSITORY_SOURCE = "REVIEWED_REPOSITORY_SOURCE"
    DIRECT_RUNTIME_OBSERVATION = "DIRECT_RUNTIME_OBSERVATION"
    THIRD_PARTY_REPORT = "THIRD_PARTY_REPORT"
    LOCAL_FIXTURE = "LOCAL_FIXTURE"
    UNTRUSTED_CONTEXT = "UNTRUSTED_CONTEXT"


class ResponseClass(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    IDENTITY_MATCH = "IDENTITY_MATCH"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    SAFE_INFORMATIONAL = "SAFE_INFORMATIONAL"


class OverallState(str, Enum):
    BLOCKED = "BLOCKED"
    IMPLEMENTATION_READY = "IMPLEMENTATION_READY"
    OBSERVATION_REQUIRED = "OBSERVATION_REQUIRED"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"
    ACTION_READY = "ACTION_READY"
    AUTHORIZED = "AUTHORIZED"


class FaucetState(str, Enum):
    NO_OFFICIAL_ENDPOINT = "NO_OFFICIAL_ENDPOINT"
    DOCUMENTED_ENDPOINT = "DOCUMENTED_ENDPOINT"
    REVIEWED_ENDPOINT = "REVIEWED_ENDPOINT"
    RUNTIME_OBSERVED = "RUNTIME_OBSERVED"
    CLAIM_REQUIREMENTS_VERIFIED = "CLAIM_REQUIREMENTS_VERIFIED"
    READY_FOR_HUMAN_APPROVAL = "READY_FOR_HUMAN_APPROVAL"
    AUTHORIZED_TO_CLAIM = "AUTHORIZED_TO_CLAIM"


_FAUCET_TRANSITIONS: Mapping[FaucetState, Mapping[str, FaucetState]] = MappingProxyType({
    FaucetState.NO_OFFICIAL_ENDPOINT: MappingProxyType({"documented": FaucetState.DOCUMENTED_ENDPOINT}),
    FaucetState.DOCUMENTED_ENDPOINT: MappingProxyType({"source_reviewed": FaucetState.REVIEWED_ENDPOINT}),
    FaucetState.REVIEWED_ENDPOINT: MappingProxyType({"runtime_observed": FaucetState.RUNTIME_OBSERVED}),
    FaucetState.RUNTIME_OBSERVED: MappingProxyType({"requirements_verified": FaucetState.CLAIM_REQUIREMENTS_VERIFIED}),
    FaucetState.CLAIM_REQUIREMENTS_VERIFIED: MappingProxyType({"request_approval": FaucetState.READY_FOR_HUMAN_APPROVAL}),
    # AUTHORIZED_TO_CLAIM is intentionally unreachable here. A separately
    # reviewed local authority store must perform that transition.
    FaucetState.READY_FOR_HUMAN_APPROVAL: MappingProxyType({}),
    FaucetState.AUTHORIZED_TO_CLAIM: MappingProxyType({}),
})


def transition_faucet(state: FaucetState, event: str) -> FaucetState:
    if not isinstance(state, FaucetState):
        raise ValueError("unknown faucet state")
    try:
        return _FAUCET_TRANSITIONS[state][event]
    except KeyError as error:
        raise ValueError(f"invalid faucet transition: {state.value}/{event}") from error


class RuntimeCapabilityObservation:
    """Opaque verifier-issued capability; never caller-constructible."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: Any, **_kwargs: Any) -> "RuntimeCapabilityObservation":
        raise PermissionError("runtime observations are issued only by the sealed verifier")

    def __copy__(self) -> "RuntimeCapabilityObservation":
        raise TypeError("runtime observations cannot be copied")

    def __deepcopy__(self, _memo: dict[int, Any]) -> "RuntimeCapabilityObservation":
        raise TypeError("runtime observations cannot be copied")

    def __reduce__(self) -> Any:
        raise TypeError("runtime observations cannot be serialized")


class ActionAuthorization:
    """Opaque action-specific human authority; readiness cannot issue it."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: Any, **_kwargs: Any) -> "ActionAuthorization":
        raise PermissionError("action authorization requires a separately reviewed local store")

    def __reduce__(self) -> Any:
        raise TypeError("action authorization cannot be serialized")


@dataclass(frozen=True)
class ProbeSpec:
    capability_id: str
    domain: Domain
    source_id: ReviewedSourceId
    method: str
    endpoint_id: str
    redirects: bool
    retry_count: int
    timeout_seconds: int
    response_cap_bytes: int
    expected_response_classes: tuple[ResponseClass, ...]

    def __post_init__(self) -> None:
        if self.method != "GET" or self.redirects or self.retry_count != 0:
            raise ValueError("runtime probe must be a no-redirect, no-retry GET")
        if not 1 <= self.timeout_seconds <= 30:
            raise ValueError("runtime probe timeout is outside policy")
        if not 1 <= self.response_cap_bytes <= 2 * 1024 * 1024:
            raise ValueError("runtime probe response cap is outside policy")


@dataclass(frozen=True)
class _ObservationRecord:
    capability_id: str
    domain: Domain
    source_id: ReviewedSourceId
    endpoint_id: str
    method: str
    response_class: ResponseClass
    observed_at: datetime
    source_hash: str
    verifier_revision: str
    policy_version: str


@dataclass(frozen=True)
class CapabilityDefinition:
    capability_id: str
    domain: Domain
    implementation_status: CapabilityState
    documented_status: CapabilityState
    source_id: ReviewedSourceId | None
    critical: bool = True


@dataclass(frozen=True)
class CapabilityEvidence:
    capability_id: str
    provenance: Provenance
    source_id: str | None
    status: str


@dataclass(frozen=True)
class CapabilityAssessment:
    capability_id: str
    domain: Domain
    implementation_status: CapabilityState
    documented_status: CapabilityState
    runtime_status: CapabilityState
    source_id: str | None
    observed_at: str | None
    observation_hash: str | None
    policy_version: str
    verifier_revision: str
    blocking_reasons: tuple[str, ...]
    ready_to_act: bool
    authorized_to_act: bool

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        for key in ("domain", "implementation_status", "documented_status", "runtime_status"):
            value[key] = value[key].value
        value["blocking_reasons"] = list(self.blocking_reasons)
        return value


_PROBES: Mapping[str, ProbeSpec] = MappingProxyType({
    "technocore.runtime": ProbeSpec("technocore.runtime", Domain.TECHNOCORE, ReviewedSourceId.TECHNOCORE_HEALTH, "GET", "reviewed:technocore-health", False, 0, 10, 64 * 1024, (ResponseClass.AVAILABLE, ResponseClass.UNAVAILABLE)),
    "export.runtime": ProbeSpec("export.runtime", Domain.EXPORT_EVIDENCE, ReviewedSourceId.TECHNOCORE_ROOMS_JSON, "GET", "reviewed:technocore-export", False, 0, 20, 2 * 1024 * 1024, (ResponseClass.AVAILABLE, ResponseClass.UNAVAILABLE)),
    "faucet.runtime": ProbeSpec("faucet.runtime", Domain.FAUCET, ReviewedSourceId.FLOP_FINANCE_TEASER, "GET", "reviewed:faucet-capability", False, 0, 10, 256 * 1024, (ResponseClass.AVAILABLE, ResponseClass.UNAVAILABLE)),
    "network.chain_identity": ProbeSpec("network.chain_identity", Domain.TESTNET_NETWORK, ReviewedSourceId.FLOP_FINANCE_TEASER, "GET", "reviewed:testnet-chain-identity", False, 0, 10, 256 * 1024, (ResponseClass.IDENTITY_MATCH, ResponseClass.IDENTITY_MISMATCH, ResponseClass.UNAVAILABLE)),
    "inference.runtime": ProbeSpec("inference.runtime", Domain.INFERENCE, ReviewedSourceId.FLOP_FINANCE_TEASER, "GET", "reviewed:inference-capability", False, 0, 10, 256 * 1024, (ResponseClass.AVAILABLE, ResponseClass.UNAVAILABLE)),
    "rail.runtime": ProbeSpec("rail.runtime", Domain.SETTLEMENT_RAIL, ReviewedSourceId.FLOP_FINANCE_TEASER, "GET", "reviewed:settlement-rail", False, 0, 10, 256 * 1024, (ResponseClass.AVAILABLE, ResponseClass.UNAVAILABLE)),
    "durability.readback": ProbeSpec("durability.readback", Domain.EVIDENCE_DURABILITY, ReviewedSourceId.TECHNOCORE_ROOMS_JSON, "GET", "reviewed:evidence-readback", False, 0, 20, 2 * 1024 * 1024, (ResponseClass.AVAILABLE, ResponseClass.UNAVAILABLE)),
})


_DEFINITIONS: tuple[CapabilityDefinition, ...] = (
    CapabilityDefinition("identity.architecture", Domain.IDENTITY, CapabilityState.IMPLEMENTED_OFFLINE, CapabilityState.DOCUMENTED_ONLY, ReviewedSourceId.TECHNOCORE_SECURITY),
    CapabilityDefinition("technocore.runtime", Domain.TECHNOCORE, CapabilityState.IMPLEMENTED_OFFLINE, CapabilityState.DOCUMENTED_ONLY, ReviewedSourceId.TECHNOCORE_HEALTH),
    CapabilityDefinition("export.runtime", Domain.EXPORT_EVIDENCE, CapabilityState.IMPLEMENTED_OFFLINE, CapabilityState.DOCUMENTED_ONLY, ReviewedSourceId.TECHNOCORE_ROOMS_JSON),
    CapabilityDefinition("faucet.runtime", Domain.FAUCET, CapabilityState.IMPLEMENTED_OFFLINE, CapabilityState.DOCUMENTED_ONLY, ReviewedSourceId.FLOP_FINANCE_TEASER),
    CapabilityDefinition("network.chain_identity", Domain.TESTNET_NETWORK, CapabilityState.IMPLEMENTED_OFFLINE, CapabilityState.DOCUMENTED_ONLY, ReviewedSourceId.FLOP_FINANCE_TEASER),
    CapabilityDefinition("inference.runtime", Domain.INFERENCE, CapabilityState.IMPLEMENTED_OFFLINE, CapabilityState.DOCUMENTED_ONLY, ReviewedSourceId.FLOP_FINANCE_TEASER),
    CapabilityDefinition("rail.runtime", Domain.SETTLEMENT_RAIL, CapabilityState.IMPLEMENTED_OFFLINE, CapabilityState.DOCUMENTED_ONLY, ReviewedSourceId.FLOP_FINANCE_TEASER),
    CapabilityDefinition("durability.readback", Domain.EVIDENCE_DURABILITY, CapabilityState.IMPLEMENTED_OFFLINE, CapabilityState.RUNTIME_NOT_OBSERVED, ReviewedSourceId.TECHNOCORE_ROOMS_JSON),
)


def _canonical_record(record: _ObservationRecord) -> bytes:
    return json.dumps({
        "capability_id": record.capability_id,
        "domain": record.domain.value,
        "source_id": record.source_id.value,
        "endpoint_id": record.endpoint_id,
        "method": record.method,
        "response_class": record.response_class.value,
        "observed_at": record.observed_at.isoformat(),
        "source_hash": record.source_hash,
        "verifier_revision": record.verifier_revision,
        "policy_version": record.policy_version,
    }, sort_keys=True, separators=(",", ":")).encode()


def _new_runtime_authority() -> tuple[Callable[..., RuntimeCapabilityObservation], Callable[[RuntimeCapabilityObservation], _ObservationRecord]]:
    registry: weakref.WeakKeyDictionary[RuntimeCapabilityObservation, _ObservationRecord] = weakref.WeakKeyDictionary()
    lock = threading.Lock()
    token_type = RuntimeCapabilityObservation
    probes = _PROBES
    fullmatch = re.fullmatch
    revision = VERIFIER_REVISION
    policy_version = POLICY_VERSION
    mapping_type = Mapping
    source_type = ReviewedSourceId
    domain_type = Domain
    response_type = ResponseClass
    datetime_type = datetime
    utc = timezone.utc
    record_type = _ObservationRecord

    def verify_fixture(fixture: Mapping[str, Any]) -> RuntimeCapabilityObservation:
        """Verify an offline reviewed-observation fixture; never performs I/O."""
        if not isinstance(fixture, mapping_type) or fixture.get("schema") != "flop-runtime-observation-fixture-v1":
            raise ValueError("runtime observation fixture schema invalid")
        capability_id = fixture.get("capability_id")
        probe = probes.get(capability_id)
        if probe is None:
            raise ValueError("runtime observation capability is not reviewed")
        try:
            source_id = source_type(fixture.get("source_id"))
            domain = domain_type(fixture.get("domain"))
            response = response_type(fixture.get("response_class"))
            observed = datetime_type.fromisoformat(str(fixture.get("observed_at")).replace("Z", "+00:00"))
        except (TypeError, ValueError) as error:
            raise ValueError("runtime observation fixture fields invalid") from error
        source_hash = fixture.get("source_hash")
        if (source_id is not probe.source_id or domain is not probe.domain
                or fixture.get("endpoint_id") != probe.endpoint_id
                or fixture.get("method") != probe.method
                or response not in probe.expected_response_classes
                or observed.tzinfo is None
                or not isinstance(source_hash, str)
                or fullmatch(r"[0-9a-f]{64}", source_hash) is None):
            raise ValueError("runtime observation does not match reviewed probe")
        record = record_type(capability_id, domain, source_id, probe.endpoint_id,
                             probe.method, response, observed.astimezone(utc),
                             source_hash, revision, policy_version)
        token = object.__new__(token_type)
        with lock:
            registry[token] = record
        return token

    def resolve(token: RuntimeCapabilityObservation) -> _ObservationRecord:
        if type(token) is not token_type:
            raise PermissionError("runtime observation authority invalid")
        with lock:
            record = registry.get(token)
        if record is None:
            raise PermissionError("runtime observation was not issued by this authority")
        return record

    return verify_fixture, resolve


verify_runtime_fixture, _resolve_observation = _new_runtime_authority()


def probe_manifest() -> tuple[ProbeSpec, ...]:
    """Return inert future probe specifications. This does not execute probes."""
    return tuple(_PROBES.values())


def public_observation(
    token: RuntimeCapabilityObservation, *,
    _resolver: Callable[[RuntimeCapabilityObservation], _ObservationRecord] = _resolve_observation,
    _canonicalizer: Callable[[_ObservationRecord], bytes] = _canonical_record,
    _sha256: Callable[[bytes], Any] = hashlib.sha256,
    _mapping_proxy: Callable[[Mapping[str, Any]], Mapping[str, Any]] = MappingProxyType,
) -> Mapping[str, Any]:
    record = _resolver(token)
    return _mapping_proxy({
        "status": "DESCRIPTIVE_ONLY",
        "capability_id": record.capability_id,
        "domain": record.domain.value,
        "source_id": record.source_id.value,
        "endpoint_id": record.endpoint_id,
        "method": record.method,
        "response_class": record.response_class.value,
        "observed_at": record.observed_at.isoformat(),
        "source_hash": record.source_hash,
        "observation_hash": _sha256(_canonicalizer(record)).hexdigest(),
        "verifier_revision": record.verifier_revision,
        "policy_version": record.policy_version,
        "authority": "NOT_SERIALIZED",
    })


def _blockers(definition: CapabilityDefinition, runtime: CapabilityState) -> list[str]:
    blockers: list[str] = []
    if definition.implementation_status is CapabilityState.NOT_IMPLEMENTED:
        blockers.append("IMPLEMENTATION_REQUIRED")
    if definition.source_id is None:
        blockers.append("OFFICIAL_ENDPOINT_UNVERIFIED")
    if runtime is CapabilityState.RUNTIME_NOT_OBSERVED:
        blockers.append("MISSING_RUNTIME_OBSERVATION")
    elif runtime is CapabilityState.STALE_RUNTIME_OBSERVATION:
        blockers.append("STALE_RUNTIME_OBSERVATION")
    elif runtime is CapabilityState.RUNTIME_UNAVAILABLE:
        blockers.append("RUNTIME_UNAVAILABLE")
    elif runtime is CapabilityState.CONFLICTING_CAPABILITY_EVIDENCE:
        blockers.append("CONFLICTING_CAPABILITY_EVIDENCE")
    domain_specific = {
        Domain.IDENTITY: ("BACKUP_DRILL_REQUIRED", "RECOVERY_DRILL_REQUIRED"),
        Domain.FAUCET: ("CLAIM_REQUIREMENTS_UNVERIFIED", "HUMAN_APPROVAL_REQUIRED"),
        Domain.TESTNET_NETWORK: ("CHAIN_ID_UNOBSERVED",),
        Domain.INFERENCE: ("COST_SPEND_SEMANTICS_REVIEW_REQUIRED", "HUMAN_APPROVAL_REQUIRED"),
        Domain.SETTLEMENT_RAIL: ("RAIL_FINALITY_UNOBSERVED", "ECONOMIC_VALUE_UNVERIFIED"),
        Domain.EVIDENCE_DURABILITY: ("RUNTIME_WRITE_NOT_AUTHORIZED", "RUNTIME_READBACK_NOT_OBSERVED"),
    }
    blockers.extend(domain_specific.get(definition.domain, ()))
    return blockers


def assess_capabilities(
    observations: tuple[RuntimeCapabilityObservation, ...] = (), *,
    now: datetime | None = None,
    ttl: timedelta = DEFAULT_OBSERVATION_TTL,
    authorization: ActionAuthorization | None = None,
    _resolver: Callable[[RuntimeCapabilityObservation], _ObservationRecord] = _resolve_observation,
    _definitions: tuple[CapabilityDefinition, ...] = _DEFINITIONS,
    _blocker_builder: Callable[[CapabilityDefinition, CapabilityState], list[str]] = _blockers,
    _canonicalizer: Callable[[_ObservationRecord], bytes] = _canonical_record,
    _policy_version: str = POLICY_VERSION,
    _verifier_revision: str = VERIFIER_REVISION,
    _sha256: Callable[[bytes], Any] = hashlib.sha256,
    _state_type: type[CapabilityState] = CapabilityState,
    _overall_type: type[OverallState] = OverallState,
    _assessment_type: type[CapabilityAssessment] = CapabilityAssessment,
    _domains: tuple[Domain, ...] = tuple(Domain),
    _mapping_proxy: Callable[[Mapping[str, Any]], Mapping[str, Any]] = MappingProxyType,
) -> Mapping[str, Any]:
    """Assess all domains without performing effects or manufacturing authority."""
    if not isinstance(observations, tuple) or ttl <= timedelta(0):
        raise ValueError("observations must be a tuple and ttl must be positive")
    clock = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    records: dict[str, _ObservationRecord] = {}
    for token in observations:
        record = _resolver(token)
        previous = records.get(record.capability_id)
        if previous is None or record.observed_at > previous.observed_at:
            records[record.capability_id] = record
    authorized = False
    if authorization is not None:
        # No authority store is configured in this package. Descriptive objects,
        # including caller-created lookalikes, cannot authorize an action.
        raise PermissionError("no testnet action authorization store is configured")
    assessments: list[CapabilityAssessment] = []
    for definition in _definitions:
        record = records.get(definition.capability_id)
        observed_at = observation_hash = None
        if record is None:
            runtime = _state_type.RUNTIME_NOT_OBSERVED
        else:
            observed_at = record.observed_at.isoformat()
            observation_hash = _sha256(_canonicalizer(record)).hexdigest()
            age = clock - record.observed_at
            if age < timedelta(0) or age > ttl:
                runtime = _state_type.STALE_RUNTIME_OBSERVATION
            elif record.response_class in (ResponseClass.UNAVAILABLE, ResponseClass.IDENTITY_MISMATCH):
                runtime = (_state_type.CONFLICTING_CAPABILITY_EVIDENCE
                           if definition.documented_status is _state_type.DOCUMENTED_ONLY
                           else _state_type.RUNTIME_UNAVAILABLE)
            else:
                runtime = _state_type.RUNTIME_OBSERVED
        blockers = _blocker_builder(definition, runtime)
        ready = runtime is _state_type.RUNTIME_OBSERVED and not blockers
        assessments.append(_assessment_type(
            definition.capability_id, definition.domain, definition.implementation_status,
            definition.documented_status, runtime,
            definition.source_id.value if definition.source_id else None,
            observed_at, observation_hash, _policy_version, _verifier_revision,
            tuple(dict.fromkeys(blockers)), ready, ready and authorized))
    domain_rows: dict[str, list[dict[str, Any]]] = {domain.value: [] for domain in _domains}
    for assessment in assessments:
        domain_rows[assessment.domain.value].append(assessment.as_dict())
    all_implemented = all(item.implementation_status is not _state_type.NOT_IMPLEMENTED for item in assessments)
    any_runtime_block = any(item.runtime_status is not _state_type.RUNTIME_OBSERVED for item in assessments)
    any_review_block = any(item.blocking_reasons for item in assessments)
    if not all_implemented:
        overall = _overall_type.BLOCKED
    elif any_runtime_block:
        overall = _overall_type.OBSERVATION_REQUIRED
    elif any_review_block:
        overall = _overall_type.HUMAN_REVIEW_REQUIRED
    else:
        overall = _overall_type.AUTHORIZED if authorized else _overall_type.ACTION_READY
    overall_blockers = sorted({reason for item in assessments for reason in item.blocking_reasons})
    return _mapping_proxy({
        "schema": MANIFEST_SCHEMA,
        "implementation_readiness": "IMPLEMENTATION_READY" if all_implemented else "BLOCKED",
        "live_runtime_readiness": overall.value,
        "overall_state": overall.value,
        "ready_to_act": all(item.ready_to_act for item in assessments),
        "authorized_to_act": all(item.authorized_to_act for item in assessments),
        "blocking_reasons": tuple(overall_blockers),
        "domains": _mapping_proxy({key: tuple(value) for key, value in domain_rows.items()}),
    })


def workload_catalog() -> tuple[Mapping[str, str], ...]:
    return tuple(MappingProxyType(item) for item in (
        {"workload_id": "scam-faucet-detection", "purpose": "detect fake faucet and wallet prompts", "mode": "OFFLINE_FIXTURE"},
        {"workload_id": "technocore-intelligence", "purpose": "summarize reviewed public metadata", "mode": "OFFLINE_FIXTURE"},
        {"workload_id": "evidence-verification", "purpose": "verify evidence integrity and provenance", "mode": "OFFLINE_FIXTURE"},
        {"workload_id": "agent-collaboration-verification", "purpose": "verify bounded collaboration artifacts", "mode": "OFFLINE_FIXTURE"},
        {"workload_id": "ecosystem-intelligence", "purpose": "classify reviewed ecosystem evidence", "mode": "OFFLINE_FIXTURE"},
    ))


def domain_readiness() -> Mapping[str, Any]:
    """Detailed offline baseline, deliberately independent from live readiness."""
    return MappingProxyType({
        "IDENTITY": {"did_exists": "REVIEW_REQUIRED", "public_did_available": "REVIEW_REQUIRED", "local_signer_implemented": True, "signer_context_hardened": True, "capability_binding_ready": True, "backup_status": "REVIEW_REQUIRED", "recovery_drill_status": "REVIEW_REQUIRED"},
        "TECHNOCORE": {"reviewed_source_configured": True, "read_path_implemented": True, "signed_write_implemented": True, "signer_context_ready": True, "nonce_lossless": True, "raw_frame_gate_ready": True, "venue_metadata_separated": True, "evidence_verifier_ready": True, "runtime_reachable": "RUNTIME_NOT_OBSERVED"},
        "EXPORT_EVIDENCE": {"export_verifier_implemented": True, "documented_export_capability": "DOCUMENTED_ONLY", "runtime_export_observed": "RUNTIME_NOT_OBSERVED", "trusted_acquisition_ready": True, "completeness_verifier_ready": True},
        "FAUCET": {"official_endpoint": "DOCUMENTED_ENDPOINT", "runtime": "RUNTIME_NOT_OBSERVED", "requirements": "REVIEW_REQUIRED", "approval": "HUMAN_APPROVAL_REQUIRED", "authorization": "BLOCKED"},
        "TESTNET_NETWORK": {"network_documented": True, "chain_id_documented": False, "chain_id_runtime_observed": False, "rpc_documented": False, "rpc_runtime_observed": False, "network_identity_verified": False, "testnet_live": False, "testnet_ready": False},
        "INFERENCE": {"inference_api_documented": True, "runtime_endpoint_observed": False, "authentication_model_reviewed": False, "request_schema_reviewed": False, "cost_spend_semantics_reviewed": False, "evidence_capture_ready": True, "smoke_workload_ready": True, "human_approval_required": True},
        "SETTLEMENT_RAIL": {"rail_adapter_implemented": True, "rail_documented": True, "runtime_rail_observed": False, "rail_crypto_verifier_ready": True, "paperrail_protocol_valid": True, "economic_value_verified": False},
        "EVIDENCE_DURABILITY": {"write_path_implemented": True, "readback_verifier_ready": True, "runtime_write_not_authorized": True, "runtime_readback_not_observed": True},
    })


def capability_manifest(
    observations: tuple[RuntimeCapabilityObservation, ...] = (), *,
    now: datetime | None = None,
    _assessor: Callable[..., Mapping[str, Any]] = assess_capabilities,
) -> dict[str, Any]:
    """Return a JSON-safe descriptive manifest with no transferable authority."""
    assessment = _assessor(observations, now=now)
    return {
        "schema": assessment["schema"],
        "implementation_readiness": assessment["implementation_readiness"],
        "live_runtime_readiness": assessment["live_runtime_readiness"],
        "overall_state": assessment["overall_state"],
        "ready_to_act": assessment["ready_to_act"],
        "authorized_to_act": assessment["authorized_to_act"],
        "blocking_reasons": list(assessment["blocking_reasons"]),
        "domains": {key: list(value) for key, value in assessment["domains"].items()},
    }
