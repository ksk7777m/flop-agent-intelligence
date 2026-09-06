"""Sealed, fail-closed testnet readiness and runtime capability model.

This module has no network or action implementation. Production callables are
closures over immutable policy. Public JSON is descriptive and carries no
runtime-observation or action authority.
"""

from __future__ import annotations

import hashlib
import json
import threading
import weakref
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .remote_content_policy import ReviewedSourceId, resolve_reviewed_source


MANIFEST_SCHEMA = "flop-runtime-capability-manifest-v1"
POLICY_VERSION = "runtime-capability-safety-policy-v2"
VERIFIER_REVISION = "runtime-capability-verifier-v2"
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
    DELEGATION_VERIFICATION = "DELEGATION_VERIFICATION"
    TOOL_OUTPUT_BUDGET = "TOOL_OUTPUT_BUDGET"
    REPLAY_SAFETY = "REPLAY_SAFETY"
    ACTIVITY_QUALITY = "ACTIVITY_QUALITY"
    PROTOCOL_MODEL = "PROTOCOL_MODEL"
    RUNTIME_DRIFT = "RUNTIME_DRIFT"


class CapabilityState(str, Enum):
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    IMPLEMENTED_OFFLINE = "IMPLEMENTED_OFFLINE"
    DOCUMENTED_ONLY = "DOCUMENTED_ONLY"
    RUNTIME_NOT_OBSERVED = "RUNTIME_NOT_OBSERVED"
    RUNTIME_OBSERVED = "RUNTIME_OBSERVED"
    RUNTIME_UNAVAILABLE = "RUNTIME_UNAVAILABLE"
    STALE_RUNTIME_OBSERVATION = "STALE_RUNTIME_OBSERVATION"
    CONFLICTING_CAPABILITY_EVIDENCE = "CONFLICTING_CAPABILITY_EVIDENCE"
    LIVE_DOC_RUNTIME_DRIFT = "LIVE_DOC_RUNTIME_DRIFT"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    READY_FOR_HUMAN_APPROVAL = "READY_FOR_HUMAN_APPROVAL"
    AUTHORIZED = "AUTHORIZED"
    BLOCKED = "BLOCKED"


class OverallState(str, Enum):
    BLOCKED = "BLOCKED"
    IMPLEMENTATION_READY = "IMPLEMENTATION_READY"
    OBSERVATION_REQUIRED = "OBSERVATION_REQUIRED"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"
    ACTION_READY = "ACTION_READY"
    AUTHORIZED = "AUTHORIZED"
    INVALID_CONFIGURATION = "INVALID_CONFIGURATION"


class Provenance(str, Enum):
    DOCUMENTATION = "DOCUMENTATION"
    SIGNED_OFFICIAL_SOURCE = "SIGNED_OFFICIAL_SOURCE"
    REVIEWED_REPOSITORY_SOURCE = "REVIEWED_REPOSITORY_SOURCE"
    DIRECT_RUNTIME_OBSERVATION = "DIRECT_RUNTIME_OBSERVATION"
    REVIEWED_LOCAL_FIXTURE = "REVIEWED_LOCAL_FIXTURE"
    THIRD_PARTY_REPORT = "THIRD_PARTY_REPORT"
    UNTRUSTED_CONTEXT = "UNTRUSTED_CONTEXT"


class ResponseClass(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"


class FaucetState(str, Enum):
    NO_OFFICIAL_ENDPOINT = "NO_OFFICIAL_ENDPOINT"
    DOCUMENTED_ENDPOINT = "DOCUMENTED_ENDPOINT"
    REVIEWED_ENDPOINT = "REVIEWED_ENDPOINT"
    RUNTIME_OBSERVED = "RUNTIME_OBSERVED"
    CLAIM_REQUIREMENTS_VERIFIED = "CLAIM_REQUIREMENTS_VERIFIED"
    READY_FOR_HUMAN_APPROVAL = "READY_FOR_HUMAN_APPROVAL"


class ReadinessAction(str, Enum):
    GENERAL_TESTNET = "GENERAL_TESTNET"
    FAUCET_CLAIM = "FAUCET_CLAIM"
    INFERENCE_REQUEST = "INFERENCE_REQUEST"
    SETTLEMENT = "SETTLEMENT"


class ReviewedRuntimeFixtureId(str, Enum):
    TECHNOCORE_AVAILABLE = "TECHNOCORE_AVAILABLE"
    TECHNOCORE_UNAVAILABLE = "TECHNOCORE_UNAVAILABLE"
    TECHNOCORE_STALE = "TECHNOCORE_STALE"
    EXPORT_AVAILABLE = "EXPORT_AVAILABLE"
    FAUCET_AVAILABLE = "FAUCET_AVAILABLE"
    NETWORK_MATCH = "NETWORK_MATCH"
    NETWORK_MISMATCH = "NETWORK_MISMATCH"
    INFERENCE_AVAILABLE = "INFERENCE_AVAILABLE"
    RAIL_AVAILABLE = "RAIL_AVAILABLE"
    DURABILITY_AVAILABLE = "DURABILITY_AVAILABLE"


class RuntimeCapabilityObservation:
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
    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: Any, **_kwargs: Any) -> "ActionAuthorization":
        raise PermissionError("no testnet action-authority issuer is configured")

    def __copy__(self) -> "ActionAuthorization":
        raise TypeError("action authorization cannot be copied")

    def __deepcopy__(self, _memo: dict[int, Any]) -> "ActionAuthorization":
        raise TypeError("action authorization cannot be copied")

    def __reduce__(self) -> Any:
        raise TypeError("action authorization cannot be serialized")


@dataclass(frozen=True)
class ProbeSpec:
    capability_id: str
    domain: Domain
    source_id: ReviewedSourceId
    method: str
    resource_id: str
    redirects: bool
    retry_count: int
    timeout_seconds: int
    response_cap_bytes: int
    expected_response_classes: tuple[ResponseClass, ...]


@dataclass(frozen=True)
class CapabilityDefinition:
    capability_id: str
    domain: Domain
    implementation_status: CapabilityState
    documented_status: CapabilityState
    source_id: ReviewedSourceId | None
    runtime_required: bool
    critical: bool
    static_blockers: tuple[str, ...]
    documented_chain_id: str | None = None
    documented_rpc_identity: str | None = None
    documented_network_identity: str | None = None


@dataclass(frozen=True)
class _Fixture:
    fixture_id: ReviewedRuntimeFixtureId
    capability_id: str
    domain: Domain
    source_id: ReviewedSourceId
    resource_id: str
    method: str
    response_class: ResponseClass
    observed_at: datetime
    payload_sha256: str
    observed_chain_id: str | None = None
    observed_rpc_identity: str | None = None
    observed_network_identity: str | None = None


@dataclass(frozen=True)
class _ObservationRecord:
    capability_id: str
    domain: Domain
    source_id: ReviewedSourceId
    resource_id: str
    method: str
    response_class: ResponseClass
    observed_at: datetime
    source_hash: str
    verifier_revision: str
    policy_version: str
    provenance: Provenance
    observed_chain_id: str | None
    observed_rpc_identity: str | None
    observed_network_identity: str | None


@dataclass(frozen=True)
class _ActionRecord:
    action: ReadinessAction
    capability_id: str
    domain: Domain
    target_resource: str
    network_identity: str
    effect_class: str
    policy_version: str
    nonce: str
    expires_at: datetime


def _probe_definitions() -> tuple[ProbeSpec, ...]:
    classes = (ResponseClass.AVAILABLE, ResponseClass.UNAVAILABLE)
    return (
        ProbeSpec("technocore.runtime", Domain.TECHNOCORE, ReviewedSourceId.TECHNOCORE_HEALTH, "GET", "reviewed:technocore-health", False, 0, 10, 65536, classes),
        ProbeSpec("export.runtime", Domain.EXPORT_EVIDENCE, ReviewedSourceId.TECHNOCORE_ROOMS_JSON, "GET", "reviewed:native-export-capability", False, 0, 20, 2097152, classes),
        ProbeSpec("faucet.runtime", Domain.FAUCET, ReviewedSourceId.FLOP_FINANCE_TEASER, "GET", "reviewed:faucet-capability", False, 0, 10, 262144, classes),
        ProbeSpec("network.identity", Domain.TESTNET_NETWORK, ReviewedSourceId.FLOP_FINANCE_TEASER, "GET", "reviewed:testnet-network-identity", False, 0, 10, 262144, classes),
        ProbeSpec("inference.runtime", Domain.INFERENCE, ReviewedSourceId.FLOP_FINANCE_TEASER, "GET", "reviewed:inference-capability", False, 0, 10, 262144, classes),
        ProbeSpec("rail.runtime", Domain.SETTLEMENT_RAIL, ReviewedSourceId.FLOP_FINANCE_TEASER, "GET", "reviewed:settlement-rail", False, 0, 10, 262144, classes),
        ProbeSpec("durability.readback", Domain.EVIDENCE_DURABILITY, ReviewedSourceId.TECHNOCORE_ROOMS_JSON, "GET", "reviewed:evidence-readback", False, 0, 20, 2097152, classes),
        ProbeSpec("technocore.config", Domain.RUNTIME_DRIFT, ReviewedSourceId.TECHNOCORE_CONFIG, "GET", "reviewed:technocore-config", False, 0, 10, 262144, classes),
    )


def _production_definitions() -> tuple[CapabilityDefinition, ...]:
    offline, documented = CapabilityState.IMPLEMENTED_OFFLINE, CapabilityState.DOCUMENTED_ONLY
    return (
        CapabilityDefinition("identity.architecture", Domain.IDENTITY, offline, documented, ReviewedSourceId.TECHNOCORE_SECURITY, False, True, ("BACKUP_DRILL_REQUIRED", "RECOVERY_DRILL_REQUIRED")),
        CapabilityDefinition("technocore.runtime", Domain.TECHNOCORE, offline, documented, ReviewedSourceId.TECHNOCORE_HEALTH, True, True, ()),
        CapabilityDefinition("export.runtime", Domain.EXPORT_EVIDENCE, offline, documented, ReviewedSourceId.TECHNOCORE_ROOMS_JSON, True, True, ("TRUSTED_ACQUISITION_RUNTIME_UNVERIFIED", "COMPLETENESS_RUNTIME_UNVERIFIED")),
        CapabilityDefinition("faucet.runtime", Domain.FAUCET, offline, documented, ReviewedSourceId.FLOP_FINANCE_TEASER, True, True, ("CLAIM_REQUIREMENTS_UNVERIFIED", "HUMAN_APPROVAL_REQUIRED", "REPLAY_LEDGER_REQUIRED", "SIDE_EFFECT_JOURNAL_REQUIRED")),
        CapabilityDefinition("network.identity", Domain.TESTNET_NETWORK, offline, documented, ReviewedSourceId.FLOP_FINANCE_TEASER, True, True, ("CHAIN_ID_UNDOCUMENTED", "RPC_IDENTITY_UNDOCUMENTED", "NETWORK_IDENTITY_UNDOCUMENTED")),
        CapabilityDefinition("inference.runtime", Domain.INFERENCE, offline, documented, ReviewedSourceId.FLOP_FINANCE_TEASER, True, True, ("REQUEST_SCHEMA_REVIEW_REQUIRED", "AUTHENTICATION_MODEL_REVIEW_REQUIRED", "COST_SPEND_SEMANTICS_REVIEW_REQUIRED", "HUMAN_APPROVAL_REQUIRED")),
        CapabilityDefinition("rail.runtime", Domain.SETTLEMENT_RAIL, offline, documented, ReviewedSourceId.FLOP_FINANCE_TEASER, True, True, ("RAIL_FINALITY_UNOBSERVED", "ECONOMIC_VALUE_UNVERIFIED", "REPLAY_LEDGER_REQUIRED", "SIDE_EFFECT_JOURNAL_REQUIRED")),
        CapabilityDefinition("durability.readback", Domain.EVIDENCE_DURABILITY, offline, CapabilityState.RUNTIME_NOT_OBSERVED, ReviewedSourceId.TECHNOCORE_ROOMS_JSON, True, True, ("RUNTIME_WRITE_NOT_AUTHORIZED", "RUNTIME_READBACK_NOT_OBSERVED")),
        CapabilityDefinition("delegation.verification", Domain.DELEGATION_VERIFICATION, offline, documented, ReviewedSourceId.TECHNOCORE_SECURITY, True, False, ("DELEGATION_RUNTIME_UNOBSERVED",)),
        CapabilityDefinition("tool.output_budget", Domain.TOOL_OUTPUT_BUDGET, offline, CapabilityState.REVIEW_REQUIRED, None, False, False, ()),
        CapabilityDefinition("replay.safety", Domain.REPLAY_SAFETY, CapabilityState.NOT_IMPLEMENTED, CapabilityState.REVIEW_REQUIRED, None, False, False, ("REPLAY_LEDGER_REQUIRED", "SIDE_EFFECT_JOURNAL_REQUIRED")),
        CapabilityDefinition("activity.quality", Domain.ACTIVITY_QUALITY, offline, CapabilityState.REVIEW_REQUIRED, None, False, False, ()),
        CapabilityDefinition("protocol.generic_models", Domain.PROTOCOL_MODEL, offline, documented, ReviewedSourceId.TECHNOCORE_SECURITY, False, False, ("UPSTREAM_VERSION_NOT_FINALIZED", "PTLC_EXPERIMENTAL_UNEXERCISED", "OWNED_ROOM_INSUFFICIENT_AS_SOLE_AUTH_EVIDENCE")),
        CapabilityDefinition("runtime.release_drift", Domain.RUNTIME_DRIFT, offline, documented, ReviewedSourceId.TECHNOCORE_CONFIG, True, False, ("RELEASE_MAIN_DOC_RUNTIME_UNRECONCILED",)),
    )


def _reviewed_fixtures(probes: Mapping[str, ProbeSpec]) -> Mapping[ReviewedRuntimeFixtureId, _Fixture]:
    sha256, datetime_type, utc = hashlib.sha256, datetime, timezone.utc
    def item(fixture_id: ReviewedRuntimeFixtureId, capability_id: str, response: ResponseClass,
             when: str, chain: str | None = None, rpc: str | None = None,
             network: str | None = None) -> _Fixture:
        probe = probes[capability_id]
        material = json.dumps({"fixture_id": fixture_id.value, "capability_id": capability_id,
                               "response": response.value, "chain": chain, "rpc": rpc,
                               "network": network}, sort_keys=True, separators=(",", ":")).encode()
        return _Fixture(fixture_id, capability_id, probe.domain, probe.source_id,
                        probe.resource_id, probe.method, response,
                        datetime_type.fromisoformat(when).astimezone(utc),
                        sha256(material).hexdigest(), chain, rpc, network)
    values = (
        item(ReviewedRuntimeFixtureId.TECHNOCORE_AVAILABLE, "technocore.runtime", ResponseClass.AVAILABLE, "2026-09-06T05:00:00+00:00"),
        item(ReviewedRuntimeFixtureId.TECHNOCORE_UNAVAILABLE, "technocore.runtime", ResponseClass.UNAVAILABLE, "2026-09-06T05:00:00+00:00"),
        item(ReviewedRuntimeFixtureId.TECHNOCORE_STALE, "technocore.runtime", ResponseClass.AVAILABLE, "2026-09-05T00:00:00+00:00"),
        item(ReviewedRuntimeFixtureId.EXPORT_AVAILABLE, "export.runtime", ResponseClass.AVAILABLE, "2026-09-06T05:00:00+00:00"),
        item(ReviewedRuntimeFixtureId.FAUCET_AVAILABLE, "faucet.runtime", ResponseClass.AVAILABLE, "2026-09-06T05:00:00+00:00"),
        item(ReviewedRuntimeFixtureId.NETWORK_MATCH, "network.identity", ResponseClass.AVAILABLE, "2026-09-06T05:00:00+00:00", "fixture-chain-a", "fixture-rpc-a", "fixture-genesis-a"),
        item(ReviewedRuntimeFixtureId.NETWORK_MISMATCH, "network.identity", ResponseClass.AVAILABLE, "2026-09-06T05:00:00+00:00", "fixture-chain-b", "fixture-rpc-b", "fixture-genesis-b"),
        item(ReviewedRuntimeFixtureId.INFERENCE_AVAILABLE, "inference.runtime", ResponseClass.AVAILABLE, "2026-09-06T05:00:00+00:00"),
        item(ReviewedRuntimeFixtureId.RAIL_AVAILABLE, "rail.runtime", ResponseClass.AVAILABLE, "2026-09-06T05:00:00+00:00"),
        item(ReviewedRuntimeFixtureId.DURABILITY_AVAILABLE, "durability.readback", ResponseClass.AVAILABLE, "2026-09-06T05:00:00+00:00"),
    )
    return MappingProxyType({value.fixture_id: value for value in values})


def _build_runtime_authority(
    probes_input: tuple[ProbeSpec, ...], source_resolver: Callable[[ReviewedSourceId], Any],
) -> tuple[Callable[[ReviewedRuntimeFixtureId], RuntimeCapabilityObservation],
           Callable[[RuntimeCapabilityObservation], _ObservationRecord],
           Callable[[RuntimeCapabilityObservation], Mapping[str, Any]],
           Callable[[], tuple[ProbeSpec, ...]]]:
    proxy, sha256, json_module = MappingProxyType, hashlib.sha256, json
    token_type, fixture_id_type = RuntimeCapabilityObservation, ReviewedRuntimeFixtureId
    observation_type, provenance = _ObservationRecord, Provenance.REVIEWED_LOCAL_FIXTURE
    revision, policy = VERIFIER_REVISION, POLICY_VERSION
    probes = proxy({item.capability_id: item for item in probes_input})
    for probe in probes.values():
        source = source_resolver(probe.source_id)
        if source.method != probe.method or source.redirects != probe.redirects:
            raise RuntimeError("reviewed probe source policy mismatch")
    fixtures = _reviewed_fixtures(probes)
    registry: weakref.WeakKeyDictionary[RuntimeCapabilityObservation, _ObservationRecord] = weakref.WeakKeyDictionary()
    lock = threading.Lock()

    def issue(fixture_id: ReviewedRuntimeFixtureId) -> RuntimeCapabilityObservation:
        if type(fixture_id) is not fixture_id_type:
            raise PermissionError("only a repository-reviewed fixture ID may issue offline evidence")
        fixture = fixtures[fixture_id]
        token = object.__new__(token_type)
        record = observation_type(fixture.capability_id, fixture.domain, fixture.source_id,
            fixture.resource_id, fixture.method, fixture.response_class, fixture.observed_at,
            fixture.payload_sha256, revision, policy, provenance, fixture.observed_chain_id,
            fixture.observed_rpc_identity, fixture.observed_network_identity)
        with lock:
            registry[token] = record
        return token

    def resolve(token: RuntimeCapabilityObservation) -> _ObservationRecord:
        if type(token) is not token_type:
            raise PermissionError("runtime observation authority invalid")
        with lock:
            record = registry.get(token)
        if record is None:
            raise PermissionError("runtime observation belongs to another authority")
        return record

    def project(token: RuntimeCapabilityObservation) -> Mapping[str, Any]:
        record = resolve(token)
        material = json_module.dumps({"capability_id": record.capability_id, "domain": record.domain.value,
            "source_id": record.source_id.value, "resource_id": record.resource_id,
            "method": record.method, "response_class": record.response_class.value,
            "observed_at": record.observed_at.isoformat(), "source_hash": record.source_hash,
            "verifier_revision": record.verifier_revision, "policy_version": record.policy_version,
            "provenance": record.provenance.value, "observed_chain_id": record.observed_chain_id,
            "observed_rpc_identity": record.observed_rpc_identity,
            "observed_network_identity": record.observed_network_identity},
            sort_keys=True, separators=(",", ":")).encode()
        return proxy({"status": "DESCRIPTIVE_ONLY", "authority": "NOT_SERIALIZED",
                      "observation_hash": sha256(material).hexdigest(), **json_module.loads(material.decode())})

    def manifest() -> tuple[ProbeSpec, ...]:
        return tuple(probes.values())
    return issue, resolve, project, manifest


def _build_faucet_transition_service() -> Callable[[FaucetState, str], FaucetState]:
    state_type = FaucetState
    graph = MappingProxyType({
        state_type.NO_OFFICIAL_ENDPOINT: MappingProxyType({"documented": state_type.DOCUMENTED_ENDPOINT}),
        state_type.DOCUMENTED_ENDPOINT: MappingProxyType({"source_reviewed": state_type.REVIEWED_ENDPOINT}),
        state_type.REVIEWED_ENDPOINT: MappingProxyType({"runtime_observed": state_type.RUNTIME_OBSERVED}),
        state_type.RUNTIME_OBSERVED: MappingProxyType({"requirements_verified": state_type.CLAIM_REQUIREMENTS_VERIFIED}),
        state_type.CLAIM_REQUIREMENTS_VERIFIED: MappingProxyType({"request_approval": state_type.READY_FOR_HUMAN_APPROVAL}),
        state_type.READY_FOR_HUMAN_APPROVAL: MappingProxyType({}),
    })
    def transition(state: FaucetState, event: str) -> FaucetState:
        if type(state) is not state_type or not isinstance(event, str):
            raise ValueError("invalid faucet transition input")
        target = graph[state].get(event)
        if target is None:
            raise ValueError("invalid faucet readiness transition")
        return target
    return transition


def _build_readiness_service(
    definitions_input: tuple[CapabilityDefinition, ...],
    resolver: Callable[[RuntimeCapabilityObservation], _ObservationRecord],
    clock: Callable[[], datetime], ttl: timedelta,
) -> tuple[Callable[..., Mapping[str, Any]], Callable[..., dict[str, Any]]]:
    proxy, state, overall, response = MappingProxyType, CapabilityState, OverallState, ResponseClass
    sha256, json_module = hashlib.sha256, json
    domain_type, action_type = Domain, ReadinessAction
    token_type, auth_type = RuntimeCapabilityObservation, ActionAuthorization
    utc, duration = timezone.utc, timedelta
    schema, policy, revision = MANIFEST_SCHEMA, POLICY_VERSION, VERIFIER_REVISION
    required_domains = frozenset({Domain.IDENTITY, Domain.TECHNOCORE, Domain.EXPORT_EVIDENCE,
        Domain.FAUCET, Domain.TESTNET_NETWORK, Domain.INFERENCE, Domain.SETTLEMENT_RAIL,
        Domain.EVIDENCE_DURABILITY})
    action_dependencies = proxy({
        action_type.GENERAL_TESTNET: required_domains,
        action_type.FAUCET_CLAIM: frozenset({Domain.IDENTITY, Domain.TECHNOCORE, Domain.FAUCET, Domain.TESTNET_NETWORK, Domain.EVIDENCE_DURABILITY}),
        action_type.INFERENCE_REQUEST: frozenset({Domain.IDENTITY, Domain.TESTNET_NETWORK, Domain.INFERENCE, Domain.EVIDENCE_DURABILITY}),
        action_type.SETTLEMENT: frozenset({Domain.IDENTITY, Domain.TESTNET_NETWORK, Domain.SETTLEMENT_RAIL, Domain.EVIDENCE_DURABILITY}),
    })
    definitions = tuple(definitions_input)
    configured_domains = frozenset(item.domain for item in definitions if item.critical)
    configuration_valid = bool(definitions) and required_domains <= configured_domains
    if not duration(minutes=1) <= ttl <= duration(days=1):
        raise ValueError("private readiness TTL is outside bounded policy")
    unavailable, observed = response.UNAVAILABLE, state.RUNTIME_OBSERVED
    stale, conflict = state.STALE_RUNTIME_OBSERVATION, state.CONFLICTING_CAPABILITY_EVIDENCE
    missing, runtime_unavailable = state.RUNTIME_NOT_OBSERVED, state.RUNTIME_UNAVAILABLE

    def assess(observations: tuple[RuntimeCapabilityObservation, ...] = (),
               action: ReadinessAction = action_type.GENERAL_TESTNET,
               authorization: ActionAuthorization | None = None) -> Mapping[str, Any]:
        if type(observations) is not tuple or type(action) is not action_type:
            raise TypeError("readiness accepts only opaque observations and a typed action")
        now = clock().astimezone(utc)
        records: dict[str, _ObservationRecord] = {}
        for token in observations:
            if type(token) is not token_type:
                raise PermissionError("descriptive observations carry no authority")
            record = resolver(token)
            prior = records.get(record.capability_id)
            if prior is None or record.observed_at > prior.observed_at:
                records[record.capability_id] = record
        if authorization is not None:
            if type(authorization) is not auth_type:
                raise PermissionError("action authorization authority invalid")
            raise PermissionError("no action-authorization record is configured")
        rows: dict[str, list[dict[str, Any]]] = {item.value: [] for item in domain_type}
        required_for_action = action_dependencies[action]
        critical_rows: list[dict[str, Any]] = []
        for definition in definitions:
            record = records.get(definition.capability_id)
            runtime_status = missing
            observed_at = source_hash = observation_hash = observed_chain = observed_rpc = observed_network = None
            blockers = list(definition.static_blockers)
            if definition.runtime_required:
                if record is None:
                    blockers.append("MISSING_RUNTIME_OBSERVATION")
                else:
                    observed_at, source_hash = record.observed_at.isoformat(), record.source_hash
                    observation_hash = sha256(json_module.dumps({
                        "capability_id": record.capability_id,
                        "domain": record.domain.value,
                        "source_id": record.source_id.value,
                        "resource_id": record.resource_id,
                        "method": record.method,
                        "response_class": record.response_class.value,
                        "observed_at": observed_at,
                        "source_hash": source_hash,
                        "verifier_revision": record.verifier_revision,
                        "policy_version": record.policy_version,
                    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                    observed_chain, observed_rpc = record.observed_chain_id, record.observed_rpc_identity
                    observed_network = record.observed_network_identity
                    age = now - record.observed_at
                    if age < duration(0) or age > ttl:
                        runtime_status, blockers = stale, blockers + ["STALE_RUNTIME_OBSERVATION"]
                    elif record.response_class is unavailable:
                        runtime_status = conflict if definition.documented_status is state.DOCUMENTED_ONLY else runtime_unavailable
                        blockers.append("CONFLICTING_CAPABILITY_EVIDENCE" if runtime_status is conflict else "RUNTIME_UNAVAILABLE")
                    elif definition.domain is domain_type.TESTNET_NETWORK and (
                        definition.documented_chain_id != observed_chain or
                        definition.documented_rpc_identity != observed_rpc or
                        definition.documented_network_identity != observed_network):
                        runtime_status, blockers = conflict, blockers + ["CONFLICTING_CAPABILITY_EVIDENCE", "NETWORK_IDENTITY_MISMATCH"]
                    else:
                        runtime_status = observed
            if definition.implementation_status is state.NOT_IMPLEMENTED:
                blockers.append("IMPLEMENTATION_REQUIRED")
            if definition.source_id is None and definition.runtime_required:
                blockers.append("OFFICIAL_ENDPOINT_UNVERIFIED")
            blockers = list(dict.fromkeys(blockers))
            required = definition.domain in required_for_action
            ready = required and definition.implementation_status is not state.NOT_IMPLEMENTED and (
                not definition.runtime_required or runtime_status is observed) and not blockers
            row = {"capability_id": definition.capability_id, "domain": definition.domain.value,
                "implementation_status": definition.implementation_status.value,
                "documented_status": definition.documented_status.value,
                "runtime_status": runtime_status.value,
                "provenance": record.provenance.value if record else None,
                "source_id": definition.source_id.value if definition.source_id else None,
                "resource_id": record.resource_id if record else None,
                "observed_at": observed_at, "source_hash": source_hash,
                "observation_hash": observation_hash,
                "policy_version": policy, "verifier_revision": revision,
                "blocking_reasons": blockers, "required_for_action": required,
                "ready_to_act": ready, "authorized_to_act": False,
                "documented_chain_id": definition.documented_chain_id,
                "observed_chain_id": observed_chain,
                "documented_rpc_identity": definition.documented_rpc_identity,
                "observed_rpc_identity": observed_rpc,
                "documented_network_identity": definition.documented_network_identity,
                "observed_network_identity": observed_network,
                "testnet_live": (definition.domain is domain_type.TESTNET_NETWORK and ready)}
            rows[definition.domain.value].append(row)
            if required:
                critical_rows.append(row)
        missing_action_domains = required_for_action - frozenset(item.domain for item in definitions)
        config_ok = configuration_valid and not missing_action_domains and bool(critical_rows)
        all_ready = config_ok and all(row["ready_to_act"] for row in critical_rows)
        if not config_ok:
            overall_state = overall.INVALID_CONFIGURATION
        elif any(row["runtime_status"] in {stale.value, conflict.value, runtime_unavailable.value} for row in critical_rows):
            overall_state = overall.BLOCKED
        elif any(row["runtime_status"] == missing.value and next(item for item in definitions if item.capability_id == row["capability_id"]).runtime_required for row in critical_rows):
            overall_state = overall.OBSERVATION_REQUIRED
        elif not all_ready:
            overall_state = overall.HUMAN_REVIEW_REQUIRED
        else:
            overall_state = overall.ACTION_READY
        blockers = sorted({reason for row in critical_rows for reason in row["blocking_reasons"]})
        if not config_ok:
            blockers = sorted(set(blockers) | {"INVALID_CONFIGURATION", "MISSING_CRITICAL_DOMAIN"})
        return proxy({"schema": schema, "status": "DESCRIPTIVE_ONLY", "action": action.value,
            "implementation_readiness": "IMPLEMENTATION_READY" if config_ok else "BLOCKED",
            "live_runtime_readiness": overall_state.value, "overall_state": overall_state.value,
            "ready_to_act": all_ready, "authorized_to_act": False,
            "blocking_reasons": tuple(blockers),
            "domains": proxy({key: tuple(value) for key, value in rows.items()})})

    def project(observations: tuple[RuntimeCapabilityObservation, ...] = (),
                action: ReadinessAction = action_type.GENERAL_TESTNET) -> dict[str, Any]:
        result = assess(observations, action)
        return {"schema": result["schema"], "status": result["status"], "action": result["action"],
            "implementation_readiness": result["implementation_readiness"],
            "live_runtime_readiness": result["live_runtime_readiness"],
            "overall_state": result["overall_state"], "ready_to_act": result["ready_to_act"],
            "authorized_to_act": result["authorized_to_act"],
            "blocking_reasons": list(result["blocking_reasons"]),
            "domains": {key: list(value) for key, value in result["domains"].items()}}
    return assess, project


_PROBES = _probe_definitions()
reviewed_runtime_observation, _resolve_observation, public_observation, probe_manifest = _build_runtime_authority(_PROBES, resolve_reviewed_source)


def _build_clock(datetime_type: type[datetime], utc: timezone) -> Callable[[], datetime]:
    def clock() -> datetime:
        return datetime_type.now(utc)
    return clock


_production_clock = _build_clock(datetime, timezone.utc)
assess_capabilities, capability_manifest = _build_readiness_service(_production_definitions(), _resolve_observation, _production_clock, DEFAULT_OBSERVATION_TTL)
transition_faucet = _build_faucet_transition_service()


def _build_static_catalogs() -> tuple[Callable[[], Mapping[str, Any]], Callable[[], tuple[Mapping[str, str], ...]]]:
    proxy = MappingProxyType
    readiness = proxy({
        "IDENTITY": proxy({"did_exists": "REVIEW_REQUIRED", "public_did_available": "REVIEW_REQUIRED", "local_signer_implemented": True, "signer_context_hardened": True, "capability_binding_ready": True, "backup_status": "REVIEW_REQUIRED", "recovery_drill_status": "REVIEW_REQUIRED", "lossless_signed_identifiers_ready": True}),
        "TECHNOCORE": proxy({"reviewed_source_configured": True, "read_path_implemented": True, "signed_write_implemented": True, "nonce_lossless": True, "raw_frame_gate_ready": True, "evidence_verifier_ready": True, "runtime_reachable": "RUNTIME_NOT_OBSERVED"}),
        "EXPORT_EVIDENCE": proxy({"export_verifier_implemented": True, "export_documented": "DOCUMENTED_ONLY", "export_runtime_observed": "RUNTIME_NOT_OBSERVED", "trusted_acquisition_ready": "IMPLEMENTED_OFFLINE", "completeness_verified": False}),
        "FAUCET": proxy({"state": "DOCUMENTED_ENDPOINT", "runtime": "RUNTIME_NOT_OBSERVED", "requirements": "REVIEW_REQUIRED", "human_approval": "REQUIRED", "authorized": False}),
        "TESTNET_NETWORK": proxy({"documented_chain_id": None, "observed_chain_id": None, "documented_rpc_identity": None, "observed_rpc_identity": None, "documented_network_identity": None, "observed_network_identity": None, "testnet_live": False}),
        "INFERENCE": proxy({"runtime": "RUNTIME_NOT_OBSERVED", "request_schema_reviewed": False, "authentication_model_reviewed": False, "cost_spend_semantics_reviewed": False, "evidence_capture_ready": True, "useful_workload_ready": True}),
        "SETTLEMENT_RAIL": proxy({"rail_adapter_implemented": True, "runtime_rail_observed": False, "rail_crypto_verifier_ready": True, "paperrail_protocol_valid": True, "economic_value_verified": False}),
        "EVIDENCE_DURABILITY": proxy({"write_path_implemented": True, "runtime_write_authorized": False, "readback_verifier_ready": True, "runtime_readback_observed": False}),
        "DELEGATION_VERIFICATION": proxy({"delegation_verifier_implemented": True, "delegation_documented": "DOCUMENTED_ONLY", "delegation_runtime_observed": False, "lossless_delegation_nonce_ready": True, "root_key_local_only": True, "delegation_ready": False}),
        "TOOL_OUTPUT_BUDGET": proxy({"policy_scope": "LOCAL_SAFETY_LAYER", "max_records": 200, "max_bytes": 2097152, "max_estimated_tokens": 131072, "framing": "UNTRUSTED_CONTENT", "auto_fetch": False, "auto_action": False}),
        "REPLAY_SAFETY": proxy({"replay_ledger_implemented": False, "side_effect_journal_implemented": False, "lossless_signed_identifiers_ready": True}),
        "ACTIVITY_QUALITY": proxy({"protocol_decoder_ready": False, "normalized_repeat_detector_ready": False, "fleet_signal_detector_ready": False, "independent_counterparty_metric_ready": False, "economic_value_classifier_ready": False, "person_identity_claimed": False}),
        "PROTOCOL_MODEL": proxy({"agreement": "GENERIC_MODEL_READY", "transfer_attempt": "GENERIC_MODEL_READY", "rail_observation": "GENERIC_MODEL_READY", "tclk_2": "UPSTREAM_VERSION_NOT_FINALIZED", "ptlc": "EXPERIMENTAL_UNEXERCISED", "owned_room_auth": "INSUFFICIENT_AS_SOLE_AUTH_EVIDENCE", "remote_mcp_key_custody": False}),
        "RUNTIME_DRIFT": proxy({"release": "RELEASE_REPORTED", "main": "MAIN_REPORTED", "live_doc": "LIVE_DOC_REPORTED", "runtime": "RUNTIME_NOT_OBSERVED", "config_surface": "FUTURE_REVIEWED_RUNTIME_SOURCE", "mutable_values": ("DOCUMENTED_VALUE", "RUNTIME_OBSERVED_VALUE", "STALE_RUNTIME_VALUE", "CONFLICTING_VALUE")}),
    })
    workloads = tuple(proxy(item) for item in (
        {"workload_id": "scam-faucet-detection", "purpose": "detect fake faucet and wallet prompts", "mode": "OFFLINE_FIXTURE"},
        {"workload_id": "technocore-intelligence", "purpose": "summarize reviewed public metadata", "mode": "OFFLINE_FIXTURE"},
        {"workload_id": "evidence-verification", "purpose": "verify evidence integrity and provenance", "mode": "OFFLINE_FIXTURE"},
        {"workload_id": "agent-collaboration-verification", "purpose": "verify bounded collaboration artifacts", "mode": "OFFLINE_FIXTURE"},
        {"workload_id": "ecosystem-intelligence", "purpose": "classify reviewed ecosystem evidence", "mode": "OFFLINE_FIXTURE"},
    ))
    def get_readiness() -> Mapping[str, Any]: return readiness
    def get_workloads() -> tuple[Mapping[str, str], ...]: return workloads
    return get_readiness, get_workloads


domain_readiness, workload_catalog = _build_static_catalogs()
SECURITY_DEPENDENCY_CAPTURE = MappingProxyType({
    "runtime issuer": "closure: fixed fixture enum, fixed records, source-validated probes, registry",
    "observation validator": "closure: exact token type and same weak registry",
    "staleness evaluator": "closure: fixed TTL, clock, UTC and duration type",
    "conflict evaluator": "closure: captured response/state/domain enums and identity comparison",
    "aggregator": "closure: immutable definitions, required domains and action dependencies",
    "Faucet transition evaluator": "closure: nested immutable graph and state enum",
    "action authority validator": "closure: exact opaque type; intentionally no issuer",
    "schema projection": "closure: captured assessor and fixed output keys",
})
