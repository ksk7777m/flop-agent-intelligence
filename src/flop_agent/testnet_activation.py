"""Offline Testnet activation interfaces and inference-evidence models.

There is deliberately no network client, endpoint input, signer, wallet key,
effect callback, approval issuer, or live adapter in this module.  Serialized
values are descriptive only and never recreate runtime or action authority.
"""
from __future__ import annotations

import hashlib
import re
import weakref
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

SCHEMA_VERSION = "flop-testnet-activation-v1"
POLICY_VERSION = "testnet-activation-safety-policy-v1"
UNRESOLVED_ENDPOINT = "UNRESOLVED_OFFICIAL_ENDPOINT"
UNRESOLVED_VALUE = "UNRESOLVED_OFFICIAL_VALUE"
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
_HASH = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
_GENERATION_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
_SECRET = re.compile(r"(?:private.?key|secret|seed|mnemonic|session.?key)", re.I)
_EVIDENCE_REFERENCE_FIELDS = frozenset({"acquisition_id", "snapshot_hash", "transport",
    "completeness", "generation", "first_seq", "last_seq", "gap_status",
    "acquisition_source"})
_ACTIVATION_PROJECTION_FIELDS = frozenset({"schema", "status", "content_label",
    "evidence_id", "state", "session_id_reference", "provider_id",
    "provider_identity_verified", "model_name", "model_hash", "measured_root",
    "runtime_model_identity_observed", "raw_request_hash", "raw_response_hash",
    "normalized_result_hash", "escrow_amount", "settled_amount", "compute_units",
    "receipt_hash", "receipt_signature_verified", "settlement_identity",
    "settlement_verified", "evidence_complete", "airdrop_scoring",
    "airdrop_eligibility_verified", "activity_class", "captured_at",
    "evidence_transport_reference", "policy_version"})


class ActivationError(ValueError):
    def __init__(self, code: str, field: str, value: Any = None):
        super().__init__(f"{code}: {field}")
        self.code = code
        self.metadata = MappingProxyType({"field": field,
                                          "type": type(value).__name__,
                                          "length": _safe_len(value)})


def _safe_len(value: Any) -> int | None:
    try:
        return len(value)
    except (TypeError, OverflowError):
        return None


class ActivationState(str, Enum):
    NO_OFFICIAL_RUNTIME = "NO_OFFICIAL_RUNTIME"
    DOCUMENTED_RUNTIME = "DOCUMENTED_RUNTIME"
    REVIEWED_RUNTIME = "REVIEWED_RUNTIME"
    RUNTIME_OBSERVED = "RUNTIME_OBSERVED"
    IDENTITY_READY = "IDENTITY_READY"
    WALLET_READY = "WALLET_READY"
    FAUCET_REQUIREMENTS_VERIFIED = "FAUCET_REQUIREMENTS_VERIFIED"
    INFERENCE_REQUIREMENTS_VERIFIED = "INFERENCE_REQUIREMENTS_VERIFIED"
    EVIDENCE_PATH_READY = "EVIDENCE_PATH_READY"
    READY_FOR_HUMAN_APPROVAL = "READY_FOR_HUMAN_APPROVAL"
    AUTHORIZED_TO_ACT = "AUTHORIZED_TO_ACT"


class CapabilityState(str, Enum):
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    IMPLEMENTED_DISABLED = "IMPLEMENTED_DISABLED"
    DOCUMENTED = "DOCUMENTED"
    RUNTIME_OBSERVED = "RUNTIME_OBSERVED"
    READY_FOR_APPROVAL = "READY_FOR_APPROVAL"
    AUTHORIZED = "AUTHORIZED"


class SourceClass(str, Enum):
    RATIFIED_PROTOCOL_PARAM = "RATIFIED_PROTOCOL_PARAM"
    RELEASE_REPORTED = "RELEASE_REPORTED"
    MAIN_REPORTED = "MAIN_REPORTED"
    LIVE_DOC_REPORTED = "LIVE_DOC_REPORTED"
    RUNTIME_OBSERVED = "RUNTIME_OBSERVED"
    WORKBOOK_DRAFT = "WORKBOOK_DRAFT"
    COMMUNITY_CLAIM = "COMMUNITY_CLAIM"


class RatificationStatus(str, Enum):
    RATIFIED = "RATIFIED"
    PROVISIONAL = "PROVISIONAL"
    UNRATIFIED = "UNRATIFIED"
    CONFLICTING_OFFICIAL_MATERIAL = "CONFLICTING_OFFICIAL_MATERIAL"


class LedgerState(str, Enum):
    OBSERVED = "OBSERVED"
    REQUEST_PREPARED = "REQUEST_PREPARED"
    SESSION_OBSERVED = "SESSION_OBSERVED"
    USAGE_OBSERVED = "USAGE_OBSERVED"
    RECEIPT_OBSERVED = "RECEIPT_OBSERVED"
    RECEIPT_VERIFIED = "RECEIPT_VERIFIED"
    SETTLEMENT_OBSERVED = "SETTLEMENT_OBSERVED"
    SETTLEMENT_VERIFIED = "SETTLEMENT_VERIFIED"
    EVIDENCE_COMPLETE = "EVIDENCE_COMPLETE"
    EVIDENCE_INCOMPLETE = "EVIDENCE_INCOMPLETE"


class ActivityClass(str, Enum):
    USEFUL_INFERENCE = "USEFUL_INFERENCE"
    UNKNOWN_UTILITY = "UNKNOWN_UTILITY"
    SELF_REFERENTIAL = "SELF_REFERENTIAL"


class EffectOutcome(str, Enum):
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    EFFECT_OUTCOME_UNKNOWN = "EFFECT_OUTCOME_UNKNOWN"


@dataclass(frozen=True)
class ParameterEvidence:
    name: str
    value: str
    source_class: SourceClass
    source_reference: str
    observed_at: str
    ratification_status: RatificationStatus
    protocol_version: str

    def public_projection(self) -> Mapping[str, Any]:
        return MappingProxyType({"status": "DESCRIPTIVE_ONLY", "name": self.name,
            "value": self.value, "source_class": self.source_class.value,
            "source_reference": self.source_reference, "observed_at": self.observed_at,
            "ratification_status": self.ratification_status.value,
            "protocol_version": self.protocol_version})


@dataclass(frozen=True)
class ParameterAssessment:
    name: str
    status: RatificationStatus
    observations: tuple[ParameterEvidence, ...]

    def public_projection(self) -> Mapping[str, Any]:
        return MappingProxyType({"status": "DESCRIPTIVE_ONLY", "parameter": self.name,
            "assessment": self.status.value,
            "observations": [dict(item.public_projection()) for item in self.observations]})


@dataclass(frozen=True)
class NetworkIdentityEvidence:
    chain_id: str | None
    genesis_identity: str | None
    rpc_identity: str | None
    protocol_version: str | None
    source_class: SourceClass

    def public_projection(self) -> Mapping[str, Any]:
        complete = all(value is not None for value in (self.chain_id, self.genesis_identity,
                                                       self.rpc_identity, self.protocol_version))
        return MappingProxyType({"status": "DESCRIPTIVE_ONLY",
            "assessment": "MATCHING_DESCRIPTIVE_EVIDENCE" if complete else "UNRESOLVED",
            "chain_id": self.chain_id, "genesis_identity": self.genesis_identity,
            "rpc_identity": self.rpc_identity, "protocol_version": self.protocol_version,
            "source_class": self.source_class.value, "runtime_observed": False,
            "ready_to_act": False, "authorized_to_act": False})


@dataclass(frozen=True)
class EvidenceTransportReference:
    acquisition_id: str
    snapshot_hash: str
    transport: str
    completeness: str
    generation: str | None
    first_seq: int | None
    last_seq: int | None
    gap_status: str
    acquisition_source: str

    def __post_init__(self) -> None:
        if (not isinstance(self.acquisition_id, str)
                or not isinstance(self.snapshot_hash, str)
                or _HASH.fullmatch(self.acquisition_id) is None
                or _HASH.fullmatch(self.snapshot_hash) is None):
            raise ActivationError("EVIDENCE_REFERENCE_INVALID", "hash")
        if (not isinstance(self.transport, str)
                or self.transport not in {"MCP_PAGE", "ROOM_EXPORT", "ROOM_DIRECT_READ",
                "DISCOVERY_SNAPSHOT", "LOCAL_ARCHIVE", "FUTURE_EVENT_FEED"}):
            raise ActivationError("EVIDENCE_REFERENCE_INVALID", "transport")
        if (not isinstance(self.completeness, str)
                or self.completeness not in {"COMPLETE_VERIFIED", "PARTIAL", "UNKNOWN",
                                             "CONFLICTING"}):
            raise ActivationError("EVIDENCE_REFERENCE_INVALID", "completeness")
        if (self.generation is not None
                and (not isinstance(self.generation, str)
                     or _GENERATION_ID.fullmatch(self.generation) is None)):
            raise ActivationError("EVIDENCE_REFERENCE_INVALID", "generation")
        for name, value in (("first_seq", self.first_seq), ("last_seq", self.last_seq)):
            if value is not None and (isinstance(value, bool) or not isinstance(value, int)
                                      or value < 0):
                raise ActivationError("EVIDENCE_REFERENCE_INVALID", name)
        if (not isinstance(self.gap_status, str)
                or self.gap_status not in {"NO_GAP_OBSERVED", "GAP_UNRESOLVED", "HISTORY_GAP",
                                           "RETENTION_LOSS_CONFIRMED"}):
            raise ActivationError("EVIDENCE_REFERENCE_INVALID", "gap_status")
        if (not isinstance(self.acquisition_source, str)
                or self.acquisition_source not in {"DIRECT_REVIEWED_SOURCE", "THIRD_PARTY_MIRROR",
                                                    "LOCAL_ARCHIVE"}):
            raise ActivationError("EVIDENCE_REFERENCE_INVALID", "acquisition_source")
        if (self.first_seq is not None and self.last_seq is not None
                and self.first_seq > self.last_seq):
            raise ActivationError("EVIDENCE_REFERENCE_INVALID", "sequence_range")

    def public_projection(self) -> Mapping[str, Any]:
        return MappingProxyType({"acquisition_id": self.acquisition_id,
            "snapshot_hash": self.snapshot_hash, "transport": self.transport,
            "completeness": self.completeness, "generation": self.generation,
            "first_seq": self.first_seq, "last_seq": self.last_seq,
            "gap_status": self.gap_status, "acquisition_source": self.acquisition_source})


@dataclass(frozen=True)
class InferenceEvidence:
    evidence_id: str
    state: LedgerState
    session_id_reference: str | None
    provider_id: str | None
    provider_identity_verified: bool
    model_name: str | None
    model_hash: str | None
    measured_root: str | None
    runtime_model_identity_observed: bool
    raw_request_hash: str | None
    raw_response_hash: str | None
    normalized_result_hash: str | None
    escrow_amount: str | None
    settled_amount: str | None
    compute_units: str | None
    receipt_hash: str | None
    receipt_signature_verified: bool
    settlement_identity: str | None
    settlement_verified: bool
    evidence_complete: bool
    activity_class: ActivityClass
    captured_at: str
    evidence_transport_reference: EvidenceTransportReference | None

    def __post_init__(self) -> None:
        if (self.evidence_transport_reference is not None
                and type(self.evidence_transport_reference) is not EvidenceTransportReference):
            raise ActivationError("EVIDENCE_REFERENCE_INVALID", "evidence_transport_reference")

    def public_projection(self) -> Mapping[str, Any]:
        return MappingProxyType({"schema": "flop-testnet-activation-v1",
            "status": "DESCRIPTIVE_ONLY", "content_label": "UNTRUSTED_CONTENT",
            "evidence_id": self.evidence_id, "state": "EVIDENCE_INCOMPLETE",
            "session_id_reference": self.session_id_reference,
            "provider_id": self.provider_id,
            "provider_identity_verified": False,
            "model_name": self.model_name, "model_hash": self.model_hash,
            "measured_root": self.measured_root,
            "runtime_model_identity_observed": False,
            "raw_request_hash": self.raw_request_hash,
            "raw_response_hash": self.raw_response_hash,
            "normalized_result_hash": self.normalized_result_hash,
            "escrow_amount": self.escrow_amount, "settled_amount": self.settled_amount,
            "compute_units": self.compute_units, "receipt_hash": self.receipt_hash,
            "receipt_signature_verified": False,
            "settlement_identity": self.settlement_identity,
            "settlement_verified": False,
            "evidence_complete": False,
            "airdrop_scoring": "AIRDROP_SCORING_UNRESOLVED",
            "airdrop_eligibility_verified": False,
            "activity_class": self.activity_class.value,
            "captured_at": self.captured_at,
            "evidence_transport_reference": (dict(self.evidence_transport_reference.public_projection())
                if self.evidence_transport_reference is not None else None),
            "policy_version": "testnet-activation-safety-policy-v1"})


class _SealedInterface:
    __slots__ = ()
    def __new__(cls, *_args: Any, **_kwargs: Any) -> "_SealedInterface":
        raise PermissionError("use the sealed offline Testnet activation service")
    def __setattr__(self, _name: str, _value: Any) -> None:
        raise PermissionError("sealed Testnet interfaces cannot be rebound")
    def __copy__(self) -> Any:
        raise TypeError("sealed Testnet interfaces cannot be copied")
    def __deepcopy__(self, _memo: Any) -> Any:
        raise TypeError("sealed Testnet interfaces cannot be copied")
    def __reduce__(self) -> Any:
        raise TypeError("sealed Testnet interfaces cannot be serialized")


class FaucetAdapter(_SealedInterface):
    __slots__ = ("_describe",)
    def discover_requirements(self) -> Mapping[str, Any]: return self._describe("FAUCET")
    def validate_network(self) -> Mapping[str, Any]: return self._describe("FAUCET_NETWORK")
    def prepare_claim_request(self) -> Mapping[str, Any]: return self._describe("FAUCET_CLAIM")
    def inspect_receipt(self, raw: bytes) -> Mapping[str, Any]: return self._describe("FAUCET_RECEIPT", raw)
    def read_back_claim(self) -> Mapping[str, Any]: return self._describe("FAUCET_READBACK")


class AgentWalletAdapter(_SealedInterface):
    __slots__ = ("_describe",)
    def get_identity(self) -> Mapping[str, Any]: return self._describe("WALLET_IDENTITY")
    def get_network(self) -> Mapping[str, Any]: return self._describe("WALLET_NETWORK")
    def get_balance(self) -> Mapping[str, Any]: return self._describe("WALLET_BALANCE")
    def prepare_stake(self) -> Mapping[str, Any]: return self._describe("WALLET_STAKE")
    def prepare_escrow(self) -> Mapping[str, Any]: return self._describe("WALLET_ESCROW")
    def prepare_transaction(self) -> Mapping[str, Any]: return self._describe("WALLET_TRANSACTION")


class InferenceSessionAdapter(_SealedInterface):
    __slots__ = ("_describe",)
    def discover_requirements(self) -> Mapping[str, Any]: return self._describe("INFERENCE")
    def validate_provider(self) -> Mapping[str, Any]: return self._describe("PROVIDER")
    def prepare_session(self) -> Mapping[str, Any]: return self._describe("INFERENCE_SESSION")
    def prepare_request(self) -> Mapping[str, Any]: return self._describe("INFERENCE_REQUEST")
    def inspect_usage(self, raw: bytes) -> Mapping[str, Any]: return self._describe("INFERENCE_USAGE", raw)
    def inspect_receipt(self, raw: bytes) -> Mapping[str, Any]: return self._describe("INFERENCE_RECEIPT", raw)
    def inspect_settlement(self, raw: bytes) -> Mapping[str, Any]: return self._describe("SETTLEMENT", raw)


class UsageReceiptAdapter(_SealedInterface):
    __slots__ = ("_describe",)
    def discover_format(self) -> Mapping[str, Any]: return self._describe("USAGE_RECEIPT_FORMAT")
    def inspect_receipt(self, raw: bytes) -> Mapping[str, Any]: return self._describe("USAGE_RECEIPT", raw)
    def verify_signature(self, raw: bytes) -> Mapping[str, Any]: return self._describe("RECEIPT_SIGNATURE", raw)
    def verify_settlement(self, raw: bytes) -> Mapping[str, Any]: return self._describe("RECEIPT_SETTLEMENT", raw)


class TestnetInferenceEvidenceLedger(_SealedInterface):
    __slots__ = ("_record", "_project")
    def record_observation(self, **fields: Any) -> InferenceEvidence: return self._record(fields)
    def public_projection(self, evidence: InferenceEvidence) -> Mapping[str, Any]: return self._project(evidence)


TestnetEvidenceLedger = TestnetInferenceEvidenceLedger


def validate_activation_projection(value: Mapping[str, Any]) -> tuple[str, ...]:
    """Reject semantic promotion in descriptive Testnet evidence."""
    errors: list[str] = []
    if not isinstance(value, Mapping):
        return ("ACTIVATION_PROJECTION_OBJECT_REQUIRED",)
    if set(value) != _ACTIVATION_PROJECTION_FIELDS:
        errors.append("ACTIVATION_PROJECTION_CLOSED_FIELDS_REQUIRED")
    if value.get("status") != "DESCRIPTIVE_ONLY": errors.append("DESCRIPTIVE_STATUS_REQUIRED")
    if value.get("receipt_signature_verified") is True: errors.append("RECEIPT_VERIFIER_UNAVAILABLE")
    if value.get("settlement_verified") is True: errors.append("SETTLEMENT_VERIFIER_UNAVAILABLE")
    if value.get("evidence_complete") is True: errors.append("EVIDENCE_COMPLETENESS_NOT_PROVEN")
    if value.get("airdrop_eligibility_verified") is True: errors.append("AIRDROP_ELIGIBILITY_UNRESOLVED")
    if value.get("authorized_to_act") is True: errors.append("ACTION_AUTHORITY_UNAVAILABLE")
    if value.get("runtime_observed") is True: errors.append("RUNTIME_OBSERVATION_UNAVAILABLE")
    if value.get("ready_to_act") is True: errors.append("RUNTIME_READINESS_UNAVAILABLE")
    if value.get("paper_rail_value_settlement_verified") is True:
        errors.append("PAPER_RAIL_IS_NOT_VALUE_SETTLEMENT")
    reference = value.get("evidence_transport_reference")
    if reference is not None and (not isinstance(reference, Mapping)
                                  or set(reference) != _EVIDENCE_REFERENCE_FIELDS):
        errors.append("EVIDENCE_REFERENCE_CLOSED_FIELDS_REQUIRED")
    elif reference is not None:
        try:
            EvidenceTransportReference(**{field: reference[field]
                for field in _EVIDENCE_REFERENCE_FIELDS})
        except (ActivationError, KeyError, TypeError):
            errors.append("EVIDENCE_REFERENCE_INVALID")
    return tuple(sorted(set(errors)))


def _bootstrap() -> tuple[Any, Any]:
    hash_type, id_type, decimal_type, secret_type = _HASH, _ID, _DECIMAL, _SECRET
    reference_fields = _EVIDENCE_REFERENCE_FIELDS
    sha256, proxy = hashlib.sha256, MappingProxyType
    error_type, bytes_type, mapping_type = ActivationError, bytes, Mapping
    evidence_type, reference_type = InferenceEvidence, EvidenceTransportReference
    state_type, activity_type = LedgerState, ActivityClass
    policy_version, schema_version, max_bytes = POLICY_VERSION, SCHEMA_VERSION, MAX_EVIDENCE_BYTES
    disabled_state = CapabilityState.IMPLEMENTED_DISABLED.value
    no_effect = EffectOutcome.NOT_ATTEMPTED.value
    issued: dict[int, weakref.ReferenceType[InferenceEvidence]] = {}

    def exact_bytes(raw: bytes) -> str:
        if not isinstance(raw, bytes_type) or len(raw) > max_bytes:
            raise error_type("EVIDENCE_BYTES_INVALID", "raw", raw)
        return sha256(raw).hexdigest()

    def describe(kind: str, raw: bytes | None = None) -> Mapping[str, Any]:
        if raw is not None: exact_hash = exact_bytes(raw)
        else: exact_hash = None
        return proxy({"schema": schema_version, "status": "DESCRIPTIVE_ONLY",
            "content_label": "UNTRUSTED_CONTENT", "capability": kind,
            "capability_state": disabled_state,
            "official_endpoint": UNRESOLVED_ENDPOINT,
            "runtime_observed": False, "ready_to_act": False,
            "authorized_to_act": False, "exact_raw_hash": exact_hash,
            "effect_outcome": no_effect,
            "replay_required_for_future_effect": True,
            "human_approval_issuer_configured": False,
            "live_action_enabled": False, "policy_version": policy_version})

    def clean_optional(name: str, value: Any, pattern: Any = id_type) -> str | None:
        if value is None: return None
        if not isinstance(value, str) or pattern.fullmatch(value) is None:
            raise error_type("FIELD_INVALID", name, value)
        return value

    def amount(name: str, value: Any) -> str | None:
        if value is None: return None
        if not isinstance(value, str) or decimal_type.fullmatch(value) is None:
            raise error_type("EXACT_DECIMAL_REQUIRED", name, value)
        return value

    def record(fields: Mapping[str, Any]) -> InferenceEvidence:
        allowed = {"session_id_reference", "provider_id", "model_name", "model_hash",
            "measured_root", "raw_request", "raw_response", "normalized_result_hash",
            "escrow_amount", "settled_amount", "compute_units", "receipt_raw",
            "settlement_identity", "activity_class", "captured_at",
            "evidence_transport_reference"}
        if set(fields) - allowed:
            if any(isinstance(name, str) and secret_type.search(name)
                   for name in set(fields) - allowed):
                raise error_type("SECRET_INPUT_REJECTED", "input_field")
            raise error_type("FIELD_NOT_ALLOWED", "input_field")
        for name in fields:
            if isinstance(name, str) and secret_type.search(name):
                raise error_type("SECRET_INPUT_REJECTED", "input_field")
        captured = clean_optional("captured_at", fields.get("captured_at"))
        if captured is None: raise error_type("FIELD_REQUIRED", "captured_at")
        activity = fields.get("activity_class", activity_type.UNKNOWN_UTILITY)
        if not isinstance(activity, activity_type): raise error_type("ENUM_INVALID", "activity_class", activity)
        transport = fields.get("evidence_transport_reference")
        if transport is not None:
            if not isinstance(transport, mapping_type) or transport.get("status") != "DESCRIPTIVE_ONLY":
                raise error_type("EVIDENCE_REFERENCE_INVALID", "evidence_transport_reference")
            if set(transport) != reference_fields | {"status"}:
                raise error_type("EVIDENCE_REFERENCE_CLOSED_FIELDS_REQUIRED",
                                 "evidence_transport_reference")
            transport = reference_type(transport.get("acquisition_id"),
                transport.get("snapshot_hash"), transport.get("transport"),
                transport.get("completeness"), transport.get("generation"),
                transport.get("first_seq"), transport.get("last_seq"),
                transport.get("gap_status"), transport.get("acquisition_source"))
        raw_request = fields.get("raw_request"); raw_response = fields.get("raw_response")
        receipt_raw = fields.get("receipt_raw")
        request_hash = exact_bytes(raw_request) if raw_request is not None else None
        response_hash = exact_bytes(raw_response) if raw_response is not None else None
        receipt_hash = exact_bytes(receipt_raw) if receipt_raw is not None else None
        values = {"session_id_reference": clean_optional("session_id_reference", fields.get("session_id_reference")),
            "provider_id": clean_optional("provider_id", fields.get("provider_id")),
            "model_name": clean_optional("model_name", fields.get("model_name")),
            "model_hash": clean_optional("model_hash", fields.get("model_hash"), hash_type),
            "measured_root": clean_optional("measured_root", fields.get("measured_root"), hash_type),
            "normalized_result_hash": clean_optional("normalized_result_hash", fields.get("normalized_result_hash"), hash_type),
            "settlement_identity": clean_optional("settlement_identity", fields.get("settlement_identity"))}
        canonical = "|".join(str(item) for item in (values["session_id_reference"],
            values["provider_id"], values["model_hash"], request_hash, response_hash,
            receipt_hash, captured)).encode("utf-8")
        evidence = evidence_type(sha256(canonical).hexdigest(), state_type.EVIDENCE_INCOMPLETE,
            values["session_id_reference"], values["provider_id"], False,
            values["model_name"], values["model_hash"], values["measured_root"], False,
            request_hash, response_hash, values["normalized_result_hash"],
            amount("escrow_amount", fields.get("escrow_amount")),
            amount("settled_amount", fields.get("settled_amount")),
            amount("compute_units", fields.get("compute_units")), receipt_hash, False,
            values["settlement_identity"], False, False, activity, captured, transport)
        identity = id(evidence)
        issued[identity] = weakref.ref(evidence, lambda _ref, key=identity: issued.pop(key, None))
        return evidence

    def safe_project(evidence: InferenceEvidence) -> Mapping[str, Any]:
        reference = evidence.evidence_transport_reference
        projected_reference = (None if reference is None else {
            "acquisition_id": reference.acquisition_id,
            "snapshot_hash": reference.snapshot_hash, "transport": reference.transport,
            "completeness": reference.completeness, "generation": reference.generation,
            "first_seq": reference.first_seq, "last_seq": reference.last_seq,
            "gap_status": reference.gap_status,
            "acquisition_source": reference.acquisition_source})
        return proxy({"schema": schema_version, "status": "DESCRIPTIVE_ONLY",
            "content_label": "UNTRUSTED_CONTENT", "evidence_id": evidence.evidence_id,
            "state": "EVIDENCE_INCOMPLETE", "session_id_reference": evidence.session_id_reference,
            "provider_id": evidence.provider_id, "provider_identity_verified": False,
            "model_name": evidence.model_name, "model_hash": evidence.model_hash,
            "measured_root": evidence.measured_root, "runtime_model_identity_observed": False,
            "raw_request_hash": evidence.raw_request_hash,
            "raw_response_hash": evidence.raw_response_hash,
            "normalized_result_hash": evidence.normalized_result_hash,
            "escrow_amount": evidence.escrow_amount, "settled_amount": evidence.settled_amount,
            "compute_units": evidence.compute_units, "receipt_hash": evidence.receipt_hash,
            "receipt_signature_verified": False,
            "settlement_identity": evidence.settlement_identity,
            "settlement_verified": False, "evidence_complete": False,
            "airdrop_scoring": "AIRDROP_SCORING_UNRESOLVED",
            "airdrop_eligibility_verified": False,
            "activity_class": evidence.activity_class.value,
            "captured_at": evidence.captured_at,
            "evidence_transport_reference": projected_reference,
            "policy_version": policy_version})

    def project(evidence: InferenceEvidence) -> Mapping[str, Any]:
        reference = issued.get(id(evidence))
        if reference is None or reference() is not evidence:
            raise PermissionError("caller-created inference evidence has no ledger authority")
        return safe_project(evidence)

    def create_interfaces() -> Mapping[str, Any]:
        result: dict[str, Any] = {}
        for name, interface in (("faucet", FaucetAdapter), ("wallet", AgentWalletAdapter),
                                ("inference", InferenceSessionAdapter),
                                ("usage_receipt", UsageReceiptAdapter)):
            item = object.__new__(interface)
            object.__setattr__(item, "_describe", describe)
            result[name] = item
        ledger = object.__new__(TestnetInferenceEvidenceLedger)
        object.__setattr__(ledger, "_record", record)
        object.__setattr__(ledger, "_project", project)
        result["evidence_ledger"] = ledger
        return proxy(result)

    status = proxy({"schema": schema_version, "status": "DESCRIPTIVE_ONLY",
        "activation_state": ActivationState.NO_OFFICIAL_RUNTIME.value,
        "network_endpoint": UNRESOLVED_ENDPOINT, "chain_id": UNRESOLVED_VALUE,
        "network_identity": UNRESOLVED_VALUE, "rpc_endpoint": UNRESOLVED_ENDPOINT,
        "faucet_endpoint": UNRESOLVED_ENDPOINT, "faucet_schema": UNRESOLVED_VALUE,
        "faucet_eligibility": UNRESOLVED_VALUE, "faucet_limits": UNRESOLVED_VALUE,
        "wallet_onboarding": UNRESOLVED_VALUE, "wallet_account_type": UNRESOLVED_VALUE,
        "agent_did": UNRESOLVED_VALUE, "agent_identity_stake": UNRESOLVED_VALUE,
        "identity_contract": UNRESOLVED_VALUE, "session_key_policy": UNRESOLVED_VALUE,
        "owner_revocation_model": UNRESOLVED_VALUE,
        "inference_endpoint": UNRESOLVED_ENDPOINT, "inference_schema": UNRESOLVED_VALUE,
        "inference_auth": UNRESOLVED_VALUE, "inference_pricing": UNRESOLVED_VALUE,
        "session_semantics": UNRESOLVED_VALUE, "escrow_semantics": UNRESOLVED_VALUE,
        "settlement_semantics": UNRESOLVED_VALUE, "usage_receipt_format": UNRESOLVED_VALUE,
        "provider_identity_format": UNRESOLVED_VALUE,
        "receipt_signature_verification": UNRESOLVED_VALUE,
        "claim_path": UNRESOLVED_VALUE, "allocation_conversion": UNRESOLVED_VALUE,
        "allocation_snapshot": UNRESOLVED_VALUE,
        "airdrop_scoring": "AIRDROP_SCORING_UNRESOLVED",
        "airdrop_eligibility_verified": False,
        "testnet_adapter_interfaces_implemented": True,
        "inference_evidence_ledger_implemented": True,
        "runtime_observed": False, "ready_to_act": False, "authorized_to_act": False,
        "receipt_verifier_available": False, "settlement_verifier_available": False,
        "network_identity_verifier_available": False,
        "provider_identity_verifier_available": False,
        "replay_required_for_future_effect": True,
        "evidence_completeness_required": True,
        "human_approval_issuer_configured": False, "live_action_enabled": False,
        "policy_version": policy_version})
    return status, create_interfaces


activation_status, _create_offline_interfaces = _bootstrap()
offline_interfaces = _create_offline_interfaces()
del _create_offline_interfaces


def assess_parameter_evidence(name: str,
                              observations: tuple[ParameterEvidence, ...]) -> ParameterAssessment:
    """Preserve disagreements; never promote drafts or pick a favorable value."""
    if not isinstance(name, str) or _ID.fullmatch(name) is None or not observations:
        raise ActivationError("PARAMETER_EVIDENCE_INVALID", "name/observations")
    if any(not isinstance(item, ParameterEvidence) or item.name != name for item in observations):
        raise ActivationError("PARAMETER_EVIDENCE_INVALID", "observations")
    official = tuple(item for item in observations if item.source_class not in
        (SourceClass.WORKBOOK_DRAFT, SourceClass.COMMUNITY_CLAIM))
    values = {item.value for item in official}
    if len(values) > 1:
        status = RatificationStatus.CONFLICTING_OFFICIAL_MATERIAL
    elif len(official) == 1 and official[0].source_class is SourceClass.RATIFIED_PROTOCOL_PARAM \
            and official[0].ratification_status is RatificationStatus.RATIFIED:
        status = RatificationStatus.RATIFIED
    else:
        status = RatificationStatus.UNRATIFIED
    return ParameterAssessment(name, status, observations)


def unknown_faucet_outcome(submitted: bool, response_received: bool) -> EffectOutcome:
    if submitted and not response_received: return EffectOutcome.EFFECT_OUTCOME_UNKNOWN
    return EffectOutcome.NOT_ATTEMPTED


def assess_network_identity(
        observations: tuple[NetworkIdentityEvidence, ...]) -> Mapping[str, Any]:
    """Require the full network tuple and preserve any mismatch."""
    if not observations or any(not isinstance(item, NetworkIdentityEvidence)
                               for item in observations):
        raise ActivationError("NETWORK_EVIDENCE_INVALID", "observations")
    identities = {(item.chain_id, item.genesis_identity, item.rpc_identity,
                   item.protocol_version) for item in observations}
    unresolved = any(None in identity for identity in identities)
    assessment = ("CONFLICTING_CAPABILITY_EVIDENCE" if len(identities) > 1 else
                  "UNRESOLVED" if unresolved else "MATCHING_DESCRIPTIVE_EVIDENCE")
    return MappingProxyType({"status": "DESCRIPTIVE_ONLY", "assessment": assessment,
        "observations": [dict(item.public_projection()) for item in observations],
        "runtime_observed": False, "ready_to_act": False, "authorized_to_act": False})


__all__ = ("ActivationError", "ActivationState", "ActivityClass", "AgentWalletAdapter",
    "CapabilityState", "EffectOutcome", "FaucetAdapter", "InferenceEvidence",
    "EvidenceTransportReference", "InferenceSessionAdapter", "LedgerState", "ParameterAssessment", "ParameterEvidence",
    "NetworkIdentityEvidence", "RatificationStatus", "SourceClass", "TestnetEvidenceLedger",
    "TestnetInferenceEvidenceLedger", "UsageReceiptAdapter", "activation_status",
    "assess_network_identity", "assess_parameter_evidence", "offline_interfaces", "unknown_faucet_outcome",
    "validate_activation_projection")
