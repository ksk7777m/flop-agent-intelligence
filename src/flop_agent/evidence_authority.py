"""Sealed authority for wire evidence.

Public observations in this module are descriptive.  Verified objects are
opaque process-local capabilities and only have meaning in the authority
instance that issued them.
"""

from __future__ import annotations

import hashlib
import json
import re
import weakref
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence

from . import wire_evidence as wire


AUTHORITY_SCHEMA_VERSION = "flop-wire-evidence-authority-v1"


class _OpaqueEvidence:
    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: Any, **_kwargs: Any) -> "_OpaqueEvidence":
        raise PermissionError("verified evidence is issued only by its sealed verifier")

    def __copy__(self) -> "_OpaqueEvidence":
        raise TypeError("verified evidence cannot be copied")

    def __deepcopy__(self, _memo: dict[int, Any]) -> "_OpaqueEvidence":
        raise TypeError("verified evidence cannot be copied")

    def __reduce__(self) -> Any:
        raise TypeError("verified evidence cannot be serialized")


class VerifiedTranscriptCompleteness(_OpaqueEvidence):
    __slots__ = ()


class TrustedAcquisitionEvidence(_OpaqueEvidence):
    """Opaque authority that a reviewed snapshot was acquired under policy."""

    __slots__ = ()


class VerifiedAgreement(_OpaqueEvidence):
    __slots__ = ()


class VerifiedRailFinality(_OpaqueEvidence):
    __slots__ = ()


class VerifiedReadBackEvidence(_OpaqueEvidence):
    __slots__ = ()


class VerifiedEvidenceBundle(_OpaqueEvidence):
    __slots__ = ()


@dataclass(frozen=True)
class ExportObservation:
    source_kind: wire.ExportSourceKind
    source_id: str
    acquired_at_ms: int
    snapshot_sha256: str
    snapshot_length: int
    verifier_revision: str
    generation: str | None
    assessment: wire.TranscriptAssessment

    def __post_init__(self) -> None:
        if not isinstance(self.source_kind, wire.ExportSourceKind):
            raise wire.WireSafetyError("EXPORT_SOURCE_INVALID", "source_kind")
        if re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", self.source_id) is None:
            raise wire.WireSafetyError("EXPORT_SOURCE_INVALID", "source_id")
        wire.validate_unix_ms(self.acquired_at_ms, field="acquired_at_ms")
        if re.fullmatch(r"[0-9a-f]{64}", self.snapshot_sha256) is None:
            raise wire.WireSafetyError("HASH_INVALID", "snapshot_sha256")
        if (isinstance(self.snapshot_length, bool)
                or not isinstance(self.snapshot_length, int)
                or not 0 <= self.snapshot_length <= wire.MAX_EXPORT_BYTES):
            raise wire.WireSafetyError("EXPORT_SIZE_INVALID", "snapshot_length")
        if re.fullmatch(r"[0-9a-f]{40}", self.verifier_revision) is None:
            raise wire.WireSafetyError("REVISION_INVALID", "verifier_revision")

    def as_public_evidence(self) -> Mapping[str, Any]:
        return MappingProxyType({
            "status": "DESCRIPTIVE_ONLY",
            "source_kind": self.source_kind.value,
            "source_id": self.source_id,
            "acquired_at_ms": self.acquired_at_ms,
            "snapshot_sha256": self.snapshot_sha256,
            "snapshot_length": self.snapshot_length,
            "verifier_revision": self.verifier_revision,
            "generation": self.generation,
            "raw_included": False,
            "structure": self.assessment.structure_status.value,
            "completeness": "TRANSCRIPT_COMPLETENESS_UNVERIFIED",
        })


@dataclass(frozen=True)
class ReadBackObservation:
    evidence_sha256: str
    events: tuple[str, ...]
    final_stage: wire.ReadBackStage

    def __post_init__(self) -> None:
        if re.fullmatch(r"[0-9a-f]{64}", self.evidence_sha256) is None:
            raise wire.WireSafetyError("HASH_INVALID", "evidence_sha256")
        if not isinstance(self.final_stage, wire.ReadBackStage):
            raise wire.WireSafetyError("READBACK_STAGE_INVALID", "final_stage")


@dataclass(frozen=True)
class _CompletenessRecord:
    snapshot_sha256: str
    source_id: str
    generation: str
    first_seq: str
    last_seq: str
    verifier_revision: str
    policy_version: str
    verified_at_ms: int


@dataclass(frozen=True)
class _TrustedAcquisitionRecord:
    observation: ExportObservation
    completeness_allowed: bool
    acquisition_started_at_ms: int
    acquisition_ended_at_ms: int
    first_seq: str
    last_seq: str
    truncation_indicated: bool
    record_count: int
    verifier_revision: str
    policy_version: str


@dataclass(frozen=True)
class _AgreementRecord:
    offer_raw_sha256: str
    offer_canonical_sha256: str
    accept_raw_sha256: str
    accept_canonical_sha256: str
    offer_id: str
    agreement_id: str
    proposer_id: str
    accepter_id: str
    statement: str
    rail: str
    reference: str
    verifier_revision: str
    policy_version: str
    verified_at_ms: int


@dataclass(frozen=True)
class _RailRecord:
    agreement_id: str
    rail: str
    reference: str
    terminal_state: str
    settlement_evidence_sha256: str
    independent_proof_sha256: str
    artifact_sha256: str
    verifier_revision: str
    policy_version: str
    verified_at_ms: int


@dataclass(frozen=True)
class _ReadBackRecord:
    artifact_sha256: str
    agreement_id: str
    rail: str
    reference: str
    events_sha256: str
    verifier_revision: str
    policy_version: str
    verified_at_ms: int


@dataclass(frozen=True)
class _BundleRecord:
    public: Mapping[str, str]
    bundle_sha256: str
    verifier_revision: str
    policy_version: str
    verified_at_ms: int


def _sha(value: bytes, _digest: Callable[[bytes], Any] = hashlib.sha256) -> str:
    return _digest(value).hexdigest()


def _proposal_raw_hash(
    value: wire.AgreementProposal, _wire: Any = wire, _hash: Callable[[bytes], str] = _sha,
) -> str:
    return _hash(_wire._canonical_json({
        "protocol": value.protocol, "proposer_id": value.proposer_id,
        "counterparty_id": value.counterparty_id,
        "proposer_public_key_b64": value.proposer_public_key_b64,
        "terms": dict(value.terms), "rail_raw": value.rail_raw,
        "reference": value.reference, "signature_b64": value.signature_b64,
        "offer_id": value.offer_id,
    }))


def _acceptance_raw_hash(
    value: wire.AgreementAcceptance, _wire: Any = wire,
    _hash: Callable[[bytes], str] = _sha,
) -> str:
    return _hash(_wire._canonical_json({
        "protocol": value.protocol, "accepter_id": value.accepter_id,
        "proposer_id": value.proposer_id,
        "accepter_public_key_b64": value.accepter_public_key_b64,
        "offer_id": value.offer_id, "statement": value.statement,
        "signature_b64": value.signature_b64,
        "agreement_id": value.agreement_id,
    }))


def _rail_observation_hash(
    value: wire.RailObservation, _wire: Any = wire,
    _hash: Callable[[bytes], str] = _sha,
) -> str:
    return _hash(_wire._canonical_json({
        "rail_raw": value.rail_raw, "rail_canonical": value.rail_canonical,
        "reference": value.reference, "terminal_state": value.terminal_state,
        "protocol_valid_observed": value.protocol_valid,
    }))


def _safe_export_assessment(
    raw: bytes, generation: str | None, _wire: Any = wire,
    _json_loads: Callable[[str], Any] = json.loads,
    _json_error: type[Exception] = json.JSONDecodeError,
    _fullmatch: Callable[[str, str], Any] = re.fullmatch,
) -> wire.TranscriptAssessment:
    if not isinstance(raw, bytes) or len(raw) > _wire.MAX_EXPORT_BYTES:
        raise _wire.WireSafetyError("EXPORT_SIZE_INVALID", "snapshot", raw)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        text = None
    if text is None:
        raise _wire.WireSafetyError(
            "EXPORT_UTF8_INVALID", "snapshot", raw, "strict UTF-8 required") from None
    issues: list[str] = []
    seqs: list[str] = []
    generations: set[str] = set()
    venue: list[wire.VenueMetadataEvidence] = []
    lines = text.splitlines()
    if len(lines) > _wire.MAX_EXPORT_RECORDS:
        raise _wire.WireSafetyError("EXPORT_SIZE_INVALID", "snapshot", raw)
    for line in lines:
        try:
            item = _json_loads(line)
        except _json_error:
            item = None
        if not isinstance(item, dict):
            issues.append("DECODE_INVALID")
            continue
        _wire._ensure_secret_safe(item, "record")
        raw_seq = item.get("seq")
        if not isinstance(raw_seq, str) or _fullmatch(r"(?:0|[1-9][0-9]*)", raw_seq) is None:
            issues.append("SEQ_INVALID")
            continue
        seqs.append(raw_seq)
        item_generation = item.get("generation")
        if item_generation is not None:
            if (not isinstance(item_generation, str)
                    or _fullmatch(r"[A-Za-z0-9._:-]{1,128}", item_generation) is None):
                issues.append("GENERATION_INVALID")
                item_generation = None
            else:
                generations.add(item_generation)
        timestamp = item.get("ts")
        if timestamp is not None:
            try:
                timestamp = _wire.validate_unix_ms(timestamp, field="ts")
            except _wire.WireSafetyError:
                timestamp = None
                issues.append("TIME_INVALID")
        venue.append(_wire.VenueMetadataEvidence(
            raw_seq, timestamp, item_generation,
            _wire.EvidenceStatus.VENUE_METADATA_OBSERVED, False))
    numeric = [int(item) for item in seqs]
    if len(numeric) != len(set(numeric)):
        issues.append("DUPLICATE_SEQUENCE")
    if any(right < left for left, right in zip(numeric, numeric[1:])):
        issues.append("SEQUENCE_REVERSAL")
    if any(right - left > 1 for left, right in zip(numeric, numeric[1:])):
        issues.append("SEQUENCE_GAP")
    if len(generations) > 1 or (generation is not None and generations and generations != {generation}):
        issues.append("GENERATION_INCONSISTENT")
    invalid = {"DECODE_INVALID", "SEQ_INVALID", "GENERATION_INVALID", "TIME_INVALID",
               "DUPLICATE_SEQUENCE", "SEQUENCE_REVERSAL", "GENERATION_INCONSISTENT"}
    structure = (_wire.EvidenceStatus.TRANSCRIPT_INVALID if invalid.intersection(issues)
                 else _wire.EvidenceStatus.TRANSCRIPT_STRUCT_VALID)
    return _wire.TranscriptAssessment(
        _wire.EvidenceStatus.EXPORT_ACQUIRED, structure,
        _wire.EvidenceStatus.TRANSCRIPT_COMPLETENESS_UNVERIFIED,
        len(venue), seqs[0] if seqs else None, seqs[-1] if seqs else None,
        tuple(dict.fromkeys(issues)), tuple(venue))


def _capture_export_assessor() -> Callable[[bytes, str | None], wire.TranscriptAssessment]:
    """Build an export assessor with no later wire-module lookups."""
    max_bytes = wire.MAX_EXPORT_BYTES
    max_records = wire.MAX_EXPORT_RECORDS
    error_type = wire.WireSafetyError
    secret_checker = wire._capture_agreement_policy()[1]
    max_unix_ms = wire.MAX_UNIX_MS
    venue_type = wire.VenueMetadataEvidence
    assessment_type = wire.TranscriptAssessment
    export_acquired = wire.EvidenceStatus.EXPORT_ACQUIRED
    venue_observed = wire.EvidenceStatus.VENUE_METADATA_OBSERVED
    transcript_invalid = wire.EvidenceStatus.TRANSCRIPT_INVALID
    transcript_valid = wire.EvidenceStatus.TRANSCRIPT_STRUCT_VALID
    completeness_unverified = wire.EvidenceStatus.TRANSCRIPT_COMPLETENESS_UNVERIFIED
    json_loads = json.loads
    json_error = json.JSONDecodeError
    seq_pattern = re.compile(r"(?:0|[1-9][0-9]*)")
    safe_id_pattern = re.compile(r"[A-Za-z0-9._:-]{1,128}")

    def assess(raw: bytes, generation: str | None) -> wire.TranscriptAssessment:
        if not isinstance(raw, bytes) or len(raw) > max_bytes:
            raise error_type("EXPORT_SIZE_INVALID", "snapshot", raw)
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            text = None
        if text is None:
            raise error_type(
                "EXPORT_UTF8_INVALID", "snapshot", raw,
                "strict UTF-8 required") from None
        issues: list[str] = []
        seqs: list[str] = []
        generations: set[str] = set()
        venue: list[wire.VenueMetadataEvidence] = []
        lines = text.splitlines()
        if len(lines) > max_records:
            raise error_type("EXPORT_SIZE_INVALID", "snapshot", raw)
        for line in lines:
            try:
                item = json_loads(line)
            except json_error:
                item = None
            if not isinstance(item, dict):
                issues.append("DECODE_INVALID")
                continue
            secret_checker(item, "record")
            raw_seq = item.get("seq")
            if not isinstance(raw_seq, str) or seq_pattern.fullmatch(raw_seq) is None:
                issues.append("SEQ_INVALID")
                continue
            seqs.append(raw_seq)
            item_generation = item.get("generation")
            if item_generation is not None:
                if (not isinstance(item_generation, str)
                        or safe_id_pattern.fullmatch(item_generation) is None):
                    issues.append("GENERATION_INVALID")
                    item_generation = None
                else:
                    generations.add(item_generation)
            timestamp = item.get("ts")
            if timestamp is not None:
                try:
                    if (isinstance(timestamp, bool) or not isinstance(timestamp, int)
                            or timestamp < 0 or timestamp > max_unix_ms):
                        raise ValueError
                except ValueError:
                    timestamp = None
                    issues.append("TIME_INVALID")
            venue_item = object.__new__(venue_type)
            for field, value in (
                ("seq", raw_seq), ("timestamp_ms", timestamp),
                ("generation", item_generation), ("provenance", venue_observed),
                ("signed_metadata", False),
            ):
                object.__setattr__(venue_item, field, value)
            venue.append(venue_item)
        numeric = [int(item) for item in seqs]
        if len(numeric) != len(set(numeric)):
            issues.append("DUPLICATE_SEQUENCE")
        if any(right < left for left, right in zip(numeric, numeric[1:])):
            issues.append("SEQUENCE_REVERSAL")
        if any(right - left > 1 for left, right in zip(numeric, numeric[1:])):
            issues.append("SEQUENCE_GAP")
        if (len(generations) > 1
                or (generation is not None and generations and generations != {generation})):
            issues.append("GENERATION_INCONSISTENT")
        invalid = {
            "DECODE_INVALID", "SEQ_INVALID", "GENERATION_INVALID", "TIME_INVALID",
            "DUPLICATE_SEQUENCE", "SEQUENCE_REVERSAL", "GENERATION_INCONSISTENT",
        }
        structure = transcript_invalid if invalid.intersection(issues) else transcript_valid
        assessment = object.__new__(assessment_type)
        for field, value in (
            ("acquisition_status", export_acquired), ("structure_status", structure),
            ("completeness_status", completeness_unverified), ("records", len(venue)),
            ("first_seq", seqs[0] if seqs else None),
            ("last_seq", seqs[-1] if seqs else None),
            ("issues", tuple(dict.fromkeys(issues))),
            ("venue_metadata", tuple(venue)),
        ):
            object.__setattr__(assessment, field, value)
        return assessment

    return assess


def observe_third_party_export(raw: bytes, *, source_id: str, acquired_at_ms: int,
                               verifier_revision: str,
                               generation: str | None = None) -> ExportObservation:
    assessment = _safe_export_assessment(raw, generation)
    return ExportObservation(
        wire.ExportSourceKind.THIRD_PARTY_SUPPLIED, source_id, acquired_at_ms,
        _sha(raw), len(raw), verifier_revision, generation, assessment)


def observed_deadline_fold(observation: ExportObservation, *, deadline_ms: int) -> str:
    """Fold unsigned venue timestamps for descriptive display only."""
    wire.validate_unix_ms(deadline_ms, field="deadline_ms")
    timestamps = tuple(
        item.timestamp_ms for item in observation.assessment.venue_metadata
        if item.timestamp_ms is not None)
    if not timestamps:
        return "DEADLINE_UNKNOWN"
    return ("PRE_DEADLINE_OBSERVED" if max(timestamps) <= deadline_ms
            else "POST_DEADLINE_OBSERVED")


class _SealedEvidenceService:
    """Base for an identity-bound facade whose issuance state lives in closures."""

    __slots__ = ()

    def __new__(cls, *_args: Any, **_kwargs: Any) -> "_SealedEvidenceService":
        raise PermissionError("evidence services are created only by the sealed root")

    @staticmethod
    def _reject() -> Any:
        raise PermissionError("evidence service instance was not issued by the sealed root")

    def acquire_reviewed_export(self, source_id: str, raw: bytes) -> TrustedAcquisitionEvidence:
        del source_id, raw
        return self._reject()

    def describe_acquisition(self, evidence: TrustedAcquisitionEvidence) -> ExportObservation:
        del evidence
        return self._reject()

    def verify_completeness(
        self, evidence: TrustedAcquisitionEvidence,
    ) -> VerifiedTranscriptCompleteness | None:
        del evidence
        return self._reject()

    def verify_agreement(
        self, proposal: wire.AgreementProposal, acceptance: wire.AgreementAcceptance,
    ) -> VerifiedAgreement | None:
        del proposal, acceptance
        return self._reject()

    def verify_rail(
        self, agreement: VerifiedAgreement, observation: wire.RailObservation,
    ) -> VerifiedRailFinality | None:
        del agreement, observation
        return self._reject()

    def describe_finality_artifact(
        self, finality: VerifiedRailFinality,
    ) -> Mapping[str, str]:
        del finality
        return self._reject()

    def verify_readback(
        self, finality: VerifiedRailFinality, evidence_sha256: str,
        events: Sequence[str],
    ) -> VerifiedReadBackEvidence | None:
        del finality, evidence_sha256, events
        return self._reject()

    def issue_bundle(
        self, *, completeness: VerifiedTranscriptCompleteness | None,
        agreement: VerifiedAgreement | None, finality: VerifiedRailFinality | None,
        readback: VerifiedReadBackEvidence | None,
    ) -> VerifiedEvidenceBundle:
        del completeness, agreement, finality, readback
        return self._reject()

    def as_public_evidence(self, bundle: VerifiedEvidenceBundle) -> Mapping[str, str]:
        del bundle
        return self._reject()


def _bootstrap_evidence_services() -> tuple[_SealedEvidenceService, Callable[[], _SealedEvidenceService]]:
    """Construct the single production root and a fixed, private offline test root.

    The configurable builder below never becomes a module attribute.  Rebinding
    module constants after this function returns cannot alter captured policy or
    issuance state.  Closure-cell mutation/introspection is outside the declared
    threat model.
    """

    # Capture every authority-relevant global before the production root is
    # created.  Later module-global rebinding cannot replace verification logic,
    # token classes, records, policy version, or canonicalization functions.
    sha256 = _sha
    (canonical_json, _secret_checker, canonicalize_rail,
     proposal_signing_bytes, acceptance_signing_bytes, verify_signature,
     recompute_offer_id, recompute_agreement_id) = wire._capture_agreement_policy()
    del _secret_checker
    assess_snapshot = _capture_export_assessor()
    wire_error = wire.WireSafetyError
    configured_export_source = wire.ExportSourceKind.CONFIGURED_REVIEWED_EXPORT
    transcript_struct_valid = wire.EvidenceStatus.TRANSCRIPT_STRUCT_VALID
    signed_content_verified = wire.EvidenceStatus.SIGNED_CONTENT_VERIFIED
    agreement_proposed = wire.AgreementState.PROPOSED
    agreement_offer_verified = wire.AgreementState.OFFER_VERIFIED
    agreement_acceptance_verified = wire.AgreementState.ACCEPTANCE_VERIFIED
    agreement_verified = wire.AgreementState.AGREEMENT_VERIFIED
    agreement_transitions = MappingProxyType({
        (agreement_proposed, "offer_verified"): agreement_offer_verified,
        (agreement_offer_verified, "acceptance_verified"): agreement_acceptance_verified,
        (agreement_acceptance_verified, "agreement_verified"): agreement_verified,
    })
    readback_not_started = wire.ReadBackStage.NOT_STARTED
    readback_write_accepted = wire.ReadBackStage.WRITE_ACCEPTED
    readback_observed = wire.ReadBackStage.READ_BACK_OBSERVED
    readback_decode_valid = wire.ReadBackStage.DECODE_VALID
    readback_signature_valid = wire.ReadBackStage.SIGNATURE_VALID
    readback_replay_valid = wire.ReadBackStage.STATE_REPLAY_VALID
    readback_confirmed = wire.ReadBackStage.EVIDENCE_CONFIRMED
    readback_transitions = MappingProxyType({
        (readback_not_started, "write_accepted"): readback_write_accepted,
        (readback_write_accepted, "read_back_observed"): readback_observed,
        (readback_observed, "decode_valid"): readback_decode_valid,
        (readback_decode_valid, "signature_valid"): readback_signature_valid,
        (readback_signature_valid, "state_replay_valid"): readback_replay_valid,
        (readback_replay_valid, "evidence_confirmed"): readback_confirmed,
    })
    schema_version = AUTHORITY_SCHEMA_VERSION
    acquisition_token_type = TrustedAcquisitionEvidence
    completeness_token_type = VerifiedTranscriptCompleteness
    agreement_token_type = VerifiedAgreement
    finality_token_type = VerifiedRailFinality
    readback_token_type = VerifiedReadBackEvidence
    bundle_token_type = VerifiedEvidenceBundle
    acquisition_record_type = _TrustedAcquisitionRecord
    completeness_record_type = _CompletenessRecord
    agreement_record_type = _AgreementRecord
    rail_record_type = _RailRecord
    readback_record_type = _ReadBackRecord
    bundle_record_type = _BundleRecord
    service_type = _SealedEvidenceService
    observation_type = ExportObservation
    mapping_proxy = MappingProxyType
    weak_key_dictionary = weakref.WeakKeyDictionary
    regex_fullmatch = re.fullmatch

    def proposal_digest(value: wire.AgreementProposal) -> str:
        return sha256(canonical_json({
            "protocol": value.protocol, "proposer_id": value.proposer_id,
            "counterparty_id": value.counterparty_id,
            "proposer_public_key_b64": value.proposer_public_key_b64,
            "terms": dict(value.terms), "rail_raw": value.rail_raw,
            "reference": value.reference, "signature_b64": value.signature_b64,
            "offer_id": value.offer_id,
        }))

    def acceptance_digest(value: wire.AgreementAcceptance) -> str:
        return sha256(canonical_json({
            "protocol": value.protocol, "accepter_id": value.accepter_id,
            "proposer_id": value.proposer_id,
            "accepter_public_key_b64": value.accepter_public_key_b64,
            "offer_id": value.offer_id, "statement": value.statement,
            "signature_b64": value.signature_b64,
            "agreement_id": value.agreement_id,
        }))

    def rail_observation_digest(value: wire.RailObservation) -> str:
        return sha256(canonical_json({
            "rail_raw": value.rail_raw, "rail_canonical": value.rail_canonical,
            "reference": value.reference, "terminal_state": value.terminal_state,
            "protocol_valid_observed": value.protocol_valid,
        }))

    fixture_raw = (b'{"seq":"1","generation":"gen-1"}\n'
                   b'{"seq":"2","generation":"gen-1"}')
    fixture_rail = wire.RailObservation.observed(
        "bitcoin", "ref-1", "COMPLETED", protocol_valid=True)
    fixture_events = ("write_accepted", "read_back_observed", "decode_valid",
                      "signature_valid", "state_replay_valid", "evidence_confirmed")

    def build_service(
        acquisitions: Mapping[str, Mapping[str, Any]],
        rail_proofs: Mapping[str, Mapping[str, Any]],
        readbacks: Mapping[str, Mapping[str, Any]],
        verifier_revision: str,
        clock_ms: Callable[[], int],
        projection_scope: str,
    ) -> _SealedEvidenceService:
        if regex_fullmatch(r"[0-9a-f]{40}", verifier_revision) is None:
            raise ValueError("exact verifier revision required")
        acquisition_policy = mapping_proxy({
            key: mapping_proxy(dict(value)) for key, value in acquisitions.items()})
        rail_policy = mapping_proxy({
            key: mapping_proxy(dict(value)) for key, value in rail_proofs.items()})
        readback_policy = mapping_proxy({
            key: mapping_proxy(dict(value)) for key, value in readbacks.items()})
        revision = verifier_revision
        clock = clock_ms
        policy_digest = sha256(canonical_json({
            "acquisitions": {key: dict(value) for key, value in acquisitions.items()},
            "rail_proofs": {key: dict(value) for key, value in rail_proofs.items()},
            "readbacks": {key: dict(value) for key, value in readbacks.items()},
            "schema": schema_version,
        }))
        provenance_marker = sha256(
            (schema_version + "|" + revision + "|" + policy_digest
             + "|" + projection_scope).encode())

        acquisitions_issued: weakref.WeakKeyDictionary[
            TrustedAcquisitionEvidence, _TrustedAcquisitionRecord] = weak_key_dictionary()
        completeness_issued: weakref.WeakKeyDictionary[
            VerifiedTranscriptCompleteness, _CompletenessRecord] = weak_key_dictionary()
        agreements_issued: weakref.WeakKeyDictionary[
            VerifiedAgreement, _AgreementRecord] = weak_key_dictionary()
        finality_issued: weakref.WeakKeyDictionary[
            VerifiedRailFinality, _RailRecord] = weak_key_dictionary()
        readbacks_issued: weakref.WeakKeyDictionary[
            VerifiedReadBackEvidence, _ReadBackRecord] = weak_key_dictionary()
        bundles_issued: weakref.WeakKeyDictionary[
            VerifiedEvidenceBundle, _BundleRecord] = weak_key_dictionary()

        def acquire(source_id: str, raw: bytes) -> TrustedAcquisitionEvidence:
            configured = acquisition_policy.get(source_id)
            digest = sha256(raw) if isinstance(raw, bytes) else ""
            if (configured is None
                    or configured.get("source_kind") != "CONFIGURED_REVIEWED_EXPORT"
                    or configured.get("snapshot_sha256") != digest
                    or configured.get("snapshot_length") != len(raw)
                    or not isinstance(configured.get("completeness_allowed"), bool)
                    or not isinstance(configured.get("truncation_indicated"), bool)):
                raise PermissionError("export is absent from sealed acquisition policy")
            generation = configured.get("generation")
            assessment = assess_snapshot(raw, generation)
            # Policy was validated by the repository-controlled bootstrap.  Use
            # direct frozen-field population so later rebinding of this module's
            # validation globals cannot alter the already-constructed root.
            observation = object.__new__(observation_type)
            for field, value in (
                ("source_kind", configured_export_source),
                ("source_id", source_id), ("acquired_at_ms", configured["acquired_at_ms"]),
                ("snapshot_sha256", digest), ("snapshot_length", len(raw)),
                ("verifier_revision", revision), ("generation", generation),
                ("assessment", assessment),
            ):
                object.__setattr__(observation, field, value)
            record = acquisition_record_type(
                observation, configured["completeness_allowed"],
                configured["acquisition_started_at_ms"],
                configured["acquisition_ended_at_ms"], configured["first_seq"],
                configured["last_seq"], configured["truncation_indicated"],
                configured["record_count"], revision, schema_version)
            token = object.__new__(acquisition_token_type)
            acquisitions_issued[token] = record
            return token

        def describe(evidence: TrustedAcquisitionEvidence) -> ExportObservation:
            record = acquisitions_issued.get(evidence)
            if record is None:
                raise PermissionError("acquisition evidence was not issued by this authority")
            return record.observation

        def completeness(evidence: TrustedAcquisitionEvidence) -> VerifiedTranscriptCompleteness | None:
            record = acquisitions_issued.get(evidence)
            report = record.observation.assessment if record is not None else None
            if (record is None or report is None or not record.completeness_allowed
                    or record.truncation_indicated
                    or record.acquisition_started_at_ms > record.observation.acquired_at_ms
                    or record.observation.acquired_at_ms > record.acquisition_ended_at_ms
                    or report.structure_status is not transcript_struct_valid
                    or report.issues or report.records != record.record_count
                    or report.first_seq != record.first_seq or report.last_seq != record.last_seq
                    or record.observation.generation is None):
                return None
            token = object.__new__(completeness_token_type)
            completeness_issued[token] = completeness_record_type(
                record.observation.snapshot_sha256, record.observation.source_id,
                record.observation.generation, record.first_seq, record.last_seq,
                revision, schema_version, clock())
            return token

        def agreement(proposal: wire.AgreementProposal,
                      acceptance: wire.AgreementAcceptance) -> VerifiedAgreement | None:
            try:
                offer_bytes = proposal_signing_bytes(
                    protocol=proposal.protocol, proposer_id=proposal.proposer_id,
                    counterparty_id=proposal.counterparty_id, terms=proposal.terms,
                    rail_raw=proposal.rail_raw, reference=proposal.reference)
                accept_bytes = acceptance_signing_bytes(
                    protocol=acceptance.protocol, accepter_id=acceptance.accepter_id,
                    proposer_id=acceptance.proposer_id, offer_id=acceptance.offer_id,
                    statement=acceptance.statement)
                offer_sig = verify_signature(
                    proposal.proposer_public_key_b64, proposal.signature_b64, offer_bytes)
                accept_sig = verify_signature(
                    acceptance.accepter_public_key_b64, acceptance.signature_b64, accept_bytes)
                offer_id = recompute_offer_id(offer_bytes, proposal.signature_b64)
                agreement_id = recompute_agreement_id(
                    acceptance.offer_id, accept_bytes, acceptance.signature_b64)
                state = agreement_proposed
                offer_valid = (offer_sig is signed_content_verified
                               and proposal.offer_id == offer_id
                               and proposal.proposer_id != proposal.counterparty_id
                               and proposal.terms.get("lock_statement") == "LOCKED"
                               and bool(proposal.reference))
                if not offer_valid:
                    return None
                state = agreement_transitions[(state, "offer_verified")]
                acceptance_valid = (
                    accept_sig is signed_content_verified
                    and acceptance.offer_id == offer_id
                    and acceptance.agreement_id == agreement_id
                    and acceptance.accepter_id == proposal.counterparty_id
                    and acceptance.proposer_id == proposal.proposer_id
                    and acceptance.protocol == proposal.protocol
                    and acceptance.statement == "ACCEPT")
                if not acceptance_valid:
                    return None
                state = agreement_transitions[(state, "acceptance_verified")]
                state = agreement_transitions[(state, "agreement_verified")]
            except (wire_error, KeyError, TypeError, ValueError):
                return None
            if state is not agreement_verified:
                return None
            token = object.__new__(agreement_token_type)
            agreements_issued[token] = agreement_record_type(
                proposal_digest(proposal), sha256(offer_bytes),
                acceptance_digest(acceptance), sha256(accept_bytes),
                offer_id, agreement_id, proposal.proposer_id, acceptance.accepter_id,
                acceptance.statement, canonicalize_rail(proposal.rail_raw)[1],
                proposal.reference,
                revision, schema_version, clock())
            return token

        def rail(agreement_token: VerifiedAgreement,
                 observation: wire.RailObservation) -> VerifiedRailFinality | None:
            agreement_record = agreements_issued.get(agreement_token)
            evidence_sha = rail_observation_digest(observation)
            proof = rail_policy.get(evidence_sha)
            if (agreement_record is None or proof is None
                    or observation.rail_canonical == "PAPER"
                    or agreement_record.rail != observation.rail_canonical
                    or agreement_record.reference != observation.reference
                    or proof.get("rail") != observation.rail_canonical
                    or proof.get("reference") != observation.reference
                    or proof.get("terminal_state") != observation.terminal_state
                    or proof.get("evidence_sha256") != evidence_sha
                    or proof.get("protocol_valid") is not True
                    or proof.get("independent_finality_verified") is not True
                    or proof.get("cryptographic_verification") is not True):
                return None
            proof_sha = sha256(canonical_json(dict(proof)))
            artifact_sha = sha256(canonical_json({
                "agreement_id": agreement_record.agreement_id,
                "rail": observation.rail_canonical,
                "reference": observation.reference,
                "terminal_state": observation.terminal_state,
                "independent_proof_sha256": proof_sha,
                "settlement_evidence_sha256": evidence_sha,
                "verifier_revision": revision,
                "policy_version": schema_version,
            }))
            token = object.__new__(finality_token_type)
            finality_issued[token] = rail_record_type(
                agreement_record.agreement_id, observation.rail_canonical,
                observation.reference, observation.terminal_state, evidence_sha,
                proof_sha, artifact_sha, revision, schema_version, clock())
            return token

        def readback(finality_token: VerifiedRailFinality, evidence_sha256: str,
                     events: Sequence[str]) -> VerifiedReadBackEvidence | None:
            finality_record = finality_issued.get(finality_token)
            configured = (readback_policy.get(finality_record.settlement_evidence_sha256)
                          if finality_record is not None else None)
            checked_events = tuple(events)
            stage = readback_not_started
            try:
                for event in checked_events:
                    stage = readback_transitions[(stage, event)]
            except KeyError:
                return None
            if (configured is None or evidence_sha256 != finality_record.artifact_sha256
                    or configured.get("rail") != finality_record.rail
                    or configured.get("reference") != finality_record.reference
                    or tuple(configured.get("events", ())) != checked_events
                    or stage is not readback_confirmed):
                return None
            token = object.__new__(readback_token_type)
            readbacks_issued[token] = readback_record_type(
                finality_record.artifact_sha256, finality_record.agreement_id,
                finality_record.rail, finality_record.reference,
                sha256("\0".join(checked_events).encode()),
                revision, schema_version, clock())
            return token

        def describe_finality(finality_token: VerifiedRailFinality) -> Mapping[str, str]:
            record = finality_issued.get(finality_token)
            if record is None:
                raise PermissionError("finality evidence was not issued by this authority")
            return mapping_proxy({
                "agreement_id": record.agreement_id,
                "rail": record.rail,
                "reference": record.reference,
                "terminal_state": record.terminal_state,
                "independent_proof_sha256": record.independent_proof_sha256,
                "settlement_evidence_sha256": record.settlement_evidence_sha256,
                "artifact_sha256": record.artifact_sha256,
                "verifier_revision": record.verifier_revision,
                "policy_version": record.policy_version,
                "authority": "DESCRIPTIVE_ONLY",
            })

        def bundle(completeness_token: VerifiedTranscriptCompleteness | None,
                   agreement_token: VerifiedAgreement | None,
                   finality_token: VerifiedRailFinality | None,
                   readback_token: VerifiedReadBackEvidence | None) -> VerifiedEvidenceBundle:
            c = completeness_issued.get(completeness_token) if completeness_token else None
            a = agreements_issued.get(agreement_token) if agreement_token else None
            f = finality_issued.get(finality_token) if finality_token else None
            r = readbacks_issued.get(readback_token) if readback_token else None
            if ((completeness_token is not None and c is None)
                    or (agreement_token is not None and a is None)
                    or (finality_token is not None and f is None)
                    or (readback_token is not None and r is None)
                    or (f is not None and (a is None or f.agreement_id != a.agreement_id))
                    or (r is not None and (f is None
                                           or r.artifact_sha256 != f.artifact_sha256
                                           or r.agreement_id != f.agreement_id
                                           or r.rail != f.rail
                                           or r.reference != f.reference
                                           or r.verifier_revision != f.verifier_revision
                                           or r.policy_version != f.policy_version))):
                raise PermissionError("bundle contains evidence not issued by this authority")
            claims = {
                "transcript": ("TRANSCRIPT_COMPLETENESS_VERIFIED" if c else
                               "TRANSCRIPT_COMPLETENESS_UNVERIFIED"),
                "agreement": "AGREEMENT_VERIFIED" if a else "AGREEMENT_UNVERIFIED",
                "settlement": "RAIL_CRYPTO_VERIFIED" if f else "RAIL_UNVERIFIED",
                "finality": "FINALITY_VERIFIED" if f else "FINALITY_UNVERIFIED",
                "read_back": "EVIDENCE_CONFIRMED" if r else "READBACK_UNVERIFIED",
            }
            bundle_sha = sha256(canonical_json({
                "claims": claims,
                "completeness_snapshot": c.snapshot_sha256 if c else None,
                "agreement_id": a.agreement_id if a else None,
                "finality_artifact_sha256": f.artifact_sha256 if f else None,
                "readback_artifact_sha256": r.artifact_sha256 if r else None,
                "verifier_revision": revision,
                "policy_version": schema_version,
            }))
            public = mapping_proxy({
                **claims,
                "projection_schema": "flop-public-evidence-projection-v1",
                "verifier_revision": revision,
                "policy_digest": policy_digest,
                "evidence_bundle_digest": bundle_sha,
                "authority_provenance": projection_scope,
                "authority_provenance_sha256": provenance_marker,
                "serialized_authority": "DESCRIPTIVE_ONLY",
            })
            token = object.__new__(bundle_token_type)
            bundles_issued[token] = bundle_record_type(
                public, bundle_sha, revision, schema_version, clock())
            return token

        def project(bundle_token: VerifiedEvidenceBundle) -> Mapping[str, str]:
            record = bundles_issued.get(bundle_token)
            if record is None:
                raise PermissionError("verified bundle was not issued by this authority")
            return record.public

        service: _SealedEvidenceService | None = None

        def require_bound(candidate: _SealedEvidenceService) -> None:
            if candidate is not service:
                raise PermissionError("evidence service instance was not issued by this authority")

        class BoundEvidenceService(service_type):
            __slots__ = ()

            def acquire_reviewed_export(self, source_id: str, raw: bytes) -> TrustedAcquisitionEvidence:
                require_bound(self)
                return acquire(source_id, raw)

            def describe_acquisition(self, evidence: TrustedAcquisitionEvidence) -> ExportObservation:
                require_bound(self)
                return describe(evidence)

            def verify_completeness(self, evidence: TrustedAcquisitionEvidence) -> VerifiedTranscriptCompleteness | None:
                require_bound(self)
                return completeness(evidence)

            def verify_agreement(self, proposal: wire.AgreementProposal, acceptance: wire.AgreementAcceptance) -> VerifiedAgreement | None:
                require_bound(self)
                return agreement(proposal, acceptance)

            def verify_rail(self, agreement_token: VerifiedAgreement, observation: wire.RailObservation) -> VerifiedRailFinality | None:
                require_bound(self)
                return rail(agreement_token, observation)

            def describe_finality_artifact(self, finality_token: VerifiedRailFinality) -> Mapping[str, str]:
                require_bound(self)
                return describe_finality(finality_token)

            def verify_readback(self, finality_token: VerifiedRailFinality,
                                evidence_sha256: str,
                                events: Sequence[str]) -> VerifiedReadBackEvidence | None:
                require_bound(self)
                return readback(finality_token, evidence_sha256, events)

            def issue_bundle(self, *, completeness: VerifiedTranscriptCompleteness | None,
                             agreement: VerifiedAgreement | None,
                             finality: VerifiedRailFinality | None,
                             readback: VerifiedReadBackEvidence | None) -> VerifiedEvidenceBundle:
                require_bound(self)
                return bundle(completeness, agreement, finality, readback)

            def as_public_evidence(self, bundle_token: VerifiedEvidenceBundle) -> Mapping[str, str]:
                require_bound(self)
                return project(bundle_token)

        service = object.__new__(BoundEvidenceService)
        return service

    # A Git commit cannot truthfully embed its own hash.  This descriptive
    # revision instead binds the repository-controlled schema and sealed root
    # policy.  It is recorded for audit context and is never a trust primitive.
    production_revision = sha256(
        (schema_version + "|production-root|fail-closed-v1").encode())[:40]
    production = build_service(
        {}, {}, {}, production_revision, lambda: 0, "SEALED_PRODUCTION_AUTHORITY")

    fixed_acquisitions = {
        "reviewed": {
            "source_kind": "CONFIGURED_REVIEWED_EXPORT", "generation": "gen-1",
            "snapshot_sha256": sha256(fixture_raw), "snapshot_length": len(fixture_raw),
            "first_seq": "1", "last_seq": "2", "record_count": 2,
            "completeness_allowed": True, "truncation_indicated": False,
            "acquisition_started_at_ms": 1,
            "acquired_at_ms": 2, "acquisition_ended_at_ms": 3,
        },
        "reviewed-truncated": {
            "source_kind": "CONFIGURED_REVIEWED_EXPORT", "generation": "gen-1",
            "snapshot_sha256": sha256(fixture_raw), "snapshot_length": len(fixture_raw),
            "first_seq": "1", "last_seq": "2", "record_count": 2,
            "completeness_allowed": True, "truncation_indicated": True,
            "acquisition_started_at_ms": 1,
            "acquired_at_ms": 2, "acquisition_ended_at_ms": 3,
        },
        "reviewed-outside-bounds": {
            "source_kind": "CONFIGURED_REVIEWED_EXPORT", "generation": "gen-1",
            "snapshot_sha256": sha256(fixture_raw), "snapshot_length": len(fixture_raw),
            "first_seq": "1", "last_seq": "2", "record_count": 2,
            "completeness_allowed": True, "truncation_indicated": False,
            "acquisition_started_at_ms": 1,
            "acquired_at_ms": 4, "acquisition_ended_at_ms": 3,
        },
        "reviewed-descriptive": {
            "source_kind": "CONFIGURED_REVIEWED_EXPORT", "generation": "gen-1",
            "snapshot_sha256": sha256(fixture_raw), "snapshot_length": len(fixture_raw),
            "first_seq": "1", "last_seq": "2", "record_count": 2,
            "completeness_allowed": False, "truncation_indicated": False,
            "acquisition_started_at_ms": 1,
            "acquired_at_ms": 2, "acquisition_ended_at_ms": 3,
        }}
    fixed_rails = {rail_observation_digest(fixture_rail): {
        "rail": fixture_rail.rail_canonical, "reference": fixture_rail.reference,
        "terminal_state": fixture_rail.terminal_state,
        "evidence_sha256": rail_observation_digest(fixture_rail),
        "protocol_valid": True, "independent_finality_verified": True,
        "cryptographic_verification": True,
    }}
    fixed_readbacks = {rail_observation_digest(fixture_rail): {
        "rail": fixture_rail.rail_canonical,
        "reference": fixture_rail.reference,
        "events": fixture_events,
    }}

    def build_fixed_test_service() -> _SealedEvidenceService:
        return build_service(fixed_acquisitions, fixed_rails, fixed_readbacks,
                             "a" * 40, lambda: 1_800_000_000_000,
                             "OFFLINE_PRODUCTION_EQUIVALENT")

    return production, build_fixed_test_service


# Production is constructed exactly once from repository-controlled, fail-closed
# policy.  Only the fixed no-argument factory is retained for offline tests.
production_evidence_authority, _build_evidence_service_for_test = _bootstrap_evidence_services()
del _bootstrap_evidence_services
