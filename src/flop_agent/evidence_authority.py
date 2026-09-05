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
    pass


class VerifiedAgreement(_OpaqueEvidence):
    pass


class VerifiedRailFinality(_OpaqueEvidence):
    pass


class VerifiedReadBackEvidence(_OpaqueEvidence):
    pass


class VerifiedEvidenceBundle(_OpaqueEvidence):
    pass


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
    verifier_revision: str
    policy_version: str
    verified_at_ms: int


@dataclass(frozen=True)
class _RailRecord:
    agreement_id: str
    rail: str
    reference: str
    terminal_state: str
    evidence_sha256: str
    verifier_revision: str
    policy_version: str
    verified_at_ms: int


@dataclass(frozen=True)
class _ReadBackRecord:
    evidence_sha256: str
    events_sha256: str
    verifier_revision: str
    policy_version: str
    verified_at_ms: int


@dataclass(frozen=True)
class _BundleRecord:
    public: Mapping[str, str]
    verifier_revision: str
    policy_version: str
    verified_at_ms: int


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _proposal_raw_hash(value: wire.AgreementProposal) -> str:
    return _sha(wire._canonical_json({
        "protocol": value.protocol, "proposer_id": value.proposer_id,
        "counterparty_id": value.counterparty_id,
        "proposer_public_key_b64": value.proposer_public_key_b64,
        "terms": dict(value.terms), "rail_raw": value.rail_raw,
        "reference": value.reference, "signature_b64": value.signature_b64,
        "offer_id": value.offer_id,
    }))


def _acceptance_raw_hash(value: wire.AgreementAcceptance) -> str:
    return _sha(wire._canonical_json({
        "protocol": value.protocol, "accepter_id": value.accepter_id,
        "proposer_id": value.proposer_id,
        "accepter_public_key_b64": value.accepter_public_key_b64,
        "offer_id": value.offer_id, "statement": value.statement,
        "signature_b64": value.signature_b64,
        "agreement_id": value.agreement_id,
    }))


def _rail_observation_hash(value: wire.RailObservation) -> str:
    return _sha(wire._canonical_json({
        "rail_raw": value.rail_raw, "rail_canonical": value.rail_canonical,
        "reference": value.reference, "terminal_state": value.terminal_state,
        "protocol_valid_observed": value.protocol_valid,
    }))


def _safe_export_assessment(raw: bytes, generation: str | None) -> wire.TranscriptAssessment:
    if not isinstance(raw, bytes) or len(raw) > wire.MAX_EXPORT_BYTES:
        raise wire.WireSafetyError("EXPORT_SIZE_INVALID", "snapshot", raw)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        text = None
    if text is None:
        raise wire.WireSafetyError(
            "EXPORT_UTF8_INVALID", "snapshot", raw, "strict UTF-8 required") from None
    issues: list[str] = []
    seqs: list[str] = []
    generations: set[str] = set()
    venue: list[wire.VenueMetadataEvidence] = []
    lines = text.splitlines()
    if len(lines) > wire.MAX_EXPORT_RECORDS:
        raise wire.WireSafetyError("EXPORT_SIZE_INVALID", "snapshot", raw)
    for line in lines:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            item = None
        if not isinstance(item, dict):
            issues.append("DECODE_INVALID")
            continue
        wire._ensure_secret_safe(item, "record")
        raw_seq = item.get("seq")
        if not isinstance(raw_seq, str) or re.fullmatch(r"(?:0|[1-9][0-9]*)", raw_seq) is None:
            issues.append("SEQ_INVALID")
            continue
        seqs.append(raw_seq)
        item_generation = item.get("generation")
        if item_generation is not None:
            if (not isinstance(item_generation, str)
                    or re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", item_generation) is None):
                issues.append("GENERATION_INVALID")
                item_generation = None
            else:
                generations.add(item_generation)
        timestamp = item.get("ts")
        if timestamp is not None:
            try:
                timestamp = wire.validate_unix_ms(timestamp, field="ts")
            except wire.WireSafetyError:
                timestamp = None
                issues.append("TIME_INVALID")
        venue.append(wire.VenueMetadataEvidence(
            raw_seq, timestamp, item_generation,
            wire.EvidenceStatus.VENUE_METADATA_OBSERVED, False))
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
    structure = (wire.EvidenceStatus.TRANSCRIPT_INVALID if invalid.intersection(issues)
                 else wire.EvidenceStatus.TRANSCRIPT_STRUCT_VALID)
    return wire.TranscriptAssessment(
        wire.EvidenceStatus.EXPORT_ACQUIRED, structure,
        wire.EvidenceStatus.TRANSCRIPT_COMPLETENESS_UNVERIFIED,
        len(venue), seqs[0] if seqs else None, seqs[-1] if seqs else None,
        tuple(dict.fromkeys(issues)), tuple(venue))


def observe_third_party_export(raw: bytes, *, source_id: str, acquired_at_ms: int,
                               verifier_revision: str,
                               generation: str | None = None) -> ExportObservation:
    assessment = _safe_export_assessment(raw, generation)
    return ExportObservation(
        wire.ExportSourceKind.THIRD_PARTY_SUPPLIED, source_id, acquired_at_ms,
        _sha(raw), len(raw), verifier_revision, generation, assessment)


class _EvidenceAuthority:
    """One closed issuance domain with captured reviewed registries."""

    def __init__(self, exports: Mapping[str, Mapping[str, str]],
                 rail_proofs: Mapping[str, Mapping[str, Any]],
                 readbacks: Mapping[str, Mapping[str, Any]],
                 verifier_revision: str, clock_ms: Callable[[], int]):
        if re.fullmatch(r"[0-9a-f]{40}", verifier_revision) is None:
            raise ValueError("exact verifier revision required")
        self.__exports = MappingProxyType({k: MappingProxyType(dict(v)) for k, v in exports.items()})
        self.__rails = MappingProxyType({k: MappingProxyType(dict(v)) for k, v in rail_proofs.items()})
        self.__readbacks = MappingProxyType({k: MappingProxyType(dict(v)) for k, v in readbacks.items()})
        self.__revision = verifier_revision
        self.__clock = clock_ms
        self.__observations: weakref.WeakKeyDictionary[ExportObservation, bytes] = weakref.WeakKeyDictionary()
        self.__complete: weakref.WeakKeyDictionary[VerifiedTranscriptCompleteness, _CompletenessRecord] = weakref.WeakKeyDictionary()
        self.__agreements: weakref.WeakKeyDictionary[VerifiedAgreement, _AgreementRecord] = weakref.WeakKeyDictionary()
        self.__finality: weakref.WeakKeyDictionary[VerifiedRailFinality, _RailRecord] = weakref.WeakKeyDictionary()
        self.__readback_tokens: weakref.WeakKeyDictionary[VerifiedReadBackEvidence, _ReadBackRecord] = weakref.WeakKeyDictionary()
        self.__bundles: weakref.WeakKeyDictionary[VerifiedEvidenceBundle, _BundleRecord] = weakref.WeakKeyDictionary()

    def observe_reviewed_export(self, source_id: str, raw: bytes, *, acquired_at_ms: int,
                                generation: str) -> ExportObservation:
        configured = self.__exports.get(source_id)
        digest = _sha(raw) if isinstance(raw, bytes) else ""
        if (configured is None or configured.get("source_kind") != "CONFIGURED_REVIEWED_EXPORT"
                or configured.get("generation") != generation
                or configured.get("snapshot_sha256") != digest):
            raise PermissionError("export is absent from the reviewed acquisition registry")
        assessment = _safe_export_assessment(raw, generation)
        observation = ExportObservation(
            wire.ExportSourceKind.CONFIGURED_REVIEWED_EXPORT, source_id,
            acquired_at_ms, digest, len(raw), self.__revision, generation, assessment)
        self.__observations[observation] = raw
        return observation

    def verify_completeness(self, observation: ExportObservation, *, first_seq: str,
                            last_seq: str, truncation_indicated: bool = False
                            ) -> VerifiedTranscriptCompleteness | None:
        raw = self.__observations.get(observation)
        report = observation.assessment if raw is not None else None
        if (raw is None or report is None or truncation_indicated
                or report.structure_status is not wire.EvidenceStatus.TRANSCRIPT_STRUCT_VALID
                or report.issues or report.first_seq != wire.parse_nonce(first_seq).decimal
                or report.last_seq != wire.parse_nonce(last_seq).decimal
                or observation.generation is None):
            return None
        token = object.__new__(VerifiedTranscriptCompleteness)
        self.__complete[token] = _CompletenessRecord(
            observation.snapshot_sha256, observation.source_id, observation.generation,
            first_seq, last_seq, self.__revision, AUTHORITY_SCHEMA_VERSION, self.__clock())
        return token

    def verify_agreement(self, proposal: wire.AgreementProposal,
                         acceptance: wire.AgreementAcceptance) -> VerifiedAgreement | None:
        try:
            offer_bytes = proposal.signing_bytes()
            accept_bytes = acceptance.signing_bytes()
            offer_sig = wire._verify_signature(
                proposal.proposer_public_key_b64, proposal.signature_b64, offer_bytes)
            accept_sig = wire._verify_signature(
                acceptance.accepter_public_key_b64, acceptance.signature_b64, accept_bytes)
            offer_id = wire.recompute_offer_id(offer_bytes, proposal.signature_b64)
            agreement_id = wire.recompute_agreement_id(
                acceptance.offer_id, accept_bytes, acceptance.signature_b64)
        except (wire.WireSafetyError, TypeError, ValueError):
            return None
        valid = (
            offer_sig is wire.EvidenceStatus.SIGNED_CONTENT_VERIFIED
            and accept_sig is wire.EvidenceStatus.SIGNED_CONTENT_VERIFIED
            and proposal.offer_id == offer_id
            and acceptance.offer_id == offer_id
            and acceptance.agreement_id == agreement_id
            and acceptance.accepter_id == proposal.counterparty_id
            and acceptance.proposer_id == proposal.proposer_id
            and acceptance.protocol == proposal.protocol
            and proposal.terms.get("lock_statement") == "LOCKED"
            and acceptance.statement == "ACCEPT" and bool(proposal.reference))
        if not valid:
            return None
        token = object.__new__(VerifiedAgreement)
        self.__agreements[token] = _AgreementRecord(
            _proposal_raw_hash(proposal), _sha(offer_bytes),
            _acceptance_raw_hash(acceptance), _sha(accept_bytes),
            offer_id, agreement_id, proposal.proposer_id, acceptance.accepter_id,
            acceptance.statement, self.__revision, AUTHORITY_SCHEMA_VERSION, self.__clock())
        return token

    def verify_rail(self, agreement: VerifiedAgreement, observation: wire.RailObservation,
                    proof_id: str) -> VerifiedRailFinality | None:
        agreement_record = self.__agreements.get(agreement)
        proof = self.__rails.get(proof_id)
        evidence_sha = _rail_observation_hash(observation)
        if (agreement_record is None or proof is None
                or observation.rail_canonical == "PAPER"
                or proof.get("agreement_id") != agreement_record.agreement_id
                or proof.get("rail") != observation.rail_canonical
                or proof.get("reference") != observation.reference
                or proof.get("terminal_state") != observation.terminal_state
                or proof.get("evidence_sha256") != evidence_sha
                or proof.get("protocol_valid") is not True
                or proof.get("independent_finality_verified") is not True
                or proof.get("cryptographic_verification") is not True):
            return None
        token = object.__new__(VerifiedRailFinality)
        self.__finality[token] = _RailRecord(
            agreement_record.agreement_id, observation.rail_canonical,
            observation.reference, observation.terminal_state, evidence_sha,
            self.__revision, AUTHORITY_SCHEMA_VERSION, self.__clock())
        return token

    def verify_readback(self, proof_id: str, evidence_sha256: str,
                        events: Sequence[str]) -> VerifiedReadBackEvidence | None:
        configured = self.__readbacks.get(proof_id)
        checked_events = tuple(events)
        stage = wire.ReadBackStage.NOT_STARTED
        try:
            for event in checked_events:
                stage = wire.advance_readback(stage, event)
        except wire.WireSafetyError:
            return None
        if (configured is None or configured.get("evidence_sha256") != evidence_sha256
                or tuple(configured.get("events", ())) != checked_events
                or stage is not wire.ReadBackStage.EVIDENCE_CONFIRMED):
            return None
        token = object.__new__(VerifiedReadBackEvidence)
        self.__readback_tokens[token] = _ReadBackRecord(
            evidence_sha256, _sha("\0".join(checked_events).encode()),
            self.__revision, AUTHORITY_SCHEMA_VERSION, self.__clock())
        return token

    def issue_bundle(self, *, completeness: VerifiedTranscriptCompleteness | None,
                     agreement: VerifiedAgreement | None,
                     finality: VerifiedRailFinality | None,
                     readback: VerifiedReadBackEvidence | None) -> VerifiedEvidenceBundle:
        c = self.__complete.get(completeness) if completeness is not None else None
        a = self.__agreements.get(agreement) if agreement is not None else None
        f = self.__finality.get(finality) if finality is not None else None
        r = self.__readback_tokens.get(readback) if readback is not None else None
        if ((completeness is not None and c is None) or (agreement is not None and a is None)
                or (finality is not None and f is None) or (readback is not None and r is None)):
            raise PermissionError("bundle contains evidence not issued by this authority")
        public = MappingProxyType({
            "transcript": ("TRANSCRIPT_COMPLETENESS_VERIFIED" if c else
                           "TRANSCRIPT_COMPLETENESS_UNVERIFIED"),
            "agreement": "AGREEMENT_VERIFIED" if a else "AGREEMENT_UNVERIFIED",
            "settlement": "RAIL_CRYPTO_VERIFIED" if f else "RAIL_UNVERIFIED",
            "finality": "FINALITY_VERIFIED" if f else "FINALITY_UNVERIFIED",
            "read_back": "EVIDENCE_CONFIRMED" if r else "READBACK_UNVERIFIED",
        })
        token = object.__new__(VerifiedEvidenceBundle)
        self.__bundles[token] = _BundleRecord(
            public, self.__revision, AUTHORITY_SCHEMA_VERSION, self.__clock())
        return token

    def as_public_evidence(self, bundle: VerifiedEvidenceBundle) -> Mapping[str, str]:
        record = self.__bundles.get(bundle)
        if record is None:
            raise PermissionError("verified bundle was not issued by this authority")
        return record.public


def _build_evidence_authority(
    exports: Mapping[str, Mapping[str, str]],
    rail_proofs: Mapping[str, Mapping[str, Any]],
    readbacks: Mapping[str, Mapping[str, Any]],
    verifier_revision: str,
    clock_ms: Callable[[], int],
) -> _EvidenceAuthority:
    return _EvidenceAuthority(exports, rail_proofs, readbacks, verifier_revision, clock_ms)


# Production starts fail-closed.  Reviewed records must be added in a separately
# reviewed package; public payloads cannot populate these mappings.
production_evidence_authority = _build_evidence_authority(
    MappingProxyType({}), MappingProxyType({}), MappingProxyType({}),
    "0" * 40, lambda: 0)
