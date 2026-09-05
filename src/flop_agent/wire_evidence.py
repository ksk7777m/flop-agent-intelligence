"""Offline wire, evidence, agreement, and finality safety primitives.

These defensive policies are intentionally protocol-conservative.  A valid
content signature does not authenticate venue metadata, prove a complete
transcript, establish an agreement, or demonstrate economic finality.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


TCLK_ALPHA_CLASSIFICATION = "TCLK_ALPHA_COORDINATION_ONLY"
WIRE_POLICY_VERSION = "flop-wire-evidence-safety-v1"
MAX_PROTOCOL_NONCE = 9_999_999_999_999_999_999
MAX_UNIX_MS = 253_402_300_799_999
MAX_EXPORT_BYTES = 2 * 1024 * 1024
MAX_EXPORT_RECORDS = 100_000
ROOM_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
SECRET_FIELD_RE = re.compile(
    r"(?:secret|preimage|witness|presig(?:\.|_)?s|payment(?:_|)?key|"
    r"private(?:_|)?key|seed|mnemonic)", re.IGNORECASE)

__all__ = (
    "ActivityQuality", "Agreement", "AgreementAcceptance", "AgreementProposal",
    "AgreementState", "AgreementVerification",
    "CapabilityEvidenceKind", "CapabilityObservation", "EvidenceBundle",
    "EvidenceLayer", "EvidenceStatus", "ExportSourceKind",
    "FinalityAssessment", "MAX_PROTOCOL_NONCE", "MAX_UNIX_MS", "NonceLexeme",
    "ActivationState", "RailCryptoStatus", "RailObservation", "RawFramePolicy",
    "ReadBackStage", "ReadinessState",
    "SigningContext", "TCLK_ALPHA_CLASSIFICATION", "TranscriptAssessment",
    "TranscriptCompletenessClaim", "TransferAttempt", "VenueMetadataEvidence",
    "WireSafetyError",
    "advance_readback", "agreement_acceptance_signing_bytes",
    "agreement_proposal_signing_bytes", "assess_export", "assess_finality",
    "build_signing_context", "canonicalize_rail", "decode_tclk_alpha_json_frame",
    "gate_tclk_alpha_frame", "parse_nonce", "recompute_agreement_id",
    "recompute_offer_id", "validate_room", "validate_unix_ms",
    "signing_capability_material", "transition_agreement",
    "verify_tclk_alpha_agreement", "wire_safety_readiness",
)


class EvidenceLayer(str, Enum):
    CRYPTOGRAPHIC_EVIDENCE = "CRYPTOGRAPHIC_EVIDENCE"
    VENUE_EVIDENCE = "VENUE_EVIDENCE"
    TRANSCRIPT_EVIDENCE = "TRANSCRIPT_EVIDENCE"
    AGREEMENT_EVIDENCE = "AGREEMENT_EVIDENCE"
    SETTLEMENT_EVIDENCE = "SETTLEMENT_EVIDENCE"


class EvidenceStatus(str, Enum):
    SIGNED_CONTENT_VERIFIED = "SIGNED_CONTENT_VERIFIED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    VENUE_METADATA_OBSERVED = "VENUE_METADATA_OBSERVED"
    DIRECT_VENUE_OBSERVATION = "DIRECT_VENUE_OBSERVATION"
    VENUE_METADATA_PROVENANCE_VERIFIED = "VENUE_METADATA_PROVENANCE_VERIFIED"
    EXPORT_ACQUIRED = "EXPORT_ACQUIRED"
    TRANSCRIPT_COMPLETENESS_UNVERIFIED = "TRANSCRIPT_COMPLETENESS_UNVERIFIED"
    TRANSCRIPT_COMPLETENESS_VERIFIED = "TRANSCRIPT_COMPLETENESS_VERIFIED"
    TRANSCRIPT_STRUCT_VALID = "TRANSCRIPT_STRUCT_VALID"
    TRANSCRIPT_INVALID = "TRANSCRIPT_INVALID"
    AGREEMENT_VERIFIED = "AGREEMENT_VERIFIED"
    AGREEMENT_INVALID = "AGREEMENT_INVALID"
    RAIL_OBSERVATION_PRESENT = "RAIL_OBSERVATION_PRESENT"
    RAIL_CRYPTO_VERIFIED = "RAIL_CRYPTO_VERIFIED"
    FINALITY_VERIFIED = "FINALITY_VERIFIED"
    FINALITY_UNVERIFIED = "FINALITY_UNVERIFIED"


class ExportSourceKind(str, Enum):
    CONFIGURED_REVIEWED_EXPORT = "CONFIGURED_REVIEWED_EXPORT"
    DIRECT_VENUE_SNAPSHOT = "DIRECT_VENUE_SNAPSHOT"
    THIRD_PARTY_SUPPLIED = "THIRD_PARTY_SUPPLIED"


class RailCryptoStatus(str, Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNVERIFIED = "UNVERIFIED"
    RAIL_CRYPTO_VERIFIED = "RAIL_CRYPTO_VERIFIED"


class ReadBackStage(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    WRITE_ACCEPTED = "WRITE_ACCEPTED"
    READ_BACK_OBSERVED = "READ_BACK_OBSERVED"
    DECODE_VALID = "DECODE_VALID"
    SIGNATURE_VALID = "SIGNATURE_VALID"
    STATE_REPLAY_VALID = "STATE_REPLAY_VALID"
    EVIDENCE_CONFIRMED = "EVIDENCE_CONFIRMED"


class CapabilityEvidenceKind(str, Enum):
    DOCUMENTED_CAPABILITY = "DOCUMENTED_CAPABILITY"
    RUNTIME_OBSERVED_CAPABILITY = "RUNTIME_OBSERVED_CAPABILITY"


class ActivityQuality(str, Enum):
    RAW_ACTIVITY = "RAW_ACTIVITY"
    PROTOCOL_VALID_ACTIVITY = "PROTOCOL_VALID_ACTIVITY"
    DECODER_REJECTED_ACTIVITY = "DECODER_REJECTED_ACTIVITY"


class ReadinessState(str, Enum):
    READY = "READY"
    DEFENSIVE_POLICY_READY = "DEFENSIVE_POLICY_READY"
    INTERFACE_READY = "INTERFACE_READY"


class ActivationState(str, Enum):
    DO_NOT_ACTIVATE = "DO_NOT_ACTIVATE"


class AgreementState(str, Enum):
    PROPOSED = "PROPOSED"
    OFFER_VERIFIED = "OFFER_VERIFIED"
    ACCEPTANCE_VERIFIED = "ACCEPTANCE_VERIFIED"
    AGREEMENT_VERIFIED = "AGREEMENT_VERIFIED"
    INVALID = "INVALID"


_AGREEMENT_TRANSITIONS: Mapping[tuple[AgreementState, str], AgreementState] = MappingProxyType({
    (AgreementState.PROPOSED, "offer_verified"): AgreementState.OFFER_VERIFIED,
    (AgreementState.OFFER_VERIFIED, "acceptance_verified"): AgreementState.ACCEPTANCE_VERIFIED,
    (AgreementState.ACCEPTANCE_VERIFIED, "agreement_verified"): AgreementState.AGREEMENT_VERIFIED,
})


def transition_agreement(state: AgreementState, event: str) -> AgreementState:
    if event == "invalid" and isinstance(state, AgreementState):
        return AgreementState.INVALID
    try:
        return _AGREEMENT_TRANSITIONS[(state, event)]
    except KeyError as error:
        raise WireSafetyError(
            "AGREEMENT_TRANSITION_INVALID", "event", event,
            "agreement verification stages must be sequential") from error


class WireSafetyError(ValueError):
    """An error whose text and metadata never include the rejected value."""

    def __init__(self, code: str, field: str, value: Any = None,
                 reason: str = "validation failed"):
        value_type = type(value).__name__
        try:
            length = len(value)  # type: ignore[arg-type]
        except (TypeError, OverflowError):
            length = None
        super().__init__(f"{code}: {field}: {reason}")
        self.code = code
        self.metadata = MappingProxyType({
            "field": field,
            "type": value_type,
            "length": length,
            "error_class": type(self).__name__,
            "reason": reason,
        })

    def as_evidence(self) -> dict[str, Any]:
        return dict(self.metadata)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        encoded = None
    if encoded is None:
        raise WireSafetyError(
            "CANONICALIZATION_INVALID", "payload", value,
            "canonical JSON construction failed") from None
    return encoded


def _ensure_secret_safe(value: Any, field: str = "payload") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if SECRET_FIELD_RE.search(str(key)):
                raise WireSafetyError(
                    "SENSITIVE_FIELD_REJECTED", field, child,
                    "sensitive field is not accepted")
            if (str(key).lower() == "statement" and isinstance(child, str)
                    and SECRET_FIELD_RE.search(child)):
                raise WireSafetyError(
                    "SENSITIVE_FIELD_REJECTED", field, child,
                    "sensitive statement content is not accepted")
            _ensure_secret_safe(child, field)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _ensure_secret_safe(child, field)


@dataclass(frozen=True)
class NonceLexeme:
    decimal: str

    def __post_init__(self) -> None:
        if not isinstance(self.decimal, str) or re.fullmatch(r"[1-9][0-9]*", self.decimal) is None:
            raise WireSafetyError(
                "NONCE_INVALID", "nonce", self.decimal,
                "canonical decimal digits required")
        if int(self.decimal) > MAX_PROTOCOL_NONCE:
            raise WireSafetyError(
                "NONCE_INVALID", "nonce", self.decimal,
                "outside reviewed protocol range")

    def __str__(self) -> str:
        return self.decimal


def parse_nonce(value: Any) -> NonceLexeme:
    if not isinstance(value, str):
        raise WireSafetyError(
            "NONCE_INVALID", "nonce", value,
            "nonce must remain an exact decimal string")
    return NonceLexeme(value)


def validate_unix_ms(value: Any, *, field: str = "timestamp_ms") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise WireSafetyError(
            "TIME_INVALID", field, value,
            "finite explicit integer milliseconds required")
    if value < 0 or value > MAX_UNIX_MS:
        raise WireSafetyError(
            "TIME_INVALID", field, value,
            "outside reviewed Unix-ms range")
    return value


@dataclass(frozen=True)
class RawFramePolicy:
    name: str
    byte_limit: int
    character_limit: int
    single_line: bool = True
    printable_ascii: bool = True

    def __post_init__(self) -> None:
        if (not SAFE_ID_RE.fullmatch(self.name)
                or isinstance(self.byte_limit, bool)
                or isinstance(self.character_limit, bool)
                or not 1 <= self.byte_limit <= MAX_EXPORT_BYTES
                or not 1 <= self.character_limit <= self.byte_limit):
            raise WireSafetyError(
                "FRAME_POLICY_INVALID", "frame_policy", self.name,
                "reviewed positive limits required")


TCLK_ALPHA_FRAME_POLICY = RawFramePolicy(
    "TCLK_ALPHA_REVIEWED_ADAPTER", 4096, 4096)
SIGNER_TEXT_FRAME_POLICY = RawFramePolicy(
    "TECHNOCORE_SIGNER_TEXT", 16_384, 4096, printable_ascii=False)


def _gate_raw_frame(raw: bytes, policy: RawFramePolicy) -> str:
    if not isinstance(raw, bytes):
        raise WireSafetyError(
            "FRAME_TYPE_INVALID", "frame", raw, "raw bytes required")
    if len(raw) > policy.byte_limit:
        raise WireSafetyError(
            "FRAME_TOO_LARGE", "frame", raw, "byte limit exceeded")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        text = None
    if text is None:
        raise WireSafetyError(
            "FRAME_UTF8_INVALID", "frame", raw, "strict UTF-8 required") from None
    if policy.single_line and ("\n" in text or "\r" in text):
        raise WireSafetyError(
            "FRAME_MULTILINE", "frame", raw, "exactly one line required")
    if len(text) > policy.character_limit:
        raise WireSafetyError(
            "FRAME_TOO_LARGE", "frame", raw, "character limit exceeded")
    if policy.printable_ascii and any(ord(char) < 0x20 or ord(char) > 0x7E for char in text):
        raise WireSafetyError(
            "FRAME_CHARACTER_INVALID", "frame", raw,
            "printable ASCII required by adapter")
    if not text:
        raise WireSafetyError("FRAME_SYNTAX_INVALID", "frame", raw, "empty frame")
    return text


def gate_tclk_alpha_frame(raw: bytes) -> str:
    return _gate_raw_frame(raw, TCLK_ALPHA_FRAME_POLICY)


def decode_tclk_alpha_json_frame(raw: bytes) -> Mapping[str, Any]:
    """Gate transport bytes before the captured structured decoder runs."""
    text = gate_tclk_alpha_frame(raw)
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        value = None
    if value is None:
        raise WireSafetyError(
            "FRAME_SYNTAX_INVALID", "frame", raw,
            "structured decode failed") from None
    if not isinstance(value, dict):
        raise WireSafetyError(
            "FRAME_SYNTAX_INVALID", "frame", raw, "object frame required")
    _ensure_secret_safe(value, "frame")
    return MappingProxyType(dict(value))


def validate_room(room: Any) -> str:
    if (not isinstance(room, str) or ROOM_RE.fullmatch(room) is None
            or room.startswith(("p-", "mb-")) or "-p-" in room):
        raise WireSafetyError(
            "ROOM_INVALID", "room", room, "reviewed public room required")
    return room


@dataclass(frozen=True)
class SigningContext:
    room: str
    nonce: NonceLexeme
    text: str
    canonical_bytes: bytes
    text_sha256: str
    canonical_sha256: str

    def capability_binding(self, *, action_class: str, target: str,
                           revision: str, config_version: str) -> Mapping[str, str]:
        if action_class not in {"IDENTITY_SIGN", "RECEIPT_SIGN", "SIGNED_ROOM_POST"}:
            raise WireSafetyError(
                "ACTION_INVALID", "action_class", action_class,
                "signing action is not reviewed")
        if not REVISION_RE.fullmatch(revision):
            raise WireSafetyError(
                "REVISION_INVALID", "revision", revision,
                "exact lowercase Git revision required")
        if not target or not config_version:
            raise WireSafetyError(
                "BINDING_INVALID", "binding", None,
                "target and config version required")
        return MappingProxyType({
            "room": self.room,
            "nonce": self.nonce.decimal,
            "text_sha256": self.text_sha256,
            "canonical_sha256": self.canonical_sha256,
            "action_class": action_class,
            "target": target,
            "revision": revision,
            "config_version": config_version,
        })


def signing_capability_material(
    context: SigningContext, *, action_class: str, target: str,
    revision: str, config_version: str, purpose: str,
) -> Mapping[str, str]:
    """Build the sole exact capability material for a signing operation."""
    binding = context.capability_binding(
        action_class=action_class, target=target, revision=revision,
        config_version=config_version)
    if not isinstance(purpose, str) or not purpose:
        raise WireSafetyError("BINDING_INVALID", "purpose")
    subject = json.dumps(
        dict(binding), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return MappingProxyType({
        "subject": subject,
        "target": target,
        "payload": context.canonical_bytes.decode("utf-8"),
        "context": purpose,
    })


def build_signing_context(room: Any, nonce: Any, text: Any, *,
                          external_challenge: bytes | None = None) -> SigningContext:
    # Validation order is security relevant: target before nonce before content.
    checked_room = validate_room(room)
    checked_nonce = parse_nonce(nonce)
    if not isinstance(text, str):
        raise WireSafetyError(
            "TEXT_INVALID", "text", text, "text must be a string")
    encoded = text.encode("utf-8", errors="strict")
    _gate_raw_frame(encoded, SIGNER_TEXT_FRAME_POLICY)
    canonical = f"{checked_room}|{checked_nonce.decimal}|{text}".encode("utf-8")
    if external_challenge is not None:
        if not isinstance(external_challenge, bytes) or external_challenge != canonical:
            raise WireSafetyError(
                "SIGNING_CONTEXT_MISMATCH", "external_challenge",
                external_challenge, "local reconstruction does not match")
    return SigningContext(
        checked_room, checked_nonce, text, canonical,
        _sha256(encoded), _sha256(canonical))


@dataclass(frozen=True)
class CapabilityObservation:
    capability: str
    evidence_kind: CapabilityEvidenceKind
    status: str
    artifact_sha256: str | None = None

    def __post_init__(self) -> None:
        if not SAFE_ID_RE.fullmatch(self.capability):
            raise WireSafetyError(
                "CAPABILITY_INVALID", "capability", self.capability,
                "safe capability identifier required")
        allowed_statuses = {
            CapabilityEvidenceKind.DOCUMENTED_CAPABILITY: {"DOCUMENTED_ONLY"},
            CapabilityEvidenceKind.RUNTIME_OBSERVED_CAPABILITY: {
                "NOT_OBSERVED_OFFLINE", "RUNTIME_OBSERVED"},
        }
        if (not isinstance(self.evidence_kind, CapabilityEvidenceKind)
                or self.status not in allowed_statuses[self.evidence_kind]):
            raise WireSafetyError(
                "CAPABILITY_STATUS_INVALID", "status", self.status,
                "status must match the capability evidence kind")
        if (self.evidence_kind is CapabilityEvidenceKind.RUNTIME_OBSERVED_CAPABILITY
                and ((self.status == "RUNTIME_OBSERVED")
                     != (self.artifact_sha256 is not None))):
            raise WireSafetyError(
                "CAPABILITY_EVIDENCE_INVALID", "artifact_sha256",
                self.artifact_sha256,
                "runtime observation requires exact artifact evidence")
        if self.artifact_sha256 is not None and re.fullmatch(
                r"[0-9a-f]{64}", self.artifact_sha256) is None:
            raise WireSafetyError(
                "HASH_INVALID", "artifact_sha256", self.artifact_sha256,
                "lowercase SHA-256 required")


@dataclass(frozen=True)
class _LocalExportSnapshot:
    source_kind: ExportSourceKind
    source_id: str
    acquired_at_ms: int
    snapshot_sha256: str
    verifier_revision: str
    generation: str | None
    raw_snapshot: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.source_kind, ExportSourceKind):
            raise WireSafetyError(
                "EXPORT_SOURCE_INVALID", "source_kind", self.source_kind,
                "typed acquisition source required")
        if not SAFE_ID_RE.fullmatch(self.source_id):
            raise WireSafetyError(
                "EXPORT_SOURCE_INVALID", "source_id", self.source_id,
                "safe configured source identifier required")
        validate_unix_ms(self.acquired_at_ms, field="acquired_at_ms")
        if re.fullmatch(r"[0-9a-f]{64}", self.snapshot_sha256) is None:
            raise WireSafetyError(
                "HASH_INVALID", "snapshot_sha256", self.snapshot_sha256,
                "lowercase SHA-256 required")
        if not REVISION_RE.fullmatch(self.verifier_revision):
            raise WireSafetyError(
                "REVISION_INVALID", "verifier_revision", self.verifier_revision,
                "exact lowercase Git revision required")
        if (self.generation is not None
                and (not isinstance(self.generation, str)
                     or SAFE_ID_RE.fullmatch(self.generation) is None)):
            raise WireSafetyError(
                "GENERATION_INVALID", "generation", self.generation,
                "safe generation identifier required")
        if not isinstance(self.raw_snapshot, bytes) or len(self.raw_snapshot) > MAX_EXPORT_BYTES:
            raise WireSafetyError(
                "EXPORT_SIZE_INVALID", "snapshot", self.raw_snapshot,
                "bounded raw export bytes required")
        if _sha256(self.raw_snapshot) != self.snapshot_sha256:
            raise WireSafetyError(
                "HASH_INVALID", "snapshot_sha256", self.snapshot_sha256,
                "snapshot hash does not match captured bytes")

    def evidence(self) -> Mapping[str, Any]:
        return MappingProxyType({
            "status": EvidenceStatus.EXPORT_ACQUIRED.value,
            "source_kind": self.source_kind.value,
            "source_id": self.source_id,
            "acquired_at_ms": self.acquired_at_ms,
            "snapshot_sha256": self.snapshot_sha256,
            "verifier_revision": self.verifier_revision,
            "generation": self.generation,
            "raw_included": False,
        })


def acquire_export_fixture(raw: bytes, *, source_kind: ExportSourceKind,
                           source_id: str, acquired_at_ms: int,
                           verifier_revision: str,
                           generation: str | None = None) -> _LocalExportSnapshot:
    del raw, source_kind, source_id, acquired_at_ms, verifier_revision, generation
    raise PermissionError(
        "raw export fixtures are sealed; use evidence_authority observation services")


@dataclass(frozen=True)
class TranscriptCompletenessClaim:
    snapshot_sha256: str
    generation: str
    first_seq: str
    last_seq: str
    independently_verified: bool

    def __post_init__(self) -> None:
        if re.fullmatch(r"[0-9a-f]{64}", self.snapshot_sha256) is None:
            raise WireSafetyError(
                "HASH_INVALID", "snapshot_sha256", self.snapshot_sha256,
                "lowercase SHA-256 required")
        if not isinstance(self.generation, str) or not SAFE_ID_RE.fullmatch(self.generation):
            raise WireSafetyError(
                "GENERATION_INVALID", "generation", self.generation,
                "safe generation identifier required")
        parse_nonce(self.first_seq)
        parse_nonce(self.last_seq)
        if not isinstance(self.independently_verified, bool):
            raise WireSafetyError(
                "COMPLETENESS_CLAIM_INVALID", "independently_verified",
                self.independently_verified, "explicit boolean required")
        if self.independently_verified:
            raise PermissionError(
                "public completeness claims are descriptive only")


@dataclass(frozen=True)
class VenueMetadataEvidence:
    seq: str
    timestamp_ms: int | None
    generation: str | None
    provenance: EvidenceStatus
    signed_metadata: bool = False

    def __post_init__(self) -> None:
        if re.fullmatch(r"(?:0|[1-9][0-9]*)", self.seq) is None:
            raise WireSafetyError(
                "SEQ_INVALID", "seq", self.seq,
                "canonical decimal sequence required")
        if self.timestamp_ms is not None:
            validate_unix_ms(self.timestamp_ms, field="timestamp_ms")
        if (self.generation is not None
                and (not isinstance(self.generation, str)
                     or SAFE_ID_RE.fullmatch(self.generation) is None)):
            raise WireSafetyError(
                "GENERATION_INVALID", "generation", self.generation,
                "safe generation identifier required")
        if self.provenance not in {
                EvidenceStatus.VENUE_METADATA_OBSERVED,
                EvidenceStatus.DIRECT_VENUE_OBSERVATION,
                EvidenceStatus.VENUE_METADATA_PROVENANCE_VERIFIED}:
            raise WireSafetyError(
                "VENUE_PROVENANCE_INVALID", "provenance", self.provenance,
                "venue evidence status required")
        if self.signed_metadata is not False:
            raise WireSafetyError(
                "VENUE_SIGNATURE_SCOPE_INVALID", "signed_metadata",
                self.signed_metadata,
                "content signatures never cover venue metadata")


@dataclass(frozen=True)
class TranscriptAssessment:
    acquisition_status: EvidenceStatus
    structure_status: EvidenceStatus
    completeness_status: EvidenceStatus
    records: int
    first_seq: str | None
    last_seq: str | None
    issues: tuple[str, ...]
    venue_metadata: tuple[VenueMetadataEvidence, ...]

    def __post_init__(self) -> None:
        if self.completeness_status is EvidenceStatus.TRANSCRIPT_COMPLETENESS_VERIFIED:
            raise PermissionError(
                "verified completeness requires opaque verifier evidence")


def assess_export(snapshot: _LocalExportSnapshot, *,
                  completeness_claim: TranscriptCompletenessClaim | None = None,
                  acquisition_first_seq: str | None = None,
                  acquisition_last_seq: str | None = None,
                  truncation_indicated: bool = False) -> TranscriptAssessment:
    try:
        text = snapshot.raw_snapshot.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        text = None
    if text is None:
        raise WireSafetyError(
            "EXPORT_UTF8_INVALID", "snapshot", snapshot.raw_snapshot,
            "strict UTF-8 required") from None
    lines = text.splitlines()
    if len(lines) > MAX_EXPORT_RECORDS:
        raise WireSafetyError(
            "EXPORT_SIZE_INVALID", "snapshot", snapshot.raw_snapshot,
            "record limit exceeded")
    issues: list[str] = []
    sequences: list[int] = []
    sequence_lexemes: list[str] = []
    generations: set[str] = set()
    venue: list[VenueMetadataEvidence] = []
    for line in lines:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            issues.append("DECODE_INVALID")
            continue
        if not isinstance(record, dict):
            issues.append("RECORD_INVALID")
            continue
        _ensure_secret_safe(record, "record")
        raw_seq = record.get("seq")
        if isinstance(raw_seq, bool) or not isinstance(raw_seq, (int, str)):
            issues.append("SEQ_INVALID")
            continue
        seq_text = str(raw_seq)
        if re.fullmatch(r"(?:0|[1-9][0-9]*)", seq_text) is None:
            issues.append("SEQ_INVALID")
            continue
        seq = int(seq_text)
        sequences.append(seq)
        sequence_lexemes.append(seq_text)
        generation = record.get("generation")
        checked_generation: str | None = None
        if generation is not None:
            if not isinstance(generation, str) or not SAFE_ID_RE.fullmatch(generation):
                issues.append("GENERATION_INVALID")
            else:
                checked_generation = generation
                generations.add(generation)
        timestamp = record.get("ts")
        timestamp_ms: int | None = None
        if timestamp is not None:
            try:
                timestamp_ms = validate_unix_ms(timestamp, field="ts")
            except WireSafetyError:
                issues.append("TIME_INVALID")
        provenance = (
            EvidenceStatus.DIRECT_VENUE_OBSERVATION
            if snapshot.source_kind is ExportSourceKind.DIRECT_VENUE_SNAPSHOT
            else EvidenceStatus.VENUE_METADATA_OBSERVED)
        venue.append(VenueMetadataEvidence(
            seq_text, timestamp_ms, checked_generation, provenance, False))
    if len(sequences) != len(set(sequences)):
        issues.append("DUPLICATE_SEQUENCE")
    if any(current < previous for previous, current in zip(sequences, sequences[1:])):
        issues.append("SEQUENCE_REVERSAL")
    ordered = sorted(set(sequences))
    if any(current - previous > 1 for previous, current in zip(ordered, ordered[1:])):
        issues.append("SEQUENCE_GAP")
    if len(generations) > 1 or (
            snapshot.generation is not None and generations
            and generations != {snapshot.generation}):
        issues.append("GENERATION_INCONSISTENT")
    first = sequence_lexemes[0] if sequence_lexemes else None
    last = sequence_lexemes[-1] if sequence_lexemes else None
    if truncation_indicated:
        issues.append("TRUNCATION_INDICATED")
    if acquisition_first_seq is not None and first != acquisition_first_seq:
        issues.append("ACQUISITION_FIRST_BOUND_MISMATCH")
    if acquisition_last_seq is not None and last != acquisition_last_seq:
        issues.append("ACQUISITION_LAST_BOUND_MISMATCH")
    structural_issues = {
        "DECODE_INVALID", "RECORD_INVALID", "SEQ_INVALID", "TIME_INVALID",
        "GENERATION_INVALID", "DUPLICATE_SEQUENCE", "SEQUENCE_REVERSAL",
        "GENERATION_INCONSISTENT",
    }
    structure = (EvidenceStatus.TRANSCRIPT_INVALID
                 if structural_issues.intersection(issues)
                 else EvidenceStatus.TRANSCRIPT_STRUCT_VALID)
    # Caller claims are descriptive only.  Completeness authority is issued by
    # evidence_authority after registry-backed reviewed acquisition.
    del completeness_claim
    complete = False
    return TranscriptAssessment(
        EvidenceStatus.EXPORT_ACQUIRED, structure,
        EvidenceStatus.TRANSCRIPT_COMPLETENESS_VERIFIED if complete
        else EvidenceStatus.TRANSCRIPT_COMPLETENESS_UNVERIFIED,
        len(venue), first, last, tuple(dict.fromkeys(issues)), tuple(venue))


RAIL_ALIASES: Mapping[str, str] = MappingProxyType({
    "paper": "PAPER",
    "paperrail": "PAPER",
    "paper-rail": "PAPER",
    "btc": "BITCOIN",
    "bitcoin": "BITCOIN",
    "ln": "LIGHTNING",
    "lightning": "LIGHTNING",
})


def canonicalize_rail(rail_raw: Any) -> tuple[str, str]:
    if not isinstance(rail_raw, str) or not rail_raw.strip():
        raise WireSafetyError(
            "RAIL_INVALID", "rail", rail_raw, "non-empty rail required")
    raw = rail_raw
    canonical = RAIL_ALIASES.get(raw.strip().lower())
    if canonical is None:
        raise WireSafetyError(
            "RAIL_UNREVIEWED", "rail", rail_raw,
            "rail alias is not reviewed")
    return raw, canonical


@dataclass(frozen=True)
class RailObservation:
    rail_raw: str
    rail_canonical: str
    reference: str
    terminal_state: str
    crypto_status: RailCryptoStatus = RailCryptoStatus.UNVERIFIED
    independent_finality_verified: bool = False
    protocol_valid: bool = False

    def __post_init__(self) -> None:
        raw, canonical = canonicalize_rail(self.rail_raw)
        if raw != self.rail_raw or canonical != self.rail_canonical:
            raise WireSafetyError(
                "RAIL_CANONICAL_INVALID", "rail_canonical", self.rail_canonical,
                "canonical rail must be derived from the preserved raw alias")
        if not SAFE_ID_RE.fullmatch(self.reference):
            raise WireSafetyError(
                "RAIL_REFERENCE_INVALID", "reference", self.reference,
                "safe reference required")
        if self.terminal_state not in {"CLAIMED", "REFUNDED", "EXPIRED", "COMPLETED"}:
            raise WireSafetyError(
                "RAIL_STATE_INVALID", "terminal_state", self.terminal_state,
                "reviewed terminal state required")
        if not isinstance(self.crypto_status, RailCryptoStatus):
            raise WireSafetyError(
                "RAIL_CRYPTO_STATUS_INVALID", "crypto_status", self.crypto_status,
                "typed rail verification status required")
        if (not isinstance(self.independent_finality_verified, bool)
                or not isinstance(self.protocol_valid, bool)):
            raise WireSafetyError(
                "RAIL_EVIDENCE_INVALID", "rail_evidence", None,
                "explicit boolean observations required")
        if (self.crypto_status is RailCryptoStatus.RAIL_CRYPTO_VERIFIED
                or self.independent_finality_verified):
            raise PermissionError(
                "public rail observations cannot carry verified authority")

    @classmethod
    def observed(cls, rail: str, reference: str, terminal_state: str, *,
                 crypto_status: RailCryptoStatus = RailCryptoStatus.UNVERIFIED,
                 independent_finality_verified: bool = False,
                 protocol_valid: bool = False) -> "RailObservation":
        raw, canonical = canonicalize_rail(rail)
        if not SAFE_ID_RE.fullmatch(reference):
            raise WireSafetyError(
                "RAIL_REFERENCE_INVALID", "reference", reference,
                "safe reference required")
        if terminal_state not in {"CLAIMED", "REFUNDED", "EXPIRED", "COMPLETED"}:
            raise WireSafetyError(
                "RAIL_STATE_INVALID", "terminal_state", terminal_state,
                "reviewed terminal state required")
        return cls(raw, canonical, reference, terminal_state, crypto_status,
                   independent_finality_verified, protocol_valid)

    @property
    def economic_value_verified(self) -> bool:
        return False


@dataclass(frozen=True)
class TransferAttempt:
    attempt_id: str
    agreement_id: str
    rail: RailObservation
    quality: ActivityQuality

    def __post_init__(self) -> None:
        if not SAFE_ID_RE.fullmatch(self.attempt_id):
            raise WireSafetyError(
                "TRANSFER_ATTEMPT_INVALID", "attempt_id", self.attempt_id,
                "safe attempt identifier required")
        if re.fullmatch(r"[0-9a-f]{64}", self.agreement_id) is None:
            raise WireSafetyError(
                "AGREEMENT_ID_INVALID", "agreement_id", self.agreement_id,
                "lowercase SHA-256 identifier required")
        if not isinstance(self.rail, RailObservation):
            raise WireSafetyError(
                "RAIL_INVALID", "rail", self.rail,
                "typed rail observation required")
        if not isinstance(self.quality, ActivityQuality):
            raise WireSafetyError(
                "ACTIVITY_QUALITY_INVALID", "quality", self.quality,
                "typed activity quality required")


@dataclass(frozen=True)
class FinalityAssessment:
    transcript_state: str | None
    rail_status: EvidenceStatus | None
    finality_status: EvidenceStatus
    economic_value_status: str
    reason: str

    def __post_init__(self) -> None:
        if self.finality_status is EvidenceStatus.FINALITY_VERIFIED:
            raise PermissionError(
                "verified finality requires opaque rail-verifier evidence")


def assess_finality(transcript_state: str | None,
                    rail: RailObservation | None) -> FinalityAssessment:
    if rail is None:
        return FinalityAssessment(
            transcript_state, None, EvidenceStatus.FINALITY_UNVERIFIED,
            "ECONOMIC_VALUE_UNVERIFIED",
            "transcript terminal state has no independent rail evidence")
    rail_status = (EvidenceStatus.RAIL_CRYPTO_VERIFIED
                   if rail.crypto_status is RailCryptoStatus.RAIL_CRYPTO_VERIFIED
                   else EvidenceStatus.RAIL_OBSERVATION_PRESENT)
    # Public RailObservation fields are descriptive and never establish
    # authoritative economic finality.
    final = False
    return FinalityAssessment(
        transcript_state, rail_status,
        EvidenceStatus.FINALITY_VERIFIED if final
        else EvidenceStatus.FINALITY_UNVERIFIED,
        "ECONOMIC_VALUE_VERIFIED" if final else "ECONOMIC_VALUE_UNVERIFIED",
        "independent rail finality verified" if final
        else "rail observation does not establish economic finality")


def _decode_b64(value: str, field: str, expected_length: int) -> bytes:
    if not isinstance(value, str):
        raise WireSafetyError(
            "CRYPTO_FIELD_INVALID", field, value, "base64url string required")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error):
        raw = None
    if raw is None:
        raise WireSafetyError(
            "CRYPTO_FIELD_INVALID", field, value, "invalid base64url") from None
    if len(raw) != expected_length:
        raise WireSafetyError(
            "CRYPTO_FIELD_INVALID", field, value, "invalid encoded length")
    return raw


def _verify_signature(public_key_b64: str, signature_b64: str,
                      payload: bytes) -> EvidenceStatus:
    try:
        public_key = _decode_b64(public_key_b64, "public_key", 32)
        signature = _decode_b64(signature_b64, "signature", 64)
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except (WireSafetyError, InvalidSignature, ValueError):
        return EvidenceStatus.SIGNATURE_INVALID
    return EvidenceStatus.SIGNED_CONTENT_VERIFIED


def _proposal_payload(protocol: str, proposer_id: str, counterparty_id: str,
                      terms: Mapping[str, Any], rail_raw: str,
                      reference: str) -> bytes:
    for name, value in (("protocol", protocol), ("proposer_id", proposer_id),
                        ("counterparty_id", counterparty_id),
                        ("reference", reference)):
        if not isinstance(value, str) or SAFE_ID_RE.fullmatch(value) is None:
            raise WireSafetyError(
                "AGREEMENT_FIELD_INVALID", name, value,
                "safe agreement identifier required")
    if proposer_id == counterparty_id:
        raise WireSafetyError(
            "COUNTERPARTY_INVALID", "counterparty_id", counterparty_id,
            "counterparty must differ from proposer")
    if not isinstance(terms, Mapping):
        raise WireSafetyError(
            "AGREEMENT_TERMS_INVALID", "terms", terms,
            "structured terms required")
    _ensure_secret_safe(terms, "terms")
    _, rail_canonical = canonicalize_rail(rail_raw)
    return b"FLOP-AGREEMENT-PROPOSAL-V1|" + _canonical_json({
        "protocol": protocol,
        "proposer_id": proposer_id,
        "counterparty_id": counterparty_id,
        "terms": dict(terms),
        "rail": rail_canonical,
        "reference": reference,
    })


def agreement_proposal_signing_bytes(*, protocol: str, proposer_id: str,
                                     counterparty_id: str,
                                     terms: Mapping[str, Any], rail_raw: str,
                                     reference: str) -> bytes:
    return _proposal_payload(
        protocol, proposer_id, counterparty_id, terms, rail_raw, reference)


def recompute_offer_id(signing_bytes: bytes, signature_b64: str) -> str:
    signature = _decode_b64(signature_b64, "signature", 64)
    return _sha256(b"FLOP-OFFER-ID-V1|" + signing_bytes + b"|" + signature)


@dataclass(frozen=True)
class AgreementProposal:
    protocol: str
    proposer_id: str
    counterparty_id: str
    proposer_public_key_b64: str
    terms: Mapping[str, Any]
    rail_raw: str
    reference: str
    signature_b64: str
    offer_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.terms, Mapping):
            raise WireSafetyError(
                "AGREEMENT_TERMS_INVALID", "terms", self.terms,
                "structured terms required")
        _proposal_payload(
            self.protocol, self.proposer_id, self.counterparty_id,
            self.terms, self.rail_raw, self.reference)
        object.__setattr__(self, "terms", MappingProxyType(dict(self.terms)))

    def signing_bytes(self) -> bytes:
        return _proposal_payload(
            self.protocol, self.proposer_id, self.counterparty_id,
            self.terms, self.rail_raw, self.reference)


def _acceptance_payload(protocol: str, accepter_id: str, proposer_id: str,
                        offer_id: str, statement: str) -> bytes:
    for name, value in (("protocol", protocol), ("accepter_id", accepter_id),
                        ("proposer_id", proposer_id)):
        if not isinstance(value, str) or SAFE_ID_RE.fullmatch(value) is None:
            raise WireSafetyError(
                "AGREEMENT_FIELD_INVALID", name, value,
                "safe agreement identifier required")
    if accepter_id == proposer_id:
        raise WireSafetyError(
            "COUNTERPARTY_INVALID", "accepter_id", accepter_id,
            "counterparty must differ from proposer")
    if not isinstance(offer_id, str) or re.fullmatch(r"[0-9a-f]{64}", offer_id) is None:
        raise WireSafetyError(
            "OFFER_ID_INVALID", "offer_id", offer_id,
            "lowercase SHA-256 identifier required")
    if not isinstance(statement, str) or statement not in {"ACCEPT", "REJECT"}:
        raise WireSafetyError(
            "AGREEMENT_STATEMENT_INVALID", "statement", statement,
            "reviewed statement required")
    _ensure_secret_safe({"statement": statement}, "statement")
    return b"FLOP-AGREEMENT-ACCEPTANCE-V1|" + _canonical_json({
        "protocol": protocol,
        "accepter_id": accepter_id,
        "proposer_id": proposer_id,
        "offer_id": offer_id,
        "statement": statement,
    })


def agreement_acceptance_signing_bytes(*, protocol: str, accepter_id: str,
                                       proposer_id: str, offer_id: str,
                                       statement: str) -> bytes:
    return _acceptance_payload(
        protocol, accepter_id, proposer_id, offer_id, statement)


@dataclass(frozen=True)
class AgreementAcceptance:
    protocol: str
    accepter_id: str
    proposer_id: str
    accepter_public_key_b64: str
    offer_id: str
    statement: str
    signature_b64: str
    agreement_id: str

    def __post_init__(self) -> None:
        _acceptance_payload(
            self.protocol, self.accepter_id, self.proposer_id,
            self.offer_id, self.statement)

    def signing_bytes(self) -> bytes:
        return _acceptance_payload(
            self.protocol, self.accepter_id, self.proposer_id,
            self.offer_id, self.statement)


@dataclass(frozen=True)
class Agreement:
    protocol: str
    offer_id: str
    agreement_id: str
    proposer_id: str
    counterparty_id: str
    status: EvidenceStatus

    def __post_init__(self) -> None:
        for name, value in (("protocol", self.protocol),
                            ("proposer_id", self.proposer_id),
                            ("counterparty_id", self.counterparty_id)):
            if not isinstance(value, str) or SAFE_ID_RE.fullmatch(value) is None:
                raise WireSafetyError(
                    "AGREEMENT_FIELD_INVALID", name, value,
                    "safe agreement identifier required")
        for name, value in (("offer_id", self.offer_id),
                            ("agreement_id", self.agreement_id)):
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise WireSafetyError(
                    "AGREEMENT_ID_INVALID", name, value,
                    "lowercase SHA-256 identifier required")
        if self.proposer_id == self.counterparty_id:
            raise WireSafetyError(
                "COUNTERPARTY_INVALID", "counterparty_id", self.counterparty_id,
                "counterparty must differ from proposer")
        if self.status not in {
                EvidenceStatus.AGREEMENT_VERIFIED,
                EvidenceStatus.AGREEMENT_INVALID}:
            raise WireSafetyError(
                "AGREEMENT_STATUS_INVALID", "status", self.status,
                "agreement evidence status required")
        if self.status is EvidenceStatus.AGREEMENT_VERIFIED:
            raise PermissionError(
                "verified agreements require opaque verifier evidence")


def recompute_agreement_id(offer_id: str, acceptance_bytes: bytes,
                           signature_b64: str) -> str:
    signature = _decode_b64(signature_b64, "signature", 64)
    return _sha256(
        b"FLOP-AGREEMENT-ID-V1|" + offer_id.encode("ascii")
        + b"|" + acceptance_bytes + b"|" + signature)


@dataclass(frozen=True)
class AgreementVerification:
    proposal_signature: EvidenceStatus
    acceptance_signature: EvidenceStatus
    offer_id_status: str
    agreement_id_status: str
    counterparty_status: str
    semantics_status: str
    agreement_status: EvidenceStatus
    classification: str = TCLK_ALPHA_CLASSIFICATION

    def __post_init__(self) -> None:
        if self.agreement_status is EvidenceStatus.AGREEMENT_VERIFIED:
            raise PermissionError(
                "public agreement reports are descriptive only")

    def verified_agreement(
        self, proposal: AgreementProposal,
        acceptance: AgreementAcceptance,
    ) -> Agreement | None:
        del proposal, acceptance
        return None


def verify_tclk_alpha_agreement(
    proposal: AgreementProposal,
    acceptance: AgreementAcceptance,
) -> AgreementVerification:
    try:
        proposal_bytes = proposal.signing_bytes()
        proposal_signature = _verify_signature(
            proposal.proposer_public_key_b64, proposal.signature_b64,
            proposal_bytes)
    except (WireSafetyError, TypeError, ValueError):
        proposal_bytes = None
        proposal_signature = EvidenceStatus.SIGNATURE_INVALID
    try:
        acceptance_bytes = acceptance.signing_bytes()
        acceptance_signature = _verify_signature(
            acceptance.accepter_public_key_b64, acceptance.signature_b64,
            acceptance_bytes)
    except (WireSafetyError, TypeError, ValueError):
        acceptance_bytes = None
        acceptance_signature = EvidenceStatus.SIGNATURE_INVALID
    try:
        offer_matches = recompute_offer_id(
            proposal_bytes, proposal.signature_b64) == proposal.offer_id
    except (WireSafetyError, TypeError, ValueError):
        offer_matches = False
    try:
        agreement_matches = recompute_agreement_id(
            acceptance.offer_id, acceptance_bytes,
            acceptance.signature_b64) == acceptance.agreement_id
    except (WireSafetyError, TypeError, ValueError, UnicodeEncodeError):
        agreement_matches = False
    counterparties = (
        proposal.proposer_id != proposal.counterparty_id
        and acceptance.accepter_id == proposal.counterparty_id
        and acceptance.proposer_id == proposal.proposer_id
        and acceptance.offer_id == proposal.offer_id
        and acceptance.protocol == proposal.protocol)
    semantics = (
        proposal.terms.get("lock_statement") == "LOCKED"
        and acceptance.statement == "ACCEPT"
        and proposal.reference != "")
    valid = (
        proposal_signature is EvidenceStatus.SIGNED_CONTENT_VERIFIED
        and acceptance_signature is EvidenceStatus.SIGNED_CONTENT_VERIFIED
        and offer_matches and agreement_matches and counterparties and semantics)
    return AgreementVerification(
        proposal_signature, acceptance_signature,
        "OFFER_ID_VERIFIED" if offer_matches else "OFFER_ID_INVALID",
        "AGREEMENT_ID_VERIFIED" if agreement_matches else "AGREEMENT_ID_INVALID",
        "COUNTERPARTY_VERIFIED" if counterparties else "COUNTERPARTY_INVALID",
        "LOCK_SEMANTICS_VERIFIED" if semantics else "LOCK_SEMANTICS_INVALID",
        # This report is descriptive.  Only evidence_authority may issue an
        # opaque VerifiedAgreement for a valid result.
        EvidenceStatus.AGREEMENT_INVALID)


_READBACK_TRANSITIONS: Mapping[tuple[ReadBackStage, str], ReadBackStage] = MappingProxyType({
    (ReadBackStage.NOT_STARTED, "write_accepted"): ReadBackStage.WRITE_ACCEPTED,
    (ReadBackStage.WRITE_ACCEPTED, "read_back_observed"): ReadBackStage.READ_BACK_OBSERVED,
    (ReadBackStage.READ_BACK_OBSERVED, "decode_valid"): ReadBackStage.DECODE_VALID,
    (ReadBackStage.DECODE_VALID, "signature_valid"): ReadBackStage.SIGNATURE_VALID,
    (ReadBackStage.SIGNATURE_VALID, "state_replay_valid"): ReadBackStage.STATE_REPLAY_VALID,
    (ReadBackStage.STATE_REPLAY_VALID, "evidence_confirmed"): ReadBackStage.EVIDENCE_CONFIRMED,
})


def advance_readback(stage: ReadBackStage, event: str) -> ReadBackStage:
    try:
        return _READBACK_TRANSITIONS[(stage, event)]
    except KeyError as error:
        raise WireSafetyError(
            "READBACK_TRANSITION_INVALID", "event", event,
            "read-back evidence stages must be sequential") from error


@dataclass(frozen=True)
class EvidenceBundle:
    cryptographic: EvidenceStatus
    venue: EvidenceStatus
    transcript: EvidenceStatus
    agreement: EvidenceStatus
    settlement: EvidenceStatus
    finality: EvidenceStatus

    def __post_init__(self) -> None:
        authoritative_only = {
            EvidenceStatus.TRANSCRIPT_COMPLETENESS_VERIFIED,
            EvidenceStatus.AGREEMENT_VERIFIED,
            EvidenceStatus.RAIL_CRYPTO_VERIFIED,
            EvidenceStatus.FINALITY_VERIFIED,
        }
        if any(getattr(self, name) in authoritative_only for name in (
                "cryptographic", "venue", "transcript", "agreement",
                "settlement", "finality")):
            raise PermissionError(
                "verified claims require an opaque VerifiedEvidenceBundle")
        allowed = {
            "cryptographic": {
                EvidenceStatus.SIGNED_CONTENT_VERIFIED,
                EvidenceStatus.SIGNATURE_INVALID,
            },
            "venue": {
                EvidenceStatus.VENUE_METADATA_OBSERVED,
                EvidenceStatus.DIRECT_VENUE_OBSERVATION,
                EvidenceStatus.VENUE_METADATA_PROVENANCE_VERIFIED,
            },
            "transcript": {
                EvidenceStatus.TRANSCRIPT_STRUCT_VALID,
                EvidenceStatus.TRANSCRIPT_INVALID,
                EvidenceStatus.TRANSCRIPT_COMPLETENESS_VERIFIED,
                EvidenceStatus.TRANSCRIPT_COMPLETENESS_UNVERIFIED,
            },
            "agreement": {
                EvidenceStatus.AGREEMENT_VERIFIED,
                EvidenceStatus.AGREEMENT_INVALID,
            },
            "settlement": {
                EvidenceStatus.RAIL_OBSERVATION_PRESENT,
                EvidenceStatus.RAIL_CRYPTO_VERIFIED,
            },
            "finality": {
                EvidenceStatus.FINALITY_VERIFIED,
                EvidenceStatus.FINALITY_UNVERIFIED,
            },
        }
        for field, statuses in allowed.items():
            if getattr(self, field) not in statuses:
                raise WireSafetyError(
                    "EVIDENCE_LAYER_INVALID", field, getattr(self, field),
                    "status belongs to a different evidence layer")

    def as_public_evidence(self) -> Mapping[str, str]:
        # Public bundles are descriptive only; this projection can never emit
        # an authoritative verified finality claim.
        return MappingProxyType({
            "cryptographic": self.cryptographic.value,
            "venue": self.venue.value,
            "transcript": self.transcript.value,
            "agreement": self.agreement.value,
            "settlement": self.settlement.value,
            "finality": EvidenceStatus.FINALITY_UNVERIFIED.value,
        })


def wire_safety_readiness() -> Mapping[str, str | ReadinessState | ActivationState]:
    return MappingProxyType({
        "nonce_safe": ReadinessState.READY,
        "venue_provenance_ready": ReadinessState.READY,
        "export_verifier_ready": ReadinessState.READY,
        "signer_context_ready": ReadinessState.READY,
        "agreement_verifier_ready": ReadinessState.READY,
        "rail_verifier_ready": ReadinessState.DEFENSIVE_POLICY_READY,
        "evidence_readback_ready": ReadinessState.INTERFACE_READY,
        "classification": TCLK_ALPHA_CLASSIFICATION,
        "activation": ActivationState.DO_NOT_ACTIVATE,
    })
