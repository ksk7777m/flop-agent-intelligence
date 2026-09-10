"""Offline TCLK transcript and unsigned venue-metadata boundary."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import sys
import types
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator

from .did_key import did_from_public_key, public_key_from_did
from .tclk_schema_evidence import (COMMIT, SCHEMA_BLOB, SCHEMA_SHA256, SCHEMA_SIZE,
    SPEC_BLOB, SPEC_SHA256, SPEC_SIZE, load_pinned_evidence)

SCHEMA = "tclk-transcript-completeness-boundary-v1"
DOMAIN = "TCLK_TRANSCRIPT_COMPLETENESS_BOUNDARY\x00V1"
POLICY = "tclk-transcript-boundary-policy-v1"
MAX_TRANSCRIPT_BYTES = 256 * 1024
MAX_RECORD_BYTES = 8192
MAX_RECORDS = 256
MAX_MEMBERS = 16
MAX_STRING_CHARS = 5000
SAFE_INTEGER_MAX = 9_007_199_254_740_991
ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = ROOT / "vendor" / "tclk" / COMMIT / "schema" / "tclk1-frames.schema.json"
RECORD_FIELDS = frozenset({"room", "seq", "ts", "from", "nonce", "sig", "text", "generation"})
REQUIRED_RECORD_FIELDS = frozenset({"room", "seq", "ts", "from", "nonce", "sig", "text"})
DID = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$")
ROOM = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
NONCE = re.compile(r"^[1-9][0-9]{0,18}$")
SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
GENERATION = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$")
DIMENSION_IDS = (
    "TRANSPORT_COMPLETION", "TRANSCRIPT_PARSE", "RECORD_COUNT_BOUNDS",
    "FRAME_SCHEMA_CONFORMANCE", "SIGNATURE_VERIFICATION", "SIGNED_PAYLOAD_BINDING",
    "DUPLICATE_DETECTION", "REPLAY_VALIDATION", "VENUE_METADATA_PRESENCE",
    "VENUE_METADATA_TYPE_VALIDITY", "INTERNAL_SEQ_CONTINUITY",
    "INTERNAL_TIMESTAMP_ORDERING", "VENUE_METADATA_AUTHENTICITY", "LOWER_BOUND_COVERAGE",
    "UPPER_BOUND_COVERAGE", "EXPORT_TRUNCATION", "SOURCE_SET_COMPLETENESS",
    "TRANSCRIPT_COMPLETENESS", "FINAL_STATE_DERIVATION", "WINNER_VERIFICATION",
    "SETTLEMENT_VERIFICATION", "CURRENTNESS_FRESHNESS",
)


class _BoundaryError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _strict_object(raw: bytes) -> Mapping[str, Any]:
    if len(raw) > MAX_RECORD_BYTES:
        raise _BoundaryError("RECORD_TOO_LARGE")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise _BoundaryError("INVALID_UTF8") from None
    members = 0
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        nonlocal members
        members += len(items)
        if members > MAX_MEMBERS:
            raise _BoundaryError("MEMBER_LIMIT_EXCEEDED")
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise _BoundaryError("DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    def integer(value: str) -> int:
        if value == "-0" or len(value.lstrip("-")) > 16:
            raise _BoundaryError("NUMERIC_REPRESENTATION_INVALID")
        parsed = int(value)
        if abs(parsed) > SAFE_INTEGER_MAX:
            raise _BoundaryError("NUMERIC_REPRESENTATION_INVALID")
        return parsed
    def number(_value: str) -> Any:
        raise _BoundaryError("NUMERIC_REPRESENTATION_INVALID")
    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_int=integer,
                           parse_float=number, parse_constant=number)
    except _BoundaryError:
        raise
    except (ValueError, RecursionError):
        raise _BoundaryError("MALFORMED_JSON") from None
    if not isinstance(value, dict):
        raise _BoundaryError("RECORD_OBJECT_REQUIRED")
    nodes = 0
    def walk(child: Any, depth: int = 0) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > 96 or depth > 8:
            raise _BoundaryError("STRUCTURE_LIMIT_EXCEEDED")
        if isinstance(child, str):
            if len(child) > MAX_STRING_CHARS or any(0xD800 <= ord(c) <= 0xDFFF for c in child):
                raise _BoundaryError("STRING_INVALID")
        elif isinstance(child, list):
            if len(child) > 32: raise _BoundaryError("ARRAY_LIMIT_EXCEEDED")
            for item in child: walk(item, depth + 1)
        elif isinstance(child, dict):
            for key, item in child.items(): walk(key, depth + 1); walk(item, depth + 1)
        elif child is not None and type(child) not in (bool, int):
            raise _BoundaryError("VALUE_TYPE_INVALID")
    walk(value)
    return value


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not TIMESTAMP.fullmatch(value):
        raise _BoundaryError("TIMESTAMP_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise _BoundaryError("TIMESTAMP_INVALID") from None
    if parsed.tzinfo != timezone.utc or parsed.year < 1970:
        raise _BoundaryError("TIMESTAMP_INVALID")
    return parsed


def _policy() -> Draft202012Validator:
    load_pinned_evidence()
    raw = SNAPSHOT.read_bytes()
    if len(raw) != SCHEMA_SIZE or _digest(raw) != SCHEMA_SHA256:
        raise _BoundaryError("PINNED_POLICY_INTEGRITY_FAILED")
    schema = json.loads(raw)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _verify(did: str, signature: str, payload: bytes) -> bool:
    try:
        public = public_key_from_did(did)
        if not hmac.compare_digest(did, did_from_public_key(public)):
            return False
        raw_signature = base64.urlsafe_b64decode(signature + "==")
        if len(raw_signature) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(public).verify(raw_signature, payload)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def _dimensions() -> list[dict[str, str]]:
    fixed = {
        0: "UNKNOWN", 7: "EVIDENCE_REQUIRED", 12: "UNKNOWN", 13: "UNKNOWN",
        14: "UNKNOWN", 16: "EVIDENCE_REQUIRED", 18: "EVIDENCE_REQUIRED",
        19: "EVIDENCE_REQUIRED", 20: "EVIDENCE_REQUIRED", 21: "NOT_EVALUATED",
    }
    return [{"dimension": name, "state": fixed.get(index, "NOT_EVALUATED")}
            for index, name in enumerate(DIMENSION_IDS)]


def _base(raw: Any) -> dict[str, Any]:
    identity = ({"byte_length": len(raw), "sha256": _digest(raw)} if type(raw) is bytes
                else {"byte_length": None, "sha256": "UNAVAILABLE"})
    return {"schema": SCHEMA, "domain": DOMAIN, "content_label": "PUBLIC_MINIMIZED_TRANSCRIPT_EVIDENCE",
        "artifact_id": "", "policy_identity": {"policy_revision": POLICY,
            "repository": "flop-labs/tclk", "commit_sha": COMMIT, "protocol": "tclk/1",
            "schema": {"blob_sha1": SCHEMA_BLOB, "sha256": SCHEMA_SHA256, "byte_length": SCHEMA_SIZE},
            "signed_field_coverage": {"source": "SPEC.md", "blob_sha1": SPEC_BLOB,
                "sha256": SPEC_SHA256, "byte_length": SPEC_SIZE,
                "signed_fields": ["room", "nonce", "text"],
                "unsigned_venue_metadata": ["seq", "ts", "generation"]},
            "venue_metadata_profile": "LOCAL_EXPORT_PROFILE_SEQ_INTEGER_RFC3339_UTC_V1"},
        "input_evidence": identity,
        "resource_policy": {"basis": "LOCAL_RESOURCE_SAFETY_POLICY", "max_transcript_bytes": MAX_TRANSCRIPT_BYTES,
            "max_record_bytes": MAX_RECORD_BYTES, "max_records": MAX_RECORDS},
        "format": {"encoding": "STRICT_UTF8", "framing": "LF_TERMINATED_JSON_LINES",
            "bom": "REJECTED", "empty_lines": "REJECTED", "crlf": "REJECTED",
            "partial_final_line": "STRUCTURAL_PARSE_REQUIRED"},
        "dimensions": _dimensions(), "errors": [], "record_count": 0, "frame_evidence": [],
        "metadata_evidence": {"seq_presence": "NOT_EVALUATED", "timestamp_presence": "NOT_EVALUATED",
            "duplicate_state": "NOT_EVALUATED", "seq_state": "NOT_EVALUATED",
            "timestamp_state": "NOT_EVALUATED", "equal_timestamp_count": 0,
            "generation_state": "NOT_EVALUATED", "authenticity": "UNKNOWN", "signed": False},
        "sender_boundary": {"frame_from_matches_signing_key": "NOT_EVALUATED",
            "transport_sender_matches_frame_from": "NOT_EVALUATED",
            "transport_sender_authenticity": "UNKNOWN"},
        "replay_indicators": {"duplicate_export_indicator_count": 0,
            "nonce_scope_reuse_indicator_count": 0, "reordered_records": False,
            "replay_validation": "UNKNOWN", "maliciousness": "NOT_INFERRED",
            "authority": "DESCRIPTIVE_ONLY_NOT_DURABLE_REPLAY_STATE"},
        "termination_evidence": {"local_profile": "NOT_EVALUATED", "tail_state": "NOT_EVALUATED",
            "actual_truncation": "UNPROVEN"},
        "boundary_evidence": {"lower": "LOWER_BOUNDARY_UNKNOWN", "upper": "UPPER_BOUNDARY_UNKNOWN",
            "prefix_truncation": "EXPORT_MAY_BE_PREFIX_TRUNCATED",
            "suffix_truncation": "EXPORT_MAY_BE_SUFFIX_TRUNCATED"},
        "completeness": "NOT_EVALUATED", "replay": "REPLAY_EVIDENCE_REQUIRED",
        "omission_judgment": "ACTUAL_EVENT_OMISSION_UNPROVEN",
        "chronology": "NOT_VERIFIED", "generation_authenticity": "UNKNOWN",
        "final_state": "FINAL_STATE_DERIVATION_BLOCKED", "winner": "WINNER_UNRESOLVED",
        "settlement": "SETTLEMENT_UNVERIFIED", "currentness": "CURRENTNESS_NOT_EVALUATED",
        "reference_time": "REFERENCE_TIME_NOT_PROVIDED", "compatibility": "COMPATIBILITY_REVIEW_REQUIRED",
        "ready_to_act": False, "authorized_to_act": False, "live_action_enabled": False,
        "production_api": {"classification": "SAFE_PURE_VALIDATOR", "network": "NONE",
            "filesystem": "FIXED_READ_ONLY", "side_effect": "NONE", "authority": "NONE"}}


def _seal(result: dict[str, Any]) -> Mapping[str, Any]:
    body = {key: value for key, value in result.items() if key != "artifact_id"}
    result["artifact_id"] = _digest(_canonical({"domain": DOMAIN, **body}))
    return result


def assess_tclk_transcript(transcript_bytes: bytes) -> Mapping[str, Any]:
    """Assess a bounded JSONL transcript without completeness or action authority."""
    result = _base(transcript_bytes); dims = result["dimensions"]
    def state(index: int, value: str) -> None: dims[index]["state"] = value
    def fail(code: str, dimension: int, completeness: str = "INCOMPLETE") -> Mapping[str, Any]:
        state(dimension, "FAILED"); result["errors"] = [code]; result["completeness"] = completeness
        state(17, "INCOMPLETE" if completeness == "INCOMPLETE" else "UNKNOWN")
        for index in (18, 19, 20): state(index, "EVIDENCE_REQUIRED")
        state(21, "NOT_EVALUATED")
        return _seal(result)
    try:
        validator = _policy()
    except Exception:
        return fail("PINNED_POLICY_INTEGRITY_FAILED", 1, "UNKNOWN")
    if type(transcript_bytes) is not bytes:
        return fail("INPUT_TYPE_INVALID", 2)
    if not transcript_bytes:
        return fail("EMPTY_TRANSCRIPT", 2)
    if len(transcript_bytes) > MAX_TRANSCRIPT_BYTES:
        return fail("TRANSCRIPT_TOO_LARGE", 2)
    state(2, "VERIFIED")
    if transcript_bytes.startswith(b"\xef\xbb\xbf"):
        return fail("BOM_REJECTED", 1)
    if b"\r" in transcript_bytes:
        return fail("CRLF_REJECTED", 1)
    terminator_missing = not transcript_bytes.endswith(b"\n")
    if terminator_missing:
        result["termination_evidence"] = {"local_profile": "FINAL_RECORD_TERMINATOR_MISSING",
            "tail_state": "POSSIBLE_TAIL_TRUNCATION", "actual_truncation": "UNPROVEN"}
        result["errors"] = ["FINAL_RECORD_TERMINATOR_MISSING"]
        lines = transcript_bytes.split(b"\n")
    else:
        result["termination_evidence"] = {"local_profile": "CONFORMANT",
            "tail_state": "NO_STRUCTURAL_TRUNCATION_OBSERVED", "actual_truncation": "UNPROVEN"}
        lines = transcript_bytes[:-1].split(b"\n")
    if any(not line for line in lines): return fail("EMPTY_RECORD", 1)
    if len(lines) > MAX_RECORDS: return fail("RECORD_COUNT_EXCEEDED", 2)
    records: list[Mapping[str, Any]] = []
    try:
        for line in lines: records.append(_strict_object(line))
    except _BoundaryError as error:
        if terminator_missing and error.code == "MALFORMED_JSON":
            result["termination_evidence"] = {"local_profile": "FAILED",
                "tail_state": "TRUNCATION_STRUCTURALLY_DETECTED",
                "actual_truncation": "STRUCTURALLY_DETECTED"}
            return fail("PARTIAL_FINAL_RECORD", 1)
        return fail(error.code, 1)
    state(1, "VERIFIED"); result["record_count"] = len(records)
    seqs: list[int] = []; times: list[datetime] = []; signed_hashes: list[str] = []
    signature_states: list[str] = []; nonce_scopes: list[tuple[str, str, str]] = []
    generations: set[str] = set()
    for index, record in enumerate(records):
        if set(record) - RECORD_FIELDS or not REQUIRED_RECORD_FIELDS.issubset(record):
            return fail("RECORD_FIELD_SET_INVALID", 1)
        seq = record["seq"]
        if type(seq) is not int or seq < 0 or seq > SAFE_INTEGER_MAX:
            return fail("SEQ_INVALID", 9)
        try: timestamp = _timestamp(record["ts"])
        except _BoundaryError as error: return fail(error.code, 9)
        for field, pattern in (("room", ROOM), ("from", DID), ("nonce", NONCE), ("sig", SIGNATURE)):
            if not isinstance(record[field], str) or not pattern.fullmatch(record[field]):
                return fail("SIGNED_RECORD_FIELD_INVALID", 5)
        if "generation" in record and (not isinstance(record["generation"], str)
                or not GENERATION.fullmatch(record["generation"])):
            return fail("GENERATION_INVALID", 9)
        if "generation" in record: generations.add(record["generation"])
        text = record["text"]
        if not isinstance(text, str) or not text.startswith("tclk1 ") or len(text) > 4096:
            return fail("SIGNED_FRAME_INVALID", 3)
        try: frame = _strict_object(text[6:].encode("ascii"))
        except (UnicodeEncodeError, _BoundaryError): return fail("SIGNED_FRAME_INVALID", 3)
        if (list(validator.iter_errors(frame)) or frame.get("from") != record["from"]
                or not hmac.compare_digest(text[6:].encode("ascii"), _canonical(frame))):
            return fail("FRAME_SCHEMA_OR_SENDER_BINDING_FAILED", 3)
        frame_type = frame.get("type")
        if not isinstance(frame_type, str): return fail("SIGNED_FRAME_INVALID", 3)
        payload = f'{record["room"]}|{record["nonce"]}|{text}'.encode("utf-8")
        sig_state = "VERIFIED" if _verify(record["from"], record["sig"], payload) else "FAILED"
        signed_hash = _digest(payload)
        metadata = {key: record[key] for key in ("seq", "ts", "generation") if key in record}
        metadata_hash = _digest(_canonical(metadata))
        result["frame_evidence"].append({"index": index, "frame_type": frame_type,
            "record_sha256": _digest(lines[index]), "signed_payload_sha256": signed_hash,
            "venue_metadata_sha256": metadata_hash,
            "signature": sig_state, "signed_payload_binding": "VERIFIED",
            "venue_metadata_binding": "UNKNOWN"})
        seqs.append(seq); times.append(timestamp); signed_hashes.append(signed_hash)
        signature_states.append(sig_state)
        nonce_scopes.append((record["from"], record["room"], record["nonce"]))
    state(3, "VERIFIED"); state(5, "VERIFIED")
    result["sender_boundary"] = {"frame_from_matches_signing_key":
        "VERIFIED" if all(item == "VERIFIED" for item in signature_states) else "FAILED",
        "transport_sender_matches_frame_from": "VERIFIED",
        "transport_sender_authenticity": "UNKNOWN"}
    state(4, "VERIFIED" if all(item == "VERIFIED" for item in signature_states) else "FAILED")
    if "FAILED" in signature_states: result["errors"].append("SIGNATURE_INVALID")
    result["metadata_evidence"]["seq_presence"] = "PRESENT_ALL"
    result["metadata_evidence"]["timestamp_presence"] = "PRESENT_ALL"
    state(8, "VERIFIED"); state(9, "VERIFIED")
    duplicate_seq = len(seqs) != len(set(seqs)); duplicate_frame = len(signed_hashes) != len(set(signed_hashes))
    result["metadata_evidence"]["duplicate_state"] = ("DUPLICATE_DETECTED" if duplicate_seq or duplicate_frame else "NONE_OBSERVED")
    state(6, "FAILED" if duplicate_seq or duplicate_frame else "VERIFIED")
    regression = any(b < a for a, b in zip(seqs, seqs[1:]))
    gap = any(b != a + 1 for a, b in zip(seqs, seqs[1:]))
    seq_state = "INTERNAL_SEQ_REGRESSION" if regression else "INTERNAL_SEQ_GAP_DETECTED" if gap else "INTERNAL_SEQ_CONTIGUOUS"
    result["metadata_evidence"]["seq_state"] = seq_state
    state(10, "FAILED" if regression else "INCOMPLETE" if gap else "VERIFIED")
    time_regression = any(b < a for a, b in zip(times, times[1:]))
    equal_times = sum(b == a for a, b in zip(times, times[1:]))
    result["metadata_evidence"]["timestamp_state"] = "TIMESTAMP_REGRESSION" if time_regression else "INTERNAL_TIMESTAMP_NONDECREASING"
    result["metadata_evidence"]["equal_timestamp_count"] = equal_times
    state(11, "FAILED" if time_regression else "VERIFIED")
    result["metadata_evidence"]["generation_state"] = ("MULTIPLE_UNSIGNED_GENERATION_LABELS_OBSERVED" if len(generations) > 1
        else "SINGLE_GENERATION_OBSERVED" if generations else "GENERATION_ABSENT")
    result["replay_indicators"] = {"duplicate_export_indicator_count": len(signed_hashes) - len(set(signed_hashes)),
        "nonce_scope_reuse_indicator_count": len(nonce_scopes) - len(set(nonce_scopes)),
        "reordered_records": regression, "replay_validation": "UNKNOWN",
        "maliciousness": "NOT_INFERRED", "authority": "DESCRIPTIVE_ONLY_NOT_DURABLE_REPLAY_STATE"}
    state(12, "UNKNOWN"); state(13, "UNKNOWN"); state(14, "UNKNOWN"); state(15, "UNKNOWN")
    state(0, "UNKNOWN"); state(7, "EVIDENCE_REQUIRED"); state(16, "EVIDENCE_REQUIRED")
    incomplete = (terminator_missing or duplicate_seq or duplicate_frame or regression or gap
        or time_regression or len(generations) > 1)
    result["completeness"] = "INCOMPLETE" if incomplete else "UNKNOWN"
    state(17, "INCOMPLETE" if incomplete else "UNKNOWN")
    for index in (18, 19, 20): state(index, "EVIDENCE_REQUIRED")
    state(21, "NOT_EVALUATED")
    return _seal(result)


__all__ = ["assess_tclk_transcript"]


class _SealedModule(types.ModuleType):
    _protected = frozenset({"SCHEMA", "DOMAIN", "POLICY", "ROOT", "SNAPSHOT", "RECORD_FIELDS",
        "REQUIRED_RECORD_FIELDS", "MAX_TRANSCRIPT_BYTES", "MAX_RECORD_BYTES", "MAX_RECORDS",
        "did_from_public_key", "public_key_from_did", "Ed25519PublicKey", "load_pinned_evidence",
        "_verify", "_policy", "_strict_object", "_timestamp",
        "_canonical", "_digest", "_base", "_seal", "assess_tclk_transcript", "__all__"})
    def __setattr__(self, name: str, value: Any) -> None:
        if name in self._protected and name in self.__dict__:
            raise AttributeError("transcript boundary dependencies are sealed")
        super().__setattr__(name, value)


sys.modules[__name__].__class__ = _SealedModule
