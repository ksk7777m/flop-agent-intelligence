"""Offline offer-global winner and accept-race epistemic boundary."""
from __future__ import annotations

import hashlib
import hmac
import json
import sys
import types
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from .tclk_accept_conformance import package_status
from .tclk_accept_preflight import MAX_INPUT_BYTES as MAX_OFFER_BYTES, validate_tclk_accept_preflight
from .tclk_schema_evidence import COMMIT, SCHEMA_BLOB, SCHEMA_SHA256, SPEC_BLOB, SPEC_SHA256
from .tclk_transcript_boundary import (_canonical as _frame_canonical,
    DID, GENERATION, MAX_TRANSCRIPT_BYTES, NONCE, ROOM, SAFE_INTEGER_MAX, SIGNATURE, RECORD_FIELDS,
    REQUIRED_RECORD_FIELDS, _strict_object, _timestamp, _verify, assess_tclk_transcript)

SCHEMA = "tclk-offer-global-winner-boundary-v1"
DOMAIN = "TCLK_OFFER_GLOBAL_WINNER_BOUNDARY\x00V1"
POLICY = "tclk-offer-global-winner-policy-v1"
MAX_CANDIDATES = 64
ROOT = Path(__file__).resolve().parents[2]
RESULT_SCHEMA = ROOT / "schemas" / "tclk-offer-global-winner-boundary.v1.json"
STAGE_IDS = (
    "OFFER_IDENTITY", "OFFER_SCHEMA_VALIDITY", "CANDIDATE_STRUCTURE",
    "OFFICIAL_ACCEPT_SCHEMA", "SIGNATURE_VALIDITY", "SIGNER_FRAME_FROM_BINDING",
    "OFFER_ACCEPT_REF_BINDING", "CONTRACT_DERIVATION", "REPLAY_EVIDENCE",
    "TRANSCRIPT_SOURCE_COMPLETENESS", "BOUNDARY_COMPLETENESS",
    "VENUE_METADATA_AUTHENTICITY", "VENUE_ORDERING_AUTHENTICITY",
    "GENERATION_CONSISTENCY", "CANDIDATE_ELIGIBILITY", "CONTRACT_LOCAL_VIEW",
    "GLOBAL_WINNER_UNIQUENESS", "RACE_CLASSIFICATION", "LOCK_OBSERVATION",
    "SETTLEMENT_VERIFICATION", "MALICIOUSNESS_ASSESSMENT", "REPUTATION_IMPACT",
    "READINESS", "AUTHORIZATION",
)
STAGE_ALLOWED = (
    frozenset({"NOT_EVALUATED", "VERIFIED"}),
    frozenset({"NOT_EVALUATED", "UNKNOWN", "VERIFIED"}),
    *[frozenset({"NOT_EVALUATED", "VERIFIED", "FAILED"}) for _ in range(6)],
    frozenset({"EVIDENCE_REQUIRED"}), frozenset({"EVIDENCE_REQUIRED"}),
    frozenset({"UNKNOWN"}), frozenset({"UNKNOWN"}), frozenset({"UNKNOWN"}),
    frozenset({"NOT_EVALUATED", "UNKNOWN", "FAILED"}),
    frozenset({"NOT_EVALUATED", "VERIFIED", "FAILED"}),
    frozenset({"NOT_EVALUATED", "VERIFIED", "FAILED"}),
    frozenset({"EVIDENCE_REQUIRED"}),
    frozenset({"NOT_EVALUATED", "CANDIDATE_ONLY", "UNRESOLVED"}),
    frozenset({"UNKNOWN"}), frozenset({"EVIDENCE_REQUIRED"}),
    frozenset({"NOT_ESTABLISHED"}), frozenset({"NO_IMPACT"}),
    frozenset({"BLOCKED"}), frozenset({"BLOCKED"}),
)
TOP_FIELDS = frozenset({"schema", "domain", "content_label", "artifact_id",
    "policy_identity", "input_evidence", "field_report_currentness", "stages", "errors",
    "candidate_count", "candidates", "offer_view", "ordering", "evidence_boundary",
    "winner", "race", "lock", "settlement", "maliciousness", "reputation",
    "compatibility", "ready_to_act", "authorized_to_act", "live_action_enabled",
    "production_api"})
CANDIDATE_FIELDS = frozenset({"ordinal", "candidate_identity", "signed_identity",
    "preflight_identity", "offer_schema_validity", "structural_validity", "official_accept_schema",
    "signature_validity", "signer_frame_from_binding", "offer_accept_ref_binding",
    "contract_derivation", "replay", "eligibility", "contract_local_view",
    "race_classification"})


class _BoundaryError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _identity(value: Any) -> Mapping[str, Any]:
    return ({"byte_length": len(value), "sha256": _digest(value)} if type(value) is bytes
            else {"byte_length": None, "sha256": "UNAVAILABLE"})


def _stages() -> list[dict[str, Any]]:
    fixed = {8: "EVIDENCE_REQUIRED", 9: "EVIDENCE_REQUIRED", 10: "UNKNOWN",
        11: "UNKNOWN", 12: "UNKNOWN", 16: "EVIDENCE_REQUIRED",
        18: "UNKNOWN", 19: "EVIDENCE_REQUIRED", 20: "NOT_ESTABLISHED",
        21: "NO_IMPACT", 22: "BLOCKED", 23: "BLOCKED"}
    return [{"ordinal": index + 1, "stage_id": name,
             "state": fixed.get(index, "NOT_EVALUATED")}
            for index, name in enumerate(STAGE_IDS)]


def _base(offer: Any, transcript: Any) -> dict[str, Any]:
    historical_id = package_status()["artifact_id"]
    return {"schema": SCHEMA, "domain": DOMAIN,
        "content_label": "PUBLIC_MINIMIZED_DESCRIPTIVE_EVIDENCE", "artifact_id": "",
        "policy_identity": {"policy_revision": POLICY, "repository": "flop-labs/tclk",
            "commit_sha": COMMIT, "schema_blob_sha1": SCHEMA_BLOB,
            "schema_sha256": SCHEMA_SHA256, "spec_blob_sha1": SPEC_BLOB,
            "spec_sha256": SPEC_SHA256,
            "preflight_policy": "offline-tclk-accept-preflight-policy-v1",
            "transcript_policy": "tclk-transcript-boundary-policy-v1"},
        "input_evidence": {"offer": _identity(offer), "transcript": _identity(transcript),
            "hash_role": "CONTENT_FINGERPRINT_NOT_AUTHORITY"},
        "field_report_currentness": {"historical_artifact_id": historical_id,
            "historical_state": "POINT_IN_TIME_REPORTED_NOT_CURRENTLY_ATTESTED",
            "correction_state": "CORRECTION_REPORTED",
            "source_evidence": "SOURCE_EVIDENCE_REQUIRED",
            "currentness": "CURRENTNESS_NOT_CONFIRMED",
            "quantitative_impact": "QUANTITATIVE_IMPACT_UNRESOLVED",
            "supersession": "SUPERSESSION_REVIEW_REQUIRED", "conflict": "NOT_ESTABLISHED"},
        "stages": _stages(), "errors": [], "candidate_count": 0, "candidates": [],
        "offer_view": {"identity": "OBSERVED", "schema_validity": "NOT_EVALUATED"},
        "ordering": {"local": "NOT_EVALUATED", "venue_authenticity": "UNKNOWN",
            "chronology": "NOT_VERIFIED"},
        "evidence_boundary": {"transcript": "NOT_EVALUATED", "source": "EVIDENCE_REQUIRED",
            "lower": "UNKNOWN", "upper": "UNKNOWN", "generation": "NOT_EVALUATED",
            "replay": "EVIDENCE_REQUIRED"},
        "winner": "GLOBAL_WINNER_UNRESOLVED", "race": "WINNER_UNRESOLVED",
        "lock": "LOCK_NOT_VERIFIED", "settlement": "SETTLEMENT_UNVERIFIED",
        "maliciousness": "NOT_ESTABLISHED", "reputation": "NO_IMPACT",
        "compatibility": "COMPATIBILITY_REVIEW_REQUIRED", "ready_to_act": False,
        "authorized_to_act": False, "live_action_enabled": False,
        "production_api": {"classification": "SAFE_PURE_VALIDATOR", "network": "NONE",
            "filesystem": "FIXED_READ_ONLY", "side_effect": "NONE", "authority": "NONE",
            "winner_verified_reachable": False, "race_lost_reachable": False}}


def _seal(result: dict[str, Any]) -> Mapping[str, Any]:
    body = {key: value for key, value in result.items() if key != "artifact_id"}
    result["artifact_id"] = _digest(_canonical({"domain": DOMAIN, **body}))
    _validate_result(result)
    return result


def _validate_result(value: Any) -> None:
    try:
        schema = json.loads(RESULT_SCHEMA.read_bytes())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)
    except Exception:
        raise _BoundaryError("RESULT_SCHEMA_INVALID") from None
    if not isinstance(value, Mapping) or set(value) != TOP_FIELDS:
        raise _BoundaryError("RESULT_FIELD_SET_INVALID")
    stages = value.get("stages")
    if not isinstance(stages, list) or len(stages) != len(STAGE_IDS):
        raise _BoundaryError("STAGE_GRAMMAR_INVALID")
    for index, (item, expected) in enumerate(zip(stages, STAGE_IDS), 1):
        if (not isinstance(item, Mapping) or set(item) != {"ordinal", "stage_id", "state"}
                or type(item["ordinal"]) is not int or item["ordinal"] != index
                or item["stage_id"] != expected or item["state"] not in STAGE_ALLOWED[index - 1]):
            raise _BoundaryError("STAGE_GRAMMAR_INVALID")
    candidates = value.get("candidates")
    if (type(value.get("candidate_count")) is not int or not isinstance(candidates, list)
            or value["candidate_count"] != len(candidates) or len(candidates) > MAX_CANDIDATES):
        raise _BoundaryError("CANDIDATE_GRAMMAR_INVALID")
    for index, item in enumerate(candidates):
        if (not isinstance(item, Mapping) or set(item) != CANDIDATE_FIELDS
                or type(item["ordinal"]) is not int or item["ordinal"] != index):
            raise _BoundaryError("CANDIDATE_GRAMMAR_INVALID")
        if (item["structural_validity"] not in {"VALID", "INVALID", "NOT_ACCEPT"}
                or item["official_accept_schema"] not in {"CONFORMANT", "NONCONFORMANT"}
                or item["signature_validity"] not in {"VALID", "INVALID"}
                or item["signer_frame_from_binding"] not in {"MATCH", "FAILED"}
                or item["offer_accept_ref_binding"] not in {"NOT_EVALUATED", "BOUND", "FAILED"}
                or item["contract_derivation"] not in {"NOT_EVALUATED", "MATCH", "MISMATCH"}
                or item["replay"] != "REPLAY_EVIDENCE_REQUIRED"
                or item["eligibility"] not in {"LOCAL_ACCEPT_ELIGIBLE", "LOCAL_ACCEPT_INELIGIBLE",
                    "MISSING_CONTRACT", "CONTRACT_TYPE_INVALID", "CONTRACT_DERIVATION_FAILED",
                    "SIGNATURE_INVALID"}):
            raise _BoundaryError("CANDIDATE_GRAMMAR_INVALID")
        eligible = (item["structural_validity"] == "VALID"
            and item["official_accept_schema"] == "CONFORMANT"
            and item["signature_validity"] == "VALID"
            and item["signer_frame_from_binding"] == "MATCH"
            and item["offer_accept_ref_binding"] == "BOUND"
            and item["contract_derivation"] == "MATCH")
        if ((item["eligibility"] == "LOCAL_ACCEPT_ELIGIBLE") is not eligible
                or (item["contract_local_view"] == "VALID") is not eligible
                or item["race_classification"] not in {"WINNER_UNRESOLVED", "RACE_LOSS_CANDIDATE"}
                or (item["race_classification"] == "RACE_LOSS_CANDIDATE" and not eligible)):
            raise _BoundaryError("CANDIDATE_STATE_CONTRADICTION")
        expected_candidate = _digest(_canonical({"domain": DOMAIN,
            **{key: child for key, child in item.items() if key != "candidate_identity"}}))
        if not isinstance(item["candidate_identity"], str) or not hmac.compare_digest(
                item["candidate_identity"], expected_candidate):
            raise _BoundaryError("CANDIDATE_IDENTITY_MISMATCH")
    race_candidates = sum(item["race_classification"] == "RACE_LOSS_CANDIDATE"
                          for item in candidates)
    if (value["winner"] != "GLOBAL_WINNER_UNRESOLVED"
            or value["race"] not in {"WINNER_UNRESOLVED", "RACE_LOSS_CANDIDATES_PRESENT"}
            or (value["race"] == "RACE_LOSS_CANDIDATES_PRESENT") is not (race_candidates >= 2)
            or value["lock"] != "LOCK_NOT_VERIFIED"
            or value["settlement"] != "SETTLEMENT_UNVERIFIED"
            or value["maliciousness"] != "NOT_ESTABLISHED"
            or value["reputation"] != "NO_IMPACT"
            or value["ready_to_act"] is not False
            or value["authorized_to_act"] is not False
            or value["live_action_enabled"] is not False):
        raise _BoundaryError("EPISTEMIC_ESCALATION_REJECTED")
    field_report = value["field_report_currentness"]
    if (not isinstance(field_report, Mapping) or set(field_report) != {"historical_artifact_id",
            "historical_state", "correction_state", "source_evidence", "currentness",
            "quantitative_impact", "supersession", "conflict"}
            or field_report.get("historical_artifact_id") != package_status()["artifact_id"]
            or field_report.get("historical_state") != "POINT_IN_TIME_REPORTED_NOT_CURRENTLY_ATTESTED"
            or field_report.get("correction_state") != "CORRECTION_REPORTED"
            or field_report.get("source_evidence") != "SOURCE_EVIDENCE_REQUIRED"
            or field_report.get("currentness") != "CURRENTNESS_NOT_CONFIRMED"
            or field_report.get("quantitative_impact") != "QUANTITATIVE_IMPACT_UNRESOLVED"
            or field_report.get("supersession") != "SUPERSESSION_REVIEW_REQUIRED"
            or field_report.get("conflict") != "NOT_ESTABLISHED"):
        raise _BoundaryError("FIELD_REPORT_AUTHORITY_INVALID")
    body = {key: value[key] for key in TOP_FIELDS if key != "artifact_id"}
    expected = _digest(_canonical({"domain": DOMAIN, **body}))
    if not isinstance(value["artifact_id"], str) or not hmac.compare_digest(value["artifact_id"], expected):
        raise _BoundaryError("ARTIFACT_IDENTITY_MISMATCH")


def _records(raw: bytes) -> list[Mapping[str, Any]]:
    if type(raw) is not bytes:
        raise _BoundaryError("INPUT_TYPE_INVALID")
    if len(raw) > MAX_TRANSCRIPT_BYTES:
        raise _BoundaryError("TRANSCRIPT_LIMIT_EXCEEDED")
    if not raw or not raw.endswith(b"\n") or b"\r" in raw:
        raise _BoundaryError("TRANSCRIPT_PROFILE_INVALID")
    lines = raw[:-1].split(b"\n")
    if len(lines) > MAX_CANDIDATES:
        raise _BoundaryError("CANDIDATE_LIMIT_EXCEEDED")
    try:
        records = [_strict_object(line) for line in lines]
    except Exception:
        raise _BoundaryError("TRANSCRIPT_PARSE_FAILED") from None
    if any(set(record) - RECORD_FIELDS or not REQUIRED_RECORD_FIELDS.issubset(record)
           for record in records):
        raise _BoundaryError("TRANSCRIPT_PARSE_FAILED")
    for record in records:
        if (type(record.get("seq")) is not int or not 0 <= record["seq"] <= SAFE_INTEGER_MAX
                or any(not isinstance(record.get(name), str) or not pattern.fullmatch(record[name])
                       for name, pattern in (("room", ROOM), ("from", DID), ("nonce", NONCE),
                                             ("sig", SIGNATURE)))
                or ("generation" in record and (not isinstance(record["generation"], str)
                    or not GENERATION.fullmatch(record["generation"])) )):
            raise _BoundaryError("TRANSCRIPT_PARSE_FAILED")
        try:
            _timestamp(record.get("ts"))
        except Exception:
            raise _BoundaryError("TRANSCRIPT_PARSE_FAILED") from None
    return records


def _candidate(ordinal: int, record: Mapping[str, Any], offer_bytes: bytes) -> dict[str, Any]:
    structural = "INVALID"
    frame: Mapping[str, Any] = {}
    raw_frame = b""
    text = record.get("text")
    if isinstance(text, str) and text.startswith("tclk1 "):
        try:
            raw_frame = text[6:].encode("ascii")
            frame = _strict_object(raw_frame)
            structural = "VALID" if frame.get("type") == "accept" else "NOT_ACCEPT"
        except Exception:
            structural = "INVALID"
    preflight = validate_tclk_accept_preflight(offer_bytes, raw_frame)
    disposition = preflight["overall_disposition"]
    official = ("CONFORMANT" if preflight["schema_conformance"]["accept"] == "CONFORMANT"
                else "NONCONFORMANT")
    sender_match = (isinstance(record.get("from"), str)
        and isinstance(frame.get("from"), str) and record["from"] == frame["from"])
    payload = b""
    signature = "INVALID"
    if all(isinstance(record.get(name), str) for name in ("room", "nonce", "from", "sig")) and isinstance(text, str):
        payload = f'{record["room"]}|{record["nonce"]}|{text}'.encode("utf-8")
        signature = "VALID" if sender_match and _verify(record["from"], record["sig"], payload) else "INVALID"
    error = preflight["errors"][0] if preflight["errors"] else ""
    if error == "ACCEPT_CONTRACT_MISSING": eligibility = "MISSING_CONTRACT"
    elif error in {"ACCEPT_CONTRACT_NULL", "ACCEPT_CONTRACT_EMPTY", "ACCEPT_CONTRACT_WRONG_TYPE",
                   "ACCEPT_CONTRACT_PATTERN_INVALID"}: eligibility = "CONTRACT_TYPE_INVALID"
    elif error == "ACCEPT_CONTRACT_RECOMPUTATION_MISMATCH": eligibility = "CONTRACT_DERIVATION_FAILED"
    elif signature != "VALID": eligibility = "SIGNATURE_INVALID"
    elif disposition == "PREFLIGHT_PASS": eligibility = "LOCAL_ACCEPT_ELIGIBLE"
    else: eligibility = "LOCAL_ACCEPT_INELIGIBLE"
    candidate = {"ordinal": ordinal, "candidate_identity": "",
        "signed_identity": _digest(payload) if payload else "UNAVAILABLE",
        "preflight_identity": preflight["artifact_id"],
        "offer_schema_validity": preflight["schema_conformance"]["offer"],
        "structural_validity": structural,
        "official_accept_schema": official, "signature_validity": signature,
        "signer_frame_from_binding": "MATCH" if sender_match else "FAILED",
        "offer_accept_ref_binding": preflight["reference_binding"],
        "contract_derivation": preflight["contract_equality"],
        "replay": "REPLAY_EVIDENCE_REQUIRED", "eligibility": eligibility,
        "contract_local_view": "VALID" if eligibility == "LOCAL_ACCEPT_ELIGIBLE" else "INVALID",
        "race_classification": "WINNER_UNRESOLVED"}
    candidate["candidate_identity"] = _digest(_canonical({"domain": DOMAIN,
        **{key: value for key, value in candidate.items() if key != "candidate_identity"}}))
    return candidate


def assess_offer_global_winner(offer_bytes: bytes, transcript_bytes: bytes) -> Mapping[str, Any]:
    """Assess local accept candidates without issuing a global winner or action authority."""
    result = _base(offer_bytes, transcript_bytes); stages = result["stages"]
    def mark(index: int, state: str) -> None: stages[index]["state"] = state
    if type(offer_bytes) is not bytes or type(transcript_bytes) is not bytes:
        result["errors"] = ["INPUT_TYPE_INVALID"]
        return _seal(result)
    if len(offer_bytes) > MAX_OFFER_BYTES:
        result["errors"] = ["OFFER_LIMIT_EXCEEDED"]
        return _seal(result)
    transcript = assess_tclk_transcript(transcript_bytes)
    result["evidence_boundary"]["transcript"] = transcript["completeness"]
    result["evidence_boundary"]["generation"] = transcript["metadata_evidence"]["generation_state"]
    try:
        records = _records(transcript_bytes)
    except _BoundaryError as error:
        result["errors"] = [error.code]
        return _seal(result)
    candidates = [_candidate(index, record, offer_bytes) for index, record in enumerate(records)]
    result["candidates"] = candidates; result["candidate_count"] = len(candidates)
    offer_valid = bool(candidates) and all(item["offer_schema_validity"] == "CONFORMANT"
        for item in candidates)
    result["offer_view"]["schema_validity"] = "VALID" if offer_valid else "NOT_ESTABLISHED"
    mark(0, "VERIFIED"); mark(1, "VERIFIED" if offer_valid else "UNKNOWN")
    mark(2, "VERIFIED" if all(item["structural_validity"] == "VALID" for item in candidates) else "FAILED")
    mark(3, "VERIFIED" if all(item["official_accept_schema"] == "CONFORMANT" for item in candidates) else "FAILED")
    mark(4, "VERIFIED" if all(item["signature_validity"] == "VALID" for item in candidates) else "FAILED")
    mark(5, "VERIFIED" if all(item["signer_frame_from_binding"] == "MATCH" for item in candidates) else "FAILED")
    mark(6, "VERIFIED" if all(item["offer_accept_ref_binding"] == "BOUND" for item in candidates) else "FAILED")
    mark(7, "VERIFIED" if all(item["contract_derivation"] == "MATCH" for item in candidates) else "FAILED")
    eligible = sum(item["eligibility"] == "LOCAL_ACCEPT_ELIGIBLE" for item in candidates)
    mark(13, "FAILED" if transcript["metadata_evidence"]["generation_state"] == "MULTIPLE_UNSIGNED_GENERATION_LABELS_OBSERVED" else "UNKNOWN")
    mark(14, "VERIFIED" if eligible == len(candidates) and eligible else "FAILED")
    mark(15, "VERIFIED" if eligible else "FAILED")
    result["ordering"]["local"] = "LOCAL_ORDER_OBSERVED"
    if eligible > 1:
        result["race"] = "RACE_LOSS_CANDIDATES_PRESENT"
        for item in candidates:
            if item["eligibility"] == "LOCAL_ACCEPT_ELIGIBLE":
                item["race_classification"] = "RACE_LOSS_CANDIDATE"
                item["candidate_identity"] = _digest(_canonical({"domain": DOMAIN,
                    **{key: value for key, value in item.items() if key != "candidate_identity"}}))
    mark(17, "CANDIDATE_ONLY" if eligible > 1 else "UNRESOLVED")
    return _seal(result)


__all__ = ["assess_offer_global_winner"]


class _SealedModule(types.ModuleType):
    _protected = frozenset({"SCHEMA", "DOMAIN", "POLICY", "MAX_CANDIDATES", "MAX_OFFER_BYTES",
        "MAX_TRANSCRIPT_BYTES", "ROOT", "RESULT_SCHEMA", "STAGE_IDS", "STAGE_ALLOWED",
        "TOP_FIELDS", "CANDIDATE_FIELDS", "RECORD_FIELDS", "REQUIRED_RECORD_FIELDS", "DID",
        "GENERATION", "NONCE", "ROOM", "SAFE_INTEGER_MAX", "SIGNATURE",
        "COMMIT", "SCHEMA_BLOB", "SCHEMA_SHA256",
        "SPEC_BLOB", "SPEC_SHA256", "Path", "Draft202012Validator", "package_status",
        "validate_tclk_accept_preflight",
        "assess_tclk_transcript", "_strict_object", "_frame_canonical", "_verify", "_canonical",
        "_digest", "_identity", "_stages", "_base", "_seal", "_validate_result", "_records", "_timestamp",
        "_candidate", "assess_offer_global_winner", "__all__"})
    def __setattr__(self, name: str, value: Any) -> None:
        if name in self._protected and name in self.__dict__:
            raise AttributeError("offer-global winner dependencies are sealed")
        super().__setattr__(name, value)


sys.modules[__name__].__class__ = _SealedModule
