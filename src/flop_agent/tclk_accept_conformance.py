"""Offline, descriptive TCLK accept conformance boundary.

The official schema revision is not retained locally.  This module can identify
obvious accept-shaped conformance failures under a fixed candidate field policy,
but it cannot verify an official schema, signature, replay state, winner, lock,
settlement, or payer behavior.
"""
from __future__ import annotations

import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Mapping

SCHEMA_VERSION = "tclk-accept-conformance-v1"
POLICY_VERSION = "tclk-accept-observatory-policy-v1"
DOMAIN = "TCLK_ACCEPT_CONFORMANCE\x00V1"
CANONICAL_ENCODING = "SORTED_ASCII_JSON_V1"
MAX_COUNT = 2**63 - 1

STAGE_FIELDS = ("FRAME_OBSERVED", "FRAME_TYPE_ACCEPT", "ACCEPT_SCHEMA_VALID",
    "SIGNATURE_VALID", "REPLAY_VALID", "CONTRACT_PRESENT",
    "CONTRACT_DERIVATION_VERIFIED", "EVIDENCE_COMPLETE",
    "OFFER_GLOBAL_VIEW_COMPLETE", "OFFER_GLOBAL_WINNER_VERIFIED",
    "LOCK_OBSERVED", "SETTLEMENT_VERIFIED")
STAGE_VALUES = frozenset({"VERIFIED", "REJECTED", "NOT_EVALUATED",
                          "EVIDENCE_REQUIRED", "UNKNOWN"})
CLASSIFICATIONS = frozenset({"LOCAL_ACCEPT_SAFETY_PROFILE_PASS",
    "REPORTED_POLICY_MISSING_CONTRACT", "REPORTED_POLICY_CONTRACT_TYPE_REJECTED",
    "LOCAL_PROFILE_UNKNOWN_FIELDS_REJECTED", "MALFORMED_FRAME", "NOT_ACCEPT_FRAME"})
PROJECTION_FIELDS = frozenset({"schema", "domain", "status", "content_label",
    "observation_id", "policy_identity", "classification_basis",
    "official_schema_conformance", "local_safety_profile", "structural_facts",
    "primary_classification", "independent_failures", "validation_stages",
    "reputation_dimensions", "payer_abandonment", "accepted_contract_count_eligible",
    "ready_to_act", "authorized_to_act", "live_action_enabled", "policy_version"})
PACKAGE_FIELDS = frozenset({"schema", "domain", "status", "content_label", "artifact_id",
    "policy_identity", "issue_reference", "field_report", "historical_reclassification",
    "reputation_boundary", "runtime_compatibility", "action_state", "policy_version"})
POLICY_FIELDS = frozenset({"protocol", "official_repository", "schema_path",
    "schema_version", "source_revision", "document_hash", "required_contract_policy",
    "additional_properties_policy", "contract_derivation_spec", "extraction_state",
    "canonical_encoding", "classification_policy_revision", "local_safety_profile_revision",
    "validation_stage_order"})
FACT_FIELDS = frozenset({"frame_parsed", "type_field_observed", "type_equals_accept",
    "contract_field_present", "contract_value_kind", "contract_value_empty",
    "contract_value_profile_shape", "unknown_fields_observed"})
REPUTATION_FIELDS = frozenset({"protocol_conformance", "signature_failure",
    "replay_behavior", "race_outcome", "evidence_completeness",
    "settlement_completion", "malicious_behavior_evidence"})
_CONTRACT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")


class ConformanceError(ValueError):
    def __init__(self, code: str, field: str):
        super().__init__(f"{code}: {field}")
        self.code = code
        self.metadata = MappingProxyType({"field": field})


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, RecursionError):
        raise ConformanceError("CANONICAL_VALUE_INVALID", "value") from None


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def schema_policy_identity() -> Mapping[str, str]:
    return MappingProxyType({
        "protocol": "TCLK/1", "official_repository": "FLOP_LABS_TCLK",
        "schema_path": "schema/tclk1-frames.schema.json",
        "schema_version": "OFFICIAL_SCHEMA_VERSION_UNVERIFIED",
        "source_revision": "REVISION_UNVERIFIED", "document_hash": "HASH_UNVERIFIED",
        "required_contract_policy": "REPORTED_REQUIRED_NOT_ATTESTED",
        "additional_properties_policy": "UNVERIFIED",
        "contract_derivation_spec": "SOURCE_EVIDENCE_REQUIRED",
        "extraction_state": "OFFICIAL_SCHEMA_REVISION_REQUIRED",
        "canonical_encoding": CANONICAL_ENCODING,
        "classification_policy_revision": "TCLK_ACCEPT_CLASSIFICATION_POLICY_V2",
        "local_safety_profile_revision": "TCLK_ACCEPT_LOCAL_SAFETY_PROFILE_V1",
        "validation_stage_order": _digest(list(STAGE_FIELDS)),
    })


def _stage_list(states: Mapping[str, str]) -> list[dict[str, Any]]:
    return [{"ordinal": ordinal, "stage_id": stage_id, "state": states[stage_id]}
            for ordinal, stage_id in enumerate(STAGE_FIELDS, 1)]


def _project(primary: str, facts: Mapping[str, Any], failures: list[str]) -> Mapping[str, Any]:
    policy = dict(schema_policy_identity())
    profile_status = ("NOT_APPLICABLE" if primary in {"MALFORMED_FRAME", "NOT_ACCEPT_FRAME"}
                      else "PASS" if primary == "LOCAL_ACCEPT_SAFETY_PROFILE_PASS" else "FAIL")
    profile = {"revision": "TCLK_ACCEPT_LOCAL_SAFETY_PROFILE_V1",
        "status": profile_status, "official_schema_authority": False}
    states = {stage: "NOT_EVALUATED" for stage in STAGE_FIELDS}
    states["FRAME_OBSERVED"] = "VERIFIED" if facts["frame_parsed"] else "REJECTED"
    if facts["frame_parsed"]:
        states["FRAME_TYPE_ACCEPT"] = "VERIFIED" if facts["type_equals_accept"] is True else "REJECTED"
    if facts["type_equals_accept"] is True:
        states["ACCEPT_SCHEMA_VALID"] = "EVIDENCE_REQUIRED"
        states["CONTRACT_PRESENT"] = "VERIFIED" if facts["contract_field_present"] else "REJECTED"
        states["EVIDENCE_COMPLETE"] = "EVIDENCE_REQUIRED"
        if profile_status == "PASS":
            states["SIGNATURE_VALID"] = "EVIDENCE_REQUIRED"
            states["REPLAY_VALID"] = "EVIDENCE_REQUIRED"
            states["CONTRACT_DERIVATION_VERIFIED"] = "EVIDENCE_REQUIRED"
            states["OFFER_GLOBAL_VIEW_COMPLETE"] = "EVIDENCE_REQUIRED"
            states["OFFER_GLOBAL_WINNER_VERIFIED"] = "EVIDENCE_REQUIRED"
            states["LOCK_OBSERVED"] = "UNKNOWN"
    reputation = {"protocol_conformance": "UNKNOWN",
        "signature_failure": "NOT_ESTABLISHED", "replay_behavior": "NOT_ESTABLISHED",
        "race_outcome": "UNRESOLVED", "evidence_completeness": "INCOMPLETE",
        "settlement_completion": "UNVERIFIED", "malicious_behavior_evidence": "ABSENT"}
    body = {"schema": SCHEMA_VERSION, "domain": DOMAIN, "status": "DESCRIPTIVE_ONLY",
        "content_label": "UNTRUSTED_CONTENT", "policy_identity": policy,
        "classification_basis": "REPORTED_UNATTESTED_POLICY",
        "official_schema_conformance": "OFFICIAL_SCHEMA_CONFORMANCE_UNKNOWN",
        "local_safety_profile": profile,
        "structural_facts": {name: facts[name] for name in FACT_FIELDS},
        "primary_classification": primary,
        "independent_failures": list(failures),
        "validation_stages": _stage_list(states),
        "reputation_dimensions": reputation,
        "payer_abandonment": "PAYER_ABANDONMENT_UNPROVEN",
        "accepted_contract_count_eligible": False, "ready_to_act": False,
        "authorized_to_act": False, "live_action_enabled": False,
        "policy_version": POLICY_VERSION}
    body["observation_id"] = _digest({"domain": DOMAIN, "schema": SCHEMA_VERSION,
        "canonical_encoding": CANONICAL_ENCODING, **body})
    return validate_projection(body)


def classify_frame(frame: Any) -> Mapping[str, Any]:
    """Classify only fixed, obvious shape facts; never claim official validity."""
    facts = {"frame_parsed": isinstance(frame, Mapping), "type_field_observed": False,
        "type_equals_accept": None, "contract_field_present": False,
        "contract_value_kind": "NOT_EVALUATED", "contract_value_empty": None,
        "contract_value_profile_shape": "NOT_EVALUATED", "unknown_fields_observed": False}
    if not isinstance(frame, Mapping):
        return _project("MALFORMED_FRAME", facts, ["FRAME_PARSE_FAILED"])
    facts["type_field_observed"] = "type" in frame
    facts["type_equals_accept"] = frame.get("type") == "accept" if "type" in frame else None
    facts["unknown_fields_observed"] = bool(set(frame) - {"type", "contract"})
    if facts["type_equals_accept"] is not True:
        return _project("NOT_ACCEPT_FRAME", facts, ["TYPE_NOT_ACCEPT"])
    facts["contract_field_present"] = "contract" in frame
    failures = []
    if facts["unknown_fields_observed"]:
        failures.append("LOCAL_PROFILE_UNKNOWN_FIELDS")
    if not facts["contract_field_present"]:
        facts["contract_value_kind"] = "MISSING"
        failures.append("REPORTED_POLICY_MISSING_CONTRACT")
        primary = ("LOCAL_PROFILE_UNKNOWN_FIELDS_REJECTED" if facts["unknown_fields_observed"]
                   else "REPORTED_POLICY_MISSING_CONTRACT")
        return _project(primary, facts, failures)
    contract = frame["contract"]
    facts["contract_value_kind"] = "NULL" if contract is None else "STRING" if isinstance(contract, str) else "OTHER"
    facts["contract_value_empty"] = (not contract) if isinstance(contract, str) else None
    if not isinstance(contract, str) or not contract or _CONTRACT.fullmatch(contract) is None:
        facts["contract_value_profile_shape"] = "REJECTED"
        failures.append("REPORTED_POLICY_CONTRACT_TYPE_REJECTED")
    else:
        facts["contract_value_profile_shape"] = "ACCEPTED"
    if failures:
        primary = ("LOCAL_PROFILE_UNKNOWN_FIELDS_REJECTED" if facts["unknown_fields_observed"]
                   else "REPORTED_POLICY_CONTRACT_TYPE_REJECTED")
        return _project(primary, facts, failures)
    return _project("LOCAL_ACCEPT_SAFETY_PROFILE_PASS", facts, [])


def validate_projection(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != PROJECTION_FIELDS:
        raise ConformanceError("FIELD_SET_INVALID", "projection")
    if (value["schema"] != SCHEMA_VERSION or value["domain"] != DOMAIN
            or value["status"] != "DESCRIPTIVE_ONLY"
            or value["content_label"] != "UNTRUSTED_CONTENT"
            or value["policy_version"] != POLICY_VERSION):
        raise ConformanceError("HEADER_INVALID", "projection")
    policy = value["policy_identity"]
    if not isinstance(policy, Mapping) or set(policy) != POLICY_FIELDS or dict(policy) != dict(schema_policy_identity()):
        raise ConformanceError("POLICY_IDENTITY_INVALID", "policy_identity")
    if value["classification_basis"] != "REPORTED_UNATTESTED_POLICY" or value["official_schema_conformance"] != "OFFICIAL_SCHEMA_CONFORMANCE_UNKNOWN":
        raise ConformanceError("OFFICIAL_SCHEMA_EVIDENCE_REQUIRED", "official_schema_conformance")
    profile = value["local_safety_profile"]
    if not isinstance(profile, Mapping) or set(profile) != {"revision", "status", "official_schema_authority"} or profile.get("revision") != "TCLK_ACCEPT_LOCAL_SAFETY_PROFILE_V1" or profile.get("status") not in {"PASS", "FAIL", "NOT_APPLICABLE"} or profile.get("official_schema_authority") is not False:
        raise ConformanceError("LOCAL_PROFILE_INVALID", "local_safety_profile")
    facts = value["structural_facts"]
    if not isinstance(facts, Mapping) or set(facts) != FACT_FIELDS:
        raise ConformanceError("STRUCTURAL_FACTS_INVALID", "structural_facts")
    for name in ("frame_parsed", "type_field_observed", "contract_field_present", "unknown_fields_observed"):
        if type(facts[name]) is not bool: raise ConformanceError("BOOLEAN_INVALID", name)
    if facts["type_equals_accept"] is not None and type(facts["type_equals_accept"]) is not bool:
        raise ConformanceError("BOOLEAN_INVALID", "type_equals_accept")
    if facts["contract_value_empty"] is not None and type(facts["contract_value_empty"]) is not bool:
        raise ConformanceError("BOOLEAN_INVALID", "contract_value_empty")
    if facts["contract_value_kind"] not in {"NOT_EVALUATED", "MISSING", "NULL", "STRING", "OTHER"}:
        raise ConformanceError("STRUCTURAL_FACTS_INVALID", "contract_value_kind")
    if facts["contract_value_profile_shape"] not in {"NOT_EVALUATED", "ACCEPTED", "REJECTED"}:
        raise ConformanceError("STRUCTURAL_FACTS_INVALID", "contract_value_profile_shape")
    if (not facts["frame_parsed"] and (facts["type_field_observed"] or facts["type_equals_accept"] is not None
            or facts["contract_field_present"] or facts["unknown_fields_observed"])):
        raise ConformanceError("STRUCTURAL_FACTS_CONTRADICTION", "frame_parsed")
    if not facts["type_field_observed"] and facts["type_equals_accept"] is not None:
        raise ConformanceError("STRUCTURAL_FACTS_CONTRADICTION", "type_equals_accept")
    if not facts["contract_field_present"] and (facts["contract_value_empty"] is not None
            or facts["contract_value_profile_shape"] != "NOT_EVALUATED"
            or facts["contract_value_kind"] not in {"NOT_EVALUATED", "MISSING"}):
        raise ConformanceError("STRUCTURAL_FACTS_CONTRADICTION", "contract_field_present")
    if facts["contract_field_present"] and (facts["contract_value_kind"] not in {"NULL", "STRING", "OTHER"}
            or facts["contract_value_profile_shape"] not in {"ACCEPTED", "REJECTED"}):
        raise ConformanceError("STRUCTURAL_FACTS_CONTRADICTION", "contract_field_present")
    if ((facts["contract_value_kind"] == "STRING") != (facts["contract_value_empty"] is not None)):
        raise ConformanceError("STRUCTURAL_FACTS_CONTRADICTION", "contract_value_empty")
    if facts["contract_value_profile_shape"] == "ACCEPTED" and not (facts["contract_value_kind"] == "STRING" and facts["contract_value_empty"] is False):
        raise ConformanceError("STRUCTURAL_FACTS_CONTRADICTION", "contract_value_profile_shape")
    stages = value["validation_stages"]
    if not isinstance(stages, list) or len(stages) != len(STAGE_FIELDS):
        raise ConformanceError("STAGE_GRAMMAR_INVALID", "validation_stages")
    stage_map = {}
    for ordinal, stage in enumerate(stages, 1):
        if not isinstance(stage, Mapping) or set(stage) != {"ordinal", "stage_id", "state"}:
            raise ConformanceError("STAGE_GRAMMAR_INVALID", "validation_stages")
        if type(stage["ordinal"]) is not int or stage["ordinal"] != ordinal or stage["stage_id"] != STAGE_FIELDS[ordinal - 1] or stage["stage_id"] in stage_map or stage["state"] not in STAGE_VALUES:
            raise ConformanceError("STAGE_GRAMMAR_INVALID", "validation_stages")
        stage_map[stage["stage_id"]] = stage["state"]
    if stage_map["ACCEPT_SCHEMA_VALID"] == "VERIFIED":
        raise ConformanceError("OFFICIAL_SCHEMA_EVIDENCE_REQUIRED", "validation_stages")
    for name in ("SIGNATURE_VALID", "REPLAY_VALID", "CONTRACT_DERIVATION_VERIFIED",
                 "OFFER_GLOBAL_WINNER_VERIFIED", "SETTLEMENT_VERIFIED"):
        if stage_map[name] == "VERIFIED": raise ConformanceError("SEALED_EVIDENCE_REQUIRED", name)
    if value["primary_classification"] not in CLASSIFICATIONS:
        raise ConformanceError("CLASSIFICATION_INVALID", "primary_classification")
    primary = value["primary_classification"]
    failures = value["independent_failures"]
    if not isinstance(failures, list) or len(failures) != len(set(failures)) or any(item not in {"FRAME_PARSE_FAILED", "TYPE_NOT_ACCEPT", "LOCAL_PROFILE_UNKNOWN_FIELDS", "REPORTED_POLICY_MISSING_CONTRACT", "REPORTED_POLICY_CONTRACT_TYPE_REJECTED"} for item in failures):
        raise ConformanceError("FAILURE_SET_INVALID", "independent_failures")
    if not facts["frame_parsed"]:
        expected_primary, expected_failures, expected_profile = "MALFORMED_FRAME", ["FRAME_PARSE_FAILED"], "NOT_APPLICABLE"
    elif facts["type_equals_accept"] is not True:
        expected_primary, expected_failures, expected_profile = "NOT_ACCEPT_FRAME", ["TYPE_NOT_ACCEPT"], "NOT_APPLICABLE"
    else:
        expected_failures = []
        if facts["unknown_fields_observed"]: expected_failures.append("LOCAL_PROFILE_UNKNOWN_FIELDS")
        if not facts["contract_field_present"]: expected_failures.append("REPORTED_POLICY_MISSING_CONTRACT")
        elif facts["contract_value_profile_shape"] == "REJECTED": expected_failures.append("REPORTED_POLICY_CONTRACT_TYPE_REJECTED")
        expected_profile = "FAIL" if expected_failures else "PASS"
        expected_primary = ("LOCAL_PROFILE_UNKNOWN_FIELDS_REJECTED" if facts["unknown_fields_observed"]
            else "REPORTED_POLICY_MISSING_CONTRACT" if not facts["contract_field_present"]
            else "REPORTED_POLICY_CONTRACT_TYPE_REJECTED" if expected_failures
            else "LOCAL_ACCEPT_SAFETY_PROFILE_PASS")
    if primary != expected_primary or failures != expected_failures or profile["status"] != expected_profile:
        raise ConformanceError("PROJECTION_CONTRADICTION", "classification")
    expected_states = {stage: "NOT_EVALUATED" for stage in STAGE_FIELDS}
    expected_states["FRAME_OBSERVED"] = "VERIFIED" if facts["frame_parsed"] else "REJECTED"
    if facts["frame_parsed"]: expected_states["FRAME_TYPE_ACCEPT"] = "VERIFIED" if facts["type_equals_accept"] is True else "REJECTED"
    if facts["type_equals_accept"] is True:
        expected_states["ACCEPT_SCHEMA_VALID"] = "EVIDENCE_REQUIRED"
        expected_states["CONTRACT_PRESENT"] = "VERIFIED" if facts["contract_field_present"] else "REJECTED"
        expected_states["EVIDENCE_COMPLETE"] = "EVIDENCE_REQUIRED"
        if expected_profile == "PASS":
            for name in ("SIGNATURE_VALID", "REPLAY_VALID", "CONTRACT_DERIVATION_VERIFIED",
                    "OFFER_GLOBAL_VIEW_COMPLETE", "OFFER_GLOBAL_WINNER_VERIFIED"):
                expected_states[name] = "EVIDENCE_REQUIRED"
            expected_states["LOCK_OBSERVED"] = "UNKNOWN"
    if stage_map != expected_states:
        raise ConformanceError("STAGE_CLASSIFICATION_CONTRADICTION", "validation_stages")
    reputation = value["reputation_dimensions"]
    if not isinstance(reputation, Mapping) or set(reputation) != REPUTATION_FIELDS:
        raise ConformanceError("REPUTATION_FIELDS_INVALID", "reputation_dimensions")
    if reputation["malicious_behavior_evidence"] != "ABSENT":
        raise ConformanceError("MALICIOUSNESS_NOT_ESTABLISHED", "reputation_dimensions")
    expected_reputation = {"protocol_conformance": "UNKNOWN",
        "signature_failure": "NOT_ESTABLISHED", "replay_behavior": "NOT_ESTABLISHED",
        "race_outcome": "UNRESOLVED", "evidence_completeness": "INCOMPLETE",
        "settlement_completion": "UNVERIFIED", "malicious_behavior_evidence": "ABSENT"}
    if dict(reputation) != expected_reputation:
        raise ConformanceError("REPUTATION_CONTRADICTION", "reputation_dimensions")
    if value["payer_abandonment"] != "PAYER_ABANDONMENT_UNPROVEN":
        raise ConformanceError("PAYER_ABANDONMENT_UNPROVEN", "payer_abandonment")
    for name in ("accepted_contract_count_eligible", "ready_to_act", "authorized_to_act", "live_action_enabled"):
        if type(value[name]) is not bool:
            raise ConformanceError("BOOLEAN_INVALID", name)
    if value["accepted_contract_count_eligible"]:
        raise ConformanceError("OFFICIAL_SCHEMA_REVISION_REQUIRED", "accepted_contract_count_eligible")
    if value["ready_to_act"] or value["authorized_to_act"] or value["live_action_enabled"]:
        raise ConformanceError("ACTION_STATE_INVALID", "projection")
    claimed = value["observation_id"]
    body = {name: value[name] for name in PROJECTION_FIELDS if name != "observation_id"}
    expected = _digest({"domain": DOMAIN, "schema": SCHEMA_VERSION,
        "canonical_encoding": CANONICAL_ENCODING, **body})
    if not isinstance(claimed, str) or claimed != expected:
        raise ConformanceError("OBSERVATION_IDENTITY_MISMATCH", "observation_id")
    return MappingProxyType({name: value[name] for name in PROJECTION_FIELDS})


def parse_projection(raw: str) -> Mapping[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, child in items:
            if key in result: raise ConformanceError("DUPLICATE_JSON_KEY", "document")
            result[key] = child
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
            parse_constant=lambda _x: (_ for _ in ()).throw(ConformanceError("NUMBER_INVALID", "document")))
    except ConformanceError: raise
    except (TypeError, ValueError, RecursionError):
        raise ConformanceError("JSON_INVALID", "document") from None
    return validate_projection(value)


def validate_count(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_COUNT:
        raise ConformanceError("COUNT_INVALID", field)
    return value


def exact_ratio(numerator: Any, denominator: Any) -> str:
    numerator = validate_count(numerator, "numerator")
    denominator = validate_count(denominator, "denominator")
    if denominator == 0 or numerator > denominator:
        raise ConformanceError("RATIO_INVALID", "ratio")
    import math
    divisor = math.gcd(numerator, denominator)
    return f"{numerator // divisor}/{denominator // divisor}"


def package_status() -> Mapping[str, Any]:
    """Return the closed package-level field-report and migration boundary."""
    value = {"schema": "tclk-accept-conformance-package-v1", "domain": DOMAIN,
        "status": "DESCRIPTIVE_ONLY", "content_label": "UNTRUSTED_CONTENT",
        "artifact_id": "", "policy_identity": dict(schema_policy_identity()),
        "issue_reference": {"reported_number": 142,
            "canonical_object_type": "ISSUE_OR_PULL_REFERENCE_UNRESOLVED",
            "maintainer_ratification": "NOT_CONFIRMED",
            "source_binding": "SOURCE_REVISION_REQUIRED"},
        "field_report": {"classification": "HIGH_SIGNAL_FIELD_REPORT",
            "ratification": "UNRATIFIED", "temporal_scope": "POINT_IN_TIME_REPORTED",
            "methodology": "METHODOLOGY_NOT_INDEPENDENTLY_REPRODUCED",
            "evergreen": False, "protocol_spec": False, "current_runtime_proof": False,
            "observation_runs": 6, "accept_typed_frames": 1022,
            "missing_contract": 922, "missing_contract_exact_ratio": exact_ratio(922, 1022),
            "missing_contract_reported_display": "90.2%", "accepting_did_count": 711,
            "affected_did_count": 666, "affected_exact_ratio": exact_ratio(666, 711),
            "affected_reported_display": "93.7%", "contract_present_sample": 56,
            "derivation_matches": 55, "derivation_match_exact_ratio": exact_ratio(55, 56)},
        "historical_reclassification": {"status": "HISTORICAL_CLASSIFICATION_UNRESOLVED",
            "evidence_requirement": "RECLASSIFICATION_EVIDENCE_REQUIRED",
            "payer_abandonment": "PAYER_ABANDONMENT_UNPROVEN",
            "underlying_frames_retained": False, "source_identity_bound": False,
            "schema_revision_bound": False, "source_set_complete": False,
            "truncation_resolved": False, "duplicates_resolved": False,
            "signature_evidence": False, "replay_evidence": False,
            "offer_global_chronology_complete": False, "lock_coverage_complete": False,
            "automatic_migration": False},
        "reputation_boundary": "MALICIOUS_BEHAVIOR_NOT_ESTABLISHED",
        "runtime_compatibility": "COMPATIBILITY_REVIEW_REQUIRED",
        "action_state": {"mode": "NO_LIVE_ACTION", "ready_to_act": False,
            "authorized_to_act": False, "live_action_enabled": False},
        "policy_version": POLICY_VERSION}
    value["artifact_id"] = _digest({"domain": DOMAIN, "schema": value["schema"],
        "canonical_encoding": CANONICAL_ENCODING,
        **{key: child for key, child in value.items() if key != "artifact_id"}})
    return validate_package_status(value)


def validate_package_status(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != PACKAGE_FIELDS:
        raise ConformanceError("FIELD_SET_INVALID", "package")
    # Rebuild the fixed projection without recursively calling this validator.
    if value["schema"] != "tclk-accept-conformance-package-v1" or value["domain"] != DOMAIN:
        raise ConformanceError("HEADER_INVALID", "package")
    if value["status"] != "DESCRIPTIVE_ONLY" or value["content_label"] != "UNTRUSTED_CONTENT":
        raise ConformanceError("HEADER_INVALID", "package")
    if not isinstance(value["policy_identity"], Mapping) or dict(value["policy_identity"]) != dict(schema_policy_identity()):
        raise ConformanceError("POLICY_IDENTITY_INVALID", "policy_identity")
    report = value["field_report"]
    required_report = {"classification", "ratification", "temporal_scope", "methodology",
        "evergreen", "protocol_spec", "current_runtime_proof", "observation_runs",
        "accept_typed_frames", "missing_contract", "missing_contract_exact_ratio",
        "missing_contract_reported_display", "accepting_did_count", "affected_did_count",
        "affected_exact_ratio", "affected_reported_display", "contract_present_sample",
        "derivation_matches", "derivation_match_exact_ratio"}
    if not isinstance(report, Mapping) or set(report) != required_report:
        raise ConformanceError("FIELD_REPORT_FIELDS_INVALID", "field_report")
    for name in ("observation_runs", "accept_typed_frames", "missing_contract",
            "accepting_did_count", "affected_did_count", "contract_present_sample",
            "derivation_matches"):
        validate_count(report[name], name)
    if (report["missing_contract"] > report["accept_typed_frames"]
            or report["affected_did_count"] > report["accepting_did_count"]
            or report["derivation_matches"] > report["contract_present_sample"]):
        raise ConformanceError("COUNT_RELATION_INVALID", "field_report")
    if report["missing_contract_exact_ratio"] != exact_ratio(report["missing_contract"], report["accept_typed_frames"]):
        raise ConformanceError("RATIO_MISMATCH", "missing_contract_exact_ratio")
    if report["affected_exact_ratio"] != exact_ratio(report["affected_did_count"], report["accepting_did_count"]):
        raise ConformanceError("RATIO_MISMATCH", "affected_exact_ratio")
    if report["derivation_match_exact_ratio"] != exact_ratio(report["derivation_matches"], report["contract_present_sample"]):
        raise ConformanceError("RATIO_MISMATCH", "derivation_match_exact_ratio")
    if (report["classification"] != "HIGH_SIGNAL_FIELD_REPORT"
            or report["ratification"] != "UNRATIFIED"
            or report["temporal_scope"] != "POINT_IN_TIME_REPORTED"
            or report["methodology"] != "METHODOLOGY_NOT_INDEPENDENTLY_REPRODUCED"
            or type(report["evergreen"]) is not bool or report["evergreen"]
            or type(report["protocol_spec"]) is not bool or report["protocol_spec"]
            or type(report["current_runtime_proof"]) is not bool or report["current_runtime_proof"]):
        raise ConformanceError("FIELD_REPORT_AUTHORITY_INVALID", "field_report")
    issue = value["issue_reference"]
    if issue != {"reported_number": 142,
            "canonical_object_type": "ISSUE_OR_PULL_REFERENCE_UNRESOLVED",
            "maintainer_ratification": "NOT_CONFIRMED",
            "source_binding": "SOURCE_REVISION_REQUIRED"}:
        raise ConformanceError("ISSUE_REFERENCE_UNRESOLVED", "issue_reference")
    historical = value["historical_reclassification"]
    if not isinstance(historical, Mapping) or historical.get("status") != "HISTORICAL_CLASSIFICATION_UNRESOLVED" or historical.get("evidence_requirement") != "RECLASSIFICATION_EVIDENCE_REQUIRED" or historical.get("payer_abandonment") != "PAYER_ABANDONMENT_UNPROVEN" or any(historical.get(name) is not False for name in ("underlying_frames_retained", "source_identity_bound", "schema_revision_bound", "source_set_complete", "truncation_resolved", "duplicates_resolved", "signature_evidence", "replay_evidence", "offer_global_chronology_complete", "lock_coverage_complete", "automatic_migration")):
        raise ConformanceError("HISTORICAL_RECLASSIFICATION_BLOCKED", "historical_reclassification")
    if set(historical) != {"status", "evidence_requirement", "payer_abandonment",
            "underlying_frames_retained", "source_identity_bound", "schema_revision_bound",
            "source_set_complete", "truncation_resolved", "duplicates_resolved",
            "signature_evidence", "replay_evidence", "offer_global_chronology_complete",
            "lock_coverage_complete", "automatic_migration"}:
        raise ConformanceError("HISTORICAL_FIELDS_INVALID", "historical_reclassification")
    if value["reputation_boundary"] != "MALICIOUS_BEHAVIOR_NOT_ESTABLISHED" or value["runtime_compatibility"] != "COMPATIBILITY_REVIEW_REQUIRED" or value["action_state"] != {"mode": "NO_LIVE_ACTION", "ready_to_act": False, "authorized_to_act": False, "live_action_enabled": False} or value["policy_version"] != POLICY_VERSION:
        raise ConformanceError("ACTION_STATE_INVALID", "package")
    body = {key: value[key] for key in PACKAGE_FIELDS if key != "artifact_id"}
    expected_id = _digest({"domain": DOMAIN, "schema": value["schema"],
        "canonical_encoding": CANONICAL_ENCODING, **body})
    if not isinstance(value["artifact_id"], str) or value["artifact_id"] != expected_id:
        raise ConformanceError("ARTIFACT_IDENTITY_MISMATCH", "artifact_id")
    return MappingProxyType({name: value[name] for name in PACKAGE_FIELDS})


__all__ = ["ConformanceError", "classify_frame", "exact_ratio", "package_status",
           "parse_projection", "schema_policy_identity", "validate_count",
           "validate_package_status", "validate_projection"]
