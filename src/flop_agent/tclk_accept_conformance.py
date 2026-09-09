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

STAGE_FIELDS = ("frame_observed", "frame_type_accept", "accept_schema_valid",
    "signature_valid", "replay_valid", "contract_present",
    "contract_derivation_verified", "evidence_complete",
    "offer_global_view_complete", "offer_global_winner_verified",
    "lock_observed", "settlement_verified")
STAGE_VALUES = frozenset({"OBSERVED", "NOT_OBSERVED", "VERIFIED", "NOT_VERIFIED",
                          "VALID", "INVALID", "COMPLETE", "INCOMPLETE", "UNKNOWN"})
CLASSIFICATIONS = frozenset({"INVALID_ACCEPT_MISSING_CONTRACT", "INVALID_ACCEPT_SCHEMA",
    "INVALID_ACCEPT_CONTRACT_TYPE", "INVALID_ACCEPT_CONTRACT_MISMATCH",
    "SIGNATURE_INVALID", "SIGNATURE_NOT_VERIFIED", "REPLAY", "REPLAY_NOT_VERIFIED",
    "ACCEPT_RACE_LOST", "RACE_STATUS_UNRESOLVED", "POLICY_REJECTED", "MALFORMED",
    "EVIDENCE_INCOMPLETE", "WINNER_UNRESOLVED", "VALID_ACCEPT_LOCK_NOT_OBSERVED",
    "PAYER_ABANDONMENT_UNPROVEN", "SETTLEMENT_UNVERIFIED"})
PROJECTION_FIELDS = frozenset({"schema", "domain", "status", "content_label",
    "observation_id", "policy_identity", "primary_classification", "stages",
    "reputation_dimensions", "payer_abandonment", "accepted_contract_count_eligible",
    "ready_to_act", "authorized_to_act", "live_action_enabled", "policy_version"})
PACKAGE_FIELDS = frozenset({"schema", "domain", "status", "content_label", "artifact_id",
    "policy_identity", "issue_reference", "field_report", "historical_reclassification",
    "runtime_compatibility", "action_state", "policy_version"})
POLICY_FIELDS = frozenset({"protocol", "official_repository", "schema_path",
    "schema_version", "source_revision", "document_hash", "required_contract_policy",
    "additional_properties_policy", "contract_derivation_spec", "extraction_state",
    "canonical_encoding"})
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
    })


def _base_stages() -> dict[str, str]:
    return {"frame_observed": "NOT_OBSERVED", "frame_type_accept": "NOT_OBSERVED",
        "accept_schema_valid": "NOT_VERIFIED", "signature_valid": "NOT_VERIFIED",
        "replay_valid": "NOT_VERIFIED", "contract_present": "NOT_OBSERVED",
        "contract_derivation_verified": "NOT_VERIFIED", "evidence_complete": "INCOMPLETE",
        "offer_global_view_complete": "INCOMPLETE",
        "offer_global_winner_verified": "NOT_VERIFIED", "lock_observed": "UNKNOWN",
        "settlement_verified": "NOT_VERIFIED"}


def _project(primary: str, stages: Mapping[str, str]) -> Mapping[str, Any]:
    policy = dict(schema_policy_identity())
    reputation = {"protocol_conformance": "FAILURE" if primary.startswith("INVALID_") else "UNRESOLVED",
        "signature_failure": "NOT_ESTABLISHED", "replay_behavior": "NOT_ESTABLISHED",
        "race_outcome": "UNRESOLVED", "evidence_completeness": "INCOMPLETE",
        "settlement_completion": "UNVERIFIED", "malicious_behavior_evidence": "ABSENT"}
    body = {"schema": SCHEMA_VERSION, "domain": DOMAIN, "status": "DESCRIPTIVE_ONLY",
        "content_label": "UNTRUSTED_CONTENT", "policy_identity": policy,
        "primary_classification": primary,
        "stages": {name: stages[name] for name in STAGE_FIELDS},
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
    stages = _base_stages()
    if not isinstance(frame, Mapping):
        return _project("MALFORMED", stages)
    stages["frame_observed"] = "OBSERVED"
    if frame.get("type") != "accept":
        return _project("POLICY_REJECTED", stages)
    stages["frame_type_accept"] = "OBSERVED"
    if set(frame) - {"type", "contract"}:
        stages["accept_schema_valid"] = "INVALID"
        return _project("INVALID_ACCEPT_SCHEMA", stages)
    if "contract" not in frame:
        stages["accept_schema_valid"] = "INVALID"
        return _project("INVALID_ACCEPT_MISSING_CONTRACT", stages)
    contract = frame["contract"]
    if not isinstance(contract, str) or not contract or _CONTRACT.fullmatch(contract) is None:
        stages["accept_schema_valid"] = "INVALID"
        return _project("INVALID_ACCEPT_CONTRACT_TYPE", stages)
    stages["contract_present"] = "OBSERVED"
    # Shape conformance is not official schema conformance without a pinned revision.
    return _project("WINNER_UNRESOLVED", stages)


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
    stages = value["stages"]
    if not isinstance(stages, Mapping) or set(stages) != set(STAGE_FIELDS):
        raise ConformanceError("STAGE_FIELDS_INVALID", "stages")
    if any(stages[name] not in STAGE_VALUES for name in STAGE_FIELDS):
        raise ConformanceError("STAGE_VALUE_INVALID", "stages")
    if stages["accept_schema_valid"] == "VERIFIED":
        raise ConformanceError("OFFICIAL_SCHEMA_REVISION_REQUIRED", "accept_schema_valid")
    if any(stages[name] == "VERIFIED" for name in ("signature_valid", "replay_valid",
            "contract_derivation_verified", "offer_global_winner_verified",
            "settlement_verified")):
        raise ConformanceError("SEALED_EVIDENCE_REQUIRED", "stages")
    if stages["offer_global_view_complete"] == "INCOMPLETE" and value["primary_classification"] == "ACCEPT_RACE_LOST":
        raise ConformanceError("GLOBAL_VIEW_REQUIRED", "primary_classification")
    if value["primary_classification"] not in CLASSIFICATIONS:
        raise ConformanceError("CLASSIFICATION_INVALID", "primary_classification")
    expected_stages = {
        "MALFORMED": _base_stages(),
        "POLICY_REJECTED": {**_base_stages(), "frame_observed": "OBSERVED"},
        "INVALID_ACCEPT_SCHEMA": {**_base_stages(), "frame_observed": "OBSERVED",
            "frame_type_accept": "OBSERVED", "accept_schema_valid": "INVALID"},
        "INVALID_ACCEPT_MISSING_CONTRACT": {**_base_stages(), "frame_observed": "OBSERVED",
            "frame_type_accept": "OBSERVED", "accept_schema_valid": "INVALID"},
        "INVALID_ACCEPT_CONTRACT_TYPE": {**_base_stages(), "frame_observed": "OBSERVED",
            "frame_type_accept": "OBSERVED", "accept_schema_valid": "INVALID"},
        "WINNER_UNRESOLVED": {**_base_stages(), "frame_observed": "OBSERVED",
            "frame_type_accept": "OBSERVED", "contract_present": "OBSERVED"},
    }
    primary = value["primary_classification"]
    if primary not in expected_stages or dict(stages) != expected_stages[primary]:
        raise ConformanceError("STAGE_CLASSIFICATION_CONTRADICTION", "stages")
    reputation = value["reputation_dimensions"]
    if not isinstance(reputation, Mapping) or set(reputation) != REPUTATION_FIELDS:
        raise ConformanceError("REPUTATION_FIELDS_INVALID", "reputation_dimensions")
    if reputation["malicious_behavior_evidence"] != "ABSENT":
        raise ConformanceError("MALICIOUSNESS_NOT_ESTABLISHED", "reputation_dimensions")
    expected_reputation = {"protocol_conformance": "FAILURE" if primary.startswith("INVALID_") else "UNRESOLVED",
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
            "derivation_matches": 55},
        "historical_reclassification": {"status": "HISTORICAL_CLASSIFICATION_UNRESOLVED",
            "evidence_requirement": "RECLASSIFICATION_EVIDENCE_REQUIRED",
            "payer_abandonment": "PAYER_ABANDONMENT_UNPROVEN",
            "underlying_frames_retained": False, "source_identity_bound": False,
            "schema_revision_bound": False, "source_set_complete": False,
            "truncation_resolved": False, "duplicates_resolved": False,
            "signature_evidence": False, "replay_evidence": False,
            "offer_global_chronology_complete": False, "lock_coverage_complete": False,
            "automatic_migration": False},
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
        "derivation_matches"}
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
    if value["runtime_compatibility"] != "COMPATIBILITY_REVIEW_REQUIRED" or value["action_state"] != {"mode": "NO_LIVE_ACTION", "ready_to_act": False, "authorized_to_act": False, "live_action_enabled": False} or value["policy_version"] != POLICY_VERSION:
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
