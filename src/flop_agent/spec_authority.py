"""Closed, descriptive FLOP specification-authority projections.

This module retains conflicting claims without selecting a parameter.  It has
no source fetcher, network client, signing interface, scoring rule, or action API.
"""
from __future__ import annotations

import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Mapping, Sequence

SCHEMA_VERSION = "flop-spec-authority-v1"
DOMAIN = "FLOP_SPEC_AUTHORITY\x00V1"
POLICY_VERSION = "flop-spec-authority-policy-v1"
CANONICAL_ENCODING_REVISION = "SORTED_ASCII_JSON_V1"

SOURCE_TYPES = frozenset({"YELLOW_PAPER", "TEASER", "WORKBOOK", "RATIFIED_PARAMS"})
AUTHORITIES = frozenset({"AUTHORITATIVE_REFERENCE", "OFFICIAL_CONTEXT",
    "SUPPORTING_WORKBOOK", "RATIFICATION_RECORD", "UNVERIFIED_SOURCE"})
PARAMETER_STATUSES = frozenset({"RATIFIED", "PROVISIONAL", "CONFLICTING", "TBD",
    "SUPERSEDED", "UNRESOLVED"})
EVIDENCE_STATUSES = frozenset({"VERIFIED_LOCAL_EVIDENCE", "SOURCE_EVIDENCE_REQUIRED",
    "REVISION_UNVERIFIED", "HASH_UNVERIFIED"})
RATIFICATION_STATES = frozenset({"SEALED_VALIDATED", "RATIFICATION_UNRESOLVED"})
CONFLICT_STATES = frozenset({"NO_CONFLICT", "SPEC_CONFLICT", "CONFLICT_ACKNOWLEDGED",
    "RATIFICATION_REQUIRED", "SOURCE_EVIDENCE_REQUIRED", "RESOLVED_BY_RATIFIED_PARAMS"})
SCORING_FIELDS = ("airdrop_scoring", "testnet_mainnet_conversion", "scoring_cap",
    "scoring_curve", "minimum_activity", "agent_vesting", "spend_to_unlock",
    "final_agent_allocation", "inference_spend_allocation_relationship")
SOURCE_FIELDS = frozenset({"source_id", "source_type", "authority", "material_status",
    "revision", "document_hash", "identity_verified", "revision_verified",
    "hash_verified", "content_attested"})
CLAIM_FIELDS = frozenset({"claim_id", "category", "value", "unit", "approximation",
    "source_id", "source_type", "authority", "source_revision", "document_hash",
    "source_identity_verified", "revision_verified", "hash_verified",
    "extraction_verified", "claim_kind", "evidence_status", "parameter_status",
    "ratification_state", "conflict_set_id", "canonical_encoding_revision"})
CONFLICT_FIELDS = frozenset({"conflict_set_id", "category", "claim_ids", "state",
    "ratification_evidence_present", "current_parameter_resolved"})
TOP_FIELDS = frozenset({"schema", "domain", "canonical_encoding_revision", "status", "content_label", "artifact_id",
    "source_set_complete", "sources", "claims_extracted", "claims", "conflicts",
    "scoring_uncertainty", "runtime_compatibility", "action_state", "policy_version"})
_ID = re.compile(r"^[A-Z0-9][A-Z0-9._:-]{0,127}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
_REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SOURCE_AUTHORITY = {
    "YELLOW_PAPER": {"AUTHORITATIVE_REFERENCE", "UNVERIFIED_SOURCE"},
    "TEASER": {"OFFICIAL_CONTEXT", "UNVERIFIED_SOURCE"},
    "WORKBOOK": {"SUPPORTING_WORKBOOK", "UNVERIFIED_SOURCE"},
    "RATIFIED_PARAMS": {"RATIFICATION_RECORD", "UNVERIFIED_SOURCE"},
}
_RETAINED_TEASER_REVISION = "teaser-capture-2026-08-27"
_RETAINED_TEASER_HASH = "f93b07c83d71f09926ee536f4e704b52336e4f8c3e6f0a3752d45224a39d3fde"


class SpecAuthorityError(ValueError):
    """Safe validation error that never echoes rejected content."""
    def __init__(self, code: str, field: str):
        super().__init__(f"{code}: {field}")
        self.code = code
        self.metadata = MappingProxyType({"field": field})


def _exact_keys(value: Any, fields: frozenset[str], field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise SpecAuthorityError("FIELD_SET_INVALID", field)
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _valid_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise SpecAuthorityError("IDENTIFIER_INVALID", field)
    return value


def _source(value: Any) -> dict[str, Any]:
    item = _exact_keys(value, SOURCE_FIELDS, "source")
    source_id = _valid_id(item["source_id"], "source_id")
    source_type = item["source_type"]
    authority = item["authority"]
    if source_type not in SOURCE_TYPES or authority not in AUTHORITIES:
        raise SpecAuthorityError("SOURCE_ENUM_INVALID", "source")
    if authority not in _SOURCE_AUTHORITY[source_type]:
        raise SpecAuthorityError("SOURCE_AUTHORITY_CONTRADICTION", "authority")
    revision = item["revision"]
    document_hash = item["document_hash"]
    if item["material_status"] not in {"OFFICIAL_DRAFT", "UNVERIFIED_CANDIDATE",
                                      "RATIFIED_RECORD", "SUPPORTING_MATERIAL"}:
        raise SpecAuthorityError("SOURCE_STATUS_INVALID", "material_status")
    for name in ("identity_verified", "revision_verified", "hash_verified", "content_attested"):
        if type(item[name]) is not bool:
            raise SpecAuthorityError("BOOLEAN_INVALID", name)
    if item["revision_verified"]:
        if not isinstance(revision, str) or _REVISION.fullmatch(revision) is None:
            raise SpecAuthorityError("REVISION_INVALID", "revision")
    elif revision != "REVISION_UNVERIFIED":
        raise SpecAuthorityError("REVISION_CONTRADICTION", "revision")
    if item["hash_verified"]:
        if not isinstance(document_hash, str) or _HASH.fullmatch(document_hash) is None:
            raise SpecAuthorityError("HASH_INVALID", "document_hash")
    elif document_hash != "HASH_UNVERIFIED":
        raise SpecAuthorityError("HASH_CONTRADICTION", "document_hash")
    if authority == "UNVERIFIED_SOURCE" and item["identity_verified"]:
        raise SpecAuthorityError("SOURCE_IDENTITY_CONTRADICTION", "identity_verified")
    if item["content_attested"] and not (item["identity_verified"] and
            item["revision_verified"] and item["hash_verified"]):
        raise SpecAuthorityError("CONTENT_ATTESTATION_CONTRADICTION", "content_attested")
    if item["material_status"] == "UNVERIFIED_CANDIDATE" and (authority != "UNVERIFIED_SOURCE"
            or item["content_attested"]):
        raise SpecAuthorityError("SOURCE_STATUS_CONTRADICTION", "material_status")
    verified_tuple = (source_id, source_type, authority, item["material_status"], revision,
        document_hash, item["identity_verified"], item["revision_verified"],
        item["hash_verified"], item["content_attested"])
    retained_tuple = ("FLOP_TEASER_CAPTURE", "TEASER", "OFFICIAL_CONTEXT",
        "OFFICIAL_DRAFT", _RETAINED_TEASER_REVISION, _RETAINED_TEASER_HASH,
        True, True, True, True)
    if any(verified_tuple[-4:]) and verified_tuple != retained_tuple:
        raise SpecAuthorityError("SEALED_SOURCE_EVIDENCE_REQUIRED", "source")
    return {name: item[name] for name in ("source_id", "source_type", "authority",
        "material_status", "revision", "document_hash", "identity_verified",
        "revision_verified", "hash_verified", "content_attested")}


def _claim_identity(item: Mapping[str, Any]) -> str:
    body = {"domain": DOMAIN, "schema": SCHEMA_VERSION}
    body.update({name: item[name] for name in sorted(CLAIM_FIELDS - {"claim_id"})})
    return _digest(body)


def _claim(value: Any, sources: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    item = _exact_keys(value, CLAIM_FIELDS, "claim")
    _valid_id(item["source_id"], "source_id")
    _valid_id(item["category"], "category")
    _valid_id(item["conflict_set_id"], "conflict_set_id")
    if item["source_id"] not in sources:
        raise SpecAuthorityError("SOURCE_REFERENCE_UNKNOWN", "source_id")
    source = sources[item["source_id"]]
    for name in ("source_type", "authority"):
        if item[name] != source[name]:
            raise SpecAuthorityError("SOURCE_BINDING_MISMATCH", name)
    if item["source_revision"] != source["revision"] or item["document_hash"] != source["document_hash"]:
        raise SpecAuthorityError("SOURCE_EVIDENCE_MISMATCH", "source_evidence")
    for claim_name, source_name in (("source_identity_verified", "identity_verified"),
            ("revision_verified", "revision_verified"), ("hash_verified", "hash_verified")):
        if type(item[claim_name]) is not bool or item[claim_name] != source[source_name]:
            raise SpecAuthorityError("SOURCE_EVIDENCE_MISMATCH", claim_name)
    if type(item["extraction_verified"]) is not bool:
        raise SpecAuthorityError("BOOLEAN_INVALID", "extraction_verified")
    if item["canonical_encoding_revision"] != CANONICAL_ENCODING_REVISION:
        raise SpecAuthorityError("CANONICAL_ENCODING_INVALID", "canonical_encoding_revision")
    if not isinstance(item["value"], str) or _DECIMAL.fullmatch(item["value"]) is None:
        raise SpecAuthorityError("DECIMAL_INVALID", "value")
    if item["unit"] != "FLOP" or type(item["approximation"]) is not bool:
        raise SpecAuthorityError("CLAIM_VALUE_INVALID", "claim")
    if item["evidence_status"] not in EVIDENCE_STATUSES or item["parameter_status"] not in PARAMETER_STATUSES:
        raise SpecAuthorityError("CLAIM_STATUS_INVALID", "claim")
    if item["ratification_state"] not in RATIFICATION_STATES:
        raise SpecAuthorityError("RATIFICATION_STATE_INVALID", "ratification_state")
    if item["claim_kind"] not in {"VERIFIED_SOURCE_BOUND_CLAIM", "UNVERIFIED_REPORTED_CLAIM"}:
        raise SpecAuthorityError("CLAIM_KIND_INVALID", "claim_kind")
    if not isinstance(item["claim_id"], str) or item["claim_id"] != _claim_identity(item):
        raise SpecAuthorityError("CLAIM_IDENTITY_MISMATCH", "claim_id")
    fully_verified = (item["source_identity_verified"] and item["revision_verified"]
        and item["hash_verified"] and item["extraction_verified"]
        and item["evidence_status"] == "VERIFIED_LOCAL_EVIDENCE")
    if (item["claim_kind"] == "VERIFIED_SOURCE_BOUND_CLAIM") != fully_verified:
        raise SpecAuthorityError("CLAIM_VERIFICATION_CONTRADICTION", "claim_kind")
    if fully_verified and not (item["source_id"] == "FLOP_TEASER_CAPTURE"
            and item["category"] == "AGENT_ALLOCATION" and item["value"] == "1200000000"
            and item["unit"] == "FLOP" and item["approximation"] is True
            and item["parameter_status"] == "CONFLICTING"
            and item["ratification_state"] == "RATIFICATION_UNRESOLVED"):
        raise SpecAuthorityError("SEALED_EXTRACTION_EVIDENCE_REQUIRED", "claim")
    ratified = (item["parameter_status"] == "RATIFIED" or
                item["ratification_state"] == "SEALED_VALIDATED")
    if ratified and not (item["source_type"] == "RATIFIED_PARAMS" and
        item["authority"] == "RATIFICATION_RECORD" and
        item["evidence_status"] == "VERIFIED_LOCAL_EVIDENCE" and
        item["ratification_state"] == "SEALED_VALIDATED" and
        source["identity_verified"] and source["revision_verified"] and source["hash_verified"]):
        raise SpecAuthorityError("RATIFICATION_EVIDENCE_REQUIRED", "parameter_status")
    result = {name: item[name] for name in ("claim_id", "category", "value", "unit",
        "approximation", "source_id", "source_type", "authority", "source_revision",
        "document_hash", "source_identity_verified", "revision_verified", "hash_verified",
        "extraction_verified", "claim_kind", "evidence_status", "parameter_status",
        "ratification_state", "conflict_set_id", "canonical_encoding_revision")}
    return result


def make_claim(**values: Any) -> Mapping[str, Any]:
    """Build a claim identity from fixed fields; this does not verify evidence."""
    item = dict(values)
    if set(item) != CLAIM_FIELDS - {"claim_id"}:
        raise SpecAuthorityError("FIELD_SET_INVALID", "claim")
    item["claim_id"] = _claim_identity(item)
    return MappingProxyType(item)


def _conflict(value: Any, claim_map: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    item = _exact_keys(value, CONFLICT_FIELDS, "conflict")
    conflict_id = _valid_id(item["conflict_set_id"], "conflict_set_id")
    _valid_id(item["category"], "category")
    ids = item["claim_ids"]
    if not isinstance(ids, Sequence) or isinstance(ids, (str, bytes)) or len(ids) < 2:
        raise SpecAuthorityError("CLAIM_SET_INVALID", "claim_ids")
    if any(not isinstance(x, str) or x not in claim_map for x in ids) or len(set(ids)) != len(ids):
        raise SpecAuthorityError("CLAIM_SET_INVALID", "claim_ids")
    if any(claim_map[x]["conflict_set_id"] != conflict_id or
           claim_map[x]["category"] != item["category"] for x in ids):
        raise SpecAuthorityError("CONFLICT_BINDING_MISMATCH", "claim_ids")
    if item["state"] not in CONFLICT_STATES or type(item["ratification_evidence_present"]) is not bool or type(item["current_parameter_resolved"]) is not bool:
        raise SpecAuthorityError("CONFLICT_STATUS_INVALID", "conflict")
    values = {claim_map[x]["value"] for x in ids}
    if len(values) > 1 and item["state"] == "NO_CONFLICT":
        raise SpecAuthorityError("CONFLICT_STATE_CONTRADICTION", "state")
    if item["state"] == "RESOLVED_BY_RATIFIED_PARAMS":
        sealed = [claim_map[x] for x in ids if claim_map[x]["parameter_status"] == "RATIFIED"]
        if not item["ratification_evidence_present"] or not item["current_parameter_resolved"] or len(sealed) != 1:
            raise SpecAuthorityError("RATIFICATION_EVIDENCE_REQUIRED", "state")
    elif item["current_parameter_resolved"]:
        raise SpecAuthorityError("RESOLUTION_CONTRADICTION", "current_parameter_resolved")
    return {"conflict_set_id": conflict_id, "category": item["category"],
        "claim_ids": list(ids), "state": item["state"],
        "ratification_evidence_present": item["ratification_evidence_present"],
        "current_parameter_resolved": item["current_parameter_resolved"]}


def artifact_identity(value: Mapping[str, Any]) -> str:
    body = {name: value[name] for name in sorted(TOP_FIELDS - {"artifact_id"})}
    return _digest(body)


def validate_public_projection(value: Any) -> Mapping[str, Any]:
    item = _exact_keys(value, TOP_FIELDS, "projection")
    if item["schema"] != SCHEMA_VERSION or item["domain"] != DOMAIN or item["canonical_encoding_revision"] != CANONICAL_ENCODING_REVISION or item["status"] != "DESCRIPTIVE_ONLY" or item["content_label"] != "UNTRUSTED_CONTENT":
        raise SpecAuthorityError("HEADER_INVALID", "projection")
    if type(item["source_set_complete"]) is not bool or type(item["claims_extracted"]) is not bool:
        raise SpecAuthorityError("BOOLEAN_INVALID", "projection")
    sources_list = item["sources"]
    if not isinstance(sources_list, list) or not sources_list:
        raise SpecAuthorityError("SOURCE_SET_INVALID", "sources")
    sources = [_source(x) for x in sources_list]
    source_map = {x["source_id"]: x for x in sources}
    if len(source_map) != len(sources):
        raise SpecAuthorityError("DUPLICATE_SOURCE_ID", "sources")
    if not isinstance(item["claims"], list):
        raise SpecAuthorityError("CLAIM_SET_INVALID", "claims")
    claims = [_claim(x, source_map) for x in item["claims"]]
    claim_map = {x["claim_id"]: x for x in claims}
    if len(claim_map) != len(claims):
        raise SpecAuthorityError("DUPLICATE_CLAIM_ID", "claims")
    if not isinstance(item["conflicts"], list):
        raise SpecAuthorityError("CONFLICT_SET_INVALID", "conflicts")
    conflicts = [_conflict(x, claim_map) for x in item["conflicts"]]
    if len({x["conflict_set_id"] for x in conflicts}) != len(conflicts):
        raise SpecAuthorityError("DUPLICATE_CONFLICT_ID", "conflicts")
    scoring = _exact_keys(item["scoring_uncertainty"], frozenset(SCORING_FIELDS), "scoring_uncertainty")
    if any(scoring[name] != "UNRESOLVED" for name in SCORING_FIELDS):
        raise SpecAuthorityError("SCORING_MUST_BE_UNRESOLVED", "scoring_uncertainty")
    if item["runtime_compatibility"] != "COMPATIBILITY_REVIEW_REQUIRED":
        raise SpecAuthorityError("COMPATIBILITY_INVALID", "runtime_compatibility")
    action = _exact_keys(item["action_state"], frozenset({"mode", "ready_to_act",
        "authorized_to_act", "live_action_enabled"}), "action_state")
    if action != {"mode": "NO_LIVE_ACTION", "ready_to_act": False,
                   "authorized_to_act": False, "live_action_enabled": False}:
        raise SpecAuthorityError("ACTION_STATE_INVALID", "action_state")
    if item["policy_version"] != POLICY_VERSION:
        raise SpecAuthorityError("POLICY_INVALID", "policy_version")
    if not isinstance(item["artifact_id"], str) or item["artifact_id"] != artifact_identity(item):
        raise SpecAuthorityError("ARTIFACT_IDENTITY_MISMATCH", "artifact_id")
    return MappingProxyType({name: item[name] for name in TOP_FIELDS})


def parse_public_json(raw: str) -> Mapping[str, Any]:
    if not isinstance(raw, str):
        raise SpecAuthorityError("JSON_INVALID", "document")
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise SpecAuthorityError("DUPLICATE_JSON_KEY", "document")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _x: (_ for _ in ()).throw(SpecAuthorityError("NUMBER_INVALID", "document")))
    except SpecAuthorityError:
        raise
    except (ValueError, TypeError, RecursionError):
        raise SpecAuthorityError("JSON_INVALID", "document") from None
    return validate_public_projection(value)


def build_projection(*, source_set_complete: bool, sources: Sequence[Mapping[str, Any]],
                     claims: Sequence[Mapping[str, Any]], conflicts: Sequence[Mapping[str, Any]]) -> Mapping[str, Any]:
    """Reconstruct every public field and compute identity locally."""
    value: dict[str, Any] = {"schema": SCHEMA_VERSION, "domain": DOMAIN,
        "canonical_encoding_revision": CANONICAL_ENCODING_REVISION,
        "status": "DESCRIPTIVE_ONLY", "content_label": "UNTRUSTED_CONTENT",
        "artifact_id": "", "source_set_complete": source_set_complete,
        "sources": [{name: x[name] for name in SOURCE_FIELDS} for x in sources],
        "claims_extracted": True,
        "claims": [{name: x[name] for name in CLAIM_FIELDS} for x in claims],
        "conflicts": [{name: x[name] for name in CONFLICT_FIELDS} for x in conflicts],
        "scoring_uncertainty": {name: "UNRESOLVED" for name in SCORING_FIELDS},
        "runtime_compatibility": "COMPATIBILITY_REVIEW_REQUIRED",
        "action_state": {"mode": "NO_LIVE_ACTION", "ready_to_act": False,
            "authorized_to_act": False, "live_action_enabled": False},
        "policy_version": POLICY_VERSION}
    value["artifact_id"] = artifact_identity(value)
    return validate_public_projection(value)


__all__ = ["SpecAuthorityError", "artifact_identity", "build_projection", "make_claim",
           "parse_public_json", "validate_public_projection"]
