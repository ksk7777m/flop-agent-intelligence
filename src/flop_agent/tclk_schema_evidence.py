"""Immutable, offline-only TCLK official schema evidence loader."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import types
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

DOMAIN = "TCLK_OFFICIAL_SCHEMA_EVIDENCE\x00V1"
SCHEMA = "tclk-official-schema-evidence-v1"
CANONICAL_ENCODING = "SORTED_ASCII_JSON_V1"
COMMIT = "5cc4ab93efbc8999a3a7e1471b639deca25998ea"
SOURCE_PATH = "schema/tclk1-frames.schema.json"
SCHEMA_BLOB = "13e3ab92a698086df65c3be98385d546ff0bb99e"
SCHEMA_SHA256 = "17071a2b3b21e8484cac9da7976088f3700e6fb6c1372268d4756b61ddd60c70"
SCHEMA_SIZE = 6070
LICENSE_BLOB = "a33f6f27c9ee1b1b31cb02a29c45adcebbf5ab33"
LICENSE_SHA256 = "9a199b2f98908456e0714c49a9d0ae7b01d43eb85c0005a040a974db5faa982a"
LICENSE_SIZE = 11340
SPEC_BLOB = "99e3e677295354b88fe49efa69f84b1b78a1036c"
SPEC_SHA256 = "f01b46edf747606402979e5bf09193e3d7032217461bf5af2135241e5d940b62"
SPEC_SIZE = 31051
FRAMES_BLOB = "0c27a9aaaefe2965725384adfd383405f9c2cd3a"
FRAMES_SHA256 = "b8077cdd2b4210f0c696ac0e98fb8fe8be9c53ba998d0f671a454829c42bfb97"
FRAMES_SIZE = 19276
VECTORS_BLOB = "42b221894d4c34a879d9f8812bc86fb8237f15a0"
VECTORS_SHA256 = "c60f109ba26547c6be0795b0eb66a861a96a7d68a36885a28f318e69a1cebb96"
VECTORS_SIZE = 3604
MAX_SCHEMA_BYTES = 64 * 1024
ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = ROOT / "vendor" / "tclk" / COMMIT / SOURCE_PATH
LICENSE = ROOT / "vendor" / "tclk" / COMMIT / "LICENSE"
SPEC = ROOT / "vendor" / "tclk" / COMMIT / "SPEC.md"
FRAMES = ROOT / "vendor" / "tclk" / COMMIT / "src" / "frames.ts"
VECTORS = ROOT / "vendor" / "tclk" / COMMIT / "tests" / "vectors.test.ts"
REQUIRED = ("type", "from", "ref", "statement", "contract", "nonce")
REFS = tuple(f"#/$defs/{name}" for name in ("accept", "cancel", "did", "heartbeat",
    "hex32", "hex33", "job", "lock", "nonce", "offer", "presig", "rail",
    "receipt", "refund", "reveal"))
FIELDS = frozenset({"schema", "domain", "status", "content_label", "artifact_id",
    "canonical_encoding",
    "source_identity", "acquisition_evidence", "snapshot_identity", "schema_semantics", "derivation_evidence",
    "issue_142_evidence", "local_profile_comparison", "trust_boundary",
    "action_state", "policy_version"})


class SchemaEvidenceError(ValueError):
    def __init__(self, code: str, field: str):
        super().__init__(f"{code}: {field}")
        self.code = code
        self.metadata = MappingProxyType({"field": field})


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, RecursionError):
        raise SchemaEvidenceError("CANONICAL_VALUE_INVALID", "value") from None


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _same(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, Mapping):
        return set(left) == set(right) and all(_same(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_same(a, b) for a, b in zip(left, right))
    return left == right


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise SchemaEvidenceError("DUPLICATE_JSON_KEY", "snapshot")
        result[key] = value
    return result


def _git_blob_id(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\x00" + raw).hexdigest()


def _read_fixed(path: Path, expected_blob: str, expected_hash: str,
                expected_size: int, field: str) -> bytes:
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise SchemaEvidenceError("SNAPSHOT_FILE_INVALID", field)
        if info.st_size != expected_size or info.st_size > MAX_SCHEMA_BYTES:
            raise SchemaEvidenceError("SNAPSHOT_SIZE_MISMATCH", field)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_size != expected_size
                    or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)):
                raise SchemaEvidenceError("SNAPSHOT_FILE_INVALID", field)
            raw = os.read(descriptor, expected_size + 1)
            if os.read(descriptor, 1) or len(raw) != expected_size:
                raise SchemaEvidenceError("SNAPSHOT_SIZE_MISMATCH", field)
        finally:
            os.close(descriptor)
    except SchemaEvidenceError:
        raise
    except OSError:
        raise SchemaEvidenceError("SNAPSHOT_READ_FAILED", field) from None
    if hashlib.sha256(raw).hexdigest() != expected_hash:
        raise SchemaEvidenceError("SNAPSHOT_HASH_MISMATCH", field)
    if _git_blob_id(raw) != expected_blob:
        raise SchemaEvidenceError("SNAPSHOT_BLOB_MISMATCH", field)
    return raw


def _extract(raw: bytes) -> Mapping[str, Any]:
    try:
        document = json.loads(raw, object_pairs_hook=_pairs,
            parse_constant=lambda _x: (_ for _ in ()).throw(
                SchemaEvidenceError("NUMBER_INVALID", "snapshot")))
    except SchemaEvidenceError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise SchemaEvidenceError("SNAPSHOT_JSON_INVALID", "snapshot") from None
    if not isinstance(document, dict) or set(document) != {"$schema", "$id", "title", "oneOf", "$defs"}:
        raise SchemaEvidenceError("SCHEMA_EXPECTATION_MISMATCH", "root")
    defs = document.get("$defs")
    accept = defs.get("accept") if isinstance(defs, dict) else None
    if not isinstance(accept, dict) or set(accept) != {"type", "required", "properties", "additionalProperties"}:
        raise SchemaEvidenceError("SCHEMA_EXPECTATION_MISMATCH", "accept")
    if accept.get("type") != "object" or accept.get("additionalProperties") is not False:
        raise SchemaEvidenceError("SCHEMA_EXPECTATION_MISMATCH", "accept")
    required = accept.get("required")
    properties = accept.get("properties")
    if (not isinstance(required, list) or len(required) != len(REQUIRED)
            or set(required) != set(REQUIRED) or not isinstance(properties, dict) or set(properties) != {
            "type", "from", "ref", "statement", "contract", "nonce", "paymentKey"}):
        raise SchemaEvidenceError("SCHEMA_EXPECTATION_MISMATCH", "accept")
    expected = {"type": {"const": "accept"}, "from": {"$ref": "#/$defs/did"},
        "ref": {"$ref": "#/$defs/hex32"},
        "statement": {"type": "string", "pattern": "^0x(?:[0-9a-f]{64}|[0-9a-f]{66})$"},
        "contract": {"$ref": "#/$defs/hex32"}, "nonce": {"$ref": "#/$defs/nonce"},
        "paymentKey": {"$ref": "#/$defs/hex33"}}
    if properties != expected:
        raise SchemaEvidenceError("SCHEMA_EXPECTATION_MISMATCH", "accept.properties")
    dependencies = {"did": {"type": "string", "pattern": "^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$"},
        "hex32": {"type": "string", "pattern": "^0x[0-9a-f]{64}$"},
        "hex33": {"type": "string", "pattern": "^0x[0-9a-f]{66}$"},
        "nonce": {"type": "string", "pattern": "^[0-9a-f]{8,64}$"}}
    if any(defs.get(name) != definition for name, definition in dependencies.items()):
        raise SchemaEvidenceError("SCHEMA_EXPECTATION_MISMATCH", "accept.dependencies")
    observed_refs = sorted({child["$ref"] for definition in defs.values()
        if isinstance(definition, dict) for child in definition.get("properties", {}).values()
        if isinstance(child, dict) and "$ref" in child} | {item["$ref"] for item in document["oneOf"]})
    if observed_refs != list(REFS) or any(not ref.startswith("#/$defs/") or ref.split("/")[-1] not in defs for ref in observed_refs):
        raise SchemaEvidenceError("REFERENCE_COMPLETENESS_FAILED", "references")
    if document["$schema"] != "https://json-schema.org/draft/2020-12/schema" or document["$id"] != "https://github.com/flop-labs/tclk/schema/tclk1-frames.schema.json":
        raise SchemaEvidenceError("SCHEMA_EXPECTATION_MISMATCH", "declaration")
    return MappingProxyType({"declared_draft": "JSON_SCHEMA_DRAFT_2020_12",
        "schema_id": "TCLK_OFFICIAL_SCHEMA_ID", "protocol_version": "TCLK_1",
        "accept_definition": "ROOT_ONE_OF_LOCAL_ACCEPT", "required_fields_source_order": list(required),
        "required_field_set": sorted(REQUIRED), "optional_field_set": ["paymentKey"],
        "contract_required": True, "contract_type": "STRING_HEX32",
        "additional_properties": "REJECTED", "references": list(REFS),
        "reference_completeness": "COMPLETE_LOCAL_SAME_DOCUMENT",
        "combinators": ["ROOT_ONE_OF"], "conditional_keywords": "ABSENT_IN_ACCEPT_CLOSURE",
        "supported_accept_keywords": ["$defs", "$ref", "additionalProperties", "const",
            "oneOf", "pattern", "properties", "required", "type"],
        "semantic_extraction": "ACCEPT_POLICY_EXTRACTION_COMPLETE_NOT_VALIDATOR"})


def _assemble() -> dict[str, Any]:
    raw = _read_fixed(SNAPSHOT, SCHEMA_BLOB, SCHEMA_SHA256, SCHEMA_SIZE, "schema_snapshot")
    _read_fixed(LICENSE, LICENSE_BLOB, LICENSE_SHA256, LICENSE_SIZE, "license_snapshot")
    _read_fixed(SPEC, SPEC_BLOB, SPEC_SHA256, SPEC_SIZE, "spec_snapshot")
    _read_fixed(FRAMES, FRAMES_BLOB, FRAMES_SHA256, FRAMES_SIZE, "frames_snapshot")
    _read_fixed(VECTORS, VECTORS_BLOB, VECTORS_SHA256, VECTORS_SIZE, "vectors_snapshot")
    semantics = dict(_extract(raw))
    value = {"schema": SCHEMA, "domain": DOMAIN, "status": "OFFLINE_PINNED_EVIDENCE",
        "content_label": "PUBLIC_MINIMIZED_EVIDENCE", "artifact_id": "",
        "canonical_encoding": CANONICAL_ENCODING,
        "source_identity": {"repository": "FLOP_LABS_TCLK", "owner": "flop-labs",
            "name": "tclk", "default_branch_observed": "main", "commit_sha": COMMIT,
            "repository_state": "OFFICIAL_REPOSITORY_IDENTITY_OBSERVED",
            "commit_state": "EXACT_COMMIT_OBSERVED"},
        "acquisition_evidence": {"mode": "READ_ONLY_ACQUISITION_COMPLETED_WITH_DEVIATION",
            "allowed_hosts": ["api.github.com", "raw.githubusercontent.com"],
            "method": "GET", "accept_encoding": "identity", "timeout_seconds": 10,
            "redirects_allowed": False, "automatic_retry_count": 0,
            "fallback_enabled": False, "credentials_used": False,
            "mutable_main_resolution_gets": 1, "api_gets": 16, "raw_gets": 10,
            "acquisition_attempt_count": 26, "manual_reexecution_occurred": True,
            "manual_reexecution_count": 1,
            "first_processing_failure": "LOCAL_BASE64_WHITESPACE_DECODER_REJECTED",
            "second_schema_attempts_classification": "MANUAL_REEXECUTION",
            "acquisition_policy_conformance": "ACQUISITION_POLICY_DEVIATION_RECORDED",
            "acquisition_audit": "ACQUISITION_AUDIT_INCOMPLETE",
            "audit_gap": "NO_SEALED_PER_REQUEST_TRANSCRIPT",
            "no_further_fetch_allowed": True,
            "content_integrity": "INDEPENDENTLY_REVALIDATED_OFFLINE",
            "offline_reproducibility": "COMPLETE_FOR_RETAINED_SOURCES",
            "resource_attempts": [
                {"source_id": "REPOSITORY_METADATA", "transport": "GITHUB_API", "attempts": 1},
                {"source_id": "MUTABLE_MAIN_RESOLUTION", "transport": "GITHUB_API", "attempts": 1},
                {"source_id": "EXACT_COMMIT_TREE", "transport": "GITHUB_API", "attempts": 3},
                {"source_id": "SCHEMA_METADATA", "transport": "GITHUB_API", "attempts": 2},
                {"source_id": "SCHEMA_RAW", "transport": "GITHUB_RAW", "attempts": 2},
                {"source_id": "LICENSE_METADATA", "transport": "GITHUB_API", "attempts": 1},
                {"source_id": "LICENSE_RAW", "transport": "GITHUB_RAW", "attempts": 1},
                {"source_id": "README_METADATA", "transport": "GITHUB_API", "attempts": 1},
                {"source_id": "README_RAW", "transport": "GITHUB_RAW", "attempts": 1},
                {"source_id": "SCHEMA_TEST_METADATA", "transport": "GITHUB_API", "attempts": 1},
                {"source_id": "SCHEMA_TEST_RAW", "transport": "GITHUB_RAW", "attempts": 1},
                {"source_id": "SPEC_METADATA", "transport": "GITHUB_API", "attempts": 1},
                {"source_id": "SPEC_RAW", "transport": "GITHUB_RAW", "attempts": 1},
                {"source_id": "COMMITMENTS_METADATA", "transport": "GITHUB_API", "attempts": 1},
                {"source_id": "COMMITMENTS_RAW", "transport": "GITHUB_RAW", "attempts": 1},
                {"source_id": "FRAMES_METADATA", "transport": "GITHUB_API", "attempts": 1},
                {"source_id": "FRAMES_RAW", "transport": "GITHUB_RAW", "attempts": 1},
                {"source_id": "VECTORS_METADATA", "transport": "GITHUB_API", "attempts": 1},
                {"source_id": "VECTORS_RAW", "transport": "GITHUB_RAW", "attempts": 1},
                {"source_id": "TCLK_TEST_METADATA", "transport": "GITHUB_API", "attempts": 1},
                {"source_id": "TCLK_TEST_RAW", "transport": "GITHUB_RAW", "attempts": 1},
                {"source_id": "ISSUE_142_IDENTITY", "transport": "GITHUB_API", "attempts": 1}],
            "all_content_gets_commit_pinned": True,
            "bounded_response": True, "content_type_validated": True,
            "content_length_validated": True, "duplicate_headers_rejected": True,
            "raw_error_material_retained": False},
        "snapshot_identity": {"source_id": "TCLK_OFFICIAL_ACCEPT_SCHEMA",
            "source_path": SOURCE_PATH, "blob_sha1": SCHEMA_BLOB,
            "content_sha256": SCHEMA_SHA256, "byte_length": SCHEMA_SIZE,
            "retention": "RAW_SCHEMA_RETAINED_EXACT_BYTES", "json_parse": "PARSED",
            "duplicate_keys": "ABSENT", "license": "APACHE_2_0_LICENSE_FILE_OBSERVED",
            "redistribution_basis": "REDISTRIBUTION_BASIS_RECORDED",
            "legal_compliance_guarantee": "NOT_ASSERTED",
            "license_blob_sha1": LICENSE_BLOB, "license_sha256": LICENSE_SHA256,
            "license_byte_length": LICENSE_SIZE},
        "schema_semantics": semantics,
        "derivation_evidence": {"status": "CONTRACT_DERIVATION_SPEC_PINNED",
            "source_state": "CONTRACT_DERIVATION_SOURCE_OBSERVED",
            "normative_spec_candidate": {"source_id": "TCLK_SPEC", "path": "SPEC.md",
                "blob_sha1": SPEC_BLOB, "sha256": SPEC_SHA256, "byte_length": SPEC_SIZE,
                "retention": "EXACT_BYTES_RETAINED"},
            "reference_implementation": {"source_id": "TCLK_FRAMES_SOURCE", "path": "src/frames.ts",
                "blob_sha1": FRAMES_BLOB, "sha256": FRAMES_SHA256, "byte_length": FRAMES_SIZE,
                "retention": "EXACT_BYTES_RETAINED"},
            "test_vector": {"source_id": "TCLK_GOLDEN_VECTORS", "path": "tests/vectors.test.ts",
                "blob_sha1": VECTORS_BLOB, "sha256": VECTORS_SHA256, "byte_length": VECTORS_SIZE,
                "retention": "EXACT_BYTES_RETAINED"},
            "algorithm": {"hash": "SHA_256", "domain_tag_ascii": "FLOP::tclk::v1|contract|",
                "payload": "CANONICAL_JSON_OBJECT_OFFER_ACCEPT_CORE",
                "object_keys": "LEXICOGRAPHIC", "array_order": "PRESERVED",
                "undefined_object_fields": "OMITTED", "non_ascii": "UTF16_CODE_UNIT_U_ESCAPE",
                "json_whitespace": "NONE", "input_encoding": "UTF_8",
                "output_encoding": "LOWERCASE_0X_HEX", "length_prefix": "NONE",
                "accept_core_fields": ["from", "nonce", "paymentKey", "ref", "statement"],
                "optional_payment_key": "OMITTED_WHEN_UNDEFINED",
                "golden_vector_consistency": "OFFLINE_RECOMPUTED_MATCH"},
            "implementation_in_scope": False},
        "issue_142_evidence": {"canonical_object_type": "ISSUE", "number": 142,
            "state": "OPEN_OBSERVED", "created_at": "2026-09-08T23:16:38Z",
            "updated_at": "2026-09-09T07:00:57Z",
            "mutable_body_sha256": "d88a952736346a1a6ada2206663195d28d9e58203a72954f480b8f339c1cae79",
            "observed_at": "OBSERVATION_TIMESTAMP_NOT_RETAINED", "current_state": False,
            "author_association": "NONE", "maintainer_ratification": "NOT_CONFIRMED",
            "authority": "NOT_PROTOCOL_SPEC", "temporal_scope": "POINT_IN_TIME_REPORTED"},
        "local_profile_comparison": {"prior_artifact": "TCLK_ACCEPT_CONFORMANCE_PACKAGE_V1",
            "prior_profile": "TCLK_ACCEPT_LOCAL_SAFETY_PROFILE_V1",
            "comparison": "SPEC_DRIFT", "reason": "LOCAL_PROFILE_FIELD_SET_DIFFERS_FROM_PINNED_ACCEPT",
            "local_required_field_set": ["contract", "type"],
            "official_required_field_set": ["contract", "from", "nonce", "ref", "statement", "type"],
            "missing_locally_enforced_fields": ["from", "nonce", "ref", "statement"],
            "extra_locally_enforced_fields": [],
            "constraint_differences": ["CONTRACT_PATTERN_DIFFERS", "OFFICIAL_PAYMENT_KEY_OPTIONAL_LOCAL_REJECTS"],
            "additional_properties_comparison": "BOTH_REJECT",
            "required_contract_policy": "ATTESTED", "official_conformance_policy": "PINNED",
            "historical_reclassification": "BLOCKED", "automatic_migration": False},
        "trust_boundary": {"maintainer_signature": "NOT_VERIFIED",
            "protocol_ratification": "NOT_INFERRED", "runtime_deployment": "NOT_PROVEN",
            "yellow_paper_settlement_conformance": "NOT_PROVEN",
            "current_main_immutability": "NOT_INFERRED", "production_network_fetch": False},
        "action_state": {"mode": "NO_LIVE_ACTION", "ready_to_act": False,
            "authorized_to_act": False, "live_action_enabled": False,
            "compatibility": "COMPATIBILITY_REVIEW_REQUIRED"},
        "policy_version": "tclk-official-schema-offline-import-v1"}
    return value


def validate_evidence(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != FIELDS:
        raise SchemaEvidenceError("FIELD_SET_INVALID", "evidence")
    expected = _assemble()
    for key in FIELDS - {"artifact_id"}:
        if not _same(value[key], expected[key]):
            raise SchemaEvidenceError("EVIDENCE_CONTRADICTION", key)
    body = {key: value[key] for key in FIELDS if key != "artifact_id"}
    identity = _digest({"domain": DOMAIN, "schema": SCHEMA,
        "canonical_encoding": CANONICAL_ENCODING, **body})
    if not isinstance(value["artifact_id"], str) or value["artifact_id"] != identity:
        raise SchemaEvidenceError("ARTIFACT_IDENTITY_MISMATCH", "artifact_id")
    return MappingProxyType({key: value[key] for key in FIELDS})


def load_pinned_evidence() -> Mapping[str, Any]:
    value = _assemble()
    value["artifact_id"] = _digest({"domain": DOMAIN, "schema": SCHEMA,
        "canonical_encoding": CANONICAL_ENCODING,
        **{key: child for key, child in value.items() if key != "artifact_id"}})
    return validate_evidence(value)


__all__ = ["SchemaEvidenceError", "load_pinned_evidence", "validate_evidence"]


class _SealedModule(types.ModuleType):
    _protected = frozenset({"ROOT", "SNAPSHOT", "LICENSE", "SPEC", "FRAMES", "VECTORS",
        "COMMIT", "SOURCE_PATH",
        "SCHEMA_BLOB", "SCHEMA_SHA256", "SCHEMA_SIZE", "LICENSE_BLOB",
        "LICENSE_SHA256", "LICENSE_SIZE", "SPEC_BLOB", "SPEC_SHA256", "SPEC_SIZE",
        "FRAMES_BLOB", "FRAMES_SHA256", "FRAMES_SIZE", "VECTORS_BLOB",
        "VECTORS_SHA256", "VECTORS_SIZE", "_read_fixed", "_extract", "_assemble",
        "load_pinned_evidence", "validate_evidence", "__all__"})

    def __setattr__(self, name: str, value: Any) -> None:
        if name in self._protected and name in self.__dict__:
            raise AttributeError("offline evidence dependencies are sealed")
        super().__setattr__(name, value)


sys.modules[__name__].__class__ = _SealedModule
