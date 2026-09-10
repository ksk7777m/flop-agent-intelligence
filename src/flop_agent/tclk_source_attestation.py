"""Offline-only verification of sealed TCLK acquisition attestations."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import sys
import time
import types
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "data/tclk_source_authorities.json"
MANIFEST_SHA256 = "a6b9fd6e879f66191a612a7aa730a3aa2b3ec4796d2a369c709672af072c3bba"
RESULT_SCHEMA = ROOT / "schemas/tclk-source-attestation.v1.json"
SCHEMA = "tclk-source-attestation-verification-v1"
ARTIFACT_VERSION = "tclk-source-attestation-v1"
DOMAIN = b"TCLK_SOURCE_ATTESTATION\x00V1|"
POLICY = "tclk-source-attestation-policy-v1"
SOURCE_TYPES = frozenset({"DIRECT_EXPORT", "MCP_PAGE", "PROVIDED_EXPORT", "LOCAL_ARCHIVE", "UNKNOWN_SOURCE"})
ARTIFACT_FIELDS = frozenset({"version", "authority_id", "authority_version", "policy_id", "key_id", "source_type", "source_binding_sha256", "generation", "acquired_at", "issued_at", "expires_at", "evidence_sha256", "context_sha256", "attestation_nonce", "signature"})
AUTHORITY_FIELDS = frozenset({"authority_id", "authority_version", "policy_id", "key_id", "public_key_b64url", "allowed_source_types", "allowed_source_ids"})
CONTEXT_FIELDS = frozenset({"source_type", "source_id", "generation", "acquisition_mode", "acquired_at", "acquisition_scope", "offer_sha256", "first_seq", "high_water_seq", "lower_boundary", "upper_boundary", "truncated", "dropped_count", "bounded_page", "retention_loss", "artifact_set_status"})
MAX_ARTIFACT_BYTES = 8192
MAX_BOUND_BYTES = 8 * 1024 * 1024
MAX_REPLAY_BYTES = 64 * 1024
STAGES = ("SCHEMA_VALIDATION", "CANONICAL_VALIDATION", "AUTHORITY_LOOKUP", "AUTHORITY_POLICY", "SIGNATURE_VERIFICATION", "DIGEST_BINDING", "GENERATION_CONTEXT_BINDING", "FRESHNESS_REPLAY", "RESULT_ISSUANCE")
DECIMAL = re.compile(r"^(?:0|[1-9][0-9]{0,18})$")


def _canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _b64decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in value):
        raise ValueError
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != value:
        raise ValueError
    return raw


def _base(inputs: tuple[Any, ...]) -> dict[str, Any]:
    return {"schema": SCHEMA, "content_label": "PUBLIC_MINIMIZED_EVIDENCE", "artifact_id": "", "policy_revision": POLICY,
            "input_evidence": {"byte_lengths": [len(v) if type(v) is bytes else None for v in inputs], "raw_content_exposed": False},
            "stages": [{"ordinal": i + 1, "stage_id": name, "state": "NOT_EVALUATED"} for i, name in enumerate(STAGES)],
            "errors": [], "source_attestation": "SOURCE_ATTESTATION_INVALID", "source_authenticity": "NOT_ESTABLISHED",
            "source_completeness": "COMPLETENESS_NOT_ESTABLISHED", "winner": "GLOBAL_WINNER_UNRESOLVED", "race_loss": "NOT_ISSUED",
            "lock": "NOT_VERIFIED", "settlement": "NOT_VERIFIED", "replay": "NOT_EVALUATED", "attestation_replay_id": "",
            "ready_to_act": False, "authorized_to_act": False, "live_action_enabled": False,
            "production_api": {"classification": "SAFE_PURE_VALIDATOR", "network": "NONE", "technocore": "NONE", "remote_mcp": "NONE", "signer": "NONE", "wallet": "NONE", "settlement": "NONE"}}


def _seal(result: dict[str, Any]) -> Mapping[str, Any]:
    result["artifact_id"] = _hash(_canon({k: v for k, v in result.items() if k != "artifact_id"}))
    _validate_result(result)
    return result


def _fail(result: dict[str, Any], code: str) -> Mapping[str, Any]:
    result["errors"] = [code]
    return _seal(result)


def _parse_exact(raw: bytes) -> Any:
    value = json.loads(raw)
    if _canon(value) != raw:
        raise ValueError
    return value


def _valid_token(value: Any, limit: int = 128) -> bool:
    return isinstance(value, str) and 0 < len(value) <= limit and value.isascii() and all(c.isalnum() or c in "._:-" for c in value)


def _valid_decimal(value: Any) -> bool:
    return isinstance(value, str) and DECIMAL.fullmatch(value) is not None


def _valid_uint(value: Any) -> bool:
    return type(value) is int and 0 <= value <= 9007199254740991


def _load_manifest(raw: bytes) -> dict[str, Any]:
    body = raw[:-1] if raw.endswith(b"\n") else raw
    value = _parse_exact(body)
    if not isinstance(value, dict) or set(value) != {"schema", "policy_revision", "authorities"} or value["schema"] != "tclk-source-authorities-v1" or value["policy_revision"] != POLICY or not isinstance(value["authorities"], list):
        raise ValueError
    authority_ids: set[str] = set()
    key_ids: set[str] = set()
    for item in value["authorities"]:
        if not isinstance(item, dict) or set(item) != AUTHORITY_FIELDS or not all(_valid_token(item[k]) for k in ("authority_id", "authority_version", "policy_id", "key_id")) or item["policy_id"] != POLICY:
            raise ValueError
        key = _b64decode(item["public_key_b64url"])
        if len(key) != 32 or not isinstance(item["allowed_source_types"], list) or not item["allowed_source_types"] or len(set(item["allowed_source_types"])) != len(item["allowed_source_types"]) or any(x not in SOURCE_TYPES for x in item["allowed_source_types"]) or not isinstance(item["allowed_source_ids"],list) or not item["allowed_source_ids"] or len(set(item["allowed_source_ids"]))!=len(item["allowed_source_ids"]) or any(not _valid_token(x) for x in item["allowed_source_ids"]):
            raise ValueError
        if item["authority_id"] in authority_ids or item["key_id"] in key_ids:
            raise ValueError
        authority_ids.add(item["authority_id"])
        key_ids.add(item["key_id"])
    return value


def _verify(evidence: bytes, descriptor: bytes, context: bytes, artifact_raw: bytes, replay_raw: bytes, manifest_raw: bytes, now: int) -> Mapping[str, Any]:
    result = _base((evidence, descriptor, context, artifact_raw, replay_raw))
    stages = result["stages"]
    if any(type(v) is not bytes for v in (evidence, descriptor, context, artifact_raw, replay_raw)) or type(now) is not int:
        return _fail(result, "INPUT_TYPE_INVALID")
    if any(len(v) > MAX_BOUND_BYTES for v in (evidence, descriptor, context)) or len(artifact_raw) > MAX_ARTIFACT_BYTES or len(replay_raw) > MAX_REPLAY_BYTES:
        return _fail(result, "INPUT_LIMIT_EXCEEDED")
    try:
        artifact = _parse_exact(artifact_raw)
    except Exception:
        return _fail(result, "SOURCE_ATTESTATION_SCHEMA_INVALID")
    if not isinstance(artifact, dict) or set(artifact) != ARTIFACT_FIELDS:
        return _fail(result, "SOURCE_ATTESTATION_SCHEMA_INVALID")
    stages[0]["state"] = "VERIFIED"
    tokens = ("authority_id", "authority_version", "policy_id", "key_id", "source_binding_sha256", "generation")
    if artifact["version"] != ARTIFACT_VERSION or not all(_valid_token(artifact[k]) for k in tokens) or not _valid_decimal(artifact["attestation_nonce"]) or artifact["policy_id"] != POLICY or artifact["source_type"] not in SOURCE_TYPES or any(not isinstance(artifact[k], str) or len(artifact[k]) != 64 or any(c not in "0123456789abcdef" for c in artifact[k]) for k in ("evidence_sha256", "context_sha256")) or any(not _valid_uint(artifact[k]) for k in ("acquired_at", "issued_at", "expires_at")) or artifact["acquired_at"] > artifact["issued_at"] or artifact["issued_at"] > artifact["expires_at"]:
        return _fail(result, "SOURCE_ATTESTATION_CANONICAL_INVALID")
    stages[1]["state"] = "VERIFIED"
    try: manifest = _load_manifest(manifest_raw)
    except Exception: return _fail(result, "SOURCE_AUTHORITY_MANIFEST_INVALID")
    matches = [x for x in manifest["authorities"] if x["authority_id"] == artifact["authority_id"] and x["authority_version"] == artifact["authority_version"] and x["key_id"] == artifact["key_id"]]
    if len(matches) != 1:
        return _fail(result, "SOURCE_ATTESTATION_UNKNOWN_AUTHORITY")
    authority = matches[0]; stages[2]["state"] = "VERIFIED"
    if authority["policy_id"] != artifact["policy_id"] or artifact["source_type"] not in authority["allowed_source_types"]:
        return _fail(result, "SOURCE_ATTESTATION_POLICY_MISMATCH")
    stages[3]["state"] = "VERIFIED"
    signed = {k: v for k, v in artifact.items() if k != "signature"}
    try:
        signature = _b64decode(artifact["signature"])
        if len(signature) != 64: raise ValueError
        Ed25519PublicKey.from_public_bytes(_b64decode(authority["public_key_b64url"])).verify(signature, DOMAIN + _canon(signed))
    except Exception:
        return _fail(result, "SOURCE_ATTESTATION_SIGNATURE_INVALID")
    stages[4]["state"] = "VERIFIED"
    if not hmac.compare_digest(artifact["evidence_sha256"], _hash(evidence)) or not hmac.compare_digest(artifact["context_sha256"], _hash(context)) or not hmac.compare_digest(artifact["source_binding_sha256"], _hash(descriptor)):
        return _fail(result, "SOURCE_ATTESTATION_DIGEST_MISMATCH")
    stages[5]["state"] = "VERIFIED"
    try: descriptor_value = _parse_exact(descriptor); context_value = _parse_exact(context)
    except Exception: return _fail(result, "SOURCE_ATTESTATION_GENERATION_MISMATCH")
    if not isinstance(descriptor_value, dict) or set(descriptor_value) != {"source_type", "source_id", "generation"} or descriptor_value.get("source_type") != artifact["source_type"] or descriptor_value.get("generation") != artifact["generation"] or not _valid_token(descriptor_value.get("source_id")) or descriptor_value.get("source_id") not in authority["allowed_source_ids"] or not isinstance(context_value, dict) or set(context_value) != CONTEXT_FIELDS or context_value.get("source_type") != artifact["source_type"] or context_value.get("source_id") != descriptor_value["source_id"] or context_value.get("generation") != artifact["generation"] or context_value.get("acquired_at") != artifact["acquired_at"] or not _valid_token(context_value.get("acquisition_mode")) or context_value.get("acquisition_scope") not in {"OFFER_WIDE", "PARTIAL"} or not isinstance(context_value.get("offer_sha256"), str) or len(context_value["offer_sha256"]) != 64 or any(c not in "0123456789abcdef" for c in context_value["offer_sha256"]) or any(not _valid_uint(context_value.get(k)) for k in ("first_seq", "high_water_seq", "dropped_count")) or context_value["first_seq"] > context_value["high_water_seq"] or any(type(context_value.get(k)) is not bool for k in ("lower_boundary", "upper_boundary", "truncated", "bounded_page", "retention_loss")) or context_value.get("artifact_set_status") not in {"NO_CONFLICTS", "CONFLICT_UNRESOLVED"}:
        return _fail(result, "SOURCE_ATTESTATION_GENERATION_MISMATCH")
    stages[6]["state"] = "VERIFIED"
    replay_id = _hash(_canon({"authority_id": artifact["authority_id"], "authority_version": artifact["authority_version"], "attestation_nonce": artifact["attestation_nonce"]}))
    try: replay = _parse_exact(replay_raw)
    except Exception: return _fail(result, "SOURCE_ATTESTATION_REPLAY_INVALID")
    if not isinstance(replay, list) or any(not isinstance(x, str) or len(x) != 64 or any(c not in "0123456789abcdef" for c in x) for x in replay):
        return _fail(result, "SOURCE_ATTESTATION_REPLAY_INVALID")
    if replay_id in replay:
        result["replay"] = "DUPLICATE_REJECTED"; return _fail(result, "SOURCE_ATTESTATION_DUPLICATE")
    if now < artifact["issued_at"] or now > artifact["expires_at"]:
        return _fail(result, "SOURCE_ATTESTATION_EXPIRED")
    stages[7]["state"] = "VERIFIED"; result["replay"] = "UNSEEN_IN_PROVIDED_LEDGER"; result["attestation_replay_id"] = replay_id
    result["source_attestation"] = "SOURCE_ATTESTATION_VERIFIED"; result["source_authenticity"] = "AUTHENTICATED_SOURCE"
    stages[8]["state"] = "VERIFIED"
    return _seal(result)


def _build_public_verifier(manifest_path: Path, manifest_sha256: str, verifier: Any, hash_bytes: Any, clock: Any) -> Any:
    """Capture reviewed dependencies so module-global rebinding cannot add trust."""
    def verify_source_attestation(evidence_bytes: bytes, source_descriptor_bytes: bytes, acquisition_context_bytes: bytes, attestation_bytes: bytes, replay_ledger_bytes: bytes) -> Mapping[str, Any]:
        """Verify provenance locally; never issue completeness, winner, or action."""
        try:
            manifest_raw = manifest_path.read_bytes()
            if not hmac.compare_digest(hash_bytes(manifest_raw), manifest_sha256): manifest_raw = b""
        except Exception: manifest_raw = b""
        return verifier(evidence_bytes, source_descriptor_bytes, acquisition_context_bytes, attestation_bytes, replay_ledger_bytes, manifest_raw, int(clock()))
    return verify_source_attestation


verify_source_attestation = _build_public_verifier(MANIFEST, MANIFEST_SHA256, _verify, _hash, time.time)


def _validate_result(value: Any) -> None:
    try:
        schema = json.loads(RESULT_SCHEMA.read_bytes()); Draft202012Validator.check_schema(schema); Draft202012Validator(schema).validate(value)
    except Exception: raise ValueError("RESULT_SCHEMA_INVALID") from None
    expected = _hash(_canon({k: v for k, v in value.items() if k != "artifact_id"}))
    if not hmac.compare_digest(value["artifact_id"], expected) or value["source_completeness"] != "COMPLETENESS_NOT_ESTABLISHED" or value["winner"] != "GLOBAL_WINNER_UNRESOLVED" or value["race_loss"] != "NOT_ISSUED" or value["lock"] != "NOT_VERIFIED" or value["settlement"] != "NOT_VERIFIED" or value["ready_to_act"] is not False or value["authorized_to_act"] is not False or value["live_action_enabled"] is not False:
        raise ValueError("AUTHORITY_ESCALATION_REJECTED")
    for index, (stage, name) in enumerate(zip(value["stages"], STAGES), 1):
        if type(stage["ordinal"]) is not int or stage["ordinal"] != index or stage["stage_id"] != name: raise ValueError("STAGE_GRAMMAR_INVALID")
    verified = value["source_attestation"] == "SOURCE_ATTESTATION_VERIFIED"
    if verified != (not value["errors"] and value["source_authenticity"] == "AUTHENTICATED_SOURCE" and value["replay"] == "UNSEEN_IN_PROVIDED_LEDGER" and len(value["attestation_replay_id"]) == 64 and all(x["state"] == "VERIFIED" for x in value["stages"])):
        raise ValueError("SOURCE_ATTESTATION_STATE_CONTRADICTION")
    if not verified and (value["source_authenticity"] != "NOT_ESTABLISHED" or value["stages"][-1]["state"] != "NOT_EVALUATED" or not value["errors"]):
        raise ValueError("SOURCE_ATTESTATION_STATE_CONTRADICTION")
    seen_not_evaluated = False
    for stage in value["stages"]:
        seen_not_evaluated = seen_not_evaluated or stage["state"] == "NOT_EVALUATED"
        if seen_not_evaluated and stage["state"] == "VERIFIED": raise ValueError("STAGE_GRAMMAR_INVALID")


__all__ = ["verify_source_attestation"]


class _Sealed(types.ModuleType):
    _protected = frozenset({"MANIFEST", "MANIFEST_SHA256", "RESULT_SCHEMA", "SCHEMA", "ARTIFACT_VERSION", "DOMAIN", "POLICY", "SOURCE_TYPES", "ARTIFACT_FIELDS", "AUTHORITY_FIELDS", "CONTEXT_FIELDS", "STAGES", "DECIMAL", "verify_source_attestation", "_valid_decimal", "_verify", "_build_public_verifier", "_validate_result", "__all__"})
    def __setattr__(self, name: str, value: Any) -> None:
        if name in self._protected and name in self.__dict__: raise AttributeError("source attestation dependencies are sealed")
        super().__setattr__(name, value)


sys.modules[__name__].__class__ = _Sealed
