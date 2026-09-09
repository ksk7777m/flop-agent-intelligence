"""Pure, offline TCLK accept preflight against the pinned official snapshot."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import sys
import types
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from .tclk_schema_evidence import COMMIT, SCHEMA_BLOB, SCHEMA_SHA256, SCHEMA_SIZE, load_pinned_evidence

SCHEMA = "offline-tclk-accept-preflight-v1"
DOMAIN = "OFFLINE_TCLK_ACCEPT_PREFLIGHT\x00V1"
POLICY_VERSION = "offline-tclk-accept-preflight-policy-v1"
MAX_INPUT_BYTES = 4096
MAX_JSON_DEPTH = 16
MAX_OBJECT_MEMBERS = 64
MAX_ARRAY_LENGTH = 32
MAX_STRING_CHARS = 1024
MAX_STRING_BYTES = 4096
MAX_NODES = 192
SAFE_INTEGER_MAX = 9_007_199_254_740_991
STAGE_IDS = (
    "PINNED_POLICY_INTEGRITY", "INPUT_BOUNDS", "UTF8_DECODE", "STRICT_JSON_PARSE",
    "OFFER_SCHEMA_CONFORMANCE", "ACCEPT_SCHEMA_CONFORMANCE",
    "OFFER_ACCEPT_REFERENCE_BINDING", "ACCEPT_SEMANTIC_VALIDATION",
    "ALL_RAILS_VALIDATION", "CONTRACT_DERIVATION_INPUT_EXTRACTION",
    "CONTRACT_ID_RECOMPUTATION", "CONTRACT_ID_EQUALITY", "INPUT_CANONICALITY",
    "PREFLIGHT_DISPOSITION",
)
KNOWN_RAILS = frozenset({"btc-htlc", "evm-htlc", "flop-htlc", "memory", "near-htlc", "paper", "x402"})
HEX32 = re.compile(r"^0x[0-9a-f]{64}$")
HEX33 = re.compile(r"^0x[0-9a-f]{66}$")
CANONICAL_RAIL = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
CONTRACT_DOMAIN = b"FLOP::tclk::v1|contract|"
OFFER_DOMAIN = b"FLOP::tclk::v1|offer|"
ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = ROOT / "vendor" / "tclk" / COMMIT / "schema" / "tclk1-frames.schema.json"
GOLDEN_OFFER_ID = "0xd001fbbf4fa36d9ab8ea88df02a8b3303539e9d59f7ff9d9bfeb679318e9ce75"
GOLDEN_CONTRACT_ID = "0x2768bf32b455317879796093ff2e5882371cbec238611ca71f555a7fcbe58e1c"


class _InputError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _canonical(value: Any) -> bytes:
    # For the admitted JSON subset this is the pinned JS canonicalJson + toAscii form.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _hash(domain: bytes, value: Any) -> str:
    return "0x" + hashlib.sha256(domain + _canonical(value)).hexdigest()


def _offer_id(offer: Mapping[str, Any]) -> str:
    return _hash(OFFER_DOMAIN, {key: value for key, value in offer.items() if key != "id"})


def _contract_id(offer: Mapping[str, Any], accept: Mapping[str, Any]) -> str:
    core = {key: accept[key] for key in ("from", "ref", "statement", "paymentKey", "nonce") if key in accept}
    return _hash(CONTRACT_DOMAIN, {"offer": offer, "accept": core})


def _point_valid(value: Any) -> bool:
    if not isinstance(value, str) or not HEX33.fullmatch(value):
        return False
    raw = bytes.fromhex(value[2:])
    if raw[0] not in (2, 3):
        return False
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    x = int.from_bytes(raw[1:], "big")
    if x >= p:
        return False
    y2 = (pow(x, 3, p) + 7) % p
    y = pow(y2, (p + 1) // 4, p)
    return pow(y, 2, p) == y2 and ((y & 1) == (raw[0] & 1) or ((p - y) & 1) == (raw[0] & 1))


def _lexical_bounds(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    chars = 0
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
                chars = 0
            else:
                chars += 1
                if chars > MAX_STRING_CHARS:
                    raise _InputError("STRING_LIMIT_EXCEEDED")
            continue
        if ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise _InputError("JSON_DEPTH_EXCEEDED")
        elif ch in "]}":
            depth -= 1


def _parse(raw: bytes) -> Mapping[str, Any]:
    if type(raw) is not bytes:
        raise _InputError("INPUT_TYPE_INVALID")
    if len(raw) > MAX_INPUT_BYTES:
        raise _InputError("INPUT_TOO_LARGE")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise _InputError("BOM_REJECTED")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise _InputError("INVALID_UTF8") from None
    _lexical_bounds(text)
    members = 0

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        nonlocal members
        members += len(items)
        if members > MAX_OBJECT_MEMBERS:
            raise _InputError("MEMBER_LIMIT_EXCEEDED")
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise _InputError("DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    def integer(value: str) -> int:
        if len(value.lstrip("-")) > 16:
            raise _InputError("NUMERIC_REPRESENTATION_INVALID")
        parsed = int(value)
        if abs(parsed) > SAFE_INTEGER_MAX:
            raise _InputError("NUMERIC_REPRESENTATION_INVALID")
        return parsed

    def forbidden_number(_value: str) -> Any:
        raise _InputError("NUMERIC_REPRESENTATION_INVALID")

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_int=integer,
                           parse_float=forbidden_number, parse_constant=forbidden_number)
    except _InputError:
        raise
    except (ValueError, RecursionError):
        raise _InputError("MALFORMED_JSON") from None
    if not isinstance(value, dict):
        raise _InputError("TOP_LEVEL_OBJECT_REQUIRED")
    nodes = 0

    def walk(child: Any) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NODES:
            raise _InputError("STRUCTURE_COMPLEXITY_EXCEEDED")
        if isinstance(child, str):
            if len(child) > MAX_STRING_CHARS or len(child.encode("utf-8")) > MAX_STRING_BYTES:
                raise _InputError("STRING_LIMIT_EXCEEDED")
        elif isinstance(child, list):
            if len(child) > MAX_ARRAY_LENGTH:
                raise _InputError("ARRAY_LIMIT_EXCEEDED")
            for item in child:
                walk(item)
        elif isinstance(child, dict):
            for key, item in child.items():
                walk(key); walk(item)
        elif child is not None and type(child) not in (bool, int):
            raise _InputError("NON_JSON_TYPE_REJECTED")
    walk(value)
    return value


def _golden() -> bool:
    payer = "did:key:z6Mk" + "f" * 44
    payee = "did:key:z6Mk" + "g" * 44
    offer: dict[str, Any] = {"type": "offer", "from": payer, "role": "payer",
        "amount": "1000000", "asset": "FLOP", "lock": "hash",
        "rails": ["flop-htlc", "x402"], "claimByMs": 1756703600000,
        "refundAfterMs": 1756707200000, "expiresMs": 1756700600000,
        "job": {"proto": "a2a", "id": "task-3f", "context": "ctx-1"},
        "nonce": "9f2c81d04c9e1f7a"}
    if not hmac.compare_digest(_offer_id(offer), GOLDEN_OFFER_ID):
        return False
    offer["id"] = GOLDEN_OFFER_ID
    accept = {"type": "accept", "from": payee, "ref": GOLDEN_OFFER_ID,
        "statement": "0x" + "ab" * 32, "nonce": "0011223344556677"}
    return hmac.compare_digest(_contract_id(offer, accept), GOLDEN_CONTRACT_ID)


def _policy() -> tuple[Mapping[str, Any], Draft202012Validator, Draft202012Validator]:
    evidence = load_pinned_evidence()
    raw = SNAPSHOT.read_bytes()
    if len(raw) != SCHEMA_SIZE or hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256:
        raise ValueError("pinned policy")
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    if blob != SCHEMA_BLOB:
        raise ValueError("pinned policy")
    document = json.loads(raw)
    Draft202012Validator.check_schema(document)
    defs = document["$defs"]
    rail = defs["rail"]
    if set(rail["x-tclk-canonicalIds"]) != KNOWN_RAILS or rail["x-tclk-canonicalPattern"] != CANONICAL_RAIL.pattern:
        raise ValueError("pinned policy")
    if not _golden():
        raise ValueError("pinned policy")
    # Root validation deliberately exercises oneOf and same-document refs; exact type is checked too.
    return evidence, Draft202012Validator(document), Draft202012Validator(document)


def _stages() -> list[dict[str, str]]:
    return [{"stage": stage, "status": "NOT_EVALUATED"} for stage in STAGE_IDS]


def _base(offer: Any, accept: Any) -> dict[str, Any]:
    def identity(value: Any) -> dict[str, Any]:
        if type(value) is bytes:
            return {"byte_length": len(value), "sha256": hashlib.sha256(value).hexdigest()}
        return {"byte_length": None, "sha256": "UNAVAILABLE"}
    return {"schema": SCHEMA, "domain": DOMAIN, "content_label": "PUBLIC_MINIMIZED_PREFLIGHT_RESULT",
        "artifact_id": "", "policy_identity": {"policy_version": POLICY_VERSION,
            "repository": "flop-labs/tclk", "commit_sha": COMMIT, "protocol": "tclk/1",
            "schema_path": "schema/tclk1-frames.schema.json", "schema_blob_sha1": SCHEMA_BLOB,
            "schema_sha256": SCHEMA_SHA256, "schema_byte_length": SCHEMA_SIZE,
            "derivation_sources": ["SPEC.md", "src/frames.ts", "tests/vectors.test.ts"]},
        "input_evidence": {"offer": identity(offer), "accept": identity(accept),
            "hash_role": "EVIDENCE_IDENTITY_ONLY_NOT_AUTHORITY_OR_SIGNING_TARGET"},
        "stages": _stages(), "errors": [],
        "schema_conformance": {"offer": "NOT_EVALUATED", "accept": "NOT_EVALUATED"},
        "reference_binding": "NOT_EVALUATED", "contract_classification": "NOT_EVALUATED",
        "contract_equality": "NOT_EVALUATED",
        "canonicality": {"derivation": "NOT_EVALUATED", "raw_offer": "NOT_EVALUATED",
            "raw_accept": "NOT_EVALUATED", "official_wire_policy": "CANONICAL_ASCII_ENCODING_SPECIFIED",
            "local_signing_safety": "LOCAL_SIGNING_SAFETY_CANONICALITY_REQUIRED"},
        "rail_disposition": {"status": "NOT_EVALUATED", "rail_count": None,
            "maturity": "VALUE_BEARING_VERIFICATION_NOT_PERFORMED"},
        "overall_disposition": "PREFLIGHT_NOT_PERFORMED", "compatibility": "COMPATIBILITY_REVIEW_REQUIRED",
        "signature_status": "NOT_EVALUATED", "replay_status": "NOT_EVALUATED",
        "winner_status": "NOT_EVALUATED", "settlement_status": "NOT_EVALUATED",
        "ready_to_act": False, "authorized_to_act": False, "live_action_enabled": False,
        "production_api": {"classification": "SAFE_PURE_VALIDATOR", "network": "NONE",
            "filesystem": "FIXED_READ_ONLY", "side_effect": "NONE", "authority": "NONE",
            "corrected_frame_output": False}}


def _seal(result: dict[str, Any]) -> Mapping[str, Any]:
    body = {key: value for key, value in result.items() if key != "artifact_id"}
    result["artifact_id"] = hashlib.sha256(_canonical({"domain": DOMAIN, **body})).hexdigest()
    return result


def validate_tclk_accept_preflight(offer_bytes: bytes, accept_bytes: bytes) -> Mapping[str, Any]:
    """Validate two bounded JSON objects without producing frames or action authority."""
    result = _base(offer_bytes, accept_bytes)
    stages = result["stages"]
    def mark(index: int, status: str) -> None: stages[index]["status"] = status
    def stop(index: int, code: str, disposition: str = "PREFLIGHT_FAIL") -> Mapping[str, Any]:
        mark(index, "QUARANTINED" if disposition == "PREFLIGHT_QUARANTINED" else "FAIL")
        mark(13, "QUARANTINED" if disposition == "PREFLIGHT_QUARANTINED" else "FAIL")
        result["errors"] = [code]
        result["overall_disposition"] = disposition
        return _seal(result)
    try:
        _evidence, offer_validator, accept_validator = _policy()
        mark(0, "PASS")
    except Exception:
        return stop(0, "PINNED_POLICY_INTEGRITY_FAILED", "PREFLIGHT_NOT_PERFORMED")
    parsed: list[Mapping[str, Any]] = []
    for raw in (offer_bytes, accept_bytes):
        try:
            parsed.append(_parse(raw))
        except _InputError as error:
            index = 1 if error.code in {"INPUT_TYPE_INVALID", "INPUT_TOO_LARGE", "JSON_DEPTH_EXCEEDED",
                "MEMBER_LIMIT_EXCEEDED", "STRING_LIMIT_EXCEEDED", "ARRAY_LIMIT_EXCEEDED",
                "STRUCTURE_COMPLEXITY_EXCEEDED"} else 2 if error.code in {"INVALID_UTF8", "BOM_REJECTED"} else 3
            return stop(index, error.code)
    mark(1, "PASS"); mark(2, "PASS"); mark(3, "PASS")
    offer, accept = parsed
    offer_errors = list(offer_validator.iter_errors(offer))
    if offer.get("type") != "offer" or offer_errors:
        result["schema_conformance"]["offer"] = "NONCONFORMANT"
        return stop(4, "OFFER_SCHEMA_NONCONFORMANT")
    result["schema_conformance"]["offer"] = "CONFORMANT"; mark(4, "PASS")
    contract = accept.get("contract") if "contract" in accept else ...
    contract_code = ("ACCEPT_CONTRACT_MISSING" if contract is ... else
        "ACCEPT_CONTRACT_NULL" if contract is None else
        "ACCEPT_CONTRACT_WRONG_TYPE" if not isinstance(contract, str) else
        "ACCEPT_CONTRACT_EMPTY" if contract == "" else
        "ACCEPT_CONTRACT_PATTERN_INVALID" if not HEX32.fullmatch(contract) else None)
    accept_errors = list(accept_validator.iter_errors(accept))
    if accept.get("type") != "accept" or accept_errors:
        result["schema_conformance"]["accept"] = "NONCONFORMANT"
        result["contract_classification"] = contract_code or "ACCEPT_SCHEMA_NONCONFORMANT"
        return stop(5, contract_code or "ACCEPT_SCHEMA_NONCONFORMANT")
    result["schema_conformance"]["accept"] = "CONFORMANT"; mark(5, "PASS")
    expected_offer = _offer_id(offer)
    if not hmac.compare_digest(offer["id"], expected_offer):
        result["reference_binding"] = "FAILED"
        return stop(6, "OFFER_ID_RECOMPUTATION_MISMATCH")
    if not hmac.compare_digest(accept["ref"], offer["id"]):
        result["reference_binding"] = "FAILED"
        return stop(6, "ACCEPT_REF_MISMATCH")
    result["reference_binding"] = "BOUND"; mark(6, "PASS")
    if accept["from"] == offer["from"]:
        return stop(7, "ACCEPT_FROM_ROLE_INVALID")
    if offer["claimByMs"] >= offer["refundAfterMs"]:
        return stop(7, "OFFER_DEADLINE_ORDER_INVALID")
    lock = offer["lock"]
    if lock == "hash" and not HEX32.fullmatch(accept["statement"]):
        return stop(7, "ACCEPT_STATEMENT_LOCK_MISMATCH")
    if lock == "point":
        if "paymentKey" not in offer or "paymentKey" not in accept:
            return stop(7, "POINT_LOCK_PAYMENT_KEY_REQUIRED")
        if not _point_valid(offer["paymentKey"]) or not _point_valid(accept["paymentKey"]) or not _point_valid(accept["statement"]):
            return stop(7, "SECP256K1_POINT_INVALID")
    elif "paymentKey" in offer and not _point_valid(offer["paymentKey"]):
        return stop(7, "SECP256K1_POINT_INVALID")
    elif "paymentKey" in accept and not _point_valid(accept["paymentKey"]):
        return stop(7, "SECP256K1_POINT_INVALID")
    mark(7, "PASS")
    rails = offer["rails"]
    result["rail_disposition"]["rail_count"] = len(rails)
    if len(set(rails)) != len(rails):
        result["rail_disposition"]["status"] = "DUPLICATE_RAILS"
        return stop(8, "DUPLICATE_RAIL")
    if any(not CANONICAL_RAIL.fullmatch(rail) for rail in rails):
        result["rail_disposition"]["status"] = "MALFORMED_OR_ALIAS"
        return stop(8, "RAIL_NONCANONICAL", "PREFLIGHT_QUARANTINED")
    if any(rail not in KNOWN_RAILS for rail in rails):
        result["rail_disposition"]["status"] = "UNKNOWN_PRESENT"
        return stop(8, "UNKNOWN_RAIL", "PREFLIGHT_QUARANTINED")
    if rails != sorted(rails):
        result["rail_disposition"]["status"] = "ORDER_AMBIGUITY"
        return stop(8, "RAIL_ORDER_NONCANONICAL")
    result["rail_disposition"]["status"] = "ALL_KNOWN"; mark(8, "PASS")
    mark(9, "PASS")
    expected_contract = _contract_id(offer, accept); mark(10, "PASS")
    result["canonicality"]["derivation"] = "DERIVATION_CANONICAL_FORM_VALID"
    if not hmac.compare_digest(accept["contract"], expected_contract):
        result["contract_classification"] = "ACCEPT_CONTRACT_RECOMPUTATION_MISMATCH"
        result["contract_equality"] = "MISMATCH"
        return stop(11, "ACCEPT_CONTRACT_RECOMPUTATION_MISMATCH")
    result["contract_classification"] = "ACCEPT_CONTRACT_MATCH"
    result["contract_equality"] = "MATCH"; mark(11, "PASS")
    offer_canonical = hmac.compare_digest(offer_bytes, _canonical(offer))
    accept_canonical = hmac.compare_digest(accept_bytes, _canonical(accept))
    result["canonicality"]["raw_offer"] = "RAW_OFFER_BYTES_CANONICAL" if offer_canonical else "RAW_BYTES_NONCANONICAL"
    result["canonicality"]["raw_accept"] = "RAW_ACCEPT_BYTES_CANONICAL" if accept_canonical else "RAW_BYTES_NONCANONICAL"
    if not offer_canonical or not accept_canonical:
        return stop(12, "RAW_BYTES_NONCANONICAL")
    mark(12, "PASS"); mark(13, "PASS")
    result["overall_disposition"] = "PREFLIGHT_PASS"
    result["compatibility"] = "OFFLINE_PINNED_POLICY_COMPATIBLE"
    return _seal(result)


__all__ = ["validate_tclk_accept_preflight"]


class _SealedModule(types.ModuleType):
    _protected = frozenset({"ROOT", "SNAPSHOT", "KNOWN_RAILS", "CONTRACT_DOMAIN", "OFFER_DOMAIN",
        "COMMIT", "SCHEMA_BLOB", "SCHEMA_SHA256", "SCHEMA_SIZE", "GOLDEN_OFFER_ID",
        "GOLDEN_CONTRACT_ID", "MAX_INPUT_BYTES", "MAX_JSON_DEPTH", "MAX_OBJECT_MEMBERS",
        "MAX_ARRAY_LENGTH", "MAX_STRING_CHARS", "MAX_STRING_BYTES", "MAX_NODES",
        "SAFE_INTEGER_MAX", "Draft202012Validator", "load_pinned_evidence", "_policy", "_parse",
        "_lexical_bounds", "_point_valid", "_golden", "_offer_id", "_contract_id", "_canonical",
        "validate_tclk_accept_preflight", "__all__"})
    def __setattr__(self, name: str, value: Any) -> None:
        if name in self._protected and name in self.__dict__:
            raise AttributeError("offline preflight dependencies are sealed")
        super().__setattr__(name, value)


sys.modules[__name__].__class__ = _SealedModule
