"""Offline-verifiable DID claim over an exact public Git revision."""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .identity import _PRODUCTION_IDENTITY_PATH, _load_identity, public_key_from_did
from .remote_content_policy import (
    LocalActionClass,
    ReviewedLocalIntent,
    require_local_intent,
)

SCHEMA = "flop-contribution-receipt-v1"
DOMAIN = "FLOP-CONTRIBUTION-RECEIPT-V1|"
RECEIPT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,126}\.json$")


class ReceiptReadError(ValueError):
    """Secret-safe receipt lookup or validation failure."""

    def __init__(self, reason: str, *, field: str = "receipt"):
        super().__init__(f"receipt validation failed: {reason}")
        self.metadata = {
            "field": field, "error_class": type(self).__name__,
            "type": "receipt", "reason": reason,
        }


def _validate_repo(repo: str) -> str:
    parsed = urlparse(repo)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("repo must be a public HTTPS URL without credentials")
    return repo.rstrip("/")


def _validate_commit(commit: str) -> str:
    value = commit.lower()
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value):
        raise ValueError("commit must be a full 40- or 64-character hexadecimal object id")
    return value


def canonical_payload(payload: Dict[str, str]) -> bytes:
    required = {"schema", "repo", "commit", "artifact_name", "timestamp"}
    if set(payload) != required or payload.get("schema") != SCHEMA:
        raise ValueError("invalid contribution receipt payload")
    normalized = {
        "artifact_name": str(payload["artifact_name"]).strip(),
        "commit": _validate_commit(payload["commit"]),
        "repo": _validate_repo(payload["repo"]),
        "schema": SCHEMA,
        "timestamp": str(payload["timestamp"]).strip(),
    }
    if not normalized["artifact_name"] or not normalized["timestamp"]:
        raise ValueError("artifact_name and timestamp are required")
    try:
        datetime.fromisoformat(normalized["timestamp"].replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("timestamp must be ISO 8601") from error
    return (DOMAIN + json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)).encode("utf-8")


def _build_receipt_signer(require_capability: Any, identity_loader: Any) -> Any:
    """Capture the capability validator and key loader before public calls exist."""
    action = LocalActionClass.RECEIPT_SIGN
    schema, domain = SCHEMA, DOMAIN
    validate_repo, validate_commit = _validate_repo, _validate_commit
    canonicalizer = canonical_payload
    encode_signature = base64.urlsafe_b64encode
    now = lambda: datetime.now(timezone.utc).isoformat()

    def create(
        identity_path: Path, repo: str, commit: str, artifact_name: str,
        timestamp: Optional[str] = None, *, intent: ReviewedLocalIntent | None = None,
    ) -> Dict[str, Any]:
        payload = {
            "schema": schema, "repo": validate_repo(repo),
            "commit": validate_commit(commit), "artifact_name": artifact_name.strip(),
            "timestamp": timestamp or now(),
        }
        canonical = canonicalizer(payload)
        canonical_text = canonical.decode("utf-8")
        require_capability(
            intent, action, canonical_text,
            target=str(identity_path.resolve()), payload=canonical_text,
            context=domain, revision=payload["commit"], config_version=schema,
            consume=True)
        key, did = identity_loader(identity_path)
        signature = encode_signature(key.sign(canonical)).decode("ascii").rstrip("=")
        return {"schema": schema, "did": did, "payload": payload, "signature": signature}

    return create


_PRODUCTION_RECEIPT_SIGNER = _build_receipt_signer(require_local_intent, _load_identity)


def _build_public_receipt_signer(identity_path: Path, signer: Any) -> Any:
    configured_identity = identity_path.resolve()
    captured_signer = signer

    def create_receipt(
        repo: str, commit: str, artifact_name: str,
        timestamp: Optional[str] = None, *,
        intent: ReviewedLocalIntent | None = None,
    ) -> Dict[str, Any]:
        return captured_signer(
            configured_identity, repo, commit, artifact_name, timestamp,
            intent=intent)

    return create_receipt


create_receipt = _build_public_receipt_signer(
    _PRODUCTION_IDENTITY_PATH, _PRODUCTION_RECEIPT_SIGNER)


def verify_receipt(receipt: Dict[str, Any]) -> Dict[str, str]:
    if set(receipt) != {"schema", "did", "payload", "signature"} or receipt.get("schema") != SCHEMA:
        raise ValueError("invalid contribution receipt envelope")
    canonical = canonical_payload(receipt["payload"])
    signature = str(receipt["signature"])
    raw = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    if len(raw) != 64:
        raise ValueError("invalid Ed25519 signature length")
    Ed25519PublicKey.from_public_bytes(public_key_from_did(str(receipt["did"]))).verify(raw, canonical)
    return {
        "status": "VALID", "did": str(receipt["did"]),
        "repo": receipt["payload"]["repo"], "commit": receipt["payload"]["commit"],
        "artifact_name": receipt["payload"]["artifact_name"],
    }


def _validate_receipt_document(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ReceiptReadError("invalid object type")
    if set(value) != {"schema", "did", "payload", "signature"}:
        raise ReceiptReadError("invalid envelope fields")
    if value.get("schema") != SCHEMA:
        raise ReceiptReadError("invalid schema", field="schema")
    if not isinstance(value.get("did"), str) or not value["did"].startswith("did:key:z"):
        raise ReceiptReadError("invalid value", field="did")
    if not isinstance(value.get("signature"), str):
        raise ReceiptReadError("invalid value type", field="signature")
    try:
        canonical_payload(value.get("payload"))
    except (KeyError, TypeError, ValueError) as error:
        raise ReceiptReadError("invalid payload", field="payload") from error
    return value


def _build_receipt_store(
    receipt_root: Path,
    text_reader: Callable[[Path], str] = lambda path: path.read_text(encoding="utf-8"),
) -> Callable[[str], Dict[str, Any]]:
    """Capture one approved receipt directory; callers provide an opaque safe ID."""
    configured_root = receipt_root.resolve()
    captured_reader = text_reader
    parser = json.loads
    validator = _validate_receipt_document
    id_pattern = RECEIPT_ID_RE

    def read(receipt_id: str) -> Dict[str, Any]:
        if not isinstance(receipt_id, str) or id_pattern.fullmatch(receipt_id) is None:
            raise ReceiptReadError("invalid identifier", field="receipt_id")
        candidate = configured_root / receipt_id
        try:
            if candidate.is_symlink():
                raise ReceiptReadError("symlink forbidden", field="receipt_id")
            resolved = candidate.resolve(strict=True)
            if resolved.parent != configured_root or not resolved.is_file():
                raise ReceiptReadError("identifier outside approved store", field="receipt_id")
            raw = captured_reader(resolved)
            value = parser(raw)
        except ReceiptReadError:
            raise
        except (OSError, json.JSONDecodeError) as error:
            raise ReceiptReadError("unavailable or malformed") from error
        return validator(value)

    return read


_PRODUCTION_RECEIPT_ROOT = Path(__file__).resolve().parents[2] / "receipts"
read_receipt = _build_receipt_store(_PRODUCTION_RECEIPT_ROOT)
