"""Offline-verifiable DID claim over an exact public Git revision."""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .identity import load_identity, public_key_from_did
from .remote_content_policy import (
    LocalActionClass,
    ReviewedLocalIntent,
    require_local_intent,
)

SCHEMA = "flop-contribution-receipt-v1"
DOMAIN = "FLOP-CONTRIBUTION-RECEIPT-V1|"


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


create_receipt = _build_receipt_signer(require_local_intent, load_identity)


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


def read_receipt(path: Path) -> Dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("receipt must be a JSON object")
    return value
