"""Dedicated Ed25519 did:key identity handling."""

from __future__ import annotations

import base64
import json
import os
import secrets
import stat
import unicodedata
from pathlib import Path
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .remote_content_policy import (
    LocalActionClass,
    ReviewedLocalIntent,
    require_local_intent,
)

MULTICODEC_ED25519 = b"\xed\x01"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
INVISIBLE_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"}


def sweep_text(text: str, limit: int = 4096) -> str:
    cleaned = "".join(" " if unicodedata.category(c) in INVISIBLE_CATEGORIES else c for c in text).strip()
    if not cleaned:
        raise ValueError("text is empty after the Technocore single-line sweep")
    if len(cleaned) > limit:
        raise ValueError("text exceeds Technocore's character limit")
    return cleaned


def _b58encode(raw: bytes) -> str:
    leading = len(raw) - len(raw.lstrip(b"\0"))
    number = int.from_bytes(raw, "big")
    out = ""
    while number:
        number, rem = divmod(number, 58)
        out = B58[rem] + out
    return "1" * leading + out


def _b58decode(value: str) -> bytes:
    number = 0
    for char in value:
        number = number * 58 + B58.index(char)
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * (len(value) - len(value.lstrip("1"))) + body


def did_from_public_key(public_key: bytes) -> str:
    if len(public_key) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return "did:key:z" + _b58encode(MULTICODEC_ED25519 + public_key)


def public_key_from_did(did: str) -> bytes:
    prefix = "did:key:z"
    if not did.startswith(prefix):
        raise ValueError("unsupported DID")
    decoded = _b58decode(did[len(prefix) :])
    if decoded[:2] != MULTICODEC_ED25519 or len(decoded) != 34:
        raise ValueError("DID is not an Ed25519 did:key")
    return decoded[2:]


def _create_identity(path: Path) -> str:
    path = path.resolve()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"identity already exists: {path}")
    seed = secrets.token_bytes(32)
    key = Ed25519PrivateKey.from_private_bytes(seed)
    public = key.public_key().public_bytes_raw()
    did = did_from_public_key(public)
    payload = {"type": "Ed25519", "did": did, "seed_b64": base64.urlsafe_b64encode(seed).decode().rstrip("=")}
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
    except Exception:
        path.unlink(missing_ok=True)
        raise
    os.chmod(path, 0o600)
    return did


def _load_identity(path: Path) -> Tuple[Ed25519PrivateKey, str]:
    """Low-level local primitive; production callers use the sealed service below."""
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise PermissionError(f"identity permissions must be 0600, got {mode:04o}")
    payload: Dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    encoded = payload["seed_b64"]
    seed = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    if len(seed) != 32:
        raise ValueError("invalid Ed25519 seed")
    key = Ed25519PrivateKey.from_private_bytes(seed)
    did = did_from_public_key(key.public_key().public_bytes_raw())
    if payload.get("did") != did:
        raise ValueError("stored DID does not match private key")
    return key, did


def canonical_message(room: str, nonce: int, text: str) -> Tuple[str, str]:
    if not (0 < nonce < 10**19):
        raise ValueError("nonce must be 1-19 digits")
    clean = sweep_text(text)
    return f"{room}|{nonce}|{clean}", clean


def _sign_message(key: Ed25519PrivateKey, room: str, nonce: int, text: str) -> Tuple[str, str]:
    """Low-level signer retained only for sealed services and offline unit fixtures."""
    canonical, clean = canonical_message(room, nonce, text)
    signature = base64.urlsafe_b64encode(key.sign(canonical.encode("utf-8"))).decode().rstrip("=")
    return signature, clean


def verify_message(did: str, signature: str, room: str, nonce: int, text: str) -> None:
    canonical, _ = canonical_message(room, nonce, text)
    raw_sig = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    Ed25519PublicKey.from_public_bytes(public_key_from_did(did)).verify(raw_sig, canonical.encode("utf-8"))


IDENTITY_SIGN_CONTEXT = "FLOP-LOCAL-IDENTITY-SIGN-V1"


def _build_local_identity_service(
    identity_path: Path, capability_validator: Any, identity_loader: Any,
    message_signer: Any, message_verifier: Any,
) -> tuple[Any, Any, Any]:
    """Capture local key access; raw key-bearing objects never leave this service."""
    configured_path = identity_path.resolve()
    action = LocalActionClass.IDENTITY_SIGN
    context = IDENTITY_SIGN_CONTEXT
    canonicalizer = canonical_message

    def get_public_did() -> str:
        _, did = identity_loader(configured_path)
        return did

    def verify_status() -> Dict[str, Any]:
        key, did = identity_loader(configured_path)
        signature, clean = message_signer(
            key, "local-check", 1, "identity verification")
        message_verifier(did, signature, "local-check", 1, clean)
        return {"did": did, "verified": True, "permission": "0600"}

    def sign_authorized(
        room: str, nonce: int, text: str, *, intent: ReviewedLocalIntent,
        revision: str, config_version: str,
    ) -> Dict[str, str]:
        canonical, _ = canonicalizer(room, nonce, text)
        capability_validator(
            intent, action, canonical, target=str(configured_path), payload=canonical,
            context=context, revision=revision, config_version=config_version,
            consume=True)
        key, did = identity_loader(configured_path)
        signature, clean = message_signer(key, room, nonce, text)
        return {"did": did, "signature": signature, "text": clean}

    return get_public_did, verify_status, sign_authorized


_PRODUCTION_IDENTITY_PATH = (
    Path(__file__).resolve().parents[2] / "secrets" / "agent_identity.json")


def _build_identity_creator(identity_path: Path, creator: Any) -> Any:
    configured_path = identity_path.resolve()
    captured_creator = creator

    def create_local_identity() -> str:
        return captured_creator(configured_path)

    return create_local_identity


create_local_identity = _build_identity_creator(
    _PRODUCTION_IDENTITY_PATH, _create_identity)
get_public_did, verify_local_identity_status, sign_with_authorized_identity = (
    _build_local_identity_service(
        _PRODUCTION_IDENTITY_PATH, require_local_intent, _load_identity,
        _sign_message, verify_message))
