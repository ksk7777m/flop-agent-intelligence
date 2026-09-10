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

from .did_key import did_from_public_key, public_key_from_did
from .remote_content_policy import (
    LocalActionClass,
    ReviewedLocalIntent,
    require_local_intent,
)
from .wire_evidence import (
    _capture_signing_policy,
    build_signing_context,
    signing_capability_material,
)

INVISIBLE_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"}


def _capture_text_sweeper() -> Any:
    category = unicodedata.category
    invisible_categories = frozenset(INVISIBLE_CATEGORIES)
    character_limit = 4096

    def sealed_sweep(text: str, limit: int = character_limit) -> str:
        cleaned = "".join(
            " " if category(char) in invisible_categories else char
            for char in text).strip()
        if not cleaned:
            raise ValueError("text is empty after the Technocore single-line sweep")
        if len(cleaned) > limit:
            raise ValueError("text exceeds Technocore's character limit")
        return cleaned

    return sealed_sweep


_SEALED_TEXT_SWEEPER = _capture_text_sweeper()


def sweep_text(text: str, limit: int = 4096) -> str:
    return _SEALED_TEXT_SWEEPER(text, limit)


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


def _load_identity(
    path: Path, *, _mode: Any = stat.S_IMODE, _json_loads: Any = json.loads,
    _b64decode: Any = base64.urlsafe_b64decode,
    _key_type: Any = Ed25519PrivateKey,
    _did_builder: Any = did_from_public_key,
) -> Tuple[Ed25519PrivateKey, str]:
    """Low-level local primitive; production callers use the sealed service below."""
    mode = _mode(path.stat().st_mode)
    if mode & 0o077:
        raise PermissionError(f"identity permissions must be 0600, got {mode:04o}")
    payload: Dict[str, Any] = _json_loads(path.read_text(encoding="utf-8"))
    encoded = payload["seed_b64"]
    seed = _b64decode(encoded + "=" * (-len(encoded) % 4))
    if len(seed) != 32:
        raise ValueError("invalid Ed25519 seed")
    key = _key_type.from_private_bytes(seed)
    did = _did_builder(key.public_key().public_bytes_raw())
    if payload.get("did") != did:
        raise ValueError("stored DID does not match private key")
    return key, did


def canonical_message(
    room: str, nonce: str, text: str, *, _sweeper: Any = _SEALED_TEXT_SWEEPER,
    _context_builder: Any = _capture_signing_policy()[0],
) -> Tuple[str, str]:
    clean = _sweeper(text)
    context = _context_builder(room, nonce, clean)
    return context.canonical_bytes.decode("utf-8"), clean


def _sign_message(
    key: Ed25519PrivateKey, room: str, nonce: str, text: str, *,
    _canonicalizer: Any = canonical_message,
    _b64encode: Any = base64.urlsafe_b64encode,
) -> Tuple[str, str]:
    """Low-level signer retained only for sealed services and offline unit fixtures."""
    canonical, clean = _canonicalizer(room, nonce, text)
    signature = _b64encode(key.sign(canonical.encode("utf-8"))).decode().rstrip("=")
    return signature, clean


def verify_message(
    did: str, signature: str, room: str, nonce: str, text: str, *,
    _canonicalizer: Any = canonical_message,
    _b64decode: Any = base64.urlsafe_b64decode,
    _public_key_type: Any = Ed25519PublicKey,
    _did_decoder: Any = public_key_from_did,
) -> None:
    canonical, _ = _canonicalizer(room, nonce, text)
    raw_sig = _b64decode(signature + "=" * (-len(signature) % 4))
    _public_key_type.from_public_bytes(_did_decoder(did)).verify(
        raw_sig, canonical.encode("utf-8"))


IDENTITY_SIGN_CONTEXT = "FLOP-LOCAL-IDENTITY-SIGN-V1"


def _build_local_identity_service(
    identity_path: Path, capability_validator: Any, identity_loader: Any,
    message_signer: Any, message_verifier: Any,
) -> tuple[Any, Any, Any]:
    """Capture local key access; raw key-bearing objects never leave this service."""
    configured_path = identity_path.resolve()
    action = LocalActionClass.IDENTITY_SIGN
    context = IDENTITY_SIGN_CONTEXT
    text_sweeper = _capture_text_sweeper()
    context_builder, capability_material_builder = _capture_signing_policy()

    def get_public_did() -> str:
        _, did = identity_loader(configured_path)
        return did

    def verify_status() -> Dict[str, Any]:
        key, did = identity_loader(configured_path)
        signature, clean = message_signer(
            key, "local-check", "1", "identity verification")
        message_verifier(did, signature, "local-check", "1", clean)
        return {"did": did, "verified": True, "permission": "0600"}

    def sign_authorized(
        room: str, nonce: str, text: str, *, intent: ReviewedLocalIntent,
        revision: str, config_version: str,
        external_challenge: bytes | None = None,
    ) -> Dict[str, str]:
        clean = text_sweeper(text)
        signing_context = context_builder(
            room, nonce, clean, external_challenge=external_challenge)
        material = capability_material_builder(
            signing_context, action_class=action.value,
            target=str(configured_path), revision=revision,
            config_version=config_version, purpose=context)
        capability_validator(
            intent, action, material["subject"], target=material["target"],
            payload=material["payload"], context=material["context"],
            revision=revision, config_version=config_version,
            consume=True)
        key, did = identity_loader(configured_path)
        signature, signed_clean = message_signer(key, room, nonce, clean)
        signed_context = context_builder(room, nonce, signed_clean)
        if (signed_clean != clean
                or signed_context.canonical_bytes != signing_context.canonical_bytes):
            raise RuntimeError("local signer canonicalization mismatch")
        return {"did": did, "signature": signature, "text": clean,
                "nonce": signing_context.nonce.decimal}

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
