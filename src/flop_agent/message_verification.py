"""Technocore message canonicalization and public-key verification only."""

from __future__ import annotations

import base64
import unicodedata
from typing import Any, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .did_key import public_key_from_did
from .wire_evidence import _capture_signing_policy


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


def canonical_message(
    room: str, nonce: str, text: str, *, _sweeper: Any = _SEALED_TEXT_SWEEPER,
    _context_builder: Any = _capture_signing_policy()[0],
) -> Tuple[str, str]:
    clean = _sweeper(text)
    context = _context_builder(room, nonce, clean)
    return context.canonical_bytes.decode("utf-8"), clean


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
