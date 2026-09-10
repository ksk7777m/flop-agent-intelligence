"""Pure public-key-only Ed25519 did:key encoding and decoding."""

from __future__ import annotations


MULTICODEC_ED25519 = b"\xed\x01"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(raw: bytes, _alphabet: str = B58) -> str:
    leading = len(raw) - len(raw.lstrip(b"\0"))
    number = int.from_bytes(raw, "big")
    out = ""
    while number:
        number, remainder = divmod(number, 58)
        out = _alphabet[remainder] + out
    return "1" * leading + out


def _b58decode(value: str, _alphabet: str = B58) -> bytes:
    number = 0
    for character in value:
        number = number * 58 + _alphabet.index(character)
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * (len(value) - len(value.lstrip("1"))) + body


def did_from_public_key(
    public_key: bytes, _prefix: bytes = MULTICODEC_ED25519,
    _encoder: object = _b58encode,
) -> str:
    if type(public_key) is not bytes or len(public_key) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return "did:key:z" + _encoder(_prefix + public_key)  # type: ignore[operator]


def public_key_from_did(
    did: str, _decoder: object = _b58decode,
    _prefix_bytes: bytes = MULTICODEC_ED25519,
) -> bytes:
    prefix = "did:key:z"
    if not isinstance(did, str) or not did.startswith(prefix):
        raise ValueError("unsupported DID")
    decoded = _decoder(did[len(prefix):])  # type: ignore[operator]
    if decoded[:2] != _prefix_bytes or len(decoded) != 34:
        raise ValueError("DID is not an Ed25519 did:key")
    return decoded[2:]


__all__ = ["did_from_public_key", "public_key_from_did"]
