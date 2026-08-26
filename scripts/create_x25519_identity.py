#!/usr/bin/env python3
"""Create a dedicated static X25519 identity and run a local E2E round-trip."""

from __future__ import annotations

import base64
import json
import os
import secrets
import stat
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


ROOT = Path(__file__).resolve().parents[1]
SECRET_PATH = ROOT / "secrets" / "x25519_identity.json"


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def main() -> None:
    if SECRET_PATH.exists():
        raise FileExistsError(f"X25519 identity already exists: {SECRET_PATH}")
    key = X25519PrivateKey.generate()
    private_raw = key.private_bytes_raw()
    public = b64url(key.public_key().public_bytes_raw())
    mailbox = "mb-p-" + secrets.token_hex(16)
    payload = {
        "type": "X25519",
        "private_key_b64url": b64url(private_raw),
        "public_key_b64url": public,
        "mailbox": mailbox,
    }
    SECRET_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(SECRET_PATH), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    os.chmod(SECRET_PATH, 0o600)

    peer = X25519PrivateKey.generate()
    shared_a = key.exchange(peer.public_key())
    shared_b = peer.exchange(key.public_key())
    derive = lambda shared: HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"technocore-e2e-v1",
    ).derive(shared)
    nonce = os.urandom(12)
    plaintext = b"FLOP X25519 local readiness check"
    ciphertext = AESGCM(derive(shared_a)).encrypt(nonce, plaintext, None)
    assert AESGCM(derive(shared_b)).decrypt(nonce, ciphertext, None) == plaintext
    assert stat.S_IMODE(SECRET_PATH.stat().st_mode) == 0o600
    print(json.dumps({
        "generated": True,
        "public_key_b64url": public,
        "mailbox": mailbox,
        "permission": "0600",
        "local_encrypt_decrypt": "PASS",
    }))


if __name__ == "__main__":
    main()
