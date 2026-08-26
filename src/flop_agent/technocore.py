"""Minimal Technocore client; no room-provided URL is ever followed."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict

from .identity import load_identity, sign_message

BASE_URL = "https://technocore.chat"
ALLOWED_READ_PATHS = {"/healthz", "/rooms", "/r/lobby?format=json", "/llms.txt", "/skill.md", "/patterns.md", "/.well-known/agent.json"}


def _request(url: str, payload: Dict[str, Any] | None = None) -> Any:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {} if data is None else {"Content-Type": "application/json"}
    req = urllib.request.Request(url, data=data, headers=headers, method="GET" if data is None else "POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            body = response.read().decode("utf-8")
            content_type = response.headers.get("Content-Type", "")
            return json.loads(body) if "json" in content_type else body
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Technocore HTTP {error.code}: {body}") from error


def read_official(path: str) -> Any:
    if path not in ALLOWED_READ_PATHS:
        raise ValueError("read path is not in the configured official allowlist")
    return _request(BASE_URL + path)


def healthcheck() -> Dict[str, Any]:
    return {
        "healthz": read_official("/healthz"),
        "rooms": read_official("/rooms"),
        "lobby": read_official("/r/lobby?format=json"),
    }


def post_signed(identity_path: Path, room: str, text: str, nonce: int | None = None) -> Dict[str, Any]:
    key, did = load_identity(identity_path)
    nonce = nonce or int(time.time_ns() // 1_000_000)
    signature, clean = sign_message(key, room, nonce, text)
    payload = {"did": did, "sig": signature, "nonce": str(nonce), "text": clean}
    _request(f"{BASE_URL}/r/{urllib.parse.quote(room, safe='')}", payload)
    # The live POST response may be the plain-text room view. Re-read JSON and
    # match all signed fields rather than parsing or trusting rendered content.
    view = _request(f"{BASE_URL}/r/{urllib.parse.quote(room, safe='')}?limit=200&format=json")
    if not isinstance(view, dict):
        raise RuntimeError("Technocore JSON verification read returned an unexpected shape")
    matches = [
        message for message in view.get("messages", [])
        if message.get("from") == did
        and str(message.get("nonce")) == str(nonce)
        and message.get("text") == clean
    ]
    if len(matches) != 1:
        raise RuntimeError(f"could not uniquely verify signed post in JSON view (matches={len(matches)})")
    return {
        **matches[0],
        "signature": signature,
        "input_text": text,
        "swept_text": clean,
    }


def find_signed(identity_path: Path, room: str, text: str) -> Dict[str, Any]:
    """Recover a confirmed recent record without reposting it."""
    _, did = load_identity(identity_path)
    clean = text.strip()
    view = _request(f"{BASE_URL}/r/{urllib.parse.quote(room, safe='')}?limit=200&format=json")
    matches = [m for m in view.get("messages", []) if m.get("from") == did and m.get("text") == clean]
    if not matches:
        raise RuntimeError("signed record not found in recent room history")
    return matches[-1]


def permalink(room: str, seq: int) -> str:
    return f"{BASE_URL}/#r/{room}/{seq}"
