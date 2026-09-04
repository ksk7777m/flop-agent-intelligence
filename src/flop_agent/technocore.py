"""Minimal Technocore client; no room-provided URL is ever followed."""

from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict

from .identity import load_identity, sign_message
from .remote_content_policy import (
    DEFAULT_RESPONSE_LIMIT,
    LocalActionClass,
    RejectRedirects,
    ReviewedLocalIntent,
    ReviewedSourceId,
    SafeRemoteError,
    SinkClass,
    authorize_sink,
    configured_official_value,
    require_local_intent,
    resolve_reviewed_source,
)

BASE_URL = "https://technocore.chat"
OFFICIAL_READ_SOURCES = frozenset({
    ReviewedSourceId.TECHNOCORE_HEALTH, ReviewedSourceId.TECHNOCORE_ROOMS,
    ReviewedSourceId.TECHNOCORE_ROOMS_JSON, ReviewedSourceId.TECHNOCORE_LOBBY_JSON,
    ReviewedSourceId.TECHNOCORE_LLMS, ReviewedSourceId.TECHNOCORE_SKILL,
    ReviewedSourceId.TECHNOCORE_PATTERNS_HOSTED,
    ReviewedSourceId.TECHNOCORE_AGENT_MANIFEST, ReviewedSourceId.TECHNOCORE_CONFIG,
})
DID_NOTE_PATH = "/kv/did-4e/1df29904c79a56"


def _decode_response(url: str, request: urllib.request.Request, *, opener: Any = None) -> Any:
    open_request = opener or urllib.request.build_opener(RejectRedirects()).open
    try:
        with open_request(request, timeout=20) as response:
            if response.geturl() != url:
                raise SafeRemoteError("FINAL_ORIGIN_MISMATCH")
            body_bytes = response.read(DEFAULT_RESPONSE_LIMIT + 1)
            if len(body_bytes) > DEFAULT_RESPONSE_LIMIT:
                raise SafeRemoteError(
                    "RESPONSE_TOO_LARGE", response_length=len(body_bytes),
                    content_sha256=hashlib.sha256(body_bytes[:DEFAULT_RESPONSE_LIMIT]).hexdigest(),
                    truncated=True)
            try:
                body = body_bytes.decode("utf-8")
            except UnicodeDecodeError as error:
                raise SafeRemoteError(
                    "INVALID_UTF8", response_length=len(body_bytes),
                    content_sha256=hashlib.sha256(body_bytes).hexdigest()) from error
            content_type = response.headers.get("Content-Type", "")
            return json.loads(body) if "json" in content_type else body
    except urllib.error.HTTPError as error:
        body = error.read(DEFAULT_RESPONSE_LIMIT + 1)
        bounded = body[:DEFAULT_RESPONSE_LIMIT]
        raise SafeRemoteError(
            "HTTP_ERROR", status=error.code, response_length=len(body),
            content_sha256=hashlib.sha256(bounded).hexdigest(),
            truncated=len(body) > DEFAULT_RESPONSE_LIMIT) from error


def _request(source_id: ReviewedSourceId, *, opener: Any = None) -> Any:
    """Read only an immutable registry entry; arbitrary URLs are not accepted."""
    source = resolve_reviewed_source(source_id)
    decision = authorize_sink(configured_official_value(source_id), SinkClass.HTTP_READ_ONLY)
    if not decision.allowed:
        raise PermissionError(decision.decision.value)
    request = urllib.request.Request(source.url, method="GET")
    return _decode_response(source.url, request, opener=opener)


def _local_request(url: str, payload: Dict[str, Any] | None, *, intent: ReviewedLocalIntent,
                   action: LocalActionClass, subject: str, target: str, capability_payload: str,
                   context: str, revision: str, config_version: str, opener: Any = None) -> Any:
    """Perform an exact-origin request only after a hash-bound local capability."""
    require_local_intent(intent, action, subject, target=target, payload=capability_payload,
                         context=context, revision=revision, config_version=config_version)
    return _authorized_local_request(url, payload, opener=opener)


def _authorized_local_request(url: str, payload: Dict[str, Any] | None, *, opener: Any = None) -> Any:
    """Internal transport called only after the public boundary consumed authority."""
    parsed = urllib.parse.urlparse(url)
    if (parsed.scheme != "https" or parsed.netloc != "technocore.chat"
            or parsed.username or parsed.password or parsed.fragment):
        raise ValueError("Technocore target is not the configured official origin")
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {} if data is None else {"Content-Type": "application/json"}
    request = urllib.request.Request(url, data=data, headers=headers, method="GET" if data is None else "POST")
    return _decode_response(url, request, opener=opener)


def read_official(source_id: ReviewedSourceId, *, opener: Any = None) -> Any:
    if source_id not in OFFICIAL_READ_SOURCES:
        raise PermissionError("source is not an approved Technocore read")
    return _request(source_id, opener=opener)


def read_presence_note(path: str, *, intent: ReviewedLocalIntent, opener: Any = None) -> Any:
    """Read only a validated public heartbeat note; 404 is represented as absent."""
    match = re.fullmatch(r"/kv/([a-z0-9][a-z0-9_-]{0,47})/hb-[a-z0-9][a-z0-9_-]{0,47}", path)
    if not match or match.group(1).startswith(("p-", "mb-")) or "-p-" in match.group(1):
        raise ValueError("not a public presence-note path")
    try:
        return _local_request(BASE_URL + path, None, intent=intent,
                              action=LocalActionClass.PRESENCE_NOTE_READ, subject=path,
                              target=path, capability_payload="", context="presence-note-read",
                              revision="0" * 40, config_version="technocore-read-v1",
                              opener=opener)
    except SafeRemoteError as error:
        if error.status == 404:
            return None
        raise


def healthcheck() -> Dict[str, Any]:
    return {
        "healthz": read_official(ReviewedSourceId.TECHNOCORE_HEALTH),
        "rooms": read_official(ReviewedSourceId.TECHNOCORE_ROOMS),
        "lobby": read_official(ReviewedSourceId.TECHNOCORE_LOBBY_JSON),
    }


def requires_signed_write(room: str) -> bool:
    return room.startswith("mb-")


def conditional_note_payload(current: str, value: str) -> Dict[str, str]:
    if not current or not value:
        raise ValueError("current and replacement note values are required")
    return {"value": value, "if": current}


def update_did_note_cas(current: str, value: str, *, intent: ReviewedLocalIntent,
                        revision: str, config_version: str, context: str,
                        opener: Any = None) -> Any:
    """Update the configured DID Note only if its exact current value matches."""
    subject = current + "\0" + value
    return _local_request(BASE_URL + DID_NOTE_PATH, conditional_note_payload(current, value),
                          intent=intent, action=LocalActionClass.DID_NOTE_CAS,
                          subject=subject, target=DID_NOTE_PATH, capability_payload=value,
                          context=context, revision=revision, config_version=config_version,
                          opener=opener)


def post_signed(identity_path: Path, room: str, text: str, *, intent: ReviewedLocalIntent,
                revision: str, config_version: str, context: str,
                nonce: int | None = None, signer=sign_message, opener: Any = None) -> Dict[str, Any]:
    subject = room + "\0" + text
    require_local_intent(intent, LocalActionClass.SIGNED_ROOM_POST, subject, target=room,
                         payload=text, context=context, revision=revision,
                         config_version=config_version)
    key, did = load_identity(identity_path)
    nonce = nonce or int(time.time_ns() // 1_000_000)
    signature, clean = signer(key, room, nonce, text)
    payload = {"did": did, "sig": signature, "nonce": str(nonce), "text": clean}
    _authorized_local_request(f"{BASE_URL}/r/{urllib.parse.quote(room, safe='')}", payload,
                              opener=opener)
    # The live POST response may be the plain-text room view. Re-read JSON and
    # match all signed fields rather than parsing or trusting rendered content.
    view = _authorized_local_request(
        f"{BASE_URL}/r/{urllib.parse.quote(room, safe='')}?limit=200&format=json", None,
        opener=opener)
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


def find_signed(identity_path: Path, room: str, text: str, *, intent: ReviewedLocalIntent,
                revision: str, config_version: str, context: str,
                opener: Any = None) -> Dict[str, Any]:
    """Recover a confirmed recent record without reposting it."""
    subject = room + "\0" + text
    require_local_intent(intent, LocalActionClass.SIGNED_RECORD_LOOKUP, subject, target=room,
                         payload=text, context=context, revision=revision,
                         config_version=config_version)
    _, did = load_identity(identity_path)
    clean = text.strip()
    view = _authorized_local_request(
        f"{BASE_URL}/r/{urllib.parse.quote(room, safe='')}?limit=200&format=json", None,
        opener=opener)
    matches = [m for m in view.get("messages", []) if m.get("from") == did and m.get("text") == clean]
    if not matches:
        raise RuntimeError("signed record not found in recent room history")
    return matches[-1]


def permalink(room: str, seq: int) -> str:
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise ValueError("permalink sequence must be a non-negative integer")
    return f"{BASE_URL}/#r/{urllib.parse.quote(str(room), safe='')}/{seq}"
