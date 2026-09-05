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

from .identity import _load_identity, _sign_message
from .remote_content_policy import (
    DEFAULT_RESPONSE_LIMIT,
    LocalActionClass,
    RejectRedirects,
    ReviewedLocalIntent,
    ReviewedSourceId,
    SafeRemoteError,
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


def _build_response_decoder(open_request: Any = None) -> Any:
    """Capture the real transport once; production callers cannot replace it."""
    configured_open = open_request or urllib.request.build_opener(RejectRedirects()).open
    http_error = urllib.error.HTTPError
    limit = DEFAULT_RESPONSE_LIMIT
    digest = hashlib.sha256
    json_loads = json.loads

    def decode(url: str, request: urllib.request.Request) -> Any:
        try:
            with configured_open(request, timeout=20) as response:
                if response.geturl() != url:
                    raise SafeRemoteError("FINAL_ORIGIN_MISMATCH")
                body_bytes = response.read(limit + 1)
                if len(body_bytes) > limit:
                    raise SafeRemoteError(
                        "RESPONSE_TOO_LARGE", response_length=len(body_bytes),
                        content_sha256=digest(body_bytes[:limit]).hexdigest(),
                        truncated=True)
                try:
                    body = body_bytes.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise SafeRemoteError(
                        "INVALID_UTF8", response_length=len(body_bytes),
                        content_sha256=digest(body_bytes).hexdigest()) from error
                content_type = response.headers.get("Content-Type", "")
                return json_loads(body) if "json" in content_type else body
        except http_error as error:
            body = error.read(limit + 1)
            bounded = body[:limit]
            raise SafeRemoteError(
                "HTTP_ERROR", status=error.code, response_length=len(body),
                content_sha256=digest(bounded).hexdigest(),
                truncated=len(body) > limit) from error

    return decode


def _authorized_local_request(url: str, payload: Dict[str, Any] | None, *, opener: Any = None) -> Any:
    """Deprecated mechanism surface: no direct transport is callable."""
    del url, payload, opener
    raise PermissionError("direct Technocore transport is sealed")


def _build_technocore_client(
    source_resolver: Any, capability_validator: Any,
    identity_loader: Any, message_signer: Any, response_decoder: Any,
) -> tuple[Any, Any, Any, Any, Any]:
    """Capture all trust and effect dependencies in one production client."""
    reviewed_reads = frozenset(OFFICIAL_READ_SOURCES)
    base_url, did_note_path = BASE_URL, DID_NOTE_PATH
    parse_url, quote_path = urllib.parse.urlparse, urllib.parse.quote
    request_type, now_ns = urllib.request.Request, time.time_ns
    json_dumps, fullmatch = json.dumps, re.fullmatch
    safe_error = SafeRemoteError
    read_action = LocalActionClass.PRESENCE_NOTE_READ
    cas_action = LocalActionClass.DID_NOTE_CAS
    post_action = LocalActionClass.SIGNED_ROOM_POST
    lookup_action = LocalActionClass.SIGNED_RECORD_LOOKUP

    def transport(url: str, payload: Dict[str, Any] | None) -> Any:
        parsed = parse_url(url)
        if (parsed.scheme != "https" or parsed.netloc != "technocore.chat"
                or parsed.username or parsed.password or parsed.fragment):
            raise ValueError("Technocore target is not the configured official origin")
        data = None if payload is None else json_dumps(payload).encode("utf-8")
        headers = {} if data is None else {"Content-Type": "application/json"}
        request = request_type(
            url, data=data, headers=headers, method="GET" if data is None else "POST")
        return response_decoder(url, request)

    def read(source_id: ReviewedSourceId) -> Any:
        if source_id not in reviewed_reads:
            raise PermissionError("source is not an approved Technocore read")
        source = source_resolver(source_id)
        return transport(source.url, None)

    def read_presence(path: str, *, intent: ReviewedLocalIntent) -> Any:
        match = fullmatch(
            r"/kv/([a-z0-9][a-z0-9_-]{0,47})/hb-[a-z0-9][a-z0-9_-]{0,47}", path)
        if (not match or match.group(1).startswith(("p-", "mb-"))
                or "-p-" in match.group(1)):
            raise ValueError("not a public presence-note path")
        capability_validator(intent, read_action, path,
                             target=path, payload="", context="presence-note-read",
                             revision="0" * 40, config_version="technocore-read-v1")
        try:
            return transport(base_url + path, None)
        except safe_error as error:
            if error.status == 404:
                return None
            raise

    def update(current: str, value: str, *, intent: ReviewedLocalIntent,
               revision: str, config_version: str, context: str) -> Any:
        if not current or not value:
            raise ValueError("current and replacement note values are required")
        subject = current + "\0" + value
        capability_validator(
            intent, cas_action, subject, target=did_note_path,
            payload=value, context=context, revision=revision,
            config_version=config_version)
        return transport(base_url + did_note_path, {"value": value, "if": current})

    def post(identity_path: Path, room: str, text: str, *, intent: ReviewedLocalIntent,
             revision: str, config_version: str, context: str,
             nonce: int | None = None) -> Dict[str, Any]:
        subject = room + "\0" + text
        capability_validator(
            intent, post_action, subject, target=room,
            payload=text, context=context, revision=revision,
            config_version=config_version)
        key, did = identity_loader(identity_path)
        selected_nonce = nonce or int(now_ns() // 1_000_000)
        signature, clean = message_signer(key, room, selected_nonce, text)
        payload = {"did": did, "sig": signature, "nonce": str(selected_nonce), "text": clean}
        transport(f"{base_url}/r/{quote_path(room, safe='')}", payload)
        view = transport(
            f"{base_url}/r/{quote_path(room, safe='')}?limit=200&format=json",
            None)
        if not isinstance(view, dict):
            raise RuntimeError("Technocore JSON verification read returned an unexpected shape")
        matches = [message for message in view.get("messages", [])
                   if message.get("from") == did
                   and str(message.get("nonce")) == str(selected_nonce)
                   and message.get("text") == clean]
        if len(matches) != 1:
            raise RuntimeError(
                f"could not uniquely verify signed post in JSON view (matches={len(matches)})")
        return {**matches[0], "signature": signature,
                "input_text": text, "swept_text": clean}

    def find(identity_path: Path, room: str, text: str, *, intent: ReviewedLocalIntent,
             revision: str, config_version: str, context: str) -> Dict[str, Any]:
        subject = room + "\0" + text
        capability_validator(
            intent, lookup_action, subject, target=room,
            payload=text, context=context, revision=revision,
            config_version=config_version)
        _, did = identity_loader(identity_path)
        clean = text.strip()
        view = transport(
            f"{base_url}/r/{quote_path(room, safe='')}?limit=200&format=json",
            None)
        matches = [message for message in view.get("messages", [])
                   if message.get("from") == did and message.get("text") == clean]
        if not matches:
            raise RuntimeError("signed record not found in recent room history")
        return matches[-1]

    return read, read_presence, update, post, find


def _build_technocore_health_service(reviewed_reader: Any) -> Any:
    """Build healthcheck with a reader captured before public invocation."""
    health = ReviewedSourceId.TECHNOCORE_HEALTH
    rooms = ReviewedSourceId.TECHNOCORE_ROOMS
    lobby = ReviewedSourceId.TECHNOCORE_LOBBY_JSON

    def check() -> Dict[str, Any]:
        return {
            "healthz": reviewed_reader(health),
            "rooms": reviewed_reader(rooms),
            "lobby": reviewed_reader(lobby),
        }

    return check


def requires_signed_write(room: str) -> bool:
    return room.startswith("mb-")


def conditional_note_payload(current: str, value: str) -> Dict[str, str]:
    if not current or not value:
        raise ValueError("current and replacement note values are required")
    return {"value": value, "if": current}


_PRODUCTION_RESPONSE_DECODER = _build_response_decoder()
read_official, read_presence_note, update_did_note_cas, post_signed, find_signed = (
    _build_technocore_client(
        resolve_reviewed_source, require_local_intent, _load_identity,
        _sign_message, _PRODUCTION_RESPONSE_DECODER))
healthcheck = _build_technocore_health_service(read_official)


def _sealed_response_decoder(*_args: Any, **_kwargs: Any) -> Any:
    raise PermissionError("direct Technocore response transport is sealed")


_decode_response = _sealed_response_decoder


def permalink(room: str, seq: int) -> str:
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise ValueError("permalink sequence must be a non-negative integer")
    return f"{BASE_URL}/#r/{urllib.parse.quote(str(room), safe='')}/{seq}"
