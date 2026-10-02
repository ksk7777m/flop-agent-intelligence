"""Minimal Technocore client; no room-provided URL is ever followed."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict

from .identity import (
    _capture_text_sweeper,
    _load_identity,
    _sign_message,
    canonical_message,
    sweep_text,
)
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
from .wire_evidence import (
    ReadBackStage,
    advance_readback,
    _capture_signing_policy,
    build_signing_context,
    signing_capability_material,
)
from .message_verification import verify_message
from .write_effect import WriteEffectError, attempt_keys, record_write_attempt

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
    safe_error = SafeRemoteError

    def decode(url: str, request: urllib.request.Request) -> Any:
        try:
            with configured_open(request, timeout=20) as response:
                if response.geturl() != url:
                    raise safe_error("FINAL_ORIGIN_MISMATCH")
                body_bytes = response.read(limit + 1)
                if len(body_bytes) > limit:
                    raise safe_error(
                        "RESPONSE_TOO_LARGE", response_length=len(body_bytes),
                        content_sha256=digest(body_bytes[:limit]).hexdigest(),
                        truncated=True)
                try:
                    body = body_bytes.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise safe_error(
                        "INVALID_UTF8", response_length=len(body_bytes),
                        content_sha256=digest(body_bytes).hexdigest()) from error
                content_type = response.headers.get("Content-Type", "")
                return json_loads(body) if "json" in content_type else body
        except http_error as error:
            body = error.read(limit + 1)
            bounded = body[:limit]
            raise safe_error(
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
    *, signature_verifier: Any = verify_message,
    attempt_recorder: Any = record_write_attempt,
) -> tuple[Any, Any, Any, Any, Any]:
    """Capture all trust and effect dependencies in one production client."""
    reviewed_reads = frozenset(OFFICIAL_READ_SOURCES)
    base_url, did_note_path = BASE_URL, DID_NOTE_PATH
    parse_url, quote_path = urllib.parse.urlparse, urllib.parse.quote
    request_type = urllib.request.Request
    json_dumps, fullmatch = json.dumps, re.fullmatch
    text_sweeper = _capture_text_sweeper()
    context_builder, capability_material_builder = _capture_signing_policy()
    safe_error = SafeRemoteError
    effect_error, stages, make_keys = WriteEffectError, ReadBackStage, attempt_keys
    advance = advance_readback
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
        attempt_recorder(*make_keys("DID_NOTE_CAS", did_note_path, current, value))
        try:
            transport(base_url + did_note_path, {"value": value, "if": current})
            transport(base_url + did_note_path, None)
        except safe_error as error:
            redirect = (error.status in {301, 302, 303, 307, 308}
                        or error.error_class == "FINAL_ORIGIN_MISMATCH")
            raise effect_error(stages.REDIRECT_REJECTED if redirect
                               else stages.EFFECT_UNKNOWN) from None
        except Exception:
            raise effect_error(stages.EFFECT_UNKNOWN) from None
        # The documented read is banner-wrapped, mutable and unsigned. No
        # substring match or 200 response may become a DID authority assertion.
        return {"transport": stages.WRITE_ACCEPTED.value,
                "write_effect": stages.EFFECT_UNKNOWN.value,
                "readback": "UNSIGNED_NOTE_AUTHORITY_UNVERIFIED", "retry_allowed": False}

    def post(identity_path: Path, room: str, text: str, *, intent: ReviewedLocalIntent,
             revision: str, config_version: str, context: str,
             nonce: str, external_challenge: bytes | None = None) -> Dict[str, Any]:
        clean = text_sweeper(text)
        signing_context = context_builder(
            room, nonce, clean, external_challenge=external_challenge)
        material = capability_material_builder(
            signing_context, action_class=post_action.value, target=room,
            revision=revision, config_version=config_version, purpose=context)
        capability_validator(
            intent, post_action, material["subject"], target=material["target"],
            payload=material["payload"], context=material["context"], revision=revision,
            config_version=config_version)
        key, did = identity_loader(identity_path)
        signature, signed_clean = message_signer(key, room, nonce, clean)
        signed_context = context_builder(room, nonce, signed_clean)
        if (signed_clean != clean
                or signed_context.canonical_bytes != signing_context.canonical_bytes):
            raise RuntimeError("local signer canonicalization mismatch")
        payload = {"did": did, "sig": signature,
                   "nonce": signing_context.nonce.decimal, "text": clean}
        attempt_recorder(*make_keys(did, room, nonce, clean))
        stage = advance(stages.NOT_STARTED, "attempt_recorded")
        try:
            transport(f"{base_url}/r/{quote_path(room, safe='')}", payload)
            stage = advance(stage, "write_accepted")
            view = transport(
                f"{base_url}/r/{quote_path(room, safe='')}?limit=200&format=json",
                None)
        except safe_error as error:
            redirect = (error.status in {301, 302, 303, 307, 308}
                        or error.error_class in {"FINAL_ORIGIN_MISMATCH", "REDIRECT_REJECTED"})
            raise effect_error(stages.REDIRECT_REJECTED if redirect
                               else stages.EFFECT_UNKNOWN) from None
        except Exception:
            raise effect_error(stages.EFFECT_UNKNOWN) from None
        stage = advance(stage, "read_back_observed")
        if not isinstance(view, dict):
            raise effect_error(stages.READBACK_MISMATCH)
        messages = view.get("messages")
        if not isinstance(messages, list):
            raise effect_error(stages.READBACK_MISMATCH)
        matches = [message for message in messages
                   if isinstance(message, dict) and message.get("from") == did
                   and message.get("nonce") == signing_context.nonce.decimal
                   and message.get("text") == clean]
        if len(matches) != 1:
            raise effect_error(stages.READBACK_MISMATCH)
        record = matches[0]
        stage = advance(stage, "decode_valid")
        try:
            if type(record.get("sig")) is not str or record["sig"] != signature:
                raise ValueError("signature binding")
            signature_verifier(did, record["sig"], room, nonce, clean)
        except Exception:
            raise effect_error(stages.SIGNATURE_INVALID) from None
        stage = advance(stage, "signature_valid")
        stage = advance(stage, "state_replay_valid")
        stage = advance(stage, "evidence_confirmed")
        return {**record, "signature": record["sig"],
                "write_effect": stage.value,
                "effect_scope": "SIGNED_ROOM_RECORD_ONLY",
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
_RAW_READ_OFFICIAL, _RAW_READ_PRESENCE_NOTE, _RAW_UPDATE_DID_NOTE_CAS, \
    _RAW_POST_SIGNED, _RAW_FIND_SIGNED = _build_technocore_client(
        resolve_reviewed_source, require_local_intent, _load_identity,
        _sign_message, _PRODUCTION_RESPONSE_DECODER)


def _build_public_technocore_client(identity_path: Path, read: Any,
                                    read_presence: Any, update: Any,
                                    post: Any, find: Any) -> tuple[Any, ...]:
    configured_identity = identity_path.resolve()
    captured_post, captured_find = post, find

    def post_signed(room: str, text: str, *, intent: ReviewedLocalIntent,
                    revision: str, config_version: str, context: str,
                    nonce: str,
                    external_challenge: bytes | None = None) -> Dict[str, Any]:
        return captured_post(
            configured_identity, room, text, intent=intent, revision=revision,
            config_version=config_version, context=context, nonce=nonce,
            external_challenge=external_challenge)

    def find_signed(room: str, text: str, *, intent: ReviewedLocalIntent,
                    revision: str, config_version: str,
                    context: str) -> Dict[str, Any]:
        return captured_find(
            configured_identity, room, text, intent=intent, revision=revision,
            config_version=config_version, context=context)

    return read, read_presence, update, post_signed, find_signed


_PRODUCTION_IDENTITY_PATH = Path(__file__).resolve().parents[2] / "secrets" / "agent_identity.json"
read_official, read_presence_note, update_did_note_cas, post_signed, find_signed = (
    _build_public_technocore_client(
        _PRODUCTION_IDENTITY_PATH, _RAW_READ_OFFICIAL,
        _RAW_READ_PRESENCE_NOTE, _RAW_UPDATE_DID_NOTE_CAS,
        _RAW_POST_SIGNED, _RAW_FIND_SIGNED))
healthcheck = _build_technocore_health_service(read_official)


def _sealed_response_decoder(*_args: Any, **_kwargs: Any) -> Any:
    raise PermissionError("direct Technocore response transport is sealed")


_decode_response = _sealed_response_decoder


def permalink(room: str, seq: int) -> str:
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise ValueError("permalink sequence must be a non-negative integer")
    return f"{BASE_URL}/#r/{urllib.parse.quote(str(room), safe='')}/{seq}"
