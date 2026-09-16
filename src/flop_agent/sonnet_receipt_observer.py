"""Read-only, durable receipt reconciliation for the fixed Sonnet registration.

The production constructor seals every protocol binding to
``sonnet_registration``.  This module owns no POST, signer, identity-loader,
nonce, request-id generator, or retrying HTTP client.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping

from . import sonnet_registration as registration
from . import sonnet_receipt_verifier as receipt_verifier


OFFICIAL_ORIGIN = "https://technocore.chat"
ROOM = "mb-sonnet-2-registration"
CONTEST_ID = "sonnet-2"
ROLE = "writer"
REFEREE_DID = "did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"
MANIFEST_COMMIT = "e1999094c359ef7390bdf07fe2a151393a5c2f51"
MANIFEST_SHA256 = "0c87c41b8b33bdd8641f77c9e481a12f2758a0e27d47b90452b1c0a2020a9547"
DEADLINE = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
MAX_PAGE_BYTES = 262_144
MAX_EXPORT_BYTES = 12 * 1024 * 1024
MAX_PAGE_RECORDS = 200
MAX_EXPORT_RECORDS = 50_000
MAX_READS = 3
LONG_POLL_SECONDS = 10
HTTP_TIMEOUT_SECONDS = 20
SUPERVISOR_MAX_WALL_SECONDS = 30 * 60
SUPERVISOR_MIN_POLL_SECONDS = 2
SUPERVISOR_MAX_READS = 902
MAX_CONSECUTIVE_READ_RETRIES = 2
RETRY_BACKOFF_SECONDS = 2
MAX_TOTAL_RETRY_WAIT_SECONDS = 60
MAX_RETRY_AFTER_SECONDS = 30
SAFE_INTEGER_MAX = 9_007_199_254_740_991
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RECEIPT_CHILD_BASENAME = "sonnet-registration-receipts"
REGISTRATION_INTERVAL_CHILD_BASENAME = "sonnet-registration-live-interval"
SESSION_LOCK_BASENAME = ".receipt-store.lock"
CURSOR_PROGRESS_BASENAME = ".receipt-cursor.progress"
LINEAGE_BINDING_SCHEMA = "sonnet-registration-observation-lineage.v1"
NEW_OBSERVATION = "NEW_OBSERVATION"
RESUMING_OBSERVATION = "RESUMING_OBSERVATION"

_RECEIPT_FIELDS = frozenset({
    "type", "contest_id", "request_id", "participant_did", "role",
    "x_account_url", "status",
})
_OPTIONAL_RECEIPT_FIELDS = frozenset({"reason"})
_RECORD_FIELDS = frozenset({"seq", "ts", "from", "text", "nonce", "sig"})
_METADATA_FIELDS = frozenset({
    "schema", "receipt_sha256", "request_reference_sha256", "contest_id",
    "room", "generation", "seq", "disposition", "verification",
    "observed_at",
})
_CHECKPOINT_FIELDS = frozenset({
    "schema", "request_reference_sha256", "lineage_binding_sha256",
    "contest_id", "room", "generation", "cursor", "observation_started_at",
})
_PROGRESS_FIELDS = _CHECKPOINT_FIELDS
_LINEAGE_BINDING_FIELDS = frozenset({
    "schema", "contest_id", "origin", "room", "request_id",
    "participant_did", "role", "x_account_url", "referee_did",
    "manifest_commit", "manifest_sha256",
})


FAILURE_CATEGORIES = frozenset({
    "READ_HTTP_400", "READ_HTTP_429", "READ_HTTP_UNEXPECTED_STATUS",
    "READ_NETWORK_TIMEOUT", "READ_CONNECTION_FAILURE", "READ_TLS_FAILURE",
    "READ_CONTENT_TYPE_MISMATCH", "READ_MALFORMED_RESPONSE",
    "READ_RESPONSE_LIMIT", "READ_GENERATION_CHANGE",
    "READ_CURSOR_REGRESSION", "READ_CURSOR_GAP", "READ_EXPORT_FAILURE",
    "READ_STORAGE_FAILURE", "READ_CHECKPOINT_FAILURE",
    "READ_CLEANUP_FAILURE", "READ_INTERNAL_FAILURE",
    "READ_STOPPED", "READ_WALL_TIMEOUT", "READ_BOUND_EXHAUSTED",
    "READ_CONTEST_DEADLINE", "READ_RECEIPT_CONFLICT",
})
FAILURE_PHASES = frozenset({"BOOTSTRAP", "POLL", "EXPORT", "CHECKPOINT", "CLEANUP"})


class ReceiptObserverError(RuntimeError):
    """A fixed error category that never reflects remote or private values."""

    def __init__(
        self, code: str, *, category: str | None = None,
        phase: str | None = None, retryable: bool = False,
        http_status: int | None = None, retry_after: int | None = None,
        read_attempt_count: int = 0,
    ):
        if category is not None and category not in FAILURE_CATEGORIES:
            category = "READ_INTERNAL_FAILURE"
        if phase is not None and phase not in FAILURE_PHASES:
            phase = "POLL"
        self.code = code
        self.category = category
        self.phase = phase
        self.retryable = retryable is True
        self.http_status = (http_status if type(http_status) is int
                            and 100 <= http_status <= 599 else None)
        self.retry_after = (retry_after if type(retry_after) is int
                            and 0 <= retry_after <= MAX_RETRY_AFTER_SECONDS
                            else None)
        self.read_attempt_count = min(
            max(read_attempt_count, 0), SUPERVISOR_MAX_READS)
        super().__init__(code)


def _read_error(
    category: str, phase: str, *, retryable: bool = False,
    http_status: int | None = None, retry_after: int | None = None,
    code: str | None = None, read_attempt_count: int = 0,
) -> ReceiptObserverError:
    return ReceiptObserverError(
        code or category, category=category, phase=phase, retryable=retryable,
        http_status=http_status, retry_after=retry_after,
        read_attempt_count=read_attempt_count)


class _PrivateDirectoryCapability:
    """A path-free, single-use descriptor capability with a redacted repr."""

    __slots__ = ("_fd", "_identity")

    def __init__(self, fd: int, identity: tuple[int, int]) -> None:
        self._fd = fd
        self._identity = identity

    def take(self) -> tuple[int, tuple[int, int]]:
        if self._fd is None:
            raise ReceiptObserverError("RECEIPT_CHILD_UNSAFE")
        fd = self._fd
        self._fd = None
        return fd, self._identity

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def __repr__(self) -> str:
        return "<private directory capability>"

    def __reduce_ex__(self, _protocol: int) -> Any:
        raise TypeError("private directory capability is not serializable")


class HttpRead:
    """Immutable transport result whose raw fields never enter repr/asdict."""

    __slots__ = (
        "status_code", "final_url", "content_type", "body", "headers",
        "redirected", "_sealed",
    )

    def __init__(
        self, status_code: int, final_url: str, content_type: str, body: bytes,
        headers: Mapping[str, str], redirected: bool = False,
    ) -> None:
        object.__setattr__(self, "status_code", status_code)
        object.__setattr__(self, "final_url", final_url)
        object.__setattr__(self, "content_type", content_type)
        object.__setattr__(self, "body", body)
        object.__setattr__(self, "headers", MappingProxyType(dict(headers)))
        object.__setattr__(self, "redirected", redirected)
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise AttributeError("HttpRead is immutable")

    def __repr__(self) -> str:
        return (
            f"HttpRead(status_code={self.status_code!r}, content_type=<redacted>, "
            f"body=<redacted>, headers=<redacted>, "
            f"redirected={self.redirected!r})"
        )

    def retry_after_values(self) -> tuple[str, ...]:
        values: list[str] = []
        for key, value in self.headers.items():
            if key.casefold() == "retry-after" and type(value) is str:
                values.extend(value.split(","))
        return tuple(values)

    def __reduce_ex__(self, _protocol: int) -> Any:
        raise TypeError("HTTP read is not serializable")


class ObserverResult:
    """Immutable result whose repr and ordinary serializers reveal no state."""

    __slots__ = (
        "status", "observer_ready", "review_required", "read_count", "cursor",
        "gap_detected", "export_fallback_used", "receipt_sha256",
        "error_category", "failure_category", "failure_phase", "retryable",
        "http_status", "observed_at", "_sealed",
    )

    def __init__(
        self, status: str, observer_ready: bool, review_required: bool,
        read_count: int, cursor: int, gap_detected: bool,
        export_fallback_used: bool, receipt_sha256: str | None = None,
        error_category: str | None = None,
        failure_category: str | None = None,
        failure_phase: str | None = None, retryable: bool = False,
        http_status: int | None = None, observed_at: str | None = None,
    ) -> None:
        values = locals()
        for name in self.__slots__:
            if name != "_sealed":
                object.__setattr__(self, name, values[name])
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise AttributeError("observer result is immutable")

    def __repr__(self) -> str:
        return "<redacted Sonnet observer result>"

    def __reduce_ex__(self, _protocol: int) -> Any:
        raise TypeError("observer result is not serializable")

    def journal_projection(self) -> Mapping[str, Any]:
        """Return only values safe for an ordinary/public journal."""
        value: dict[str, Any] = {
            "status": self.status,
            "failure_category": self.failure_category,
            "failure_phase": self.failure_phase,
            "retryable": self.retryable,
            "observed_at": (self.observed_at
                            or datetime.now(timezone.utc).isoformat().replace(
                                "+00:00", "Z")),
            "read_attempt_count": min(max(self.read_count, 0), SUPERVISOR_MAX_READS),
        }
        if self.http_status is not None:
            value["http_status"] = self.http_status
        return MappingProxyType(value)


class _Config:
    """Immutable private configuration that cannot be dataclass-serialized."""

    __slots__ = (
        "origin", "room", "contest_id", "request_id", "participant_did",
        "role", "x_account_url", "referee_did", "manifest_commit",
        "manifest_sha256", "expected_generation", "initial_since",
        "observation_started_at", "deadline", "max_reads", "wait_seconds",
        "_sealed",
    )

    def __init__(
        self, origin: str, room: str, contest_id: str, request_id: str,
        participant_did: str, role: str, x_account_url: str,
        referee_did: str, manifest_commit: str, manifest_sha256: str,
        expected_generation: int, initial_since: int,
        observation_started_at: datetime, deadline: datetime,
        max_reads: int = MAX_READS, wait_seconds: int = LONG_POLL_SECONDS,
    ) -> None:
        values = locals()
        for name in self.__slots__:
            if name != "_sealed":
                object.__setattr__(self, name, values[name])
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise AttributeError("receipt observer config is immutable")

    def __repr__(self) -> str:
        return "<sealed receipt observer config>"

    def __reduce_ex__(self, _protocol: int) -> Any:
        raise TypeError("receipt observer config is not serializable")


def _utc(value: datetime) -> datetime:
    if (type(value) is not datetime or value.tzinfo is None
            or value.utcoffset() != timezone.utc.utcoffset(value)):
        raise ReceiptObserverError("TIME_INVALID")
    return value.astimezone(timezone.utc)


def _validate_config(config: _Config) -> None:
    if (config.origin != OFFICIAL_ORIGIN or config.room != ROOM
            or config.contest_id != CONTEST_ID or config.role != ROLE
            or config.referee_did != REFEREE_DID
            or config.manifest_commit != MANIFEST_COMMIT
            or config.manifest_sha256 != MANIFEST_SHA256):
        raise ReceiptObserverError("TRUST_ANCHOR_MISMATCH")
    for value in (config.request_id, config.participant_did, config.x_account_url):
        if type(value) is not str or not value:
            raise ReceiptObserverError("PRIVATE_CONFIG_INVALID")
    for value in (config.expected_generation, config.initial_since):
        if type(value) is not int or not 0 <= value <= SAFE_INTEGER_MAX:
            raise ReceiptObserverError("CURSOR_CONFIG_INVALID")
    if config.expected_generation < 1:
        raise ReceiptObserverError("GENERATION_INVALID")
    if (type(config.max_reads) is not int
            or not 1 <= config.max_reads <= SUPERVISOR_MAX_READS
            or type(config.wait_seconds) is not int
            or not 0 <= config.wait_seconds <= LONG_POLL_SECONDS):
        raise ReceiptObserverError("READ_BOUND_INVALID")
    if _utc(config.observation_started_at) >= _utc(config.deadline):
        raise ReceiptObserverError("OBSERVATION_WINDOW_INVALID")


def _json_object(raw: bytes, *, code: str) -> dict[str, Any]:
    def no_duplicates(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ReceiptObserverError(code)
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=no_duplicates)
    except (ValueError, UnicodeError):
        raise ReceiptObserverError(code) from None
    if type(value) is not dict:
        raise ReceiptObserverError(code)
    return value


def _lineage_binding_sha256(
    *, contest_id: str, origin: str, room: str, request_id: str,
    participant_did: str, role: str, x_account_url: str, referee_did: str,
    manifest_commit: str, manifest_sha256: str,
) -> str:
    """Digest one exact, versioned observation condition without normalization."""
    binding = {
        "schema": LINEAGE_BINDING_SCHEMA,
        "contest_id": contest_id,
        "origin": origin,
        "room": room,
        "request_id": request_id,
        "participant_did": participant_did,
        "role": role,
        "x_account_url": x_account_url,
        "referee_did": referee_did,
        "manifest_commit": manifest_commit,
        "manifest_sha256": manifest_sha256,
    }
    if (set(binding) != _LINEAGE_BINDING_FIELDS
            or any(type(value) is not str or not value
                   for value in binding.values())):
        raise ReceiptObserverError("LINEAGE_BINDING_INVALID")
    canonical = json.dumps(
        binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _config_lineage_binding_sha256(config: _Config) -> str:
    return _lineage_binding_sha256(
        contest_id=config.contest_id, origin=config.origin, room=config.room,
        request_id=config.request_id, participant_did=config.participant_did,
        role=config.role, x_account_url=config.x_account_url,
        referee_did=config.referee_did,
        manifest_commit=config.manifest_commit,
        manifest_sha256=config.manifest_sha256)


def _validate_restart_payloads(
    checkpoint_raw: bytes, progress_raw: bytes | None, *,
    request_reference_sha256: str, lineage_binding_sha256: str,
) -> dict[str, Any]:
    """Apply the shared P0.5 semantic checks to already bounded payloads."""
    checkpoint = _json_object(
        checkpoint_raw, code="EVIDENCE_CHECKPOINT_INVALID")
    if checkpoint.get("schema") == "sonnet-registration-receipt-checkpoint.v1":
        raise ReceiptObserverError("LEGACY_CHECKPOINT_LINEAGE_UNVERIFIED")
    if (set(checkpoint) != _CHECKPOINT_FIELDS
            or checkpoint.get("schema")
            != "sonnet-registration-receipt-checkpoint.v2"
            or checkpoint.get("contest_id") != CONTEST_ID
            or checkpoint.get("room") != ROOM
            or checkpoint.get("request_reference_sha256")
            != request_reference_sha256
            or checkpoint.get("lineage_binding_sha256")
            != lineage_binding_sha256
            or type(checkpoint.get("generation")) is not int
            or not 1 <= checkpoint["generation"] <= SAFE_INTEGER_MAX
            or type(checkpoint.get("cursor")) is not int
            or not 0 <= checkpoint["cursor"] <= SAFE_INTEGER_MAX
            or type(checkpoint.get("observation_started_at")) is not str):
        raise ReceiptObserverError("CHECKPOINT_RESTART_BINDING_INVALID")
    try:
        started = datetime.fromisoformat(
            checkpoint["observation_started_at"].replace("Z", "+00:00"))
        _utc(started)
    except (ValueError, ReceiptObserverError):
        raise ReceiptObserverError(
            "CHECKPOINT_RESTART_BINDING_INVALID") from None
    if progress_raw is not None:
        progress = _json_object(
            progress_raw, code="CHECKPOINT_RESTART_BINDING_INVALID")
        if progress.get("schema") == "sonnet-registration-receipt-progress.v1":
            raise ReceiptObserverError("LEGACY_CHECKPOINT_LINEAGE_UNVERIFIED")
        if (set(progress) != _PROGRESS_FIELDS
                or progress.get("schema")
                != "sonnet-registration-receipt-progress.v2"
                or progress.get("request_reference_sha256")
                != checkpoint["request_reference_sha256"]
                or progress.get("lineage_binding_sha256")
                != checkpoint["lineage_binding_sha256"]
                or progress.get("contest_id") != checkpoint["contest_id"]
                or progress.get("room") != checkpoint["room"]
                or type(progress.get("generation")) is not int
                or progress["generation"] != checkpoint["generation"]
                or type(progress.get("cursor")) is not int
                or not checkpoint["cursor"] <= progress["cursor"]
                <= SAFE_INTEGER_MAX
                or progress.get("observation_started_at")
                != checkpoint["observation_started_at"]):
            raise ReceiptObserverError("CHECKPOINT_RESTART_BINDING_INVALID")
        checkpoint = dict(checkpoint)
        checkpoint["cursor"] = progress["cursor"]
    return checkpoint


_PRODUCTION_LINEAGE_BINDING_SHA256 = _lineage_binding_sha256(
    contest_id=CONTEST_ID, origin=OFFICIAL_ORIGIN, room=ROOM,
    request_id=registration.REQUEST_ID,
    participant_did=registration.PARTICIPANT_DID, role=ROLE,
    x_account_url=registration.X_ACCOUNT_URL, referee_did=REFEREE_DID,
    manifest_commit=MANIFEST_COMMIT, manifest_sha256=MANIFEST_SHA256)


def _normalize_record(value: Any) -> dict[str, Any]:
    if (type(value) is not dict or not {"seq", "ts", "from", "text"} <= set(value)
            or not set(value) <= _RECORD_FIELDS
            or type(value.get("seq")) is not int
            or not 0 <= value["seq"] <= SAFE_INTEGER_MAX
            or any(type(value.get(key)) is not str for key in ("ts", "from", "text"))
            or len(value["text"].encode("utf-8")) > 4096):
        raise ReceiptObserverError("RECORD_INVALID")
    signed = "nonce" in value or "sig" in value
    if signed:
        if (set(value) != _RECORD_FIELDS or type(value.get("sig")) is not str
                or len(value["sig"]) != 86 or type(value.get("nonce")) is not int
                or not 1 <= value["nonce"] <= 9_999_999_999_999_999_999):
            raise ReceiptObserverError("SIGNED_RECORD_INVALID")
    return dict(value)


def _canonical_record(record: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(record), sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")


def _classify_receipt(
    record: Mapping[str, Any], *, config: _Config,
    signature_verifier: Callable[[str, str, str, str, str], None] | None,
    trusted_classifier: Callable[[Mapping[str, Any]], Mapping[str, str]] | None,
) -> tuple[str, bytes]:
    normalized = _normalize_record(record)
    if normalized.get("from") != config.referee_did:
        raise ReceiptObserverError("RECEIPT_REFEREE_MISMATCH")
    nonce = str(normalized["nonce"])
    if trusted_classifier is not None:
        candidate = dict(normalized)
        candidate["nonce"] = nonce
        try:
            result = trusted_classifier(candidate)
        except Exception:
            raise ReceiptObserverError("RECEIPT_VERIFICATION_FAILED") from None
        if result.get("status") not in {"ACCEPTED_VERIFIED", "REJECTED_VERIFIED"}:
            raise ReceiptObserverError("RECEIPT_VERIFICATION_FAILED")
        return ("ACCEPTED" if result["status"] == "ACCEPTED_VERIFIED" else "REJECTED",
                _canonical_record(normalized))
    if signature_verifier is None:
        raise ReceiptObserverError("RECEIPT_VERIFIER_UNAVAILABLE")
    try:
        signature_verifier(
            normalized["from"], normalized["sig"], config.room, nonce,
            normalized["text"])
    except Exception:
        raise ReceiptObserverError("RECEIPT_SIGNATURE_INVALID") from None
    receipt = _json_object(
        normalized["text"].encode("utf-8"), code="RECEIPT_SCHEMA_INVALID")
    if (not _RECEIPT_FIELDS <= set(receipt)
            or not set(receipt) <= _RECEIPT_FIELDS | _OPTIONAL_RECEIPT_FIELDS
            or receipt.get("type") != "sonnet.receipt.v1"
            or receipt.get("contest_id") != config.contest_id
            or receipt.get("request_id") != config.request_id
            or receipt.get("participant_did") != config.participant_did
            or receipt.get("role") != config.role
            or receipt.get("x_account_url") != config.x_account_url
            or receipt.get("status") not in {"accepted", "rejected"}
            or ("reason" in receipt and type(receipt["reason"]) is not str)):
        raise ReceiptObserverError("RECEIPT_BINDING_MISMATCH")
    return ("ACCEPTED" if receipt["status"] == "accepted" else "REJECTED",
            _canonical_record(normalized))


def _parse_page(
    read: HttpRead, *, expected_url: str, since: int, wait_seconds: int,
) -> tuple[int, int, list[dict[str, Any]], bool, bool | None]:
    if (type(read.status_code) is not int or read.status_code != 200
            or read.redirected or read.final_url != expected_url):
        raise _read_error(
            "READ_MALFORMED_RESPONSE", "POLL", code="PAGE_TRANSPORT_INVALID")
    if (read.content_type.split(";", 1)[0].strip().lower()
            != "application/json"):
        raise _read_error(
            "READ_CONTENT_TYPE_MISMATCH", "POLL", code="PAGE_TRANSPORT_INVALID")
    if len(read.body) > MAX_PAGE_BYTES:
        raise _read_error(
            "READ_RESPONSE_LIMIT", "POLL", code="PAGE_TRANSPORT_INVALID")
    try:
        value = _json_object(read.body, code="PAGE_JSON_INVALID")
    except ReceiptObserverError:
        raise _read_error(
            "READ_MALFORMED_RESPONSE", "POLL", code="PAGE_JSON_INVALID") from None
    allowed = {"room", "count", "first_seq", "last_seq", "generation", "messages", "wait_held"}
    required = allowed - {"wait_held"}
    if (not required <= set(value) or not set(value) <= allowed
            or value.get("room") != ROOM
            or type(value.get("count")) is not int
            or not 0 <= value["count"] <= MAX_PAGE_RECORDS
            or type(value.get("generation")) is not int
            or not 1 <= value["generation"] <= SAFE_INTEGER_MAX
            or type(value.get("last_seq")) is not int
            or not 0 <= value["last_seq"] <= SAFE_INTEGER_MAX
            or type(value.get("messages")) is not list
            or value["count"] != len(value["messages"])
            or ("wait_held" in value and type(value["wait_held"]) is not bool)):
        raise _read_error(
            "READ_MALFORMED_RESPONSE", "POLL", code="PAGE_SCHEMA_INVALID")
    try:
        records = [_normalize_record(record) for record in value["messages"]]
    except ReceiptObserverError:
        raise _read_error(
            "READ_MALFORMED_RESPONSE", "POLL", code="PAGE_SCHEMA_INVALID") from None
    seqs = [record["seq"] for record in records]
    if records:
        if (type(value.get("first_seq")) is not int
                or value["first_seq"] != seqs[0] or value["last_seq"] != seqs[-1]
                or seqs != list(range(seqs[0], seqs[0] + len(seqs)))
                or seqs[0] <= since):
            raise _read_error(
                "READ_CURSOR_REGRESSION", "POLL", code="PAGE_SEQUENCE_INVALID")
    elif (value.get("first_seq") is not None
          or value["last_seq"] != since):
        raise _read_error(
            "READ_CURSOR_REGRESSION", "POLL", code="PAGE_SEQUENCE_INVALID")
    wait_held = value.get("wait_held")
    if records and "wait_held" in value:
        raise _read_error(
            "READ_MALFORMED_RESPONSE", "POLL", code="PAGE_SCHEMA_INVALID")
    if wait_seconds > 0 and not records and type(wait_held) is not bool:
        # Official prose makes this conditional signal authoritative.  Missing
        # cannot safely be guessed as a held long-poll.
        raise _read_error(
            "READ_MALFORMED_RESPONSE", "POLL", code="PAGE_SCHEMA_INVALID")
    return (value["generation"], value["last_seq"], records,
            bool(records and seqs[0] > since + 1), wait_held)


def _parse_export(read: HttpRead, *, expected_url: str, expected_generation: int) -> list[dict[str, Any]]:
    generation_header = read.headers.get("X-Room-Generation")
    if (type(read.status_code) is not int or read.status_code != 200
            or read.redirected or read.final_url != expected_url
            or read.content_type.split(";", 1)[0].strip().lower() != "application/x-ndjson"
            or len(read.body) > MAX_EXPORT_BYTES
            or type(generation_header) is not str or not generation_header.isdigit()
            or int(generation_header) != expected_generation):
        raise ReceiptObserverError("EXPORT_TRANSPORT_INVALID")
    if not read.body:
        return []
    lines = read.body.splitlines()
    if len(lines) > MAX_EXPORT_RECORDS or any(not line for line in lines):
        raise ReceiptObserverError("EXPORT_BOUND_INVALID")
    records = [_normalize_record(_json_object(line, code="EXPORT_RECORD_INVALID")) for line in lines]
    seqs = [record["seq"] for record in records]
    if seqs != list(range(seqs[0], seqs[0] + len(seqs))):
        raise ReceiptObserverError("EXPORT_SEQUENCE_INVALID")
    return records


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


class FixedReadonlyTransport:
    """GET-only transport with fixed origin/room and no proxy or retry."""

    __slots__ = ("_opener", "_state_lock", "_active_response", "_closed")

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _RejectRedirect())
        self._state_lock = threading.Lock()
        self._active_response: Any | None = None
        self._closed = False

    @staticmethod
    def highwater_url() -> str:
        return (
            "https://technocore.chat/r/mb-sonnet-2-registration?"
            "format=json&limit=1")

    @staticmethod
    def page_url(since: int, wait_seconds: int) -> str:
        query = urllib.parse.urlencode({
            "since": str(since), "limit": "200",
            "wait": str(wait_seconds), "format": "json",
        })
        return f"https://technocore.chat/r/mb-sonnet-2-registration?{query}"

    @staticmethod
    def export_url() -> str:
        return "https://technocore.chat/r/mb-sonnet-2-registration/export"

    def _get(self, url: str, maximum: int) -> HttpRead:
        with self._state_lock:
            if self._closed:
                raise ReceiptObserverError("TRANSPORT_CLOSED")
        request = urllib.request.Request(url, method="GET", headers={
            "Accept": "application/json, application/x-ndjson",
            "Accept-Encoding": "identity",
        })
        response: Any | None = None
        try:
            response = self._opener.open(request, timeout=HTTP_TIMEOUT_SECONDS)
            with self._state_lock:
                if self._closed:
                    response.close()
                    raise ReceiptObserverError("TRANSPORT_CLOSED")
                self._active_response = response
            with response:
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = response.read(min(65_536, maximum + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > maximum:
                        raise ReceiptObserverError("RESPONSE_TOO_LARGE")
                return HttpRead(
                    int(response.status), response.geturl(),
                    response.headers.get("Content-Type", ""), b"".join(chunks),
                    MappingProxyType({
                        "X-Room-Generation": response.headers.get(
                            "X-Room-Generation", "")}),
                    redirected=response.geturl() != url)
        except urllib.error.HTTPError as error:
            try:
                retry_after = tuple(error.headers.get_all("Retry-After", []))
                return HttpRead(
                    int(error.code), url, "", b"",
                    MappingProxyType({
                        "Retry-After": ",".join(retry_after),
                    } if retry_after else {}))
            finally:
                error.close()
        except ReceiptObserverError:
            raise
        except (TimeoutError, socket.timeout):
            raise _read_error(
                "READ_NETWORK_TIMEOUT", "POLL", retryable=True) from None
        except ssl.SSLError:
            raise _read_error("READ_TLS_FAILURE", "POLL") from None
        except urllib.error.URLError as error:
            reason = error.reason
            if isinstance(reason, (TimeoutError, socket.timeout)):
                raise _read_error(
                    "READ_NETWORK_TIMEOUT", "POLL", retryable=True) from None
            if isinstance(reason, ssl.SSLError):
                raise _read_error("READ_TLS_FAILURE", "POLL") from None
            raise _read_error(
                "READ_CONNECTION_FAILURE", "POLL", retryable=True) from None
        except OSError:
            raise _read_error(
                "READ_CONNECTION_FAILURE", "POLL", retryable=True) from None
        finally:
            with self._state_lock:
                if self._active_response is response:
                    self._active_response = None
            if response is not None:
                response.close()

    def read_highwater(self) -> HttpRead:
        return self._get(self.highwater_url(), MAX_PAGE_BYTES)

    def read_page(self, since: int, wait_seconds: int) -> HttpRead:
        return self._get(self.page_url(since, wait_seconds), MAX_PAGE_BYTES)

    def read_export(self) -> HttpRead:
        return self._get(self.export_url(), MAX_EXPORT_BYTES)

    def close(self) -> None:
        with self._state_lock:
            self._closed = True
            response = self._active_response
            self._active_response = None
        if response is not None:
            response.close()


def _is_within(candidate: Path, boundary: Path) -> bool:
    try:
        return os.path.commonpath((str(candidate), str(boundary))) == str(boundary)
    except (TypeError, ValueError):
        return False


def _is_within_by_inode(candidate: Path, boundary: Path) -> bool:
    """Compare existing ancestry by inode to resist case and separator aliases."""
    try:
        boundary_info = boundary.lstat()
        current = candidate
        while True:
            info = current.lstat()
            if ((info.st_dev, info.st_ino)
                    == (boundary_info.st_dev, boundary_info.st_ino)):
                return True
            if current.parent == current:
                return False
            current = current.parent
    except OSError:
        return False


def _is_known_cloud_sync_path(candidate: Path) -> bool:
    blocked = {"cloudstorage", "mobile documents", "dropbox", "onedrive",
               "google drive"}
    return any(component.casefold() in blocked for component in candidate.parts)


def _read_small_file(path: Path, maximum: int = 4096) -> str:
    fd: int | None = None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_size > maximum):
            raise OSError
        raw = os.read(fd, maximum + 1)
        if len(raw) > maximum:
            raise OSError
        return raw.decode("utf-8")
    except (OSError, UnicodeError):
        raise ReceiptObserverError(
            "PRIVATE_ROOT_REPOSITORY_BOUNDARY_UNAVAILABLE") from None
    finally:
        if fd is not None:
            os.close(fd)


def _known_worktree_roots(
    repository_root: Path,
    _read: Callable[[Path], str] = _read_small_file,
) -> tuple[Path, ...]:
    """Read bounded local Git metadata without invoking Git or exposing paths."""
    roots = {repository_root}
    git_directory = repository_root / ".git"
    if git_directory.is_symlink():
        raise ReceiptObserverError(
            "PRIVATE_ROOT_REPOSITORY_BOUNDARY_UNAVAILABLE")
    if git_directory.is_file():
        value = _read(git_directory).strip()
        if not value.startswith("gitdir: "):
            raise ReceiptObserverError(
                "PRIVATE_ROOT_REPOSITORY_BOUNDARY_UNAVAILABLE")
        git_directory = Path(value[8:])
        if not git_directory.is_absolute():
            git_directory = (repository_root / git_directory).absolute()
    try:
        resolved_git_directory = git_directory.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ReceiptObserverError(
            "PRIVATE_ROOT_REPOSITORY_BOUNDARY_UNAVAILABLE") from None
    common = (resolved_git_directory.parents[1]
              if resolved_git_directory.parent.name == "worktrees"
              else resolved_git_directory)
    worktrees = common / "worktrees"
    if worktrees.exists():
        if worktrees.is_symlink():
            raise ReceiptObserverError(
                "PRIVATE_ROOT_REPOSITORY_BOUNDARY_UNAVAILABLE")
        try:
            entries = tuple(worktrees.iterdir())
        except OSError:
            raise ReceiptObserverError(
                "PRIVATE_ROOT_REPOSITORY_BOUNDARY_UNAVAILABLE") from None
        for entry in entries:
            if entry.is_symlink() or not entry.is_dir():
                raise ReceiptObserverError(
                    "PRIVATE_ROOT_REPOSITORY_BOUNDARY_UNAVAILABLE")
            gitdir = _read(entry / "gitdir").strip()
            candidate = Path(gitdir)
            if not candidate.is_absolute() or candidate.name != ".git":
                raise ReceiptObserverError(
                    "PRIVATE_ROOT_REPOSITORY_BOUNDARY_UNAVAILABLE")
            roots.add(candidate.parent.absolute())
    return tuple(roots)


def _filesystem_is_local(path: Path) -> bool:
    """Fail closed unless the mounted filesystem is from a local allowlist."""
    local = {"apfs", "hfs", "hfsplus", "ext4", "xfs", "btrfs", "zfs",
             "ufs", "overlay", "overlayfs", "tmpfs"}
    network = {"nfs", "nfs4", "smbfs", "afpfs", "webdav", "cifs",
               "sshfs", "fuse.sshfs"}
    try:
        if sys.platform == "darwin":
            mounted = subprocess.run(
                ["/usr/bin/stat", "-f", "%T", str(path)], capture_output=True,
                text=True, check=True, timeout=2).stdout.strip()
            lines = subprocess.run(
                ["/sbin/mount"], capture_output=True, text=True, check=True,
                timeout=2).stdout.splitlines()
            matches = [line for line in lines if f" on {mounted} (" in line]
            if len(matches) != 1:
                return False
            kind = matches[0].split("(", 1)[1].split(",", 1)[0].strip().lower()
        elif sys.platform.startswith("linux"):
            device = os.stat(path).st_dev
            identity = f"{os.major(device)}:{os.minor(device)}"
            raw = Path("/proc/self/mountinfo").read_text(
                encoding="utf-8", errors="strict")
            if len(raw.encode("utf-8")) > 1024 * 1024:
                return False
            matches = []
            for line in raw.splitlines():
                left, marker, right = line.partition(" - ")
                fields = left.split()
                if marker and len(fields) >= 5 and fields[2] == identity:
                    matches.append((len(fields[4]), right.split()[0]))
            if not matches:
                return False
            kind = max(matches)[1].lower()
        else:
            return False
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError, IndexError):
        return False
    return kind in local and kind not in network


def _open_receipt_child_core(
    private_runtime_root: Path | None, *, repository_roots: tuple[Path, ...],
    filesystem_validator: Callable[[Path], bool],
    _within: Callable[[Path, Path], bool] = _is_within,
    _within_by_inode: Callable[[Path, Path], bool] = _is_within_by_inode,
    _cloud_sync_path: Callable[[Path], bool] = _is_known_cloud_sync_path,
    _child_basename: str = RECEIPT_CHILD_BASENAME,
) -> _PrivateDirectoryCapability:
    if private_runtime_root is None or private_runtime_root == "":
        raise ReceiptObserverError("PRIVATE_ROOT_NOT_CONFIGURED")
    if type(private_runtime_root) is not type(Path()):
        raise ReceiptObserverError("PRIVATE_ROOT_NOT_CONFIGURED")
    if not private_runtime_root.is_absolute():
        raise ReceiptObserverError("PRIVATE_ROOT_NOT_ABSOLUTE")
    if ".." in private_runtime_root.parts:
        raise ReceiptObserverError("PRIVATE_ROOT_PATH_TRAVERSAL")
    lexical_root = private_runtime_root.absolute()
    if _cloud_sync_path(lexical_root):
        raise ReceiptObserverError("PRIVATE_ROOT_UNSAFE_LOCATION")
    if any(_within(lexical_root, boundary.absolute())
           for boundary in repository_roots):
        raise ReceiptObserverError("PRIVATE_ROOT_INSIDE_REPOSITORY")
    current = Path(lexical_root.anchor)
    try:
        info = current.lstat()
        for component in lexical_root.parts[1:]:
            current = current / component
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ReceiptObserverError("PRIVATE_ROOT_SYMLINK")
        if not stat.S_ISDIR(info.st_mode):
            raise ReceiptObserverError("PRIVATE_ROOT_NOT_DIRECTORY")
        if lexical_root.resolve(strict=True) != lexical_root:
            raise ReceiptObserverError("PRIVATE_ROOT_SYMLINK")
        if any(boundary.exists()
               and _within_by_inode(lexical_root, boundary)
               for boundary in repository_roots):
            raise ReceiptObserverError("PRIVATE_ROOT_INSIDE_REPOSITORY")
    except ReceiptObserverError:
        raise
    except FileNotFoundError:
        raise ReceiptObserverError("PRIVATE_ROOT_NOT_CONFIGURED") from None
    except (OSError, RuntimeError):
        raise ReceiptObserverError("PRIVATE_ROOT_SYMLINK") from None
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    root_fd: int | None = None
    child_fd: int | None = None
    try:
        root_fd = os.open(lexical_root, flags)
        root_info = os.fstat(root_fd)
        current_info = os.stat(lexical_root, follow_symlinks=False)
        if not stat.S_ISDIR(root_info.st_mode):
            raise ReceiptObserverError("PRIVATE_ROOT_NOT_DIRECTORY")
        if root_info.st_uid != os.getuid():
            raise ReceiptObserverError("PRIVATE_ROOT_UNSAFE_OWNER")
        if stat.S_IMODE(root_info.st_mode) != 0o700:
            raise ReceiptObserverError("PRIVATE_ROOT_UNSAFE_MODE")
        if ((root_info.st_dev, root_info.st_ino)
                != (current_info.st_dev, current_info.st_ino)):
            raise ReceiptObserverError("PRIVATE_ROOT_SYMLINK")
        if not filesystem_validator(lexical_root):
            raise ReceiptObserverError("PRIVATE_ROOT_UNSAFE_FILESYSTEM")
        post_validation_info = os.stat(lexical_root, follow_symlinks=False)
        if ((root_info.st_dev, root_info.st_ino)
                != (post_validation_info.st_dev, post_validation_info.st_ino)):
            raise ReceiptObserverError("PRIVATE_ROOT_SYMLINK")
        try:
            child_fd = os.open(_child_basename, flags, dir_fd=root_fd)
        except FileNotFoundError:
            raise ReceiptObserverError("RECEIPT_CHILD_NOT_PROVISIONED") from None
        child_info = os.fstat(child_fd)
        child_current = os.stat(
            _child_basename, dir_fd=root_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(child_info.st_mode)
                or stat.S_ISLNK(child_current.st_mode)
                or child_info.st_uid != os.getuid()
                or stat.S_IMODE(child_info.st_mode) != 0o700
                or (child_info.st_dev, child_info.st_ino)
                != (child_current.st_dev, child_current.st_ino)
                or child_info.st_dev != root_info.st_dev):
            raise ReceiptObserverError("RECEIPT_CHILD_UNSAFE")
        capability = _PrivateDirectoryCapability(
            child_fd, (child_info.st_dev, child_info.st_ino))
        child_fd = None
        return capability
    except OSError:
        raise ReceiptObserverError("RECEIPT_CHILD_UNSAFE") from None
    finally:
        if child_fd is not None:
            os.close(child_fd)
        if root_fd is not None:
            os.close(root_fd)


class PrivateReceiptStore:
    """Descriptor-anchored private evidence store; callers supply an existing root."""

    __slots__ = ("_fd", "_identity", "_session_lock_fd")

    def __init__(self, root: Path | _PrivateDirectoryCapability):
        self._session_lock_fd = None
        if isinstance(root, _PrivateDirectoryCapability):
            self._fd, self._identity = root.take()
            return
        descriptor: int | None = None
        try:
            candidate = Path(root)
            if not candidate.is_absolute() or candidate.resolve(strict=True) != candidate:
                raise OSError
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(candidate, flags)
            info = os.fstat(descriptor)
            current = os.stat(candidate, follow_symlinks=False)
            if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
                    or info.st_uid != os.getuid()
                    or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)):
                raise OSError
        except (OSError, RuntimeError, ValueError):
            if descriptor is not None:
                os.close(descriptor)
            raise ReceiptObserverError("EVIDENCE_ROOT_UNSAFE") from None
        self._fd = descriptor
        self._identity = (info.st_dev, info.st_ino)

    def close(self) -> None:
        failed = False
        if self._session_lock_fd is not None:
            descriptor = self._session_lock_fd
            self._session_lock_fd = None
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                failed = True
            try:
                os.close(descriptor)
            except OSError:
                failed = True
        if self._fd is not None:
            descriptor = self._fd
            self._fd = None
            try:
                os.close(descriptor)
            except OSError:
                failed = True
        if failed:
            raise ReceiptObserverError("EVIDENCE_CLOSE_FAILED")

    def _check_root(self) -> int:
        if self._fd is None:
            raise ReceiptObserverError("EVIDENCE_STORE_CLOSED")
        info = os.fstat(self._fd)
        if ((info.st_dev, info.st_ino) != self._identity
                or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid()):
            raise ReceiptObserverError("EVIDENCE_ROOT_UNSAFE")
        return self._fd

    def _read(self, name: str, maximum: int) -> bytes:
        if "/" in name or name in {".", ".."}:
            raise ReceiptObserverError("EVIDENCE_NAME_INVALID")
        fd: int | None = None
        try:
            fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=self._check_root())
            info = os.fstat(fd)
            current = os.stat(
                name, dir_fd=self._check_root(), follow_symlinks=False)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, min(65_536, maximum + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > maximum:
                    break
        except OSError:
            raise ReceiptObserverError("EVIDENCE_READ_FAILED") from None
        finally:
            if fd is not None:
                os.close(fd)
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.getuid() or info.st_nlink != 1
                or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)
                or total > maximum):
            raise ReceiptObserverError("EVIDENCE_FILE_UNSAFE")
        return b"".join(chunks)

    def _validate_artifact_file(self, name: str, maximum: int) -> None:
        """Validate a recognized artifact inode without reading its content."""
        if "/" in name or name in {".", ".."}:
            raise ReceiptObserverError("EVIDENCE_NAME_INVALID")
        root_fd = self._check_root()
        fd: int | None = None
        try:
            before = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode):
                raise ReceiptObserverError("EVIDENCE_FILE_UNSAFE")
            fd = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=root_fd)
            opened = os.fstat(fd)
            current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except ReceiptObserverError:
            raise
        except OSError:
            raise ReceiptObserverError("EVIDENCE_FILE_UNSAFE") from None
        finally:
            if fd is not None:
                os.close(fd)
        if (not stat.S_ISREG(opened.st_mode)
                or stat.S_IMODE(opened.st_mode) != 0o600
                or opened.st_uid != os.getuid() or opened.st_nlink != 1
                or opened.st_size > maximum
                or (before.st_dev, before.st_ino)
                != (opened.st_dev, opened.st_ino)
                or (opened.st_dev, opened.st_ino)
                != (current.st_dev, current.st_ino)):
            raise ReceiptObserverError("EVIDENCE_FILE_UNSAFE")

    def acquire_session_lock(self, *, create: bool) -> None:
        """Hold the fixed process lock until ``close``; never wait for it."""
        if self._session_lock_fd is not None:
            raise ReceiptObserverError("EVIDENCE_LOCK_UNSAFE")
        flags = ((os.O_RDWR | os.O_CREAT) if create else os.O_RDONLY)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(
                SESSION_LOCK_BASENAME, flags, 0o600,
                dir_fd=self._check_root())
            info = os.fstat(descriptor)
            current = os.stat(
                SESSION_LOCK_BASENAME, dir_fd=self._check_root(),
                follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode)
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != os.getuid() or info.st_nlink != 1
                    or (info.st_dev, info.st_ino)
                    != (current.st_dev, current.st_ino)):
                raise ReceiptObserverError("EVIDENCE_LOCK_UNSAFE")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ReceiptObserverError("EVIDENCE_LOCK_HELD") from None
            self._session_lock_fd = descriptor
            descriptor = None
        except FileNotFoundError:
            raise ReceiptObserverError("EVIDENCE_LOCK_ABSENT") from None
        except ReceiptObserverError:
            raise
        except OSError:
            raise ReceiptObserverError("EVIDENCE_LOCK_UNSAFE") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _atomic_write(self, name: str, raw: bytes) -> str:
        root_fd = self._check_root()
        owns_lock = self._session_lock_fd is None
        lock_fd = self._session_lock_fd
        if owns_lock:
            try:
                lock_fd = os.open(
                    SESSION_LOCK_BASENAME,
                    os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                    0o600, dir_fd=root_fd)
                lock_info = os.fstat(lock_fd)
                if (not stat.S_ISREG(lock_info.st_mode)
                        or stat.S_IMODE(lock_info.st_mode) != 0o600
                        or lock_info.st_uid != os.getuid()
                        or lock_info.st_nlink != 1):
                    raise ReceiptObserverError("EVIDENCE_LOCK_UNSAFE")
            except ReceiptObserverError:
                if lock_fd is not None:
                    os.close(lock_fd)
                raise
            except OSError:
                if lock_fd is not None:
                    os.close(lock_fd)
                raise ReceiptObserverError("EVIDENCE_LOCK_UNSAFE") from None
        assert lock_fd is not None
        temporary = f".tmp-{uuid.uuid4().hex}"
        try:
            if owns_lock:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                existing_info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                existing_info = None
            except OSError:
                raise ReceiptObserverError("EVIDENCE_EXISTING_UNSAFE") from None
            if existing_info is not None and not stat.S_ISREG(existing_info.st_mode):
                raise ReceiptObserverError("EVIDENCE_EXISTING_UNSAFE")
            if existing_info is not None:
                existing = self._read(name, len(raw))
                if existing != raw:
                    raise ReceiptObserverError("EVIDENCE_CONFLICT")
                return "DEDUPLICATED"
            fd = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600, dir_fd=root_fd)
            try:
                view = memoryview(raw)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise ReceiptObserverError("EVIDENCE_WRITE_FAILED")
                    view = view[written:]
                os.fsync(fd)
                if stat.S_IMODE(os.fstat(fd).st_mode) != 0o600:
                    raise ReceiptObserverError("EVIDENCE_FILE_UNSAFE")
            finally:
                os.close(fd)
            os.rename(temporary, name, src_dir_fd=root_fd, dst_dir_fd=root_fd)
            os.fsync(root_fd)
            return "ARCHIVED"
        except OSError:
            raise ReceiptObserverError("EVIDENCE_WRITE_FAILED") from None
        finally:
            try:
                os.unlink(temporary, dir_fd=root_fd)
            except FileNotFoundError:
                pass
            if owns_lock:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)

    def _atomic_replace(self, name: str, raw: bytes) -> str:
        """Durably replace one fixed mutable file under the held store lock."""
        if name != CURSOR_PROGRESS_BASENAME:
            raise ReceiptObserverError("EVIDENCE_NAME_INVALID")
        root_fd = self._check_root()
        owns_lock = self._session_lock_fd is None
        lock_fd = self._session_lock_fd
        if owns_lock:
            try:
                lock_fd = os.open(
                    SESSION_LOCK_BASENAME,
                    os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                    0o600, dir_fd=root_fd)
                lock_info = os.fstat(lock_fd)
                if (not stat.S_ISREG(lock_info.st_mode)
                        or stat.S_IMODE(lock_info.st_mode) != 0o600
                        or lock_info.st_uid != os.getuid()
                        or lock_info.st_nlink != 1):
                    raise ReceiptObserverError("EVIDENCE_LOCK_UNSAFE")
            except ReceiptObserverError:
                if lock_fd is not None:
                    os.close(lock_fd)
                raise
            except OSError:
                if lock_fd is not None:
                    os.close(lock_fd)
                raise ReceiptObserverError("EVIDENCE_LOCK_UNSAFE") from None
        assert lock_fd is not None
        temporary = f".tmp-{uuid.uuid4().hex}"
        try:
            if owns_lock:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                existing_info = os.stat(
                    name, dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                existing_info = None
            except OSError:
                raise ReceiptObserverError("EVIDENCE_EXISTING_UNSAFE") from None
            if existing_info is not None and (
                    not stat.S_ISREG(existing_info.st_mode)
                    or stat.S_IMODE(existing_info.st_mode) != 0o600
                    or existing_info.st_uid != os.getuid()
                    or existing_info.st_nlink != 1):
                raise ReceiptObserverError("EVIDENCE_EXISTING_UNSAFE")
            if existing_info is not None and self._read(name, MAX_PAGE_BYTES) == raw:
                return "DEDUPLICATED"
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o600, dir_fd=root_fd)
            try:
                view = memoryview(raw)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise ReceiptObserverError("EVIDENCE_WRITE_FAILED")
                    view = view[written:]
                os.fsync(fd)
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode)
                        or stat.S_IMODE(info.st_mode) != 0o600
                        or info.st_uid != os.getuid() or info.st_nlink != 1):
                    raise ReceiptObserverError("EVIDENCE_FILE_UNSAFE")
            finally:
                os.close(fd)
            os.rename(temporary, name, src_dir_fd=root_fd, dst_dir_fd=root_fd)
            if self._read(name, MAX_PAGE_BYTES) != raw:
                raise ReceiptObserverError("EVIDENCE_WRITE_FAILED")
            os.fsync(root_fd)
            return "ARCHIVED"
        except OSError:
            raise ReceiptObserverError("EVIDENCE_WRITE_FAILED") from None
        finally:
            try:
                os.unlink(temporary, dir_fd=root_fd)
            except FileNotFoundError:
                pass
            if owns_lock:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)

    def archive(
        self, raw_record: bytes, *, disposition: str, generation: int, seq: int,
        observed_at: datetime, request_reference_sha256: str,
    ) -> Mapping[str, str]:
        digest = hashlib.sha256(raw_record).hexdigest()
        metadata = {
            "schema": "sonnet-registration-receipt-evidence.v1",
            "receipt_sha256": digest,
            "request_reference_sha256": request_reference_sha256,
            "contest_id": CONTEST_ID,
            "room": ROOM,
            "generation": generation,
            "seq": seq,
            "disposition": disposition,
            "verification": "PINNED_REFEREE_SIGNATURE_VALID",
            "observed_at": _utc(observed_at).isoformat().replace("+00:00", "Z"),
        }
        metadata_raw = json.dumps(
            metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8")
        blob_status = self._atomic_write(f"{digest}.receipt", raw_record)
        metadata_status = self._atomic_write(f"{digest}.json", metadata_raw)
        if hashlib.sha256(self._read(f"{digest}.receipt", len(raw_record))).hexdigest() != digest:
            raise ReceiptObserverError("EVIDENCE_DIGEST_MISMATCH")
        return MappingProxyType({
            "status": "DEDUPLICATED" if metadata_status == "DEDUPLICATED" else "ARCHIVED",
            "blob_status": blob_status,
            "receipt_sha256": digest,
        })

    def mark_conflict(
        self, evidence: Mapping[str, str], *, request_reference_sha256: str,
    ) -> None:
        """Durably block reconciliation before writing either conflicting blob."""
        marker = {
            "schema": "sonnet-registration-receipt-conflict.v1",
            "request_reference_sha256": request_reference_sha256,
            "evidence": dict(sorted(evidence.items())),
        }
        raw = json.dumps(
            marker, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8")
        marker_digest = hashlib.sha256(raw).hexdigest()
        self._atomic_write(f"{marker_digest}.conflict", raw)

    def save_checkpoint(
        self, *, generation: int, cursor: int, observation_started_at: datetime,
        request_reference_sha256: str, lineage_binding_sha256: str,
    ) -> None:
        """Create immutable lineage, then durably advance its verified cursor."""
        existing = self.load_restart_checkpoint(
            request_reference_sha256=request_reference_sha256,
            lineage_binding_sha256=lineage_binding_sha256,
            allow_terminal_without_checkpoint=True)
        if existing is not None:
            expected_started = _utc(observation_started_at).isoformat().replace(
                "+00:00", "Z")
            if (existing["generation"] != generation
                    or existing["observation_started_at"] != expected_started
                    or cursor < existing["cursor"]):
                raise ReceiptObserverError(
                    "CHECKPOINT_RESTART_BINDING_INVALID")
            if cursor == existing["cursor"]:
                return
            progress = {
                "schema": "sonnet-registration-receipt-progress.v2",
                "request_reference_sha256": request_reference_sha256,
                "lineage_binding_sha256": lineage_binding_sha256,
                "contest_id": CONTEST_ID,
                "room": ROOM,
                "generation": generation,
                "cursor": cursor,
                "observation_started_at": expected_started,
            }
            progress_raw = json.dumps(
                progress, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
            self._atomic_replace(CURSOR_PROGRESS_BASENAME, progress_raw)
            return
        checkpoint = {
            "schema": "sonnet-registration-receipt-checkpoint.v2",
            "request_reference_sha256": request_reference_sha256,
            "lineage_binding_sha256": lineage_binding_sha256,
            "contest_id": CONTEST_ID,
            "room": ROOM,
            "generation": generation,
            "cursor": cursor,
            "observation_started_at": _utc(observation_started_at).isoformat().replace(
                "+00:00", "Z"),
        }
        raw = json.dumps(
            checkpoint, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        self._atomic_write(f"{digest}.checkpoint", raw)

    def load_checkpoint(
        self, *, generation: int, initial_since: int,
        observation_started_at: datetime, request_reference_sha256: str,
        lineage_binding_sha256: str,
    ) -> dict[str, Any] | None:
        """Return immutable lineage with its latest durable verified cursor."""
        checkpoint = self.load_restart_checkpoint(
            request_reference_sha256=request_reference_sha256,
            lineage_binding_sha256=lineage_binding_sha256,
            allow_terminal_without_checkpoint=True)
        if checkpoint is None:
            return None
        expected_started = _utc(observation_started_at).isoformat().replace(
            "+00:00", "Z")
        if (checkpoint["generation"] != generation
                or checkpoint["observation_started_at"] != expected_started
                or checkpoint["cursor"] < initial_since):
            raise ReceiptObserverError("SAVED_CHECKPOINT_BINDING_MISMATCH")
        return checkpoint

    def load_restart_checkpoint(
        self, *, request_reference_sha256: str, lineage_binding_sha256: str,
        allow_terminal_without_checkpoint: bool = False,
    ) -> dict[str, Any] | None:
        """Strictly recover one persistent observation identity, if present."""
        root_fd = self._check_root()
        try:
            names = os.listdir(root_fd)
        except OSError:
            raise ReceiptObserverError("EVIDENCE_READ_FAILED") from None
        checkpoint_names: list[str] = []
        progress_present = False
        receipts: set[str] = set()
        metadata: set[str] = set()
        for name in names:
            if name == SESSION_LOCK_BASENAME:
                continue
            if name == CURSOR_PROGRESS_BASENAME:
                progress_present = True
                continue
            suffix = next((item for item in (
                ".checkpoint", ".receipt", ".json", ".conflict")
                if name.endswith(item)), None)
            if suffix is None or name.startswith(".tmp-"):
                raise ReceiptObserverError("EVIDENCE_UNKNOWN_ARTIFACT")
            digest = name.removesuffix(suffix)
            if (len(digest) != 64
                    or any(character not in "0123456789abcdef"
                           for character in digest)):
                raise ReceiptObserverError("EVIDENCE_NAME_INVALID")
            if suffix in {".receipt", ".json", ".conflict"}:
                self._validate_artifact_file(name, MAX_PAGE_BYTES)
            if suffix == ".checkpoint":
                checkpoint_names.append(name)
            elif suffix == ".receipt":
                receipts.add(digest)
            elif suffix == ".json":
                metadata.add(digest)
            else:
                if not allow_terminal_without_checkpoint:
                    raise ReceiptObserverError("CONFLICTING_VALID_RECEIPTS")
        if len(checkpoint_names) > 1:
            raise ReceiptObserverError("CHECKPOINT_RESTART_AMBIGUOUS")
        if not checkpoint_names:
            if progress_present:
                raise ReceiptObserverError("CHECKPOINT_RESTART_BINDING_INVALID")
            if receipts != metadata:
                raise ReceiptObserverError("EVIDENCE_ORPHAN_RECEIPT")
            if receipts and not allow_terminal_without_checkpoint:
                raise ReceiptObserverError("CHECKPOINT_RESTART_BINDING_INVALID")
            return None
        name = checkpoint_names[0]
        digest = name.removesuffix(".checkpoint")
        raw = self._read(name, MAX_PAGE_BYTES)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ReceiptObserverError("EVIDENCE_DIGEST_MISMATCH")
        progress_raw = None
        if progress_present:
            progress_raw = self._read(CURSOR_PROGRESS_BASENAME, MAX_PAGE_BYTES)
        return _validate_restart_payloads(
            raw, progress_raw,
            request_reference_sha256=request_reference_sha256,
            lineage_binding_sha256=lineage_binding_sha256)

    def load(self) -> list[tuple[dict[str, Any], dict[str, Any], bytes]]:
        root_fd = self._check_root()
        try:
            names = os.listdir(root_fd)
        except OSError:
            raise ReceiptObserverError("EVIDENCE_READ_FAILED") from None
        receipts = {
            name.removesuffix(".receipt") for name in names
            if name.endswith(".receipt")}
        metadata_names = {
            name.removesuffix(".json") for name in names
            if name.endswith(".json")}
        conflict_names = [name for name in names if name.endswith(".conflict")]
        for name in sorted(
                item for item in names
                if item.endswith((".receipt", ".json", ".conflict"))):
            self._validate_artifact_file(name, MAX_PAGE_BYTES)
        if conflict_names:
            if len(conflict_names) != 1:
                raise ReceiptObserverError("CONFLICTING_VALID_RECEIPTS")
            conflict_name = conflict_names[0]
            digest = conflict_name.removesuffix(".conflict")
            raw = self._read(conflict_name, MAX_PAGE_BYTES)
            marker = _json_object(raw, code="EVIDENCE_CONFLICT_INVALID")
            evidence = marker.get("evidence")
            if (hashlib.sha256(raw).hexdigest() != digest
                    or set(marker) != {
                        "schema", "request_reference_sha256", "evidence"}
                    or marker.get("schema")
                    != "sonnet-registration-receipt-conflict.v1"
                    or type(marker.get("request_reference_sha256")) is not str
                    or len(marker["request_reference_sha256"]) != 64
                    or type(evidence) is not dict or len(evidence) < 2
                    or set(evidence.values()) != {"ACCEPTED", "REJECTED"}
                    or any(type(item) is not str or len(item) != 64
                           or any(character not in "0123456789abcdef"
                                  for character in item)
                           for item in evidence)):
                raise ReceiptObserverError("EVIDENCE_CONFLICT_INVALID")
            expected = set(evidence)
            if expected <= receipts and expected <= metadata_names:
                raise ReceiptObserverError("CONFLICTING_VALID_RECEIPTS")
            # A crash can leave the fail-closed marker before both verified
            # receipt pairs are archived.  Do not reconcile a partial pair as
            # terminal; re-read from the unchanged durable cursor instead.
            return []
        if receipts != metadata_names:
            # A verified archive consists of two independently atomic files.
            # A crash between them must replay the unchanged durable cursor,
            # never treat the surviving half as terminal evidence.
            return []
        results: list[tuple[dict[str, Any], dict[str, Any], bytes]] = []
        for name in sorted(item for item in names if item.endswith(".json")):
            digest = name[:-5]
            if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
                raise ReceiptObserverError("EVIDENCE_NAME_INVALID")
            metadata_raw = self._read(name, MAX_PAGE_BYTES)
            metadata = _json_object(metadata_raw, code="EVIDENCE_METADATA_INVALID")
            if (set(metadata) != _METADATA_FIELDS or metadata.get("receipt_sha256") != digest
                    or metadata.get("schema") != "sonnet-registration-receipt-evidence.v1"
                    or metadata.get("contest_id") != CONTEST_ID or metadata.get("room") != ROOM
                    or metadata.get("verification") != "PINNED_REFEREE_SIGNATURE_VALID"
                    or metadata.get("disposition") not in {"ACCEPTED", "REJECTED"}
                    or type(metadata.get("generation")) is not int
                    or not 1 <= metadata["generation"] <= SAFE_INTEGER_MAX
                    or type(metadata.get("seq")) is not int
                    or not 0 <= metadata["seq"] <= SAFE_INTEGER_MAX
                    or type(metadata.get("request_reference_sha256")) is not str
                    or len(metadata["request_reference_sha256"]) != 64
                    or type(metadata.get("observed_at")) is not str):
                raise ReceiptObserverError("EVIDENCE_METADATA_INVALID")
            try:
                observed_at = datetime.fromisoformat(
                    metadata["observed_at"].replace("Z", "+00:00"))
            except ValueError:
                raise ReceiptObserverError("EVIDENCE_METADATA_INVALID") from None
            _utc(observed_at)
            raw = self._read(f"{digest}.receipt", MAX_PAGE_BYTES)
            if hashlib.sha256(raw).hexdigest() != digest:
                raise ReceiptObserverError("EVIDENCE_DIGEST_MISMATCH")
            record = _json_object(raw, code="EVIDENCE_RECORD_INVALID")
            results.append((record, metadata, raw))
        return results


class _ObservationRestartCapability:
    """Single-use, path-free ownership of one locked observation lineage."""

    __slots__ = ("_store", "_mode", "_checkpoint", "_identity", "_used")

    def __init__(
        self, store: PrivateReceiptStore, *, mode: str,
        checkpoint: Mapping[str, Any] | None, identity: datetime,
    ) -> None:
        self._store = store
        self._mode = mode
        self._checkpoint = (None if checkpoint is None
                            else MappingProxyType(dict(checkpoint)))
        self._identity = _utc(identity)
        self._used = False

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def has_saved_receipt(self) -> bool:
        if self._used:
            raise ReceiptObserverError("RESTART_CAPABILITY_CONSUMED")
        return bool(self._store.load())

    def _consume(
        self,
    ) -> tuple[PrivateReceiptStore, str, Mapping[str, Any] | None, datetime]:
        if self._used:
            raise ReceiptObserverError("RESTART_CAPABILITY_CONSUMED")
        self._used = True
        return self._store, self._mode, self._checkpoint, self._identity

    def close(self) -> None:
        if not self._used:
            self._used = True
            self._store.close()

    def __repr__(self) -> str:
        return "<opaque Sonnet observation restart capability>"

    def __copy__(self) -> Any:
        raise TypeError("restart capability is not copyable")

    def __deepcopy__(self, _memo: Any) -> Any:
        raise TypeError("restart capability is not copyable")

    def __reduce_ex__(self, _protocol: int) -> Any:
        raise TypeError("restart capability is not serializable")


def _prepare_restart_core(
    private_runtime_root: Path | None, *, clock: Callable[[], datetime],
    create_lock: bool,
    _open_child: Callable[..., _PrivateDirectoryCapability] = _open_receipt_child_core,
    _worktrees: Callable[[Path], tuple[Path, ...]] = _known_worktree_roots,
    _repository_root: Path = REPOSITORY_ROOT,
    _filesystem_validator: Callable[[Path], bool] = _filesystem_is_local,
    _store_type: type[PrivateReceiptStore] = PrivateReceiptStore,
    _request_id: str = registration.REQUEST_ID,
    _lineage_binding_sha256: str = _PRODUCTION_LINEAGE_BINDING_SHA256,
) -> _ObservationRestartCapability:
    capability = _open_child(
        private_runtime_root,
        repository_roots=_worktrees(_repository_root),
        filesystem_validator=_filesystem_validator)
    store: PrivateReceiptStore | None = None
    try:
        store = _store_type(capability)
        store.acquire_session_lock(create=create_lock)
        reference = hashlib.sha256(
            _request_id.encode("utf-8")).hexdigest()
        checkpoint = store.load_restart_checkpoint(
            request_reference_sha256=reference,
            lineage_binding_sha256=_lineage_binding_sha256)
        # Validate any terminal evidence before permitting network bootstrap.
        store.load()
        if checkpoint is None:
            return _ObservationRestartCapability(
                store, mode=NEW_OBSERVATION, checkpoint=None,
                identity=_utc(clock()))
        identity = datetime.fromisoformat(
            checkpoint["observation_started_at"].replace("Z", "+00:00"))
        return _ObservationRestartCapability(
            store, mode=RESUMING_OBSERVATION, checkpoint=checkpoint,
            identity=identity)
    except BaseException:
        if store is not None:
            store.close()
        else:
            capability.close()
        raise


def validate_production_restart(
    *, private_runtime_root: Path | None,
) -> Mapping[str, str]:
    """Read-only, network-free validation with a fixed sanitized result."""
    capability: _ObservationRestartCapability | None = None
    try:
        capability = _prepare_restart_core(
            private_runtime_root, clock=lambda: datetime.now(timezone.utc),
            create_lock=False)
        status = ("RESTART_VALIDATION_PASS"
                  if capability.mode == RESUMING_OBSERVATION
                  else "NEW_OBSERVATION_AVAILABLE")
        return MappingProxyType({"status": status, "mode": capability.mode})
    except ReceiptObserverError as error:
        if error.code == "EVIDENCE_LOCK_ABSENT":
            # A never-started child legitimately has no lock artifact.  Reopen
            # descriptor-relative and accept only a completely empty lineage.
            store: PrivateReceiptStore | None = None
            child: _PrivateDirectoryCapability | None = None
            try:
                child = _open_receipt_child_core(
                    private_runtime_root,
                    repository_roots=_known_worktree_roots(REPOSITORY_ROOT),
                    filesystem_validator=_filesystem_is_local)
                store = PrivateReceiptStore(child)
                reference = hashlib.sha256(
                    registration.REQUEST_ID.encode("utf-8")).hexdigest()
                if (store.load_restart_checkpoint(
                        request_reference_sha256=reference,
                        lineage_binding_sha256=
                        _PRODUCTION_LINEAGE_BINDING_SHA256) is None
                        and not store.load()):
                    return MappingProxyType({
                        "status": "NEW_OBSERVATION_AVAILABLE",
                        "mode": NEW_OBSERVATION,
                    })
            except ReceiptObserverError as validation_error:
                status = {
                    "CHECKPOINT_RESTART_AMBIGUOUS":
                        "CHECKPOINT_RESTART_AMBIGUOUS",
                    "LEGACY_CHECKPOINT_LINEAGE_UNVERIFIED":
                        "LEGACY_CHECKPOINT_LINEAGE_UNVERIFIED",
                }.get(validation_error.code)
                if status is not None:
                    return MappingProxyType({"status": status})
            except Exception:
                pass
            finally:
                if store is not None:
                    store.close()
                elif child is not None:
                    child.close()
        status = {
            "EVIDENCE_LOCK_HELD": "LOCK_HELD",
            "CHECKPOINT_RESTART_AMBIGUOUS": "CHECKPOINT_RESTART_AMBIGUOUS",
            "LEGACY_CHECKPOINT_LINEAGE_UNVERIFIED":
                "LEGACY_CHECKPOINT_LINEAGE_UNVERIFIED",
        }.get(error.code, "CHECKPOINT_RESTART_BINDING_INVALID")
        return MappingProxyType({"status": status})
    except Exception:
        return MappingProxyType({"status": "CHECKPOINT_RESTART_BINDING_INVALID"})
    finally:
        if capability is not None:
            capability.close()


def _seal_restart_preparer() -> Callable[..., _ObservationRestartCapability]:
    core = _prepare_restart_core
    clock = lambda: datetime.now(timezone.utc)

    def prepare(
        *, private_runtime_root: Path | None,
    ) -> _ObservationRestartCapability:
        return core(private_runtime_root, clock=clock, create_lock=True)

    return prepare


prepare_production_observation = _seal_restart_preparer()
del _seal_restart_preparer


def _seal_registration_interval_preparer() -> Callable[..., _ObservationRestartCapability]:
    """Bind an explicit post-gap interval to its own pre-provisioned child."""
    core = _prepare_restart_core
    child_core = _open_receipt_child_core
    child_basename = REGISTRATION_INTERVAL_CHILD_BASENAME
    repository_root = REPOSITORY_ROOT
    worktrees = _known_worktree_roots
    filesystem_validator = _filesystem_is_local

    def open_child(
        private_runtime_root: Path | None, *, repository_roots: tuple[Path, ...],
        filesystem_validator: Callable[[Path], bool],
    ) -> _PrivateDirectoryCapability:
        return child_core(
            private_runtime_root, repository_roots=repository_roots,
            filesystem_validator=filesystem_validator,
            _child_basename=child_basename)

    def prepare(
        *, private_runtime_root: Path | None,
    ) -> _ObservationRestartCapability:
        # The first session lock is also the durable one-shot start marker for
        # this dedicated interval.  Any existing lock means an attempt already
        # began, even if it failed before the first checkpoint.
        inspection = open_child(
            private_runtime_root,
            repository_roots=worktrees(repository_root),
            filesystem_validator=filesystem_validator)
        store: PrivateReceiptStore | None = None
        try:
            store = PrivateReceiptStore(inspection)
            try:
                store.acquire_session_lock(create=False)
            except ReceiptObserverError as error:
                if error.code != "EVIDENCE_LOCK_ABSENT":
                    raise ReceiptObserverError(
                        "REGISTRATION_INTERVAL_ALREADY_STARTED") from None
            else:
                raise ReceiptObserverError(
                    "REGISTRATION_INTERVAL_ALREADY_STARTED")
        finally:
            if store is not None:
                store.close()
            else:
                inspection.close()
        capability = core(
            private_runtime_root, clock=lambda: datetime.now(timezone.utc),
            create_lock=True, _open_child=open_child,
            _worktrees=worktrees, _repository_root=repository_root,
            _filesystem_validator=filesystem_validator)
        if capability.mode != NEW_OBSERVATION:
            capability.close()
            raise ReceiptObserverError("REGISTRATION_INTERVAL_ALREADY_STARTED")
        return capability

    return prepare


prepare_production_registration_interval = _seal_registration_interval_preparer()
del _seal_registration_interval_preparer


class ReceiptObserver:
    """Bounded state machine for one fixed request; all network use is read-only."""

    __slots__ = ("_config", "_transport", "_store", "_verify",
                 "_trusted_classifier", "_clock", "_cursor", "_ready", "_reads",
                 "_wait_not_held", "_record_guard")

    def __init__(
        self, config: _Config, transport: Any, store: PrivateReceiptStore,
        signature_verifier: Callable[[str, str, str, str, str], None] | None,
        clock: Callable[[], datetime],
        trusted_classifier: Callable[[Mapping[str, Any]], Mapping[str, str]] | None = None,
        record_guard: Callable[[list[dict[str, Any]], int], None] | None = None,
    ):
        _validate_config(config)
        if (signature_verifier is None) == (trusted_classifier is None):
            raise ReceiptObserverError("RECEIPT_VERIFIER_INVALID")
        self._config = config
        self._transport = transport
        self._store = store
        self._verify = signature_verifier
        self._trusted_classifier = trusted_classifier
        self._clock = clock
        self._cursor = config.initial_since
        self._ready = False
        self._reads = 0
        self._wait_not_held = False
        self._record_guard = record_guard

    @property
    def ready(self) -> bool:
        return self._ready

    @property
    def cursor(self) -> int:
        return self._cursor

    def _safe(self, *, error: str | ReceiptObserverError, gap: bool = False,
              exported: bool = False, review: bool = False) -> ObserverResult:
        self._ready = False
        failure = error if isinstance(error, ReceiptObserverError) else None
        if failure is None and type(error) is str and error != "AWAITING_RECEIPT":
            fixed = {
                "SUPERVISOR_STOPPED": ("READ_STOPPED", "POLL"),
                "SUPERVISOR_TIMEOUT": ("READ_WALL_TIMEOUT", "POLL"),
                "SUPERVISOR_READ_LIMIT": ("READ_BOUND_EXHAUSTED", "POLL"),
                "BOUNDED_OBSERVATION_COMPLETE": (
                    "READ_BOUND_EXHAUSTED", "POLL"),
                "DEADLINE_REACHED": ("READ_CONTEST_DEADLINE", "POLL"),
                "CONFLICTING_VALID_RECEIPTS": (
                    "READ_RECEIPT_CONFLICT", "POLL"),
            }
            category, phase = fixed.get(
                error, ("READ_INTERNAL_FAILURE", "POLL"))
            failure = _read_error(category, phase, code=error)
        if failure is not None and failure.category is None:
            if (failure.code.startswith("EVIDENCE_")
                    or failure.code.startswith("SAVED_")
                    or failure.code.startswith("LOCK_")):
                failure = _read_error(
                    "READ_STORAGE_FAILURE", "CHECKPOINT", code=failure.code)
            else:
                failure = _read_error(
                    "READ_INTERNAL_FAILURE", "POLL", code=failure.code)
        code = failure.code if failure is not None else error
        observed_at: str | None = None
        try:
            observed_at = _utc(self._clock()).isoformat().replace("+00:00", "Z")
        except Exception:
            pass
        return ObserverResult(
            "UNCONFIRMED", False, review, self._reads, self._cursor, gap,
            exported, error_category=code,
            failure_category=failure.category if failure else None,
            failure_phase=failure.phase if failure else None,
            retryable=failure.retryable if failure else False,
            http_status=failure.http_status if failure else None,
            observed_at=observed_at)

    def _receipts(
        self, records: list[dict[str, Any]], generation: int, *, persist: bool = True,
    ) -> ObserverResult | None:
        verified: dict[str, tuple[str, bytes, int]] = {}
        for record in records:
            if record.get("from") != self._config.referee_did:
                continue
            try:
                text = _json_object(record["text"].encode("utf-8"), code="UNTRUSTED_RECORD")
            except ReceiptObserverError:
                continue
            if text.get("type") != "sonnet.receipt.v1" or text.get("request_id") != self._config.request_id:
                continue
            try:
                disposition, raw = _classify_receipt(
                    record, config=self._config, signature_verifier=self._verify,
                    trusted_classifier=self._trusted_classifier)
            except ReceiptObserverError:
                continue
            signed_record = _canonical_record({
                key: record[key] for key in ("from", "sig", "nonce", "text")})
            signed_record_digest = hashlib.sha256(signed_record).hexdigest()
            verified[signed_record_digest] = (disposition, raw, record["seq"])
        if not verified:
            return None
        dispositions = {item[0] for item in verified.values()}
        if len(dispositions) != 1:
            if persist:
                request_reference = hashlib.sha256(
                    self._config.request_id.encode("utf-8")).hexdigest()
                self._store.mark_conflict(
                    {hashlib.sha256(raw).hexdigest(): disposition
                     for disposition, raw, _seq in verified.values()},
                    request_reference_sha256=request_reference)
                for disposition, raw, seq in verified.values():
                    self._store.archive(
                        raw, disposition=disposition, generation=generation, seq=seq,
                        observed_at=_utc(self._clock()),
                        request_reference_sha256=request_reference)
            return self._safe(error="CONFLICTING_VALID_RECEIPTS", review=True)
        disposition = next(iter(dispositions))
        digest: str | None = None
        for disposition, raw, seq in verified.values():
            if persist:
                archived = self._store.archive(
                    raw, disposition=disposition, generation=generation, seq=seq,
                    observed_at=_utc(self._clock()),
                    request_reference_sha256=hashlib.sha256(
                        self._config.request_id.encode("utf-8")).hexdigest())
                digest = archived["receipt_sha256"]
            else:
                digest = hashlib.sha256(raw).hexdigest()
        self._ready = True
        return ObserverResult(
            disposition, True, False, self._reads, self._cursor, False, False,
            receipt_sha256=digest)

    def reconcile_saved(self) -> ObserverResult:
        try:
            saved = self._store.load()
            if any(
                metadata["generation"] != self._config.expected_generation
                or metadata["seq"] != record.get("seq")
                or metadata["request_reference_sha256"] != hashlib.sha256(
                    self._config.request_id.encode("utf-8")).hexdigest()
                for record, metadata, _raw in saved
            ):
                return self._safe(error="SAVED_EVIDENCE_BINDING_MISMATCH", review=True)
            records = [record for record, _metadata, _raw in saved]
            if not records:
                return self._safe(error="NO_SAVED_RECEIPT")
            result = self._receipts(
                records, self._config.expected_generation, persist=False)
            if result is None or len(records) != len({hashlib.sha256(raw).hexdigest() for _, _, raw in saved}):
                return self._safe(error="SAVED_EVIDENCE_INVALID", review=True)
            if any(metadata["disposition"] != result.status
                   for _record, metadata, _raw in saved):
                return self._safe(error="SAVED_EVIDENCE_BINDING_MISMATCH", review=True)
            return result
        except ReceiptObserverError as error:
            return self._safe(error=error, review=True)

    def _read(self, wait_seconds: int) -> ObserverResult | None:
        expected_url = FixedReadonlyTransport.page_url(self._cursor, wait_seconds)
        self._reads += 1
        self._wait_not_held = False
        read = self._transport.read_page(self._cursor, wait_seconds)
        status = read.status_code
        if status == 400:
            raise _read_error("READ_HTTP_400", "POLL", http_status=400)
        if status == 429:
            values = read.retry_after_values()
            if (len(values) != 1 or not values[0].isdigit()
                    or not 0 < int(values[0]) <= MAX_RETRY_AFTER_SECONDS):
                raise _read_error("READ_HTTP_429", "POLL", http_status=429)
            raise _read_error(
                "READ_HTTP_429", "POLL", retryable=True, http_status=429,
                retry_after=int(values[0]))
        if status != 200:
            retryable = status == 408 or (type(status) is int and 500 <= status <= 599)
            raise _read_error(
                "READ_HTTP_UNEXPECTED_STATUS", "POLL", retryable=retryable,
                http_status=status)
        generation, last_seq, records, gap, wait_held = _parse_page(
            read, expected_url=expected_url, since=self._cursor,
            wait_seconds=wait_seconds)
        if generation != self._config.expected_generation:
            raise _read_error(
                "READ_GENERATION_CHANGE", "POLL", code="GENERATION_CHANGED")
        if self._record_guard is not None:
            self._record_guard(records, generation)
        try:
            # Establish the immutable lineage at the pre-response cursor
            # before any receipt pair can be only partially archived.  This is
            # not progress: the verified response's last_seq is persisted only
            # after all terminal evidence is durable.
            self._store.save_checkpoint(
                generation=generation, cursor=self._cursor,
                observation_started_at=self._config.observation_started_at,
                request_reference_sha256=hashlib.sha256(
                    self._config.request_id.encode("utf-8")).hexdigest(),
                lineage_binding_sha256=
                    _config_lineage_binding_sha256(self._config))
        except Exception:
            raise _read_error("READ_CHECKPOINT_FAILURE", "CHECKPOINT") from None
        if gap:
            try:
                self._reads += 1
                export = self._transport.read_export()
                exported = _parse_export(
                    export, expected_url=FixedReadonlyTransport.export_url(),
                    expected_generation=self._config.expected_generation)
                if self._record_guard is not None:
                    self._record_guard(exported, generation)
            except ReceiptObserverError:
                raise _read_error("READ_EXPORT_FAILURE", "EXPORT") from None
            except Exception:
                raise _read_error("READ_EXPORT_FAILURE", "EXPORT") from None
            found = self._receipts(exported, generation)
            if found is not None:
                self._cursor = last_seq
                try:
                    self._store.save_checkpoint(
                        generation=generation, cursor=self._cursor,
                        observation_started_at=self._config.observation_started_at,
                        request_reference_sha256=hashlib.sha256(
                            self._config.request_id.encode("utf-8")).hexdigest(),
                        lineage_binding_sha256=
                            _config_lineage_binding_sha256(self._config))
                except Exception:
                    raise _read_error(
                        "READ_CHECKPOINT_FAILURE", "CHECKPOINT") from None
                return ObserverResult(
                    found.status, found.observer_ready, found.review_required,
                    self._reads, self._cursor, True, True,
                    found.receipt_sha256, found.error_category)
            raise _read_error(
                "READ_CURSOR_GAP", "EXPORT", code="CURSOR_GAP_UNRESOLVED")
        self._cursor = last_seq
        found = self._receipts(records, generation)
        try:
            self._store.save_checkpoint(
                generation=generation, cursor=self._cursor,
                observation_started_at=self._config.observation_started_at,
                request_reference_sha256=hashlib.sha256(
                    self._config.request_id.encode("utf-8")).hexdigest(),
                lineage_binding_sha256=
                    _config_lineage_binding_sha256(self._config))
        except Exception:
            raise _read_error("READ_CHECKPOINT_FAILURE", "CHECKPOINT") from None
        self._wait_not_held = (
            wait_seconds > 0 and not records and wait_held is False)
        return found

    def prepare(self) -> ObserverResult:
        if self._reads:
            return self._safe(error="PREPARE_ALREADY_CALLED")
        try:
            saved = self._store.load()
            if saved:
                return self.reconcile_saved()
            expected_reference = hashlib.sha256(
                self._config.request_id.encode("utf-8")).hexdigest()
            checkpoint = self._store.load_checkpoint(
                generation=self._config.expected_generation,
                initial_since=self._config.initial_since,
                observation_started_at=self._config.observation_started_at,
                request_reference_sha256=expected_reference,
                lineage_binding_sha256=
                    _config_lineage_binding_sha256(self._config))
            if checkpoint is not None:
                self._cursor = checkpoint["cursor"]
            result = self._read(0)
            if result is not None:
                return result
            self._ready = True
            return ObserverResult(
                "UNCONFIRMED", True, False, self._reads, self._cursor,
                False, False, error_category="AWAITING_RECEIPT")
        except ReceiptObserverError as error:
            return self._safe(
                error=error,
                review=(error.code.startswith("EVIDENCE_")
                        or error.code.startswith("SAVED_")
                        or error.code in {
                            "GENERATION_CHANGED", "CURSOR_GAP_UNRESOLVED",
                        }))

    def observe(self) -> ObserverResult:
        if not self._ready:
            return self._safe(error="OBSERVER_NOT_READY")
        while self._reads < self._config.max_reads:
            if _utc(self._clock()) >= self._config.deadline:
                return self._safe(error="DEADLINE_REACHED")
            try:
                result = self._read(self._config.wait_seconds)
            except ReceiptObserverError as error:
                return self._safe(error=error)
            if result is not None:
                return result
        return self._safe(error="BOUNDED_OBSERVATION_COMPLETE")


class ReceiptObservationSession:
    """Background observation that keeps polling after its ready signal."""

    __slots__ = (
        "_ready", "_done", "_stop", "_result", "_thread", "_observer",
        "_monotonic", "_wall_deadline", "_waiter",
    )

    def __init__(
        self, observer: ReceiptObserver, *,
        monotonic: Callable[[], float] = time.monotonic,
        maximum_wall_seconds: int = SUPERVISOR_MAX_WALL_SECONDS,
        minimum_poll_seconds: int = SUPERVISOR_MIN_POLL_SECONDS,
        waiter: Callable[[threading.Event, float], bool] | None = None,
    ) -> None:
        if (type(maximum_wall_seconds) is not int
                or not HTTP_TIMEOUT_SECONDS < maximum_wall_seconds
                <= SUPERVISOR_MAX_WALL_SECONDS
                or type(minimum_poll_seconds) is not int
                or not 0 <= minimum_poll_seconds
                <= SUPERVISOR_MIN_POLL_SECONDS):
            raise ReceiptObserverError("SUPERVISOR_BOUND_INVALID")
        self._ready = threading.Event()
        self._done = threading.Event()
        self._stop = threading.Event()
        self._result: ObserverResult | None = None
        self._observer = observer
        self._monotonic = monotonic
        self._waiter = waiter or (lambda event, seconds: event.wait(seconds))
        self._wall_deadline = monotonic() + maximum_wall_seconds

        def run() -> None:
            retry_count = 0
            retry_wait_total = 0
            try:
                prepared = observer.prepare()
                if (prepared.observer_ready and prepared.status == "UNCONFIRMED"
                        and prepared.error_category == "AWAITING_RECEIPT"):
                    self._ready.set()
                    last_request_started = self._monotonic()
                    while observer._reads < observer._config.max_reads:
                        if self._stop.is_set():
                            self._result = observer._safe(
                                error="SUPERVISOR_STOPPED")
                            break
                        remaining = self._wall_deadline - self._monotonic()
                        if remaining <= 0:
                            self._result = observer._safe(
                                error="SUPERVISOR_TIMEOUT")
                            break
                        elapsed = self._monotonic() - last_request_started
                        delay = min(
                            max(0.0, minimum_poll_seconds - elapsed), remaining)
                        if delay and self._waiter(self._stop, delay):
                            self._result = observer._safe(
                                error="SUPERVISOR_STOPPED")
                            break
                        remaining = self._wall_deadline - self._monotonic()
                        if remaining <= 0:
                            self._result = observer._safe(
                                error="SUPERVISOR_TIMEOUT")
                            break
                        # Never start a request which can outlive the hard wall.
                        if remaining <= HTTP_TIMEOUT_SECONDS:
                            if self._waiter(self._stop, remaining):
                                self._result = observer._safe(
                                    error="SUPERVISOR_STOPPED")
                            else:
                                self._result = observer._safe(
                                    error="SUPERVISOR_TIMEOUT")
                            break
                        if _utc(observer._clock()) >= observer._config.deadline:
                            self._result = observer._safe(
                                error="DEADLINE_REACHED")
                            break
                        last_request_started = self._monotonic()
                        try:
                            result = observer._read(
                                observer._config.wait_seconds)
                        except ReceiptObserverError as error:
                            delay = (error.retry_after if error.retry_after is not None
                                     else RETRY_BACKOFF_SECONDS)
                            remaining = self._wall_deadline - self._monotonic()
                            can_retry = (
                                error.retryable
                                and retry_count < MAX_CONSECUTIVE_READ_RETRIES
                                and retry_wait_total + delay
                                <= MAX_TOTAL_RETRY_WAIT_SECONDS
                                and observer._reads < observer._config.max_reads
                                and remaining > delay + HTTP_TIMEOUT_SECONDS)
                            if can_retry:
                                retry_count += 1
                                retry_wait_total += delay
                                if self._waiter(self._stop, delay):
                                    self._result = observer._safe(
                                        error="SUPERVISOR_STOPPED")
                                    break
                                continue
                            if error.retryable:
                                error = _read_error(
                                    error.category or "READ_INTERNAL_FAILURE",
                                    error.phase or "POLL", retryable=False,
                                    http_status=error.http_status,
                                    code=error.code)
                            review = (
                                error.code.startswith("EVIDENCE_")
                                or error.code.startswith("SAVED_")
                                or error.code in {
                                    "GENERATION_CHANGED",
                                    "CURSOR_GAP_UNRESOLVED",
                                    "CONFLICTING_VALID_RECEIPTS",
                                })
                            self._result = observer._safe(
                                error=("SUPERVISOR_STOPPED"
                                       if self._stop.is_set() else error),
                                review=False if self._stop.is_set() else review)
                            break
                        if self._stop.is_set():
                            self._result = observer._safe(
                                error="SUPERVISOR_STOPPED")
                            break
                        if result is not None:
                            self._result = result
                            break
                        retry_count = 0
                        if getattr(observer, "_wait_not_held", False):
                            delay = min(
                                float(observer._config.wait_seconds),
                                max(0.0, self._wall_deadline - self._monotonic()))
                            if delay and self._waiter(self._stop, delay):
                                self._result = observer._safe(
                                    error="SUPERVISOR_STOPPED")
                                break
                    if self._result is None:
                        self._result = observer._safe(
                            error="SUPERVISOR_READ_LIMIT")
                else:
                    self._result = prepared
            except Exception:
                failure = _read_error("READ_INTERNAL_FAILURE", "POLL")
                self._result = observer._safe(
                    error=("SUPERVISOR_STOPPED" if self._stop.is_set()
                           else failure), review=not self._stop.is_set())
            finally:
                cleanup_failed = False
                close_transport = getattr(observer._transport, "close", None)
                if close_transport is not None:
                    try:
                        close_transport()
                    except Exception:
                        cleanup_failed = True
                try:
                    observer._store.close()
                except Exception:
                    cleanup_failed = True
                finally:
                    # Cleanup diagnostics must never erase the causally earlier
                    # terminal classification or a verified receipt result.
                    if cleanup_failed and self._result is None:
                        self._result = observer._safe(
                            error=_read_error(
                                "READ_CLEANUP_FAILURE", "CLEANUP"),
                            review=True)
                    self._done.set()

        self._thread = threading.Thread(
            target=run, name="sonnet-receipt-observer", daemon=False)
        self._thread.start()

    def wait_until_ready(self, timeout: float | None = None) -> bool:
        """Wait for readiness; false also means bounded terminal completion."""
        if self._ready.wait(timeout):
            return True
        return False

    def wait_for_result(self, timeout: float | None = None) -> ObserverResult | None:
        """Return the terminal three-state result, or None on local wait timeout."""
        if not self._done.wait(timeout):
            return None
        return self._result

    def stop(self) -> None:
        """Request one-way shutdown and interrupt an active production read."""
        self._stop.set()
        close_transport = getattr(self._observer._transport, "close", None)
        if close_transport is not None:
            try:
                close_transport()
            except Exception:
                pass

    def is_running(self) -> bool:
        return not self._done.is_set()

    def remaining_seconds(self) -> int:
        return max(0, int(self._wall_deadline - self._monotonic()))

    def __repr__(self) -> str:
        return "<Sonnet receipt observation session>"


class _ProductionReceiptObserver:
    """Production facade that exposes only continuous start and saved recovery."""

    __slots__ = ("_observer", "_started", "_session_factory")

    def __init__(
        self, observer: ReceiptObserver,
        session_factory: Callable[[ReceiptObserver], ReceiptObservationSession],
    ) -> None:
        self._observer = observer
        self._started = False
        self._session_factory = session_factory

    def start(self) -> ReceiptObservationSession:
        if self._started:
            raise ReceiptObserverError("OBSERVER_ALREADY_STARTED")
        self._started = True
        try:
            return self._session_factory(self._observer)
        except BaseException:
            close_transport = getattr(self._observer._transport, "close", None)
            if close_transport is not None:
                try:
                    close_transport()
                except Exception:
                    pass
            try:
                self._observer._store.close()
            except Exception:
                pass
            raise

    def reconcile_saved(self) -> ObserverResult:
        if self._started:
            raise ReceiptObserverError("OBSERVER_ALREADY_STARTED")
        return self._observer.reconcile_saved()

    def __repr__(self) -> str:
        return "<fixed Sonnet receipt observer>"


def _seal_production_factory() -> tuple[Callable[..., _ProductionReceiptObserver],
                                        Callable[..., _ProductionReceiptObserver]]:
    config_type = _Config
    observer_type = ReceiptObserver
    production_type = _ProductionReceiptObserver
    session_type = ReceiptObservationSession
    transport_type = FixedReadonlyTransport
    restart_capability_type = _ObservationRestartCapability
    trusted_classifier = receipt_verifier._classify_observed_receipt
    origin = OFFICIAL_ORIGIN
    room = ROOM
    contest_id = CONTEST_ID
    request_id = registration.REQUEST_ID
    participant_did = registration.PARTICIPANT_DID
    role = ROLE
    x_account_url = registration.X_ACCOUNT_URL
    referee_did = REFEREE_DID
    manifest_commit = MANIFEST_COMMIT
    manifest_sha256 = MANIFEST_SHA256
    deadline = DEADLINE
    maximum_wall_seconds = SUPERVISOR_MAX_WALL_SECONDS
    minimum_poll_seconds = SUPERVISOR_MIN_POLL_SECONDS
    maximum_reads = SUPERVISOR_MAX_READS

    def production_session(observer: ReceiptObserver) -> ReceiptObservationSession:
        return session_type(
            observer, maximum_wall_seconds=maximum_wall_seconds,
            minimum_poll_seconds=minimum_poll_seconds)

    def production_config(
        *, expected_generation: int, initial_since: int,
        observation_started_at: datetime,
    ) -> _Config:
        return config_type(
            origin, room, contest_id, request_id, participant_did, role,
            x_account_url, referee_did, manifest_commit, manifest_sha256,
            expected_generation, initial_since, observation_started_at, deadline,
            max_reads=maximum_reads)

    def build_core(
        *, restart_capability: _ObservationRestartCapability,
        observed_generation: int | None = None,
        observed_cursor: int | None = None,
        record_guard: Callable[[list[dict[str, Any]], int], None] | None = None,
    ) -> _ProductionReceiptObserver:
        """Consume one verified lineage; callers cannot inject saved bindings."""
        if not isinstance(restart_capability, restart_capability_type):
            raise ReceiptObserverError("RESTART_CAPABILITY_INVALID")
        store, mode, checkpoint, identity = restart_capability._consume()
        try:
            if mode == RESUMING_OBSERVATION:
                if checkpoint is None or (observed_generation is not None
                                          or observed_cursor is not None):
                    raise ReceiptObserverError("RESTART_CAPABILITY_INVALID")
                generation = checkpoint["generation"]
                cursor = checkpoint["cursor"]
            elif mode == NEW_OBSERVATION:
                if (checkpoint is not None
                        or type(observed_generation) is not int
                        or type(observed_cursor) is not int):
                    raise ReceiptObserverError("RESTART_CAPABILITY_INVALID")
                generation = observed_generation
                cursor = observed_cursor
            else:
                raise ReceiptObserverError("RESTART_CAPABILITY_INVALID")
            config = production_config(
                expected_generation=generation, initial_since=cursor,
                observation_started_at=identity)
            core = observer_type(
                config, transport_type(), store, None,
                lambda: datetime.now(timezone.utc), trusted_classifier,
                record_guard)
            return production_type(core, production_session)
        except BaseException:
            store.close()
            raise

    def build(
        *, restart_capability: _ObservationRestartCapability,
        observed_generation: int | None = None,
        observed_cursor: int | None = None,
    ) -> _ProductionReceiptObserver:
        # Keep the fixed config/verifier visible in this sealed production
        # closure for the existing audit surface; build_core consumes the same
        # captured objects.
        _fixed_audit_surface = (production_config, trusted_classifier)
        return build_core(
            restart_capability=restart_capability,
            observed_generation=observed_generation,
            observed_cursor=observed_cursor)

    def build_guarded(
        *, restart_capability: _ObservationRestartCapability,
        observed_generation: int | None = None,
        observed_cursor: int | None = None,
        record_guard: Callable[[list[dict[str, Any]], int], None],
    ) -> _ProductionReceiptObserver:
        if not callable(record_guard):
            raise ReceiptObserverError("RECORD_GUARD_INVALID")
        return build_core(
            restart_capability=restart_capability,
            observed_generation=observed_generation,
            observed_cursor=observed_cursor,
            record_guard=record_guard)

    return build, build_guarded


(build_production_receipt_observer,
 _build_guarded_production_receipt_observer) = _seal_production_factory()
del _seal_production_factory


def _build_receipt_observer_for_test(
    *, config: _Config, transport: Any, store: PrivateReceiptStore,
    signature_verifier: Callable[[str, str, str, str, str], None],
    clock: Callable[[], datetime],
    record_guard: Callable[[list[dict[str, Any]], int], None] | None = None,
) -> ReceiptObserver:
    """Fixture-only seam; production protocol bindings remain sealed."""
    return ReceiptObserver(
        config, transport, store, signature_verifier, clock,
        record_guard=record_guard)
