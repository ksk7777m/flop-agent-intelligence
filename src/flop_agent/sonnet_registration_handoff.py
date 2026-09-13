"""Durable, production-disabled handoff for one Sonnet-2 registration POST."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import ssl
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Iterator, Mapping

from . import sonnet_registration as registration


SCHEMA_VERSION = "sonnet2-registration-journal-v1"
APPROVAL_SCHEMA_VERSION = "sonnet2-registration-approval-v1"
POLICY_VERSION = "sonnet2-registration-durable-handoff-v1"
MAX_JOURNAL_BYTES = 1024 * 1024
MAX_JOURNAL_RECORDS = 32
MAX_RESPONSE_BYTES = 16 * 1024
TRANSPORT_TIMEOUT_SECONDS = 20
ZERO_HASH = "0" * 64
PRODUCTION_ROOT = (
    Path(__file__).resolve().parents[2] / "runtime" / "sonnet-2"
    / "registration-bf8de59d-6e06-48b3-914b-6ac75cf07f4a" / "execution-journal"
)

_JOURNAL_MATERIAL = {
    **registration.fixed_binding(),
    "policy_version": POLICY_VERSION,
    "schema": SCHEMA_VERSION,
}
JOURNAL_ID = hashlib.sha256(json.dumps(
    _JOURNAL_MATERIAL, sort_keys=True, separators=(",", ":"),
    ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()
REQUEST_BODY_BYTE_LENGTH = len(json.dumps({
    "did": registration.PARTICIPANT_DID, "sig": "A" * 86,
    "nonce": registration.NONCE, "text": registration.PACKET_TEXT,
}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))


class HandoffError(RuntimeError):
    """Fixed-code failure which does not reflect local or remote values."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class JournalState(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    INTENT_RECORDED = "INTENT_RECORDED"
    LOCAL_SIGNATURE_CREATED = "LOCAL_SIGNATURE_CREATED"
    POST_ATTEMPT_RECORDED = "POST_ATTEMPT_RECORDED"
    POST_RESPONSE_OBSERVED = "POST_RESPONSE_OBSERVED"
    AWAITING_REFEREE_RECEIPT = "AWAITING_REFEREE_RECEIPT"
    RECEIPT_ACCEPTED = "RECEIPT_ACCEPTED"
    RECEIPT_REJECTED = "RECEIPT_REJECTED"
    WRITE_OUTCOME_UNKNOWN = "WRITE_OUTCOME_UNKNOWN"


@dataclass(frozen=True)
class HandoffTransportObservation:
    status_code: int
    final_url: str
    body: bytes
    redirected: bool = False
    complete: bool = True
    tls_valid: bool = True


_APPROVAL_FIELDS = frozenset({
    "schema", "approval_id", "decision", "reviewer", "action_class",
    "participant_did", "room", "request_id", "nonce", "packet_sha256",
    "signing_target_sha256", "role", "x_account_url", "referee_did",
    "manifest_sha256", "issued_at", "expires_at", "journal_id",
})
_RECORD_FIELDS = frozenset({
    "schema", "journal_id", "sequence", "previous_hash", "event", "state",
    "registration_id", "packet_sha256", "signing_target_sha256", "nonce",
    "approval_id_sha256", "http_status", "receipt_status", "created_at",
    "record_hash",
})
_EVENT_STATE = {
    "INTENT": JournalState.INTENT_RECORDED,
    "LOCAL_SIGNATURE": JournalState.LOCAL_SIGNATURE_CREATED,
    "POST_ATTEMPT": JournalState.POST_ATTEMPT_RECORDED,
    "POST_RESPONSE": JournalState.POST_RESPONSE_OBSERVED,
    "AWAIT_RECEIPT": JournalState.AWAITING_REFEREE_RECEIPT,
    "RECEIPT_ACCEPTED": JournalState.RECEIPT_ACCEPTED,
    "RECEIPT_REJECTED": JournalState.RECEIPT_REJECTED,
    "OUTCOME_UNKNOWN": JournalState.WRITE_OUTCOME_UNKNOWN,
}
_NEXT_STATES = {
    JournalState.NOT_STARTED: {JournalState.INTENT_RECORDED},
    JournalState.INTENT_RECORDED: {
        JournalState.LOCAL_SIGNATURE_CREATED,
        JournalState.RECEIPT_ACCEPTED, JournalState.RECEIPT_REJECTED,
    },
    JournalState.LOCAL_SIGNATURE_CREATED: {
        JournalState.POST_ATTEMPT_RECORDED,
        JournalState.RECEIPT_ACCEPTED, JournalState.RECEIPT_REJECTED,
    },
    JournalState.POST_ATTEMPT_RECORDED: {
        JournalState.POST_RESPONSE_OBSERVED, JournalState.WRITE_OUTCOME_UNKNOWN,
        JournalState.RECEIPT_ACCEPTED, JournalState.RECEIPT_REJECTED,
    },
    JournalState.POST_RESPONSE_OBSERVED: {
        JournalState.AWAITING_REFEREE_RECEIPT,
        JournalState.RECEIPT_ACCEPTED, JournalState.RECEIPT_REJECTED,
    },
    JournalState.AWAITING_REFEREE_RECEIPT: {
        JournalState.RECEIPT_ACCEPTED, JournalState.RECEIPT_REJECTED,
    },
    JournalState.WRITE_OUTCOME_UNKNOWN: {
        JournalState.RECEIPT_ACCEPTED, JournalState.RECEIPT_REJECTED,
    },
    JournalState.RECEIPT_ACCEPTED: set(),
    JournalState.RECEIPT_REJECTED: set(),
}


def approval_schema() -> Mapping[str, Any]:
    """Return the closed descriptive schema; it is not an approval."""
    properties = {
        "schema": {"const": APPROVAL_SCHEMA_VERSION},
        "approval_id": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "decision": {"const": "APPROVED"},
        "reviewer": {"type": "string", "minLength": 1, "maxLength": 128},
        "action_class": {"const": registration.ACTION_CLASS},
        "participant_did": {"const": registration.PARTICIPANT_DID},
        "room": {"const": registration.ROOM},
        "request_id": {"const": registration.REQUEST_ID},
        "nonce": {"const": registration.NONCE},
        "packet_sha256": {"const": registration.PACKET_SHA256},
        "signing_target_sha256": {"const": registration.SIGNING_TARGET_SHA256},
        "role": {"const": registration.ROLE},
        "x_account_url": {"const": registration.X_ACCOUNT_URL},
        "referee_did": {"const": registration.REFEREE_DID},
        "manifest_sha256": {"const": registration.MANIFEST_SHA256},
        "issued_at": {"type": "string", "format": "date-time"},
        "expires_at": {"type": "string", "format": "date-time"},
        "journal_id": {"const": JOURNAL_ID},
    }
    return MappingProxyType({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object", "additionalProperties": False,
        "required": sorted(_APPROVAL_FIELDS), "properties": properties,
    })


def _parse_time(value: Any) -> datetime:
    if type(value) is not str:
        raise HandoffError("APPROVAL_TIME_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise HandoffError("APPROVAL_TIME_INVALID") from None
    if parsed.tzinfo is None:
        raise HandoffError("APPROVAL_TIME_INVALID")
    return parsed.astimezone(timezone.utc)


def validate_approval_artifact(
    artifact: Mapping[str, Any], *, trusted_reviewers: frozenset[str], now: datetime,
) -> Mapping[str, Any]:
    """Validate an exact configured artifact; validation itself grants no permit."""
    if not isinstance(artifact, Mapping) or set(artifact) != _APPROVAL_FIELDS:
        raise HandoffError("APPROVAL_FIELDS_INVALID")
    expected = {
        "schema": APPROVAL_SCHEMA_VERSION, "decision": "APPROVED",
        "action_class": registration.ACTION_CLASS,
        "participant_did": registration.PARTICIPANT_DID,
        "room": registration.ROOM, "request_id": registration.REQUEST_ID,
        "nonce": registration.NONCE, "packet_sha256": registration.PACKET_SHA256,
        "signing_target_sha256": registration.SIGNING_TARGET_SHA256,
        "role": registration.ROLE, "x_account_url": registration.X_ACCOUNT_URL,
        "referee_did": registration.REFEREE_DID,
        "manifest_sha256": registration.MANIFEST_SHA256,
        "journal_id": JOURNAL_ID,
    }
    if any(type(artifact.get(key)) is not str or artifact.get(key) != value
           for key, value in expected.items()):
        raise HandoffError("APPROVAL_BINDING_INVALID")
    approval_id = artifact.get("approval_id")
    if (type(approval_id) is not str or len(approval_id) != 64
            or any(character not in "0123456789abcdef" for character in approval_id)):
        raise HandoffError("APPROVAL_ID_INVALID")
    reviewer = artifact.get("reviewer")
    if type(reviewer) is not str or reviewer not in trusted_reviewers:
        raise HandoffError("APPROVAL_REVIEWER_INVALID")
    issued, expires = _parse_time(artifact.get("issued_at")), _parse_time(artifact.get("expires_at"))
    current = now.astimezone(timezone.utc)
    if (expires <= issued or (expires - issued).total_seconds() > 900
            or current < issued or current > expires):
        raise HandoffError("APPROVAL_EXPIRED")
    return MappingProxyType(dict(artifact))


def _record_hash(record: Mapping[str, Any]) -> str:
    body = dict(record)
    body.pop("record_hash", None)
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _decode_records(data: bytes) -> list[dict[str, Any]]:
    if len(data) > MAX_JOURNAL_BYTES:
        raise HandoffError("JOURNAL_OVERSIZED")
    if not data:
        raise HandoffError("JOURNAL_EMPTY")
    chunks = data.splitlines(keepends=True)
    if len(chunks) > MAX_JOURNAL_RECORDS:
        raise HandoffError("JOURNAL_OVERSIZED")
    records: list[dict[str, Any]] = []
    previous_hash, previous_state = ZERO_HASH, JournalState.NOT_STARTED
    approval_id_sha256: str | None = None

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise HandoffError("JOURNAL_DUPLICATE_FIELD")
            result[key] = value
        return result

    for sequence, chunk in enumerate(chunks):
        if not chunk.endswith(b"\n"):
            raise HandoffError("JOURNAL_TRUNCATED")
        try:
            record = json.loads(chunk[:-1].decode("utf-8"), object_pairs_hook=pairs)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HandoffError("JOURNAL_INVALID") from None
        if type(record) is not dict or set(record) != _RECORD_FIELDS:
            raise HandoffError("JOURNAL_FIELDS_INVALID")
        event, state_value = record.get("event"), record.get("state")
        try:
            current_state = JournalState(state_value)
        except (TypeError, ValueError):
            raise HandoffError("JOURNAL_STATE_INVALID") from None
        if (_EVENT_STATE.get(event) is not current_state
                or current_state not in _NEXT_STATES[previous_state]):
            raise HandoffError("JOURNAL_TRANSITION_INVALID")
        fixed = {
            "schema": SCHEMA_VERSION, "journal_id": JOURNAL_ID,
            "sequence": sequence, "previous_hash": previous_hash,
            "registration_id": registration.REQUEST_ID,
            "packet_sha256": registration.PACKET_SHA256,
            "signing_target_sha256": registration.SIGNING_TARGET_SHA256,
            "nonce": registration.NONCE,
        }
        if any(type(record.get(key)) is not type(value) or record.get(key) != value
               for key, value in fixed.items()):
            raise HandoffError("JOURNAL_BINDING_INVALID")
        for key in ("approval_id_sha256", "record_hash"):
            value = record.get(key)
            if (type(value) is not str or len(value) != 64
                    or any(character not in "0123456789abcdef" for character in value)):
                raise HandoffError("JOURNAL_HASH_INVALID")
        if approval_id_sha256 is None:
            approval_id_sha256 = record["approval_id_sha256"]
        elif record["approval_id_sha256"] != approval_id_sha256:
            raise HandoffError("JOURNAL_APPROVAL_FORK")
        if record["record_hash"] != _record_hash(record):
            raise HandoffError("JOURNAL_HASH_INVALID")
        if current_state is JournalState.POST_RESPONSE_OBSERVED:
            status_code = record.get("http_status")
            if type(status_code) is not int or not 200 <= status_code < 300:
                raise HandoffError("JOURNAL_RESPONSE_INVALID")
        elif record.get("http_status") is not None:
            raise HandoffError("JOURNAL_RESPONSE_INVALID")
        expected_receipt = (
            "accepted" if current_state is JournalState.RECEIPT_ACCEPTED else
            "rejected" if current_state is JournalState.RECEIPT_REJECTED else None)
        if record.get("receipt_status") != expected_receipt:
            raise HandoffError("JOURNAL_RECEIPT_INVALID")
        if type(record.get("created_at")) is not str:
            raise HandoffError("JOURNAL_TIME_INVALID")
        records.append(record)
        previous_hash, previous_state = record["record_hash"], current_state
    return records


def _safe_directory(path: Path, *, create: bool) -> None:
    if create:
        path.mkdir(mode=0o700, parents=False, exist_ok=True)
    try:
        info = path.lstat()
    except OSError:
        raise HandoffError("JOURNAL_DIRECTORY_UNSAFE") from None
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise HandoffError("JOURNAL_DIRECTORY_UNSAFE")


def _safe_file_info(info: os.stat_result) -> None:
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise HandoffError("JOURNAL_FILE_UNSAFE")


class _Journal:
    def __init__(self, root: Path, clock: Callable[[], datetime]):
        self.root, self.clock = root, clock
        self.journal_name = "registration-journal.jsonl"
        self.lock_name = "registration-journal.lock"

    @contextmanager
    def lock(self) -> Iterator[None]:
        _safe_directory(self.root.parent, create=False)
        _safe_directory(self.root, create=True)
        directory_fd = os.open(
            self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0))
        lock_fd = -1
        try:
            opened = os.fstat(directory_fd)
            named = self.root.lstat()
            if ((opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                    or not stat.S_ISDIR(opened.st_mode)):
                raise HandoffError("JOURNAL_DIRECTORY_UNSAFE")
            lock_fd = os.open(
                self.lock_name, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                0o600, dir_fd=directory_fd)
            _safe_file_info(os.fstat(lock_fd))
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise HandoffError("JOURNAL_LOCKED") from None
            yield
        finally:
            if lock_fd >= 0:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
            os.close(directory_fd)

    def read(self) -> list[dict[str, Any]]:
        directory_fd = file_fd = -1
        try:
            _safe_directory(self.root, create=False)
            directory_fd = os.open(
                self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0))
            file_fd = os.open(
                self.journal_name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd)
            opened = os.fstat(file_fd)
            named = os.stat(
                self.journal_name, dir_fd=directory_fd, follow_symlinks=False)
            _safe_file_info(opened)
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                raise HandoffError("JOURNAL_FILE_UNSAFE")
            chunks: list[bytes] = []
            remaining = MAX_JOURNAL_BYTES + 1
            while remaining:
                chunk = os.read(file_fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
        except FileNotFoundError:
            return []
        except OSError:
            raise HandoffError("JOURNAL_READ_FAILED") from None
        finally:
            if file_fd >= 0:
                os.close(file_fd)
            if directory_fd >= 0:
                os.close(directory_fd)
        return _decode_records(data)

    def append(self, *, event: str, approval_id: str | None = None,
               approval_id_sha256: str | None = None,
               http_status: int | None = None,
               receipt_status: str | None = None) -> Mapping[str, Any]:
        records = self.read()
        prior = JournalState(records[-1]["state"]) if records else JournalState.NOT_STARTED
        state = _EVENT_STATE.get(event)
        if state is None or state not in _NEXT_STATES[prior]:
            raise HandoffError("JOURNAL_TRANSITION_INVALID")
        if approval_id is not None:
            approval_hash = hashlib.sha256(approval_id.encode("ascii")).hexdigest()
        elif (type(approval_id_sha256) is str and len(approval_id_sha256) == 64
              and all(character in "0123456789abcdef"
                      for character in approval_id_sha256)):
            approval_hash = approval_id_sha256
        else:
            raise HandoffError("APPROVAL_ID_INVALID")
        record = {
            "schema": SCHEMA_VERSION, "journal_id": JOURNAL_ID,
            "sequence": len(records),
            "previous_hash": records[-1]["record_hash"] if records else ZERO_HASH,
            "event": event, "state": state.value,
            "registration_id": registration.REQUEST_ID,
            "packet_sha256": registration.PACKET_SHA256,
            "signing_target_sha256": registration.SIGNING_TARGET_SHA256,
            "nonce": registration.NONCE, "approval_id_sha256": approval_hash,
            "http_status": http_status, "receipt_status": receipt_status,
            "created_at": self.clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "record_hash": "",
        }
        record["record_hash"] = _record_hash(record)
        candidate = [*records, record]
        encoded = b"".join(json.dumps(
            item, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False).encode("utf-8") + b"\n" for item in candidate)
        if _decode_records(encoded) != candidate:
            raise HandoffError("JOURNAL_CANDIDATE_INVALID")
        temporary = f".{self.journal_name}.{os.getpid()}.tmp"
        directory_fd = os.open(
            self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0))
        fd = -1
        replaced = False
        try:
            fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY
                         | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=directory_fd)
            _safe_file_info(os.fstat(fd))
            offset = 0
            while offset < len(encoded):
                written = os.write(fd, encoded[offset:])
                if written <= 0:
                    raise HandoffError("JOURNAL_WRITE_FAILED")
                offset += written
            os.fsync(fd)
            os.close(fd)
            fd = -1
            os.replace(temporary, self.journal_name,
                       src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            replaced = True
            os.fsync(directory_fd)
            published = os.stat(self.journal_name, dir_fd=directory_fd, follow_symlinks=False)
            _safe_file_info(published)
        except OSError:
            raise HandoffError(
                "JOURNAL_DURABILITY_UNKNOWN" if replaced else "JOURNAL_WRITE_FAILED") from None
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass
            os.close(directory_fd)
        return MappingProxyType(dict(record))

    def inspect(self) -> Mapping[str, Any]:
        if not self.root.exists():
            return MappingProxyType({
                "journal_id": JOURNAL_ID, "state": JournalState.NOT_STARTED.value,
                "record_count": 0, "execution_blocked": False,
                "reconciliation_only": False, "retry_count": 0,
            })
        _safe_directory(self.root, create=False)
        records = self.read()
        state = JournalState(records[-1]["state"]) if records else JournalState.NOT_STARTED
        return MappingProxyType({
            "journal_id": JOURNAL_ID, "state": state.value,
            "record_count": len(records),
            "execution_blocked": state is not JournalState.NOT_STARTED,
            "reconciliation_only": state is not JournalState.NOT_STARTED,
            "retry_count": 0,
        })


class _HandoffService:
    __slots__ = ("_execute", "_reconcile", "_inspect")

    def __init__(self, token: object, execute: Callable[..., Any],
                 reconcile: Callable[..., Any], inspect: Callable[..., Any]):
        if token is not _SERVICE_TOKEN:
            raise TypeError("handoff service is sealed")
        object.__setattr__(self, "_execute", execute)
        object.__setattr__(self, "_reconcile", reconcile)
        object.__setattr__(self, "_inspect", inspect)

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise AttributeError("handoff service is immutable")

    def execute(self, candidate: Mapping[str, Any], approval_id: str) -> Mapping[str, Any]:
        return self._execute(candidate, approval_id)

    def reconcile(self, receipt: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._reconcile(receipt)

    def inspect(self) -> Mapping[str, Any]:
        return self._inspect()


_SERVICE_TOKEN = object()


def _build_handoff(
    *, root: Path, approvals: Mapping[str, Mapping[str, Any]],
    trusted_reviewers: frozenset[str], clock: Callable[[], datetime],
    registration_checker: Callable[[], str], key_loader: Callable[[], tuple[Any, str]],
    signer: Callable[[Any, bytes], str],
    transport: Callable[..., HandoffTransportObservation],
    receipt_classifier: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    fault: Callable[[str], None] | None = None,
) -> _HandoffService:
    configured_approvals = MappingProxyType({
        key: MappingProxyType(dict(value)) for key, value in approvals.items()})
    reviewers = frozenset(trusted_reviewers)
    journal = _Journal(root, clock)
    journal_lock = journal.lock
    journal_inspect = journal.inspect
    journal_append = journal.append
    journal_read = journal.read
    used_approvals: set[str] = set()
    trip = fault or (lambda _point: None)
    validate_candidate = registration.validate_candidate
    validate_approval = validate_approval_artifact
    boundary_error = HandoffError
    participant_did = registration.PARTICIPANT_DID
    signing_target = registration.SIGNING_TARGET_BYTES
    nonce = registration.NONCE
    post_url = registration.POST_URL
    observation_type = HandoffTransportObservation
    max_response_bytes = MAX_RESPONSE_BYTES
    request_body_byte_length = REQUEST_BODY_BYTE_LENGTH
    transport_timeout_seconds = TRANSPORT_TIMEOUT_SECONDS
    state_type = JournalState
    proxy = MappingProxyType
    json_dumps, json_loads = json.dumps, json.loads
    json_decode_error = json.JSONDecodeError
    transport_errors = (TimeoutError, ConnectionError, OSError, ssl.SSLError)
    service_type, service_token = _HandoffService, _SERVICE_TOKEN

    def execute(candidate: Mapping[str, Any], approval_id: str) -> Mapping[str, Any]:
        checked = validate_candidate(candidate)
        if registration_checker() != "ELIGIBLE_UNREGISTERED_CONFIRMED":
            raise boundary_error("REGISTRATION_STATE_UNRESOLVED")
        artifact = configured_approvals.get(approval_id)
        if artifact is None:
            raise boundary_error("APPROVAL_NOT_ISSUED")
        validated_approval = validate_approval(
            artifact, trusted_reviewers=reviewers, now=clock())
        if validated_approval["approval_id"] != approval_id:
            raise boundary_error("APPROVAL_ID_MISMATCH")
        with journal_lock():
            if approval_id in used_approvals:
                raise boundary_error("APPROVAL_ALREADY_USED")
            status = journal_inspect()
            if status["state"] != state_type.NOT_STARTED.value:
                raise boundary_error("JOURNAL_ALREADY_USED")
            journal_append(event="INTENT", approval_id=approval_id)
            used_approvals.add(approval_id)
            trip("AFTER_INTENT")
            key, did = key_loader()
            if did != participant_did:
                raise boundary_error("IDENTITY_DID_MISMATCH")
            signature = signer(key, signing_target)
            if (type(signature) is not str or len(signature) != 86
                    or any(character not in
                           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                           for character in signature)):
                raise boundary_error("SIGNATURE_INVALID")
            journal_append(event="LOCAL_SIGNATURE", approval_id=approval_id)
            trip("AFTER_LOCAL_SIGNATURE")
            payload = {
                "did": did, "sig": signature, "nonce": nonce,
                "text": checked["packet"],
            }
            request_body = json_dumps(
                payload, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False).encode("utf-8")
            if len(request_body) != request_body_byte_length:
                raise boundary_error("REQUEST_BODY_SIZE_INVALID")
            trip("BEFORE_POST_ATTEMPT_RECORD")
            journal_append(event="POST_ATTEMPT", approval_id=approval_id)
            trip("AFTER_POST_ATTEMPT")
            try:
                response = transport(
                    post_url, request_body, method="POST",
                    timeout_seconds=transport_timeout_seconds,
                    allow_redirects=False, allow_proxy=False,
                    credential_forwarding=False,
                )
                trip("AFTER_TRANSPORT_INVOCATION")
            except transport_errors:
                journal_append(event="OUTCOME_UNKNOWN", approval_id=approval_id)
                return proxy({
                    "status": state_type.WRITE_OUTCOME_UNKNOWN.value,
                    "transport_invocations": 1, "retry_count": 0,
                    "receipt_required": True,
                })
            invalid = (
                type(response) is not observation_type
                or response.redirected or response.final_url != post_url
                or response.tls_valid is not True or response.complete is not True
                or type(response.status_code) is not int
                or not 200 <= response.status_code < 300
                or type(response.body) is not bytes
                or len(response.body) > max_response_bytes
            )
            if not invalid:
                try:
                    decoded = json_loads(response.body.decode("utf-8"))
                    invalid = type(decoded) is not dict
                except (UnicodeDecodeError, json_decode_error):
                    invalid = True
            if invalid:
                journal_append(event="OUTCOME_UNKNOWN", approval_id=approval_id)
                return proxy({
                    "status": state_type.WRITE_OUTCOME_UNKNOWN.value,
                    "transport_invocations": 1, "retry_count": 0,
                    "receipt_required": True,
                })
            journal_append(event="POST_RESPONSE", approval_id=approval_id,
                           http_status=response.status_code)
            journal_append(event="AWAIT_RECEIPT", approval_id=approval_id)
            return proxy({
                "status": state_type.AWAITING_REFEREE_RECEIPT.value,
                "transport_invocations": 1, "retry_count": 0,
                "receipt_required": True,
            })

    def reconcile(receipt: Mapping[str, Any]) -> Mapping[str, Any]:
        with journal_lock():
            status = journal_inspect()
            state = state_type(status["state"])
            if state is state_type.NOT_STARTED:
                raise boundary_error("JOURNAL_INTENT_REQUIRED")
            if state in {state_type.RECEIPT_ACCEPTED, state_type.RECEIPT_REJECTED}:
                raise boundary_error("RECEIPT_ALREADY_RECORDED")
            classified = receipt_classifier(receipt)
            outcome = classified.get("status")
            if outcome == "ACCEPTED_VERIFIED":
                event, public = "RECEIPT_ACCEPTED", state_type.RECEIPT_ACCEPTED
            elif outcome == "REJECTED_VERIFIED":
                event, public = "RECEIPT_REJECTED", state_type.RECEIPT_REJECTED
            else:
                raise boundary_error("RECEIPT_UNVERIFIED")
            approval_hash = journal_read()[0]["approval_id_sha256"]
            journal_append(event=event, approval_id_sha256=approval_hash,
                           receipt_status="accepted" if event == "RECEIPT_ACCEPTED" else "rejected")
            return proxy({
                "status": public.value, "transport_invocations": 0,
                "retry_count": 0, "referee_signature": "VALID",
            })

    return service_type(service_token, execute, reconcile, journal_inspect)


def _disabled(*_args: Any, **_kwargs: Any) -> Any:
    raise HandoffError("REGISTRATION_WRITE_APPROVAL_REQUIRED")


def _build_handoff_for_test(**kwargs: Any) -> _HandoffService:
    """Private fixture seam. Production exposes no approvals or live adapters."""
    return _build_handoff(**kwargs)


production_handoff_service = _build_handoff(
    root=PRODUCTION_ROOT, approvals=MappingProxyType({}),
    trusted_reviewers=frozenset(), clock=lambda: datetime.now(timezone.utc),
    registration_checker=_disabled, key_loader=_disabled, signer=_disabled,
    transport=_disabled,
    receipt_classifier=registration.production_registration_service.classify_receipt,
)
