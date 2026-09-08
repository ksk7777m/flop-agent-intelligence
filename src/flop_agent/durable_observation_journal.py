"""Durable, local-only observation attempt journal and recovery boundary.

The production facade captures one repository-owned ignored runtime path.  It
contains no observer, URL, network client, signer, scheduler, or retry path.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import threading
import weakref
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .observation_retention import (CANONICAL_ENCODING, FIXED_SOURCES,
    HASH_ALGORITHM, OBSERVATION_POLICY, PREDICATE_POLICY_HASHES, PredicatePolicy,
    SOURCE_ORDER_HASH, SOURCE_SET_ID)
from .remote_content_policy import DEFAULT_HTTP_TIMEOUT_SECONDS, DEFAULT_RESPONSE_LIMIT

SCHEMA_VERSION = "durable-observation-attempt-journal-v1"
POLICY_VERSION = "local-durable-observation-journal-policy-v1"
IDENTITY_DOMAIN = "FLOP_DURABLE_OBSERVATION_JOURNAL_V1"
JOURNAL_ID = hashlib.sha256((IDENTITY_DOMAIN + ":repository-journal").encode()).hexdigest()
ROOT = Path(__file__).resolve().parents[2]
_PRODUCTION_ROOT = ROOT / "runtime" / "observation-attempt-journal"
_STAMP = "2026-09-08T06:00:00Z"
_ZERO = "0" * 64


class JournalError(RuntimeError):
    def __init__(self, code: str, field: str = "journal"):
        super().__init__(f"{code}: {field}")
        self.code = code


class AttemptState(str, Enum):
    PREPARED = "PREPARED"
    INTENT_DURABLE = "INTENT_DURABLE"
    IN_PROGRESS = "IN_PROGRESS"
    INTERRUPTED = "INTERRUPTED"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
    RESULTS_COMPLETE = "RESULTS_COMPLETE"
    EVIDENCE_COMMITTED = "EVIDENCE_COMMITTED"
    FINALIZED = "FINALIZED"
    ABANDONED = "ABANDONED"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"


class SourceState(str, Enum):
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    INTENT_DURABLE = "INTENT_DURABLE"
    REQUEST_MAY_HAVE_STARTED = "REQUEST_MAY_HAVE_STARTED"
    RESULT_DURABLE = "RESULT_DURABLE"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
    FAILED_CONFIRMED = "FAILED_CONFIRMED"


class Integrity(str, Enum):
    ABSENT = "ABSENT"
    VALID = "VALID"
    TORN_TAIL = "TORN_TAIL"
    CORRUPT = "CORRUPT"


class Durability(str, Enum):
    NOT_FOUND = "NOT_FOUND"
    CONFIRMED = "CONFIRMED"
    UNKNOWN = "UNKNOWN"


class _AttemptToken:
    __slots__ = ("__weakref__",)
    def __new__(cls, *_args: Any, **_kwargs: Any) -> "_AttemptToken":
        raise PermissionError("sealed journal attempt required")
    def __reduce__(self) -> Any: raise TypeError("journal tokens cannot be serialized")
    def __copy__(self) -> Any: raise TypeError("journal tokens cannot be copied")
    def __deepcopy__(self, _memo: Any) -> Any: raise TypeError("journal tokens cannot be copied")


class _ResultToken(_AttemptToken): pass
class _EvidenceToken(_AttemptToken): pass


@dataclass(frozen=True)
class _Handle:
    attempt_id: str
    plan_id: str
    generation: int
    issuer_pid: int


def _strict_hash(value: Mapping[str, Any], domain: str) -> str:
    def check(item: Any) -> None:
        if item is None or type(item) in {str, bool, int}: return
        if type(item) is list:
            for child in item: check(child)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for child in item.values(): check(child)
            return
        raise JournalError("CANONICAL_TYPE_INVALID", "record")
    envelope = {"canonical_encoding": CANONICAL_ENCODING, "domain": IDENTITY_DOMAIN,
        "hash_algorithm": HASH_ALGORITHM, "record_domain": domain, "value": dict(value)}
    check(envelope)
    encoded = json.dumps(envelope, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


_FIXED_PLAN_MATERIAL = {
    "schema": "manual-readonly-reobservation-runner-v1",
    "operation": "READ_ONLY_REOBSERVATION", "observation_policy": OBSERVATION_POLICY,
    "predicate_policy": PredicatePolicy.V2.value,
    "predicate_policy_hash": PREDICATE_POLICY_HASHES[PredicatePolicy.V2],
    "source_set_id": SOURCE_SET_ID, "source_order_hash": SOURCE_ORDER_HASH,
    "sources": [source.value for source in FIXED_SOURCES], "method": "GET",
    "request_count_per_source": 1, "retry_count": 0,
    "timeout_policy": {"seconds": DEFAULT_HTTP_TIMEOUT_SECONDS,
                       "body_bytes": DEFAULT_RESPONSE_LIMIT},
    "redirects_allowed": False, "alternate_url": None, "fallback": None,
    "remote_mcp_enabled": False, "signing_enabled": False,
    "external_write_enabled": False, "scheduler_enabled": False,
    "automatic_resume_allowed": False,
    "evidence_schema": "manual-reobservation-evidence-v1",
    "journal_schema": SCHEMA_VERSION, "generation": 0}
FIXED_REOBSERVATION_PLAN_ID = hashlib.sha256(json.dumps({
    "canonical_encoding": CANONICAL_ENCODING,
    "domain": "FLOP_MANUAL_READONLY_REOBSERVATION_RUNNER_V1",
    "hash_algorithm": HASH_ALGORITHM, "record_domain": "FIXED_PLAN",
    "value": _FIXED_PLAN_MATERIAL}, sort_keys=True, separators=(",", ":"),
    ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()


def _decode_line(raw: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result: raise JournalError("DUPLICATE_FIELD")
            result[key] = value
        return result
    try: value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise JournalError("RECORD_INVALID") from None
    if type(value) is not dict: raise JournalError("RECORD_INVALID")
    return value


_RECORD_FIELDS = {"schema", "journal_id", "plan_id", "attempt_id", "predicate_policy",
    "source_set_id", "source_order_hash", "attempt_generation", "sequence",
    "previous_hash", "record_type", "attempt_state", "source_id", "source_ordinal",
    "source_state", "result_id", "evidence_id", "created_at",
    "reconciliation_required", "record_hash"}
_RECORD_STATES = {
    "PLAN_PREPARED": {AttemptState.PREPARED.value},
    "PERMIT_CONSUMED": {AttemptState.PREPARED.value},
    "ATTEMPT_INTENT": {AttemptState.INTENT_DURABLE.value},
    "SOURCE_INTENT": {AttemptState.IN_PROGRESS.value},
    "REQUEST_BOUNDARY": {AttemptState.IN_PROGRESS.value},
    "SOURCE_RESULT": {AttemptState.IN_PROGRESS.value, AttemptState.RESULTS_COMPLETE.value},
    "EVIDENCE_COMMIT": {AttemptState.EVIDENCE_COMMITTED.value},
    "FINALIZE": {AttemptState.FINALIZED.value},
}


def _validate_record(value: Mapping[str, Any], previous: str, sequence: int,
                     plan_id: str | None, attempt_id: str | None) -> None:
    if set(value) != _RECORD_FIELDS: raise JournalError("RECORD_FIELDS_INVALID")
    if value.get("schema") != SCHEMA_VERSION or value.get("journal_id") != JOURNAL_ID:
        raise JournalError("RECORD_DOMAIN_INVALID")
    for name in ("plan_id", "attempt_id", "source_order_hash", "record_hash"):
        item = value.get(name)
        if type(item) is not str or len(item) != 64 or any(c not in "0123456789abcdef" for c in item):
            raise JournalError("RECORD_ID_INVALID")
    if value.get("predicate_policy") != PredicatePolicy.V2.value:
        raise JournalError("PREDICATE_INVALID")
    if value.get("source_set_id") != SOURCE_SET_ID or value.get("source_order_hash") != SOURCE_ORDER_HASH:
        raise JournalError("SOURCE_SET_INVALID")
    if type(value.get("sequence")) is not int or value["sequence"] != sequence:
        raise JournalError("SEQUENCE_INVALID")
    if type(value.get("attempt_generation")) is not int or value["attempt_generation"] != 0:
        raise JournalError("GENERATION_INVALID")
    if value.get("previous_hash") != previous: raise JournalError("HASH_CHAIN_INVALID")
    if plan_id is not None and value.get("plan_id") != plan_id: raise JournalError("PLAN_FORK")
    if attempt_id is not None and value.get("attempt_id") != attempt_id: raise JournalError("ATTEMPT_FORK")
    body = dict(value); claimed = body.pop("record_hash")
    if claimed != _strict_hash(body, "JOURNAL_RECORD"): raise JournalError("RECORD_HASH_INVALID")
    record_type = value.get("record_type")
    if record_type not in _RECORD_STATES or value.get("attempt_state") not in _RECORD_STATES[record_type]:
        raise JournalError("RECORD_TRANSITION_INVALID")
    source_id, ordinal = value.get("source_id"), value.get("source_ordinal")
    if source_id is None:
        if ordinal is not None or value.get("source_state") is not None: raise JournalError("SOURCE_BINDING_INVALID")
    else:
        expected = [source.value for source in FIXED_SOURCES]
        if type(ordinal) is not int or not 0 <= ordinal < 4 or source_id != expected[ordinal]:
            raise JournalError("SOURCE_BINDING_INVALID")
    source_records = {"SOURCE_INTENT", "REQUEST_BOUNDARY", "SOURCE_RESULT"}
    if (record_type in source_records) != (source_id is not None):
        raise JournalError("RECORD_SOURCE_CONTRADICTION")
    if (record_type == "SOURCE_RESULT") != (value.get("result_id") is not None):
        raise JournalError("RESULT_BINDING_INVALID")
    if (record_type == "EVIDENCE_COMMIT") != (value.get("evidence_id") is not None):
        raise JournalError("EVIDENCE_BINDING_INVALID")
    for name in ("result_id", "evidence_id"):
        item = value.get(name)
        if item is not None and (type(item) is not str or len(item) != 64
                or any(c not in "0123456789abcdef" for c in item)):
            raise JournalError("RECORD_ID_INVALID")
    for name in ("reconciliation_required",):
        if type(value.get(name)) is not bool: raise JournalError("BOOLEAN_INVALID")


def _inspect_bytes(data: bytes) -> tuple[Integrity, list[dict[str, Any]]]:
    if not data: return Integrity.ABSENT, []
    chunks = data.splitlines(keepends=True); records: list[dict[str, Any]] = []
    previous = _ZERO; plan_id = attempt_id = None
    for index, chunk in enumerate(chunks):
        if not chunk.endswith(b"\n"):
            if index == len(chunks) - 1: return Integrity.TORN_TAIL, records
            return Integrity.CORRUPT, []
        try:
            record = _decode_line(chunk[:-1])
            _validate_record(record, previous, index, plan_id, attempt_id)
        except JournalError:
            return Integrity.CORRUPT, []
        plan_id = record["plan_id"] if plan_id is None else plan_id
        attempt_id = record["attempt_id"] if attempt_id is None else attempt_id
        previous = record["record_hash"]; records.append(record)
        if len(records) > 256: return Integrity.CORRUPT, []
    if not _history_valid(records): return Integrity.CORRUPT, []
    return Integrity.VALID, records


def _history_valid(records: list[dict[str, Any]]) -> bool:
    if not records or records[0]["record_type"] != "PLAN_PREPARED": return False
    index = 1
    if index < len(records) and records[index]["record_type"] == "PERMIT_CONSUMED": index += 1
    if index == len(records): return True
    if records[index]["record_type"] != "ATTEMPT_INTENT": return False
    index += 1
    for ordinal in range(4):
        if index == len(records): return True
        if (records[index]["record_type"] != "SOURCE_INTENT"
                or records[index]["source_ordinal"] != ordinal): return False
        index += 1
        if index == len(records): return True
        if records[index]["record_type"] == "REQUEST_BOUNDARY":
            if records[index]["source_ordinal"] != ordinal: return False
            index += 1
            if index == len(records): return True
        if (records[index]["record_type"] != "SOURCE_RESULT"
                or records[index]["source_ordinal"] != ordinal): return False
        expected_state = (AttemptState.RESULTS_COMPLETE.value if ordinal == 3
                          else AttemptState.IN_PROGRESS.value)
        if records[index]["attempt_state"] != expected_state: return False
        index += 1
    if index == len(records): return True
    if records[index]["record_type"] != "EVIDENCE_COMMIT": return False
    index += 1
    if index == len(records): return True
    return (index + 1 == len(records)
            and records[index]["record_type"] == "FINALIZE")


def _safe_regular_info(info: os.stat_result) -> None:
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1):
        raise JournalError("LOCAL_ARTIFACT_UNSAFE")


def _secure_root(root: Path) -> None:
    try:
        root.parent.mkdir(exist_ok=True, mode=0o700)
        for directory in (root.parent,):
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
                raise JournalError("JOURNAL_PARENT_UNSAFE")
        root.mkdir(exist_ok=True, mode=0o700)
        info = root.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise JournalError("JOURNAL_ROOT_UNSAFE")
    except OSError:
        raise JournalError("JOURNAL_ROOT_UNSAFE") from None


def _open_root(root: Path, os_module: Any) -> int:
    """Open and anchor the fixed root through its verified parent directory."""
    _secure_root(root)
    flags = os_module.O_RDONLY | getattr(os_module, "O_DIRECTORY", 0) | getattr(os_module, "O_NOFOLLOW", 0)
    parent_fd = root_fd = -1
    try:
        parent_fd = os_module.open(root.parent, flags)
        parent_info = os_module.fstat(parent_fd); parent_path_info = root.parent.lstat()
        if ((parent_info.st_dev, parent_info.st_ino) != (parent_path_info.st_dev, parent_path_info.st_ino)
                or not stat.S_ISDIR(parent_info.st_mode) or stat.S_IMODE(parent_info.st_mode) != 0o700
                or parent_info.st_uid != os_module.getuid()):
            raise JournalError("JOURNAL_PARENT_UNSAFE")
        root_fd = os_module.open(root.name, flags, dir_fd=parent_fd)
        root_info = os_module.fstat(root_fd); root_path_info = root.lstat()
        if ((root_info.st_dev, root_info.st_ino) != (root_path_info.st_dev, root_path_info.st_ino)
                or not stat.S_ISDIR(root_info.st_mode) or stat.S_IMODE(root_info.st_mode) != 0o700
                or root_info.st_uid != os_module.getuid()):
            raise JournalError("JOURNAL_ROOT_UNSAFE")
        result = root_fd; root_fd = -1; return result
    except OSError:
        raise JournalError("JOURNAL_ROOT_UNSAFE") from None
    finally:
        if root_fd >= 0: os_module.close(root_fd)
        if parent_fd >= 0: os_module.close(parent_fd)


def _build_store(root: Path, *, os_module: Any = os,
                 fault: Callable[[str], None] | None = None,
                 fixture_issuers: bool = False) -> tuple[Callable[..., Any], ...]:
    """Private fixture seam. Production captures the fixed root and real OS."""
    lock = threading.Lock(); io_lock = threading.RLock()
    registry: weakref.WeakKeyDictionary[_AttemptToken, _Handle] = weakref.WeakKeyDictionary()
    results: weakref.WeakKeyDictionary[_ResultToken, str] = weakref.WeakKeyDictionary()
    evidence: weakref.WeakKeyDictionary[_EvidenceToken, str] = weakref.WeakKeyDictionary()
    durability_unknown = False
    journal_name = "journal.jsonl"; lock_name = "journal.lock"; temporary_name = ".journal.candidate"

    def trip(point: str) -> None:
        if fault is not None: fault(point)

    def locked() -> tuple[int, int]:
        root_fd = _open_root(root, os_module)
        flags = os_module.O_CREAT | os_module.O_RDWR | getattr(os_module, "O_NOFOLLOW", 0)
        try: descriptor = os_module.open(lock_name, flags, 0o600, dir_fd=root_fd)
        except OSError:
            os_module.close(root_fd); raise JournalError("LOCK_UNSAFE") from None
        try:
            info = os_module.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != os_module.getuid() or info.st_nlink != 1):
                raise JournalError("LOCK_UNSAFE")
            try: fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise JournalError("DUPLICATE_WRITER") from None
            anchored = os_module.stat(lock_name, dir_fd=root_fd, follow_symlinks=False)
            if (info.st_dev, info.st_ino) != (anchored.st_dev, anchored.st_ino):
                raise JournalError("LOCK_UNSAFE")
            return descriptor, root_fd
        except Exception:
            os_module.close(descriptor); os_module.close(root_fd); raise

    def read_at(root_fd: int) -> tuple[Integrity, list[dict[str, Any]]]:
        flags = os_module.O_RDONLY | getattr(os_module, "O_NOFOLLOW", 0)
        try: descriptor = os_module.open(journal_name, flags, dir_fd=root_fd)
        except FileNotFoundError: return Integrity.ABSENT, []
        except OSError: raise JournalError("LOCAL_ARTIFACT_UNSAFE") from None
        try:
            info = os_module.fstat(descriptor)
            anchored = os_module.stat(journal_name, dir_fd=root_fd, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != os_module.getuid() or info.st_nlink != 1
                    or (info.st_dev, info.st_ino) != (anchored.st_dev, anchored.st_ino)):
                raise JournalError("LOCAL_ARTIFACT_UNSAFE")
            chunks = []; total = 0
            while True:
                chunk = os_module.read(descriptor, 65536)
                if not chunk: break
                total += len(chunk)
                if total > 2 * 1024 * 1024: raise JournalError("JOURNAL_TOO_LARGE")
                chunks.append(chunk)
            data = b"".join(chunks)
        finally: os_module.close(descriptor)
        return (Integrity.CORRUPT, []) if not data else _inspect_bytes(data)

    def read() -> tuple[Integrity, list[dict[str, Any]]]:
        root_fd = _open_root(root, os_module)
        try: return read_at(root_fd)
        finally: os_module.close(root_fd)

    def append(fields: dict[str, Any]) -> dict[str, Any]:
        nonlocal durability_unknown
        with io_lock:
          lock_fd = dir_fd = -1; published_replaced = False
          try:
            if durability_unknown: raise JournalError("DURABILITY_RECONCILIATION_REQUIRED")
            lock_fd, dir_fd = locked(); trip("LOCKED")
            integrity, records = read_at(dir_fd)
            if integrity is not Integrity.ABSENT and integrity is not Integrity.VALID:
                raise JournalError("JOURNAL_RECONCILIATION_REQUIRED")
            if records and records[-1]["attempt_state"] in {AttemptState.FINALIZED.value, AttemptState.ABANDONED.value}:
                raise JournalError("ATTEMPT_TERMINAL")
            sequence = len(records); previous = records[-1]["record_hash"] if records else _ZERO
            record = {"schema": SCHEMA_VERSION, "journal_id": JOURNAL_ID,
                "plan_id": fields["plan_id"], "attempt_id": fields["attempt_id"],
                "predicate_policy": PredicatePolicy.V2.value, "source_set_id": SOURCE_SET_ID,
                "source_order_hash": SOURCE_ORDER_HASH, "attempt_generation": 0,
                "sequence": sequence, "previous_hash": previous,
                "record_type": fields["record_type"], "attempt_state": fields["attempt_state"],
                "source_id": fields.get("source_id"), "source_ordinal": fields.get("source_ordinal"),
                "source_state": fields.get("source_state"), "result_id": fields.get("result_id"),
                "evidence_id": fields.get("evidence_id"), "created_at": _STAMP,
                "reconciliation_required": fields.get("reconciliation_required", False)}
            record["record_hash"] = _strict_hash(record, "JOURNAL_RECORD")
            encoded = b"".join(json.dumps(item, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False).encode() + b"\n" for item in [*records, record])
            if len(encoded) > 2 * 1024 * 1024: raise JournalError("JOURNAL_LIMIT_REACHED")
            candidate_integrity, candidate_records = _inspect_bytes(encoded)
            if candidate_integrity is not Integrity.VALID or candidate_records != [*records, record]:
                raise JournalError("CANDIDATE_INVALID")
            fd = os_module.open(temporary_name, os_module.O_CREAT | os_module.O_EXCL | os_module.O_WRONLY
                | getattr(os_module, "O_NOFOLLOW", 0), 0o600, dir_fd=dir_fd)
            try:
                temp_info = os_module.fstat(fd)
                if (not stat.S_ISREG(temp_info.st_mode) or stat.S_IMODE(temp_info.st_mode) != 0o600
                        or temp_info.st_uid != os_module.getuid() or temp_info.st_nlink != 1):
                    raise JournalError("TEMP_UNSAFE")
                offset = 0
                while offset < len(encoded):
                    count = os_module.write(fd, encoded[offset:])
                    if count <= 0: raise JournalError("SHORT_WRITE")
                    offset += count; trip("WRITE_PARTIAL")
                os_module.fsync(fd); trip("FILE_FSYNCED")
            finally: os_module.close(fd)
            candidate_entry = os_module.stat(temporary_name, dir_fd=dir_fd, follow_symlinks=False)
            if ((candidate_entry.st_dev, candidate_entry.st_ino) != (temp_info.st_dev, temp_info.st_ino)
                    or not stat.S_ISREG(candidate_entry.st_mode)
                    or stat.S_IMODE(candidate_entry.st_mode) != 0o600
                    or candidate_entry.st_uid != os_module.getuid() or candidate_entry.st_nlink != 1):
                raise JournalError("TEMP_UNSAFE")
            os_module.replace(temporary_name, journal_name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            published_replaced = True; trip("RENAMED")
            try: os_module.fsync(dir_fd)
            except OSError:
                durability_unknown = True
                raise JournalError("DIRECTORY_FSYNC_DURABILITY_UNKNOWN") from None
            trip("DIRECTORY_FSYNCED")
            published = os_module.stat(journal_name, dir_fd=dir_fd, follow_symlinks=False)
            _safe_regular_info(published)
            if (published.st_dev, published.st_ino) != (temp_info.st_dev, temp_info.st_ino):
                raise JournalError("PUBLISHED_IDENTITY_INVALID")
            return record
          except OSError:
            if published_replaced:
                durability_unknown = True
                raise JournalError("DIRECTORY_FSYNC_DURABILITY_UNKNOWN") from None
            raise JournalError("LOCAL_PERSISTENCE_FAILED") from None
          finally:
            try:
                if dir_fd >= 0: os_module.unlink(temporary_name, dir_fd=dir_fd)
            except FileNotFoundError: pass
            except OSError: pass
            if dir_fd >= 0: os_module.close(dir_fd)
            if lock_fd >= 0:
                try: fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally: os_module.close(lock_fd)

    def resolve(token: _AttemptToken) -> _Handle:
        if type(token) is not _AttemptToken: raise JournalError("SEALED_ATTEMPT_REQUIRED")
        with lock: handle = registry.get(token)
        if handle is None: raise JournalError("STALE_OR_FOREIGN_ATTEMPT")
        if handle.issuer_pid != os_module.getpid(): raise JournalError("FOREIGN_PROCESS_ATTEMPT")
        integrity, records = read()
        if integrity is not Integrity.VALID or not records or records[-1]["attempt_id"] != handle.attempt_id:
            raise JournalError("JOURNAL_RECONCILIATION_REQUIRED")
        return handle

    def prepare() -> _AttemptToken:
        if durability_unknown: raise JournalError("DURABILITY_RECONCILIATION_REQUIRED")
        integrity, records = read()
        if integrity is not Integrity.ABSENT: raise JournalError("JOURNAL_ALREADY_EXISTS")
        plan_id = FIXED_REOBSERVATION_PLAN_ID
        attempt_id = _strict_hash({"journal_id": JOURNAL_ID, "plan_id": plan_id,
            "generation": 0}, "ATTEMPT")
        trip("BEFORE_CREATE")
        append({"plan_id": plan_id, "attempt_id": attempt_id, "record_type": "PLAN_PREPARED",
            "attempt_state": AttemptState.PREPARED.value})
        trip("PLAN_DURABLE")
        token = object.__new__(_AttemptToken)
        with lock: registry[token] = _Handle(attempt_id, plan_id, 0, os_module.getpid())
        return token

    def transition(token: _AttemptToken, record_type: str, state: AttemptState,
                   source: Any = None, source_state: SourceState | None = None,
                   result_id: str | None = None, evidence_id: str | None = None,
                   reconciliation: bool = False) -> Mapping[str, Any]:
        handle = resolve(token); integrity, records = read(); assert integrity is Integrity.VALID
        if type(state) is not AttemptState: raise JournalError("STATE_INVALID")
        source_id = ordinal = None
        if source is not None:
            if type(source) is not type(FIXED_SOURCES[0]) or source not in FIXED_SOURCES:
                raise JournalError("SOURCE_INVALID")
            ordinal = FIXED_SOURCES.index(source); source_id = source.value
            if any(item["source_id"] == source_id and item["source_state"] in {
                SourceState.INTENT_DURABLE.value, SourceState.REQUEST_MAY_HAVE_STARTED.value,
                SourceState.RESULT_DURABLE.value, SourceState.FAILED_CONFIRMED.value}
                and source_state is SourceState.INTENT_DURABLE for item in records):
                raise JournalError("DUPLICATE_SOURCE_INTENT")
        record = append({"plan_id": handle.plan_id, "attempt_id": handle.attempt_id,
            "record_type": record_type, "attempt_state": state.value,
            "source_id": source_id, "source_ordinal": ordinal,
            "source_state": None if source_state is None else source_state.value,
            "result_id": result_id, "evidence_id": evidence_id,
            "reconciliation_required": reconciliation})
        return MappingProxyType({"sequence": record["sequence"], "state": state.value,
            "plan_id": handle.plan_id, "attempt_id": handle.attempt_id,
            "attempt_generation": handle.generation, "record_hash": record["record_hash"],
            "durable": True, "network_invocations": 0})

    def durable_intent(token: _AttemptToken) -> Mapping[str, Any]:
        with io_lock:
            resolve(token); integrity, records = read(); assert integrity is Integrity.VALID
            if any(item["record_type"] == "ATTEMPT_INTENT" for item in records):
                raise JournalError("DUPLICATE_ATTEMPT_INTENT")
            value = transition(token, "ATTEMPT_INTENT", AttemptState.INTENT_DURABLE)
            trip("ATTEMPT_INTENT_DURABLE"); return value

    def permit_consumed(token: _AttemptToken) -> Mapping[str, Any]:
        with io_lock:
            resolve(token); integrity, records = read(); assert integrity is Integrity.VALID
            if any(item["record_type"] == "PERMIT_CONSUMED" for item in records):
                raise JournalError("DUPLICATE_PERMIT_CONSUMPTION")
            if any(item["record_type"] == "ATTEMPT_INTENT" for item in records):
                raise JournalError("PERMIT_CONSUMPTION_ORDER_INVALID")
            value = transition(token, "PERMIT_CONSUMED", AttemptState.PREPARED)
            trip("PERMIT_CONSUMED_DURABLE"); return value

    def source_intent(token: _AttemptToken, source: Any) -> Mapping[str, Any]:
        with io_lock:
            trip("BEFORE_SOURCE_INTENT")
            resolve(token); integrity, records = read(); assert integrity is Integrity.VALID
            if not any(item["record_type"] == "ATTEMPT_INTENT" for item in records):
                raise JournalError("ATTEMPT_INTENT_REQUIRED")
            if type(source) is not type(FIXED_SOURCES[0]) or source not in FIXED_SOURCES:
                raise JournalError("SOURCE_INVALID")
            durable_sources = {item["source_id"] for item in records
                if item["source_state"] == SourceState.RESULT_DURABLE.value}
            if FIXED_SOURCES.index(source) != len(durable_sources):
                raise JournalError("SOURCE_ORDER_OR_PRIOR_OUTCOME_INVALID")
            value = transition(token, "SOURCE_INTENT", AttemptState.IN_PROGRESS, source,
                               SourceState.INTENT_DURABLE)
            trip("SOURCE_INTENT_DURABLE"); return value

    def request_may_have_started(token: _AttemptToken, source: Any) -> Mapping[str, Any]:
        with io_lock:
            resolve(token); integrity, records = read(); assert integrity is Integrity.VALID
            if type(source) is not type(FIXED_SOURCES[0]) or source not in FIXED_SOURCES:
                raise JournalError("SOURCE_INVALID")
            states = [item["source_state"] for item in records if item["source_id"] == source.value]
            if not states or states[-1] != SourceState.INTENT_DURABLE.value:
                raise JournalError("SOURCE_INTENT_REQUIRED")
            value = transition(token, "REQUEST_BOUNDARY", AttemptState.IN_PROGRESS, source,
                               SourceState.REQUEST_MAY_HAVE_STARTED)
            trip("REQUEST_MAY_HAVE_STARTED"); return value

    def issue_result(source: Any, minimized_result_id: str | None = None) -> _ResultToken:
        if not fixture_issuers: raise JournalError("LIVE_EVIDENCE_ISSUER_UNAVAILABLE")
        if type(source) is not type(FIXED_SOURCES[0]) or source not in FIXED_SOURCES:
            raise JournalError("SOURCE_INVALID")
        if minimized_result_id is not None and (type(minimized_result_id) is not str
                or len(minimized_result_id) != 64
                or any(c not in "0123456789abcdef" for c in minimized_result_id)):
            raise JournalError("RESULT_ID_INVALID")
        token = object.__new__(_ResultToken); results[token] = (minimized_result_id
            or _strict_hash({"source_id": source.value, "fixture": True}, "FIXTURE_RESULT"))
        return token

    def result_durable(token: _AttemptToken, source: Any, result: _ResultToken) -> Mapping[str, Any]:
        with io_lock:
            if type(result) is not _ResultToken or result not in results: raise JournalError("SEALED_RESULT_REQUIRED")
            if type(source) is not type(FIXED_SOURCES[0]) or source not in FIXED_SOURCES:
                raise JournalError("SOURCE_INVALID")
            integrity, records = read(); assert integrity is Integrity.VALID
            if not any(item["source_id"] == source.value and item["source_state"] in {
                SourceState.INTENT_DURABLE.value, SourceState.REQUEST_MAY_HAVE_STARTED.value} for item in records):
                raise JournalError("SOURCE_INTENT_REQUIRED")
            if any(item["source_id"] == source.value and item["source_state"] == SourceState.RESULT_DURABLE.value
                   for item in records): raise JournalError("DUPLICATE_SOURCE_RESULT")
            state = AttemptState.RESULTS_COMPLETE if len({item["source_id"] for item in records
                if item["source_state"] == SourceState.RESULT_DURABLE.value} | {source.value}) == 4 else AttemptState.IN_PROGRESS
            trip("RESPONSE_RECEIVED_BEFORE_RESULT")
            value = transition(token, "SOURCE_RESULT", state, source, SourceState.RESULT_DURABLE,
                               result_id=results[result])
            trip("ALL_RESULTS_DURABLE" if state is AttemptState.RESULTS_COMPLETE
                 else "SOURCE_RESULT_DURABLE")
            return value

    def issue_evidence(minimized_evidence_id: str | None = None) -> _EvidenceToken:
        if not fixture_issuers: raise JournalError("LIVE_EVIDENCE_ISSUER_UNAVAILABLE")
        if minimized_evidence_id is not None and (type(minimized_evidence_id) is not str
                or len(minimized_evidence_id) != 64
                or any(c not in "0123456789abcdef" for c in minimized_evidence_id)):
            raise JournalError("EVIDENCE_ID_INVALID")
        token = object.__new__(_EvidenceToken); evidence[token] = (minimized_evidence_id
            or _strict_hash({"predicate_policy": PredicatePolicy.V2.value,
                             "fixture": True}, "FIXTURE_EVIDENCE"))
        return token

    def commit(token: _AttemptToken, sealed: _EvidenceToken) -> Mapping[str, Any]:
        with io_lock:
            if type(sealed) is not _EvidenceToken or sealed not in evidence: raise JournalError("SEALED_V2_EVIDENCE_REQUIRED")
            integrity, records = read(); assert integrity is Integrity.VALID
            if any(item["record_type"] == "EVIDENCE_COMMIT" for item in records):
                raise JournalError("DUPLICATE_EVIDENCE_COMMIT")
            if len({item["source_id"] for item in records if item["source_state"] == SourceState.RESULT_DURABLE.value}) != 4:
                raise JournalError("FOUR_DURABLE_RESULTS_REQUIRED")
            value = transition(token, "EVIDENCE_COMMIT", AttemptState.EVIDENCE_COMMITTED,
                               evidence_id=evidence[sealed])
            trip("EVIDENCE_COMMITTED"); return value

    def finalize(token: _AttemptToken) -> Mapping[str, Any]:
        with io_lock:
            integrity, records = read(); assert integrity is Integrity.VALID
            if records and records[-1]["attempt_state"] == AttemptState.FINALIZED.value:
                raise JournalError("ATTEMPT_TERMINAL")
            if not records or records[-1]["attempt_state"] != AttemptState.EVIDENCE_COMMITTED.value:
                raise JournalError("EVIDENCE_COMMIT_REQUIRED")
            trip("BEFORE_FINALIZE")
            value = transition(token, "FINALIZE", AttemptState.FINALIZED)
            trip("FINALIZED"); return value

    def inspect() -> Mapping[str, Any]:
        integrity, records = read(); last = records[-1] if records else None
        sources = []
        for ordinal, source in enumerate(FIXED_SOURCES):
            states = [item["source_state"] for item in records if item["source_id"] == source.value]
            state = states[-1] if states else SourceState.NOT_ATTEMPTED.value
            if state in {SourceState.INTENT_DURABLE.value, SourceState.REQUEST_MAY_HAVE_STARTED.value}:
                state = SourceState.OUTCOME_UNKNOWN.value
            sources.append({"source_id": source.value, "ordinal": ordinal, "state": state})
        unknown = any(item["state"] == SourceState.OUTCOME_UNKNOWN.value for item in sources)
        corrupt = integrity in {Integrity.CORRUPT, Integrity.TORN_TAIL}
        final = bool(last and last["attempt_state"] == AttemptState.FINALIZED.value)
        unfinished = bool(records) and not final
        needs_reconciliation = (durability_unknown or corrupt or unknown
                                or integrity is Integrity.ABSENT or unfinished)
        new_review = durability_unknown or corrupt or unknown or integrity is Integrity.ABSENT
        projection = {"schema": SCHEMA_VERSION, "status": "DESCRIPTIVE_ONLY",
            "durable_state_found": integrity is not Integrity.ABSENT,
            "journal_integrity": integrity.value,
            "durability": (Durability.UNKNOWN.value if durability_unknown else
                Durability.NOT_FOUND.value if integrity is Integrity.ABSENT else Durability.CONFIRMED.value),
            "attempt_state": (AttemptState.RECONCILIATION_REQUIRED.value
                if durability_unknown or corrupt or unknown
                else last["attempt_state"] if last else AttemptState.RECONCILIATION_REQUIRED.value),
            "record_count": len(records), "last_sequence": last["sequence"] if last else None,
            "attempt_generation": 0 if records else None, "predicate_policy": PredicatePolicy.V2.value,
            "source_set_id": SOURCE_SET_ID, "source_order_hash": SOURCE_ORDER_HASH,
            "sources": sources, "evidence_committed": any(item["record_type"] == "EVIDENCE_COMMIT" for item in records),
            "finalized": final, "reconciliation_required": needs_reconciliation,
            "execution_blocked": True, "automatic_resume_allowed": False,
            "automatic_retry_allowed": False, "new_human_review_required": new_review,
            "new_plan_required": new_review,
            "manual_investigation_required": durability_unknown or corrupt,
            "retry_count": 0, "raw_content_retained": False, "live_action_enabled": False,
            "ready_to_act": False, "authorized_to_act": False, "policy_version": POLICY_VERSION}
        if validate_projection(projection): raise JournalError("PUBLIC_PROJECTION_INVALID")
        return MappingProxyType(projection)

    production = (prepare, durable_intent, source_intent, request_may_have_started,
                  result_durable, commit, finalize, inspect, permit_consumed)
    return production + ((issue_result, issue_evidence) if fixture_issuers else ())


def validate_projection(value: Mapping[str, Any]) -> tuple[str, ...]:
    fields = {"schema", "status", "durable_state_found", "journal_integrity", "attempt_state",
        "durability", "record_count", "last_sequence", "attempt_generation", "predicate_policy", "source_set_id",
        "source_order_hash", "sources", "evidence_committed", "finalized",
        "reconciliation_required", "execution_blocked", "automatic_resume_allowed",
        "automatic_retry_allowed", "new_human_review_required", "new_plan_required",
        "manual_investigation_required", "retry_count", "raw_content_retained",
        "live_action_enabled", "ready_to_act", "authorized_to_act", "policy_version"}
    source_fields = {"source_id", "ordinal", "state"}; errors = []
    if not isinstance(value, Mapping) or set(value) != fields: return ("CLOSED_FIELDS_REQUIRED",)
    sources = value.get("sources")
    if (type(sources) is not list or len(sources) != 4
            or any(type(item) is not dict or set(item) != source_fields for item in sources)):
        errors.append("CLOSED_SOURCES_REQUIRED")
    else:
        expected = [source.value for source in FIXED_SOURCES]
        if [item.get("source_id") for item in sources] != expected or [item.get("ordinal") for item in sources] != list(range(4)):
            errors.append("SOURCE_ORDER_INVALID")
        if any(item.get("state") not in {state.value for state in SourceState} for item in sources):
            errors.append("SOURCE_STATE_INVALID")
    if value.get("schema") != SCHEMA_VERSION or value.get("status") != "DESCRIPTIVE_ONLY": errors.append("SCHEMA_INVALID")
    if value.get("journal_integrity") not in {item.value for item in Integrity}: errors.append("INTEGRITY_INVALID")
    if value.get("durability") not in {item.value for item in Durability}: errors.append("DURABILITY_INVALID")
    if value.get("attempt_state") not in {item.value for item in AttemptState}: errors.append("ATTEMPT_STATE_INVALID")
    if type(value.get("record_count")) is not int or not 0 <= value["record_count"] <= 256: errors.append("COUNT_INVALID")
    count, last_sequence = value.get("record_count"), value.get("last_sequence")
    generation = value.get("attempt_generation")
    if type(count) is int:
        if count == 0:
            if last_sequence is not None or generation is not None:
                errors.append("EMPTY_STATE_CONTRADICTION")
            if value.get("journal_integrity") == Integrity.ABSENT.value:
                if (value.get("durable_state_found") is not False
                        or value.get("durability") != Durability.NOT_FOUND.value):
                    errors.append("ABSENT_DURABILITY_CONTRADICTION")
            elif (value.get("durable_state_found") is not True
                  or value.get("durability") not in {Durability.CONFIRMED.value, Durability.UNKNOWN.value}):
                errors.append("CORRUPT_STATE_CONTRADICTION")
        elif (type(last_sequence) is not int or last_sequence != count - 1
              or type(generation) is not int or generation != 0
              or value.get("durable_state_found") is not True):
            errors.append("DURABLE_STATE_CONTRADICTION")
        elif value.get("durability") not in {Durability.CONFIRMED.value, Durability.UNKNOWN.value}:
            errors.append("DURABILITY_STATE_CONTRADICTION")
    for name in ("durable_state_found", "evidence_committed", "finalized", "reconciliation_required",
                 "execution_blocked", "new_human_review_required", "new_plan_required",
                 "manual_investigation_required"):
        if type(value.get(name)) is not bool: errors.append("BOOLEAN_INVALID")
    if any(value.get(name) is not False for name in ("automatic_resume_allowed", "automatic_retry_allowed",
        "raw_content_retained", "live_action_enabled", "ready_to_act", "authorized_to_act")):
        errors.append("AUTHORITY_PROHIBITED")
    if value.get("execution_blocked") is not True:
        errors.append("EXECUTION_MUST_REMAIN_BLOCKED")
    if value.get("retry_count") != 0 or value.get("predicate_policy") != PredicatePolicy.V2.value:
        errors.append("POLICY_INVALID")
    if value.get("source_set_id") != SOURCE_SET_ID or value.get("source_order_hash") != SOURCE_ORDER_HASH:
        errors.append("SOURCE_SET_INVALID")
    if value.get("policy_version") != POLICY_VERSION: errors.append("POLICY_VERSION_INVALID")
    source_unknown = type(sources) is list and any(isinstance(item, Mapping)
        and item.get("state") == SourceState.OUTCOME_UNKNOWN.value for item in sources)
    if (value.get("journal_integrity") in {Integrity.CORRUPT.value, Integrity.TORN_TAIL.value}
            and (value.get("manual_investigation_required") is not True
                 or value.get("reconciliation_required") is not True
                 or value.get("execution_blocked") is not True)):
        errors.append("CORRUPTION_BOUNDARY_INVALID")
    if value.get("durability") == Durability.UNKNOWN.value and (
            value.get("reconciliation_required") is not True
            or value.get("manual_investigation_required") is not True
            or value.get("execution_blocked") is not True):
        errors.append("DURABILITY_UNKNOWN_BOUNDARY_INVALID")
    if source_unknown and (value.get("reconciliation_required") is not True
            or value.get("automatic_retry_allowed") is not False
            or value.get("new_human_review_required") is not True
            or value.get("new_plan_required") is not True):
        errors.append("UNKNOWN_OUTCOME_BOUNDARY_INVALID")
    if value.get("finalized") is True and (value.get("evidence_committed") is not True
            or value.get("execution_blocked") is not True
            or value.get("attempt_state") != AttemptState.FINALIZED.value
            or type(sources) is not list
            or any(not isinstance(item, Mapping)
                   or item.get("state") != SourceState.RESULT_DURABLE.value for item in sources)):
        errors.append("FINALIZATION_CONTRADICTION")
    if value.get("evidence_committed") is True and (type(sources) is not list
            or any(not isinstance(item, Mapping)
                   or item.get("state") != SourceState.RESULT_DURABLE.value for item in sources)):
        errors.append("EVIDENCE_COMMIT_CONTRADICTION")
    if (value.get("attempt_state") != AttemptState.FINALIZED.value
            and value.get("reconciliation_required") is not True):
        errors.append("UNFINISHED_RECONCILIATION_REQUIRED")
    return tuple(sorted(set(errors)))


(_prepare_attempt, _record_attempt_intent, _record_source_intent,
 _record_request_boundary, _record_source_result, _commit_evidence,
 _finalize_attempt, inspect_journal, _record_permit_consumed) = _build_store(_PRODUCTION_ROOT)

prepare_attempt = _prepare_attempt
record_attempt_intent = _record_attempt_intent
record_source_intent = _record_source_intent
record_request_may_have_started = _record_request_boundary
record_source_result = _record_source_result
commit_evidence = _commit_evidence
finalize_attempt = _finalize_attempt

__all__ = ("AttemptState", "Durability", "Integrity", "JournalError", "SourceState", "commit_evidence",
    "finalize_attempt", "inspect_journal", "prepare_attempt", "record_attempt_intent",
    "record_request_may_have_started", "record_source_intent", "record_source_result",
    "validate_projection")
