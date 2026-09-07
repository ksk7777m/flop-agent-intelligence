"""Offline, fail-closed evidence transport and retention semantics.

Remote content is never fetched or acted upon here.  Public projections are
descriptive; completeness authority is an opaque, process-local capability.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import weakref
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

POLICY_VERSION = "evidence-transport-retention-policy-v1"
SCHEMA_VERSION = "flop-evidence-transport-v1"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_PARSED_RECORDS = 100_000
MAX_ESTIMATED_TOKENS = 600_000
_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_ROOM = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_SECRET_FIELD = re.compile(r"(?:secret|private.?key|seed|mnemonic|wallet)", re.IGNORECASE)


class EvidenceTransportError(ValueError):
    def __init__(self, code: str, field: str, value: Any = None):
        super().__init__(f"{code}: {field}")
        self.code = code
        self.metadata = MappingProxyType({"field": field, "type": type(value).__name__,
                                          "length": _safe_len(value)})


def _safe_len(value: Any) -> int | None:
    try:
        return len(value)
    except (TypeError, OverflowError):
        return None


class Transport(str, Enum):
    MCP_PAGE = "MCP_PAGE"
    ROOM_EXPORT = "ROOM_EXPORT"
    ROOM_DIRECT_READ = "ROOM_DIRECT_READ"
    DISCOVERY_SNAPSHOT = "DISCOVERY_SNAPSHOT"
    LOCAL_ARCHIVE = "LOCAL_ARCHIVE"
    FUTURE_EVENT_FEED = "FUTURE_EVENT_FEED"


class Completeness(str, Enum):
    COMPLETE_VERIFIED = "COMPLETE_VERIFIED"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"
    CONFLICTING = "CONFLICTING"


class GapStatus(str, Enum):
    NO_GAP_OBSERVED = "NO_GAP_OBSERVED"
    GAP_UNRESOLVED = "GAP_UNRESOLVED"
    HISTORY_GAP = "HISTORY_GAP"
    RETENTION_LOSS_CONFIRMED = "RETENTION_LOSS_CONFIRMED"


class RetentionStatus(str, Enum):
    RETENTION_FLOOR_UNKNOWN = "RETENTION_FLOOR_UNKNOWN"
    RETENTION_FLOOR_OBSERVED = "RETENTION_FLOOR_OBSERVED"
    RETENTION_CHANGED = "RETENTION_CHANGED"
    RETENTION_CONFLICTING = "RETENTION_CONFLICTING"


class DiscoveryCompleteness(str, Enum):
    VERIFIED = "VERIFIED"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


class FindingStatus(str, Enum):
    FOUND = "FOUND"
    NOT_IN_VISIBLE_PAGE = "NOT_IN_VISIBLE_PAGE"
    GAP_UNRESOLVED = "GAP_UNRESOLVED"
    HISTORY_GAP = "HISTORY_GAP"
    RETENTION_LOSS_CONFIRMED = "RETENTION_LOSS_CONFIRMED"
    NOT_FOUND_CONFIRMED = "NOT_FOUND_CONFIRMED"


class RoomStatus(str, Enum):
    ROOM_OBSERVED = "ROOM_OBSERVED"
    ROOM_NOT_IN_DISCOVERY_SNAPSHOT = "ROOM_NOT_IN_DISCOVERY_SNAPSHOT"
    ROOM_STATUS_UNKNOWN = "ROOM_STATUS_UNKNOWN"
    ROOM_DELETION_CONFIRMED = "ROOM_DELETION_CONFIRMED"


class AcquisitionSource(str, Enum):
    DIRECT_REVIEWED_SOURCE = "DIRECT_REVIEWED_SOURCE"
    THIRD_PARTY_MIRROR = "THIRD_PARTY_MIRROR"
    LOCAL_ARCHIVE = "LOCAL_ARCHIVE"


@dataclass(frozen=True)
class EvidenceSnapshot:
    transport: Transport
    room: str
    page_limit: int | None
    returned_records: int
    truncated: bool | None
    completeness: Completeness
    generation: str | None
    first_seq: int | None
    last_seq: int | None
    requested_since: int | None
    requested_limit: int | None
    snapshot_hash: str
    acquisition_source: AcquisitionSource
    acquired_at: int
    source_revision: str
    policy_version: str
    gap_status: GapStatus
    retention_status: RetentionStatus
    transport_acquired: bool = True
    content_parsed: bool = True
    content_verified: bool = False
    transport_complete: bool = False
    transcript_complete: bool = False
    history_complete: bool = False
    retention_status_known: bool = False

    def public_projection(self) -> Mapping[str, Any]:
        return MappingProxyType({
            "schema": SCHEMA_VERSION, "status": "DESCRIPTIVE_ONLY",
            "content_label": "UNTRUSTED_CONTENT", "transport": self.transport.value,
            "room": self.room, "page_limit": self.page_limit,
            "returned_records": self.returned_records, "truncated": self.truncated,
            "completeness": self.completeness.value, "generation": self.generation,
            "first_seq": self.first_seq, "last_seq": self.last_seq,
            "requested_since": self.requested_since, "requested_limit": self.requested_limit,
            "snapshot_hash": self.snapshot_hash,
            "acquisition_source": self.acquisition_source.value,
            "acquired_at": self.acquired_at, "source_revision": self.source_revision,
            "policy_version": self.policy_version, "gap_status": self.gap_status.value,
            "retention_status": self.retention_status.value,
            "transport_acquired": self.transport_acquired, "content_parsed": self.content_parsed,
            "content_verified": self.content_verified,
            "transport_complete": self.transport_complete,
            "transcript_complete": self.transcript_complete,
            "history_complete": self.history_complete,
            "retention_status_known": self.retention_status_known,
        })


@dataclass(frozen=True)
class SearchResult:
    finding: FindingStatus
    coverage: Completeness
    snapshot_hash: str


class _CompletenessProof:
    __slots__ = ("__weakref__",)
    def __new__(cls, *_args: Any, **_kwargs: Any) -> "_CompletenessProof":
        raise PermissionError("completeness proofs are issued only by a sealed authority")
    def __reduce__(self) -> Any:
        raise TypeError("completeness proofs cannot be serialized")
    def __copy__(self) -> Any:
        raise TypeError("completeness proofs cannot be copied")
    def __deepcopy__(self, _memo: Any) -> Any:
        raise TypeError("completeness proofs cannot be copied")


def _parse_jsonl(raw: bytes, *, _max_bytes: int = MAX_RESPONSE_BYTES,
                 _max_tokens: int = MAX_ESTIMATED_TOKENS,
                 _max_records: int = MAX_PARSED_RECORDS,
                 _loads: Any = json.loads, _json_error: Any = json.JSONDecodeError,
                 _secret_field: Any = _SECRET_FIELD,
                 _error: Any = EvidenceTransportError,
                 _mapping: Any = MappingProxyType,
                 _gap: Any = GapStatus) -> tuple[tuple[Mapping[str, Any], ...], int | None, int | None, GapStatus]:
    if not isinstance(raw, bytes) or len(raw) > _max_bytes:
        raise _error("RESPONSE_SIZE_INVALID", "raw", raw)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise _error("RESPONSE_UTF8_INVALID", "raw", raw) from None
    if (len(text) + 3) // 4 > _max_tokens:
        raise _error("TOKEN_BUDGET_EXCEEDED", "raw", raw)
    lines = text.splitlines()
    if len(lines) > _max_records:
        raise _error("RECORD_BUDGET_EXCEEDED", "raw", raw)
    records, seqs = [], []
    for line in lines:
        try:
            item = _loads(line)
        except (_json_error, UnicodeError):
            raise _error("RESPONSE_SYNTAX_INVALID", "raw", raw) from None
        if not isinstance(item, dict) or isinstance(item.get("seq"), bool) or not isinstance(item.get("seq"), int) or item["seq"] < 0:
            raise _error("RECORD_INVALID", "raw", raw)
        if any(_secret_field.search(str(key)) for key in item):
            raise _error("SENSITIVE_FIELD_REJECTED", "raw", raw)
        records.append(_mapping(dict(item))); seqs.append(item["seq"])
    internal_gap = any(b != a + 1 for a, b in zip(seqs, seqs[1:]))
    return tuple(records), (seqs[0] if seqs else None), (seqs[-1] if seqs else None), (_gap.HISTORY_GAP if internal_gap else _gap.NO_GAP_OBSERVED)


def _bootstrap(reviewed_complete_exports: frozenset[tuple[str, str, int, int]] = frozenset(),
               reviewed_retention_losses: frozenset[str] = frozenset()) -> tuple[Any, Any]:
    transport_type, source_type = Transport, AcquisitionSource
    completeness_type, gap_type, retention_type = Completeness, GapStatus, RetentionStatus
    snapshot_type, search_type, finding_type = EvidenceSnapshot, SearchResult, FindingStatus
    error_type, proof_type = EvidenceTransportError, _CompletenessProof
    room_re, safe_id_re, revision_re = _ROOM, _SAFE_ID, _REVISION
    parse_jsonl, sha256 = _parse_jsonl, hashlib.sha256
    policy_version, replace_snapshot = POLICY_VERSION, replace
    max_response_bytes = MAX_RESPONSE_BYTES
    mapping_proxy, os_module, stat_module = MappingProxyType, os, stat
    token = object()
    registry: weakref.WeakKeyDictionary[_CompletenessProof, tuple[object, str]] = weakref.WeakKeyDictionary()
    acquired: dict[int, weakref.ReferenceType[EvidenceSnapshot]] = {}

    def remember(snapshot: EvidenceSnapshot) -> EvidenceSnapshot:
        identity = id(snapshot)
        acquired[identity] = weakref.ref(snapshot, lambda _ref, key=identity: acquired.pop(key, None))
        return snapshot

    def require_snapshot(snapshot: EvidenceSnapshot) -> None:
        reference = acquired.get(id(snapshot))
        if reference is None or reference() is not snapshot:
            raise PermissionError("caller-created evidence has no acquisition authority")

    class EvidenceTransportService:
        __slots__ = ("__archive_root",)
        def __new__(cls, *_args: Any, **_kwargs: Any) -> Any:
            raise PermissionError("use the sealed evidence transport service")

        def acquire(self, *, transport: Transport, room: str, raw: bytes,
                    acquisition_source: AcquisitionSource, acquired_at: int,
                    source_revision: str, generation: str | None = None,
                    page_limit: int | None = None, requested_since: int | None = None,
                    requested_limit: int | None = None, truncated: bool | None = None) -> EvidenceSnapshot:
            if not isinstance(transport, transport_type) or not isinstance(acquisition_source, source_type):
                raise error_type("ENUM_INVALID", "transport/source")
            if not isinstance(room, str) or room_re.fullmatch(room) is None:
                raise error_type("ROOM_INVALID", "room", room)
            if not isinstance(source_revision, str) or revision_re.fullmatch(source_revision) is None:
                raise error_type("REVISION_INVALID", "source_revision", source_revision)
            if generation is not None and (not isinstance(generation, str) or safe_id_re.fullmatch(generation) is None):
                raise error_type("GENERATION_INVALID", "generation", generation)
            for field, value in (("acquired_at", acquired_at), ("page_limit", page_limit),
                                 ("requested_since", requested_since), ("requested_limit", requested_limit)):
                if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                    raise error_type("BOUND_INVALID", field, value)
            records, first, last, gap = parse_jsonl(raw)
            if requested_since is not None and first is not None and first > requested_since + 1:
                gap = gap_type.GAP_UNRESOLVED
            completeness = completeness_type.PARTIAL if truncated is True else completeness_type.UNKNOWN
            return remember(snapshot_type(transport, room, page_limit, len(records), truncated,
                completeness, generation, first, last, requested_since, requested_limit,
                sha256(raw).hexdigest(), acquisition_source, acquired_at,
                source_revision, policy_version, gap, retention_type.RETENTION_FLOOR_UNKNOWN))

        def issue_complete_export_proof(self, snapshot: EvidenceSnapshot) -> _CompletenessProof:
            require_snapshot(snapshot)
            if (snapshot.transport is not transport_type.ROOM_EXPORT or snapshot.truncated is not False
                    or snapshot.acquisition_source is not source_type.DIRECT_REVIEWED_SOURCE
                    or snapshot.generation is None
                    or snapshot.gap_status is not gap_type.NO_GAP_OBSERVED
                    or (snapshot.snapshot_hash, snapshot.generation,
                        snapshot.first_seq, snapshot.last_seq) not in reviewed_complete_exports):
                raise error_type("COMPLETENESS_NOT_PROVEN", "snapshot")
            proof = object.__new__(proof_type)
            registry[proof] = (token, snapshot.snapshot_hash)
            return proof

        def apply_completeness(self, snapshot: EvidenceSnapshot, proof: _CompletenessProof) -> EvidenceSnapshot:
            require_snapshot(snapshot)
            try:
                record = registry.get(proof)
            except TypeError:
                record = None
            if record != (token, snapshot.snapshot_hash):
                raise PermissionError("cross-authority or forged completeness proof")
            return remember(replace_snapshot(snapshot, completeness=completeness_type.COMPLETE_VERIFIED,
                           transport_complete=True, transcript_complete=True,
                           history_complete=True, retention_status_known=True,
                           retention_status=retention_type.RETENTION_FLOOR_OBSERVED))

        def confirm_retention_loss(self, snapshot: EvidenceSnapshot) -> EvidenceSnapshot:
            require_snapshot(snapshot)
            if snapshot.snapshot_hash not in reviewed_retention_losses:
                raise error_type("RETENTION_LOSS_NOT_PROVEN", "snapshot")
            return remember(replace_snapshot(
                snapshot, gap_status=gap_type.RETENTION_LOSS_CONFIRMED,
                retention_status=retention_type.RETENTION_FLOOR_OBSERVED,
                retention_status_known=True))

        def search(self, snapshot: EvidenceSnapshot, seq: int) -> SearchResult:
            require_snapshot(snapshot)
            if snapshot.first_seq is not None and snapshot.last_seq is not None and snapshot.first_seq <= seq <= snapshot.last_seq:
                return search_type(finding_type.FOUND, snapshot.completeness, snapshot.snapshot_hash)
            finding = (finding_type.NOT_FOUND_CONFIRMED if snapshot.completeness is completeness_type.COMPLETE_VERIFIED
                       else finding_type.NOT_IN_VISIBLE_PAGE)
            return search_type(finding, snapshot.completeness, snapshot.snapshot_hash)

        def compare(self, left: EvidenceSnapshot, right: EvidenceSnapshot) -> Completeness:
            require_snapshot(left); require_snapshot(right)
            if left.room != right.room or left.generation != right.generation:
                return completeness_type.CONFLICTING
            if left.completeness is completeness_type.COMPLETE_VERIFIED and right.completeness is completeness_type.COMPLETE_VERIFIED and (left.first_seq, left.last_seq) != (right.first_seq, right.last_seq):
                return completeness_type.CONFLICTING
            if completeness_type.PARTIAL in (left.completeness, right.completeness):
                return completeness_type.PARTIAL
            if completeness_type.UNKNOWN in (left.completeness, right.completeness):
                return completeness_type.UNKNOWN
            return completeness_type.COMPLETE_VERIFIED

        def archive(self, snapshot: EvidenceSnapshot, raw: bytes) -> Mapping[str, Any]:
            require_snapshot(snapshot)
            root = self.__archive_root
            if root is None:
                raise PermissionError("local archive is not configured")
            if sha256(raw).hexdigest() != snapshot.snapshot_hash:
                raise error_type("SNAPSHOT_HASH_MISMATCH", "raw", raw)
            if root.is_symlink() or not root.is_dir():
                raise error_type("ARCHIVE_ROOT_UNSAFE", "archive_root")
            name = f"{snapshot.snapshot_hash}-{snapshot.acquired_at}.snapshot"
            path = root / name
            flags = os_module.O_WRONLY | os_module.O_CREAT | os_module.O_EXCL
            if hasattr(os_module, "O_NOFOLLOW"): flags |= os_module.O_NOFOLLOW
            try:
                fd = os_module.open(path, flags, 0o600)
            except FileExistsError:
                try:
                    existing = path.lstat()
                    existing_raw = path.read_bytes()
                except OSError:
                    raise error_type("ARCHIVE_EXISTING_UNSAFE", "archive") from None
                if (not stat_module.S_ISREG(existing.st_mode)
                        or stat_module.S_IMODE(existing.st_mode) != 0o600
                        or len(existing_raw) > max_response_bytes
                        or sha256(existing_raw).hexdigest() != snapshot.snapshot_hash):
                    raise error_type("ARCHIVE_EXISTING_UNSAFE", "archive")
                return mapping_proxy({"status": "DEDUPLICATED", "snapshot_hash": snapshot.snapshot_hash})
            try:
                view = memoryview(raw)
                while view:
                    written = os_module.write(fd, view)
                    if written <= 0:
                        raise error_type("ARCHIVE_WRITE_FAILED", "archive")
                    view = view[written:]
                os_module.fsync(fd)
            finally:
                os_module.close(fd)
            if stat_module.S_IMODE(path.stat().st_mode) != 0o600:
                raise error_type("ARCHIVE_MODE_INVALID", "archive")
            return mapping_proxy({"status": "ARCHIVED", "snapshot_hash": snapshot.snapshot_hash})

    production = object.__new__(EvidenceTransportService); production._EvidenceTransportService__archive_root = None
    def build_for_test(archive_root: Path | None = None, *,
                       reviewed_complete_exports: frozenset[tuple[str, str, int, int]] = frozenset(),
                       reviewed_retention_losses: frozenset[str] = frozenset()) -> Any:
        # Each fixture service gets a distinct process-local authority registry.
        service, _unused_builder = _bootstrap(reviewed_complete_exports, reviewed_retention_losses)
        if archive_root is not None:
            archive_root.mkdir(mode=0o700, parents=True, exist_ok=True)
            if archive_root.is_symlink():
                raise EvidenceTransportError("ARCHIVE_ROOT_UNSAFE", "archive_root")
            archive_root = archive_root.resolve(strict=True)
        service._EvidenceTransportService__archive_root = archive_root
        return service
    return production, build_for_test


production_evidence_transport, _build_evidence_transport_service_for_test = _bootstrap()


def assess_room_presence(room: str, visible_rooms: tuple[str, ...], discovery: DiscoveryCompleteness) -> RoomStatus:
    if room in visible_rooms:
        return RoomStatus.ROOM_OBSERVED
    if discovery is DiscoveryCompleteness.VERIFIED:
        return RoomStatus.ROOM_STATUS_UNKNOWN
    return RoomStatus.ROOM_NOT_IN_DISCOVERY_SNAPSHOT
