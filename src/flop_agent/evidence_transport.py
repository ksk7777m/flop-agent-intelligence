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
import tempfile
from contextlib import contextmanager
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
    acquisition_id: str
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
            "acquisition_id": self.acquisition_id,
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

    def public_projection(self) -> Mapping[str, Any]:
        return MappingProxyType({"status": "DESCRIPTIVE_ONLY", "finding": self.finding.value,
                                 "coverage": self.coverage.value,
                                 "snapshot_hash": self.snapshot_hash})


@dataclass(frozen=True)
class ConflictResult:
    status: str
    comparison_kind: str
    target_seq: int | None
    left: Mapping[str, Any]
    right: Mapping[str, Any]
    left_finding: FindingStatus | None
    right_finding: FindingStatus | None
    finding_conflict: bool
    completeness_conflict: bool
    provenance_conflict: bool
    generation_conflict: bool
    content_conflict: bool

    def public_projection(self) -> Mapping[str, Any]:
        return MappingProxyType({
            "status": "DESCRIPTIVE_ONLY", "result": self.status,
            "comparison_kind": self.comparison_kind, "target_seq": self.target_seq,
            "left": dict(self.left), "right": dict(self.right),
            "left_finding": self.left_finding.value if self.left_finding else None,
            "right_finding": self.right_finding.value if self.right_finding else None,
            "finding_conflict": self.finding_conflict,
            "completeness_conflict": self.completeness_conflict,
            "provenance_conflict": self.provenance_conflict,
            "generation_conflict": self.generation_conflict,
            "content_conflict": self.content_conflict,
        })


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


class VerifiedRetentionEvidence(_CompletenessProof):
    __slots__ = ()


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


def _canonical_json(value: Mapping[str, Any], *, _dumps: Any = json.dumps) -> bytes:
    return _dumps(value, sort_keys=True, separators=(",", ":"),
                  ensure_ascii=True).encode("ascii")


def validate_evidence_projection(value: Mapping[str, Any]) -> tuple[str, ...]:
    """Return deterministic semantic errors; never grants evidence authority."""
    errors: list[str] = []
    completeness = value.get("completeness", value.get("coverage"))
    if value.get("transport_complete") is True and completeness != "COMPLETE_VERIFIED":
        errors.append("TRANSPORT_COMPLETE_REQUIRES_COMPLETE_VERIFIED")
    if value.get("transcript_complete") is True and completeness != "COMPLETE_VERIFIED":
        errors.append("TRANSCRIPT_COMPLETE_REQUIRES_COMPLETE_VERIFIED")
    if value.get("history_complete") is True and completeness != "COMPLETE_VERIFIED":
        errors.append("HISTORY_COMPLETE_REQUIRES_COMPLETE_VERIFIED")
    if value.get("gap_status") == "RETENTION_LOSS_CONFIRMED" and value.get("retention_status_known") is not True:
        errors.append("RETENTION_LOSS_REQUIRES_KNOWN_RETENTION")
    if value.get("finding") == "NOT_FOUND_CONFIRMED" and completeness != "COMPLETE_VERIFIED":
        errors.append("CONFIRMED_ABSENCE_REQUIRES_COMPLETE_VERIFIED")
    if value.get("finding") == "FOUND" and value.get("target_observed") is False:
        errors.append("FOUND_REQUIRES_EXACT_OBSERVATION")
    if (value.get("room_status") == "ROOM_DELETION_CONFIRMED"
            and value.get("discovery_completeness") in ("UNKNOWN", "PARTIAL")
            and value.get("independent_deletion_evidence") is not True):
        errors.append("DELETION_REQUIRES_INDEPENDENT_EVIDENCE")
    first, last = value.get("first_seq"), value.get("last_seq")
    if isinstance(first, int) and isinstance(last, int) and first > last:
        errors.append("SEQUENCE_RANGE_INVALID")
    return tuple(sorted(set(errors)))


def _open_directory_no_symlinks(path: Path, *, _os: Any = os,
                                _stat: Any = stat,
                                _error: Any = EvidenceTransportError) -> int:
    absolute = path.absolute()
    if not absolute.is_absolute():
        raise _error("ARCHIVE_ROOT_UNSAFE", "archive_root")
    # macOS exposes these two fixed system aliases; enter their canonical
    # /private locations before the no-follow descriptor walk.
    if absolute.parts[1:2] in (("var",), ("tmp",)):
        absolute = Path("/private").joinpath(*absolute.parts[1:])
    flags = _os.O_RDONLY | getattr(_os, "O_DIRECTORY", 0) | getattr(_os, "O_NOFOLLOW", 0)
    descriptor = _os.open("/", flags)
    try:
        for component in absolute.parts[1:]:
            if component in ("", ".", ".."):
                raise _error("ARCHIVE_ROOT_UNSAFE", "archive_root")
            child = _os.open(component, flags, dir_fd=descriptor)
            info = _os.fstat(child)
            if not _stat.S_ISDIR(info.st_mode):
                _os.close(child)
                raise _error("ARCHIVE_ROOT_UNSAFE", "archive_root")
            _os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        _os.close(descriptor)
        raise


def _bootstrap(reviewed_complete_acquisitions: frozenset[str] = frozenset(),
               reviewed_retention_acquisitions: frozenset[str] = frozenset()) -> tuple[Any, Any]:
    transport_type, source_type = Transport, AcquisitionSource
    completeness_type, gap_type, retention_type = Completeness, GapStatus, RetentionStatus
    snapshot_type, search_type, finding_type = EvidenceSnapshot, SearchResult, FindingStatus
    conflict_type, error_type = ConflictResult, EvidenceTransportError
    proof_type, retention_proof_type = _CompletenessProof, VerifiedRetentionEvidence
    room_re, safe_id_re, revision_re = _ROOM, _SAFE_ID, _REVISION
    parse_jsonl, sha256, canonical_json = _parse_jsonl, hashlib.sha256, _canonical_json
    json_loads, fullmatch = json.loads, re.fullmatch
    policy_version, schema_version, replace_snapshot = POLICY_VERSION, SCHEMA_VERSION, replace
    max_response_bytes = MAX_RESPONSE_BYTES
    mapping_proxy, os_module, stat_module, enum_type = MappingProxyType, os, stat, Enum
    token = object()
    registry: weakref.WeakKeyDictionary[_CompletenessProof, tuple[object, str, str]] = weakref.WeakKeyDictionary()
    acquired: dict[int, weakref.ReferenceType[EvidenceSnapshot]] = {}
    records: dict[int, tuple[frozenset[int], Mapping[int, str]]] = {}

    def with_identity(snapshot: EvidenceSnapshot) -> EvidenceSnapshot:
        fields = {name: (value.value if isinstance(value, enum_type) else value)
                  for name, value in snapshot.__dict__.items()
                  if name != "acquisition_id"}
        fields["schema_version"] = schema_version
        return replace_snapshot(snapshot,
            acquisition_id=sha256(canonical_json(fields)).hexdigest())

    def safe_projection(snapshot: EvidenceSnapshot) -> Mapping[str, Any]:
        return mapping_proxy({
            "schema": schema_version, "status": "DESCRIPTIVE_ONLY",
            "content_label": "UNTRUSTED_CONTENT", "acquisition_id": snapshot.acquisition_id,
            "transport": snapshot.transport.value, "room": snapshot.room,
            "page_limit": snapshot.page_limit, "returned_records": snapshot.returned_records,
            "truncated": snapshot.truncated, "completeness": snapshot.completeness.value,
            "generation": snapshot.generation, "first_seq": snapshot.first_seq,
            "last_seq": snapshot.last_seq, "requested_since": snapshot.requested_since,
            "requested_limit": snapshot.requested_limit, "snapshot_hash": snapshot.snapshot_hash,
            "acquisition_source": snapshot.acquisition_source.value,
            "acquired_at": snapshot.acquired_at, "source_revision": snapshot.source_revision,
            "policy_version": snapshot.policy_version, "gap_status": snapshot.gap_status.value,
            "retention_status": snapshot.retention_status.value,
            "transport_acquired": snapshot.transport_acquired,
            "content_parsed": snapshot.content_parsed,
            "content_verified": snapshot.content_verified,
            "transport_complete": snapshot.transport_complete,
            "transcript_complete": snapshot.transcript_complete,
            "history_complete": snapshot.history_complete,
            "retention_status_known": snapshot.retention_status_known})

    def remember(snapshot: EvidenceSnapshot) -> EvidenceSnapshot:
        identity = id(snapshot)
        def discard(_ref: Any, key: int = identity) -> None:
            acquired.pop(key, None); records.pop(key, None)
        acquired[identity] = weakref.ref(snapshot, discard)
        return snapshot

    def require_snapshot(snapshot: EvidenceSnapshot) -> None:
        reference = acquired.get(id(snapshot))
        if reference is None or reference() is not snapshot:
            raise PermissionError("caller-created evidence has no acquisition authority")

    class EvidenceTransportService:
        __slots__ = ("__archive_root", "__archive_fd", "__archive_identity")
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
            parsed, first, last, gap = parse_jsonl(raw)
            if requested_since is not None and first is not None and first > requested_since + 1:
                gap = gap_type.GAP_UNRESOLVED
            completeness = completeness_type.PARTIAL if truncated is True else completeness_type.UNKNOWN
            raw_hash = sha256(raw).hexdigest()
            snapshot = remember(with_identity(snapshot_type("", transport, room, page_limit,
                len(parsed), truncated, completeness, generation, first, last,
                requested_since, requested_limit, raw_hash, acquisition_source, acquired_at,
                source_revision, policy_version, gap, retention_type.RETENTION_FLOOR_UNKNOWN)))
            records[id(snapshot)] = (frozenset(item["seq"] for item in parsed),
                mapping_proxy({item["seq"]: sha256(canonical_json(dict(item))).hexdigest()
                               for item in parsed}))
            return snapshot

        def issue_complete_export_proof(self, snapshot: EvidenceSnapshot) -> _CompletenessProof:
            require_snapshot(snapshot)
            if (snapshot.transport is not transport_type.ROOM_EXPORT or snapshot.truncated is not False
                    or snapshot.acquisition_source is not source_type.DIRECT_REVIEWED_SOURCE
                    or snapshot.generation is None
                    or snapshot.gap_status is not gap_type.NO_GAP_OBSERVED
                    or snapshot.acquisition_id not in reviewed_complete_acquisitions):
                raise error_type("COMPLETENESS_NOT_PROVEN", "snapshot")
            proof = object.__new__(proof_type)
            registry[proof] = (token, snapshot.acquisition_id, "COMPLETE_EXPORT")
            return proof

        def apply_completeness(self, snapshot: EvidenceSnapshot, proof: _CompletenessProof) -> EvidenceSnapshot:
            require_snapshot(snapshot)
            try:
                record = registry.get(proof)
            except TypeError:
                record = None
            if record != (token, snapshot.acquisition_id, "COMPLETE_EXPORT"):
                raise PermissionError("cross-authority or forged completeness proof")
            elevated = remember(with_identity(replace_snapshot(snapshot, completeness=completeness_type.COMPLETE_VERIFIED,
                           transport_complete=True, transcript_complete=True,
                           history_complete=True, retention_status_known=True,
                           retention_status=retention_type.RETENTION_FLOOR_OBSERVED)))
            records[id(elevated)] = records[id(snapshot)]
            return elevated

        def issue_retention_evidence(self, snapshot: EvidenceSnapshot) -> VerifiedRetentionEvidence:
            require_snapshot(snapshot)
            if (snapshot.acquisition_id not in reviewed_retention_acquisitions
                    or snapshot.transport is not transport_type.ROOM_EXPORT
                    or snapshot.acquisition_source is not source_type.DIRECT_REVIEWED_SOURCE
                    or snapshot.generation is None or snapshot.truncated is not False):
                raise error_type("RETENTION_LOSS_NOT_PROVEN", "snapshot")
            proof = object.__new__(retention_proof_type)
            registry[proof] = (token, snapshot.acquisition_id, "REVIEWED_RETENTION_LOSS")
            return proof

        def confirm_retention_loss(self, snapshot: EvidenceSnapshot,
                                   evidence: VerifiedRetentionEvidence) -> EvidenceSnapshot:
            require_snapshot(snapshot)
            try:
                record = registry.get(evidence)
            except TypeError:
                record = None
            if record != (token, snapshot.acquisition_id, "REVIEWED_RETENTION_LOSS"):
                raise PermissionError("cross-authority, forged, or mismatched retention evidence")
            elevated = remember(with_identity(replace_snapshot(
                snapshot, gap_status=gap_type.RETENTION_LOSS_CONFIRMED,
                retention_status=retention_type.RETENTION_FLOOR_OBSERVED,
                retention_status_known=True)))
            records[id(elevated)] = records[id(snapshot)]
            return elevated

        def search(self, snapshot: EvidenceSnapshot, seq: int) -> SearchResult:
            require_snapshot(snapshot)
            observed, _content = records[id(snapshot)]
            if seq in observed:
                return search_type(finding_type.FOUND, snapshot.completeness, snapshot.snapshot_hash)
            if snapshot.gap_status in (gap_type.HISTORY_GAP, gap_type.GAP_UNRESOLVED):
                return search_type(finding_type.GAP_UNRESOLVED, snapshot.completeness, snapshot.snapshot_hash)
            finding = (finding_type.NOT_FOUND_CONFIRMED if snapshot.completeness is completeness_type.COMPLETE_VERIFIED
                       else finding_type.NOT_IN_VISIBLE_PAGE)
            return search_type(finding, snapshot.completeness, snapshot.snapshot_hash)

        def reconcile(self, left: EvidenceSnapshot, right: EvidenceSnapshot,
                      target_seq: int | None = None) -> ConflictResult:
            require_snapshot(left); require_snapshot(right)
            left_finding = self.search(left, target_seq).finding if target_seq is not None else None
            right_finding = self.search(right, target_seq).finding if target_seq is not None else None
            left_observed, left_content = records[id(left)]
            right_observed, right_content = records[id(right)]
            common = left_observed.intersection(right_observed)
            content_conflict = any(left_content[seq] != right_content[seq] for seq in common)
            generation_conflict = left.generation != right.generation
            provenance_conflict = left.room != right.room
            finding_conflict = left_finding != right_finding
            completeness_conflict = left.completeness != right.completeness
            conflict = (provenance_conflict or generation_conflict or content_conflict
                        or finding_conflict or completeness_conflict)
            def root(item: EvidenceSnapshot) -> Mapping[str, Any]:
                return mapping_proxy({"acquisition_id": item.acquisition_id,
                    "snapshot_hash": item.snapshot_hash, "source": item.acquisition_source.value,
                    "transport": item.transport.value, "generation": item.generation,
                    "first_seq": item.first_seq, "last_seq": item.last_seq})
            kind = ("PROVENANCE_CONFLICT" if provenance_conflict else
                    "GENERATION_CONFLICT" if generation_conflict else
                    "CONTENT_CONFLICT" if content_conflict else
                    "RECOVERY_EVIDENCE" if finding_conflict else
                    "COMPLETENESS_CONFLICT" if completeness_conflict else "CONSISTENT")
            return conflict_type("CONFLICTING_EVIDENCE" if conflict else "CONSISTENT_EVIDENCE",
                kind, target_seq, root(left), root(right), left_finding, right_finding,
                finding_conflict, completeness_conflict, provenance_conflict,
                generation_conflict, content_conflict)

        def archive(self, snapshot: EvidenceSnapshot, raw: bytes) -> Mapping[str, Any]:
            require_snapshot(snapshot)
            root = self.__archive_root
            root_fd = self.__archive_fd
            if root is None or root_fd is None:
                raise PermissionError("local archive is not configured")
            if sha256(raw).hexdigest() != snapshot.snapshot_hash:
                raise error_type("SNAPSHOT_HASH_MISMATCH", "raw", raw)
            try:
                current = os_module.stat(root, follow_symlinks=False)
                anchored = os_module.fstat(root_fd)
            except OSError:
                raise error_type("ARCHIVE_ROOT_UNSAFE", "archive_root") from None
            if (not stat_module.S_ISDIR(current.st_mode)
                    or (current.st_dev, current.st_ino) != self.__archive_identity
                    or (anchored.st_dev, anchored.st_ino) != self.__archive_identity
                    or stat_module.S_IMODE(anchored.st_mode) != 0o700
                    or anchored.st_uid != os_module.getuid()):
                raise error_type("ARCHIVE_ROOT_UNSAFE", "archive_root")
            blob_name = f"{snapshot.snapshot_hash}.blob"
            metadata_name = f"{snapshot.acquisition_id}.json"
            flags = os_module.O_WRONLY | os_module.O_CREAT | os_module.O_EXCL
            if hasattr(os_module, "O_NOFOLLOW"): flags |= os_module.O_NOFOLLOW
            blob_status = "ARCHIVED"
            try:
                fd = os_module.open(blob_name, flags, 0o600, dir_fd=root_fd)
            except FileExistsError:
                try:
                    check_flags = os_module.O_RDONLY
                    if hasattr(os_module, "O_NOFOLLOW"): check_flags |= os_module.O_NOFOLLOW
                    existing_fd = os_module.open(blob_name, check_flags, dir_fd=root_fd)
                    existing = os_module.fstat(existing_fd)
                    chunks, total = [], 0
                    while True:
                        chunk = os_module.read(existing_fd, min(65536, max_response_bytes + 1 - total))
                        if not chunk: break
                        chunks.append(chunk); total += len(chunk)
                        if total > max_response_bytes: break
                    os_module.close(existing_fd)
                except OSError:
                    raise error_type("ARCHIVE_EXISTING_UNSAFE", "archive") from None
                if (not stat_module.S_ISREG(existing.st_mode)
                        or stat_module.S_IMODE(existing.st_mode) != 0o600
                        or total > max_response_bytes
                        or sha256(b"".join(chunks)).hexdigest() != snapshot.snapshot_hash):
                    raise error_type("ARCHIVE_EXISTING_UNSAFE", "archive")
                blob_status = "DEDUPLICATED"
            else:
                try:
                    view = memoryview(raw)
                    while view:
                        written = os_module.write(fd, view)
                        if written <= 0: raise error_type("ARCHIVE_WRITE_FAILED", "archive")
                        view = view[written:]
                    os_module.fsync(fd)
                    if stat_module.S_IMODE(os_module.fstat(fd).st_mode) != 0o600:
                        raise error_type("ARCHIVE_MODE_INVALID", "archive")
                finally:
                    os_module.close(fd)
            metadata = canonical_json(dict(safe_projection(snapshot)))
            try:
                metadata_fd = os_module.open(metadata_name, flags, 0o600, dir_fd=root_fd)
            except FileExistsError:
                read_flags = os_module.O_RDONLY | getattr(os_module, "O_NOFOLLOW", 0)
                try:
                    existing_fd = os_module.open(metadata_name, read_flags, dir_fd=root_fd)
                    existing_info = os_module.fstat(existing_fd)
                    existing_metadata = os_module.read(existing_fd, max_response_bytes + 1)
                    os_module.close(existing_fd)
                except OSError:
                    raise error_type("ARCHIVE_METADATA_UNSAFE", "metadata") from None
                if (not stat_module.S_ISREG(existing_info.st_mode)
                        or stat_module.S_IMODE(existing_info.st_mode) != 0o600
                        or existing_metadata != metadata):
                    raise error_type("ARCHIVE_METADATA_UNSAFE", "metadata")
                return mapping_proxy({"status": "DEDUPLICATED", "blob_status": blob_status,
                                      "snapshot_hash": snapshot.snapshot_hash,
                                      "acquisition_id": snapshot.acquisition_id})
            try:
                view = memoryview(metadata)
                while view:
                    written = os_module.write(metadata_fd, view)
                    if written <= 0: raise error_type("ARCHIVE_WRITE_FAILED", "metadata")
                    view = view[written:]
                os_module.fsync(metadata_fd)
            finally:
                os_module.close(metadata_fd)
            os_module.fsync(root_fd)
            return mapping_proxy({"status": "ARCHIVED", "blob_status": blob_status,
                                  "snapshot_hash": snapshot.snapshot_hash,
                                  "acquisition_id": snapshot.acquisition_id})

        def archived_metadata(self, acquisition_id: str) -> Mapping[str, Any]:
            root_fd = self.__archive_fd
            if root_fd is None or not isinstance(acquisition_id, str) or fullmatch(r"[0-9a-f]{64}", acquisition_id) is None:
                raise error_type("ARCHIVE_READ_INVALID", "acquisition_id")
            flags = os_module.O_RDONLY
            if hasattr(os_module, "O_NOFOLLOW"): flags |= os_module.O_NOFOLLOW
            try:
                fd = os_module.open(f"{acquisition_id}.json", flags, dir_fd=root_fd)
                info = os_module.fstat(fd)
                raw_metadata = os_module.read(fd, max_response_bytes + 1)
            except OSError:
                raise error_type("ARCHIVE_READ_FAILED", "metadata") from None
            finally:
                if "fd" in locals(): os_module.close(fd)
            if (not stat_module.S_ISREG(info.st_mode) or stat_module.S_IMODE(info.st_mode) != 0o600
                    or len(raw_metadata) > max_response_bytes):
                raise error_type("ARCHIVE_METADATA_UNSAFE", "metadata")
            try:
                value = json_loads(raw_metadata)
            except (ValueError, UnicodeError):
                raise error_type("ARCHIVE_METADATA_INVALID", "metadata") from None
            return mapping_proxy(value)

    production = object.__new__(EvidenceTransportService)
    production._EvidenceTransportService__archive_root = None
    production._EvidenceTransportService__archive_fd = None
    production._EvidenceTransportService__archive_identity = None
    def build_for_test(archive_root: Path | None = None, *,
                       reviewed_complete_acquisitions: frozenset[str] = frozenset(),
                       reviewed_retention_acquisitions: frozenset[str] = frozenset()) -> Any:
        # Each fixture service gets a distinct process-local authority registry.
        service, _unused_builder = _bootstrap(reviewed_complete_acquisitions, reviewed_retention_acquisitions)
        service._EvidenceTransportService__archive_root = None
        service._EvidenceTransportService__archive_fd = None
        service._EvidenceTransportService__archive_identity = None
        if archive_root is not None:
            archive_root.mkdir(mode=0o700, parents=True, exist_ok=True)
            if archive_root.is_symlink():
                raise EvidenceTransportError("ARCHIVE_ROOT_UNSAFE", "archive_root")
            archive_root = archive_root.absolute()
            try:
                root_fd = _open_directory_no_symlinks(archive_root)
            except OSError:
                raise EvidenceTransportError("ARCHIVE_ROOT_UNSAFE", "archive_root") from None
            root_info = os.fstat(root_fd)
            if (not stat.S_ISDIR(root_info.st_mode) or stat.S_IMODE(root_info.st_mode) != 0o700
                    or root_info.st_uid != os.getuid()):
                os.close(root_fd)
                raise EvidenceTransportError("ARCHIVE_ROOT_UNSAFE", "archive_root")
            service._EvidenceTransportService__archive_root = archive_root
            service._EvidenceTransportService__archive_fd = root_fd
            service._EvidenceTransportService__archive_identity = (root_info.st_dev, root_info.st_ino)
        return service
    return production, build_for_test


production_evidence_transport, _build_production_equivalent_evidence_service_for_test = _bootstrap()


@contextmanager
def _isolated_production_equivalent_boundary():
    """No-argument, offline boundary for real privileged-path security tests."""
    raw = b'{"seq":1,"text":"fixture"}\n{"seq":2,"text":"fixture"}'
    revision = "a" * 40
    probe = _build_production_equivalent_evidence_service_for_test()
    candidate = probe.acquire(transport=Transport.ROOM_EXPORT, room="lobby", raw=raw,
        acquisition_source=AcquisitionSource.DIRECT_REVIEWED_SOURCE, acquired_at=1,
        source_revision=revision, generation="g1", page_limit=20,
        requested_since=0, requested_limit=20, truncated=False)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory) / "authority" / "archive"
        root.mkdir(parents=True, mode=0o700)
        service = _build_production_equivalent_evidence_service_for_test(
            root, reviewed_complete_acquisitions=frozenset({candidate.acquisition_id}),
            reviewed_retention_acquisitions=frozenset({candidate.acquisition_id}))
        snapshot = service.acquire(transport=Transport.ROOM_EXPORT, room="lobby", raw=raw,
            acquisition_source=AcquisitionSource.DIRECT_REVIEWED_SOURCE, acquired_at=1,
            source_revision=revision, generation="g1", page_limit=20,
            requested_since=0, requested_limit=20, truncated=False)
        try:
            yield service, root, snapshot, raw
        finally:
            descriptor = service._EvidenceTransportService__archive_fd
            service._EvidenceTransportService__archive_fd = None
            if descriptor is not None:
                os.close(descriptor)


def assess_room_presence(room: str, visible_rooms: tuple[str, ...], discovery: DiscoveryCompleteness) -> RoomStatus:
    if room in visible_rooms:
        return RoomStatus.ROOM_OBSERVED
    if discovery is DiscoveryCompleteness.VERIFIED:
        return RoomStatus.ROOM_STATUS_UNKNOWN
    return RoomStatus.ROOM_NOT_IN_DISCOVERY_SNAPSHOT
