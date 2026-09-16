"""One-shot, evidence-preserving migration of the Sonnet checkpoint lineage.

The production entry point lives in ``scripts/migrate_sonnet_checkpoint.py``.
Importing this module never opens production storage and never starts network
or observer capabilities.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping

from . import sonnet_receipt_observer as observer
from . import sonnet_registration as registration


ARCHIVE_BASENAME = "sonnet-registration-checkpoint-migration-archive"
ARCHIVE_CHECKPOINT = "legacy.checkpoint"
ARCHIVE_PROGRESS = "legacy.progress"
ARCHIVE_MANIFEST = "migration.archive.json"
TRANSACTION_MARKER = ".checkpoint-migration.transaction"
STAGED_CHECKPOINT = ".tmp-checkpoint-migration-v2"
STAGED_PROGRESS = ".tmp-progress-migration-v2"
MAX_ARTIFACT_BYTES = observer.MAX_PAGE_BYTES

LEGACY_CHECKPOINT_SCHEMA = "sonnet-registration-receipt-checkpoint.v1"
LEGACY_PROGRESS_SCHEMA = "sonnet-registration-receipt-progress.v1"
CHECKPOINT_V2_SCHEMA = "sonnet-registration-receipt-checkpoint.v2"
PROGRESS_V2_SCHEMA = "sonnet-registration-receipt-progress.v2"
MARKER_SCHEMA = "sonnet-registration-checkpoint-migration.v1"
ARCHIVE_SCHEMA = "sonnet-registration-checkpoint-archive.v1"

_LEGACY_FIELDS = frozenset({
    "schema", "request_reference_sha256", "contest_id", "room",
    "generation", "cursor", "observation_started_at",
})
_ARCHIVE_NAMES = frozenset({
    ARCHIVE_CHECKPOINT, ARCHIVE_PROGRESS, ARCHIVE_MANIFEST,
})


class MigrationError(RuntimeError):
    """A fixed migration category without paths or evidence values."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return "<Sonnet checkpoint migration error>"


class _MigrationPlan:
    """Opaque, single-use correlation of one read-only legacy inventory."""

    __slots__ = (
        "_root", "_checkpoint_digest", "_progress_digest", "_status",
        "_used",
    )

    def __init__(
        self, root: Path, *, checkpoint_digest: str | None,
        progress_digest: str | None, status: str,
    ) -> None:
        self._root = root
        self._checkpoint_digest = checkpoint_digest
        self._progress_digest = progress_digest
        self._status = status
        self._used = False

    @property
    def status(self) -> str:
        return self._status

    def _consume(self) -> tuple[Path, str | None, str | None, str]:
        if self._used:
            raise MigrationError("MIGRATION_PLAN_CONSUMED")
        self._used = True
        return (
            self._root, self._checkpoint_digest, self._progress_digest,
            self._status,
        )

    def __repr__(self) -> str:
        return "<opaque Sonnet checkpoint migration plan>"

    def __copy__(self) -> Any:
        raise TypeError("migration plan is not copyable")

    def __deepcopy__(self, _memo: Any) -> Any:
        raise TypeError("migration plan is not copyable")

    def __reduce_ex__(self, _protocol: int) -> Any:
        raise TypeError("migration plan is not serializable")


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value), sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    ).encode("utf-8")


def _request_reference() -> str:
    return hashlib.sha256(registration.REQUEST_ID.encode("utf-8")).hexdigest()


def _validate_legacy(
    value: Mapping[str, Any], *, schema: str,
) -> dict[str, Any]:
    if (set(value) != _LEGACY_FIELDS or value.get("schema") != schema
            or value.get("request_reference_sha256") != _request_reference()
            or value.get("contest_id") != observer.CONTEST_ID
            or value.get("room") != observer.ROOM
            or type(value.get("generation")) is not int
            or not 1 <= value["generation"] <= observer.SAFE_INTEGER_MAX
            or type(value.get("cursor")) is not int
            or not 0 <= value["cursor"] <= observer.SAFE_INTEGER_MAX
            or type(value.get("observation_started_at")) is not str):
        raise MigrationError("LEGACY_MIGRATION_BINDING_INVALID")
    try:
        parsed = datetime.fromisoformat(
            value["observation_started_at"].replace("Z", "+00:00"))
        observer._utc(parsed)
    except (ValueError, observer.ReceiptObserverError):
        raise MigrationError("LEGACY_MIGRATION_BINDING_INVALID") from None
    return dict(value)


def _read_legacy_inventory(
    store: observer.PrivateReceiptStore,
) -> tuple[str, bytes, dict[str, Any], bytes | None, dict[str, Any] | None]:
    root_fd = store._check_root()
    try:
        names = os.listdir(root_fd)
    except OSError:
        raise MigrationError("LEGACY_MIGRATION_STORAGE_INVALID") from None
    checkpoint_names = []
    progress_present = False
    for name in names:
        if name == observer.SESSION_LOCK_BASENAME:
            continue
        if name == observer.CURSOR_PROGRESS_BASENAME:
            progress_present = True
            continue
        if name.endswith(".checkpoint"):
            checkpoint_names.append(name)
            continue
        raise MigrationError("LEGACY_MIGRATION_UNEXPECTED_ARTIFACT")
    if len(checkpoint_names) != 1:
        raise MigrationError("LEGACY_MIGRATION_INVENTORY_INVALID")
    checkpoint_name = checkpoint_names[0]
    suffix_digest = checkpoint_name.removesuffix(".checkpoint")
    if (len(suffix_digest) != 64
            or any(item not in "0123456789abcdef" for item in suffix_digest)):
        raise MigrationError("LEGACY_MIGRATION_INVENTORY_INVALID")
    try:
        store._validate_artifact_file(checkpoint_name, MAX_ARTIFACT_BYTES)
        checkpoint_raw = store._read(checkpoint_name, MAX_ARTIFACT_BYTES)
        if hashlib.sha256(checkpoint_raw).hexdigest() != suffix_digest:
            raise MigrationError("LEGACY_MIGRATION_DIGEST_INVALID")
        checkpoint = _validate_legacy(
            observer._json_object(
                checkpoint_raw, code="LEGACY_MIGRATION_PARSE_INVALID"),
            schema=LEGACY_CHECKPOINT_SCHEMA)
        progress_raw = None
        progress = None
        if progress_present:
            store._validate_artifact_file(
                observer.CURSOR_PROGRESS_BASENAME, MAX_ARTIFACT_BYTES)
            progress_raw = store._read(
                observer.CURSOR_PROGRESS_BASENAME, MAX_ARTIFACT_BYTES)
            progress = _validate_legacy(
                observer._json_object(
                    progress_raw, code="LEGACY_MIGRATION_PARSE_INVALID"),
                schema=LEGACY_PROGRESS_SCHEMA)
            if (progress["request_reference_sha256"]
                    != checkpoint["request_reference_sha256"]
                    or progress["contest_id"] != checkpoint["contest_id"]
                    or progress["room"] != checkpoint["room"]
                    or progress["generation"] != checkpoint["generation"]
                    or progress["observation_started_at"]
                    != checkpoint["observation_started_at"]
                    or progress["cursor"] < checkpoint["cursor"]):
                raise MigrationError("LEGACY_MIGRATION_PROGRESS_INVALID")
        return checkpoint_name, checkpoint_raw, checkpoint, progress_raw, progress
    except MigrationError:
        raise
    except observer.ReceiptObserverError:
        raise MigrationError("LEGACY_MIGRATION_STORAGE_INVALID") from None


def _open_stores(
    root: Path, *, worktrees: Callable[[Path], tuple[Path, ...]],
    repository_root: Path, filesystem_validator: Callable[[Path], bool],
) -> tuple[observer.PrivateReceiptStore, observer.PrivateReceiptStore]:
    roots = worktrees(repository_root)
    active_capability = observer._open_receipt_child_core(
        root, repository_roots=roots,
        filesystem_validator=filesystem_validator)
    archive_capability = None
    active = None
    try:
        active = observer.PrivateReceiptStore(active_capability)
        archive_capability = observer._open_receipt_child_core(
            root, repository_roots=roots,
            filesystem_validator=filesystem_validator,
            _child_basename=ARCHIVE_BASENAME)
        archive = observer.PrivateReceiptStore(archive_capability)
        return active, archive
    except BaseException:
        if active is not None:
            active.close()
        else:
            active_capability.close()
        if archive_capability is not None:
            archive_capability.close()
        raise


def _close_stores(
    active: observer.PrivateReceiptStore | None,
    archive: observer.PrivateReceiptStore | None, *, primary: BaseException | None,
) -> None:
    failed = False
    for store in (archive, active):
        if store is not None:
            try:
                store.close()
            except Exception:
                failed = True
    if failed and primary is None:
        raise MigrationError("LEGACY_MIGRATION_CLEANUP_FAILED")


def _archive_inventory(archive: observer.PrivateReceiptStore) -> set[str]:
    try:
        names = set(os.listdir(archive._check_root()))
    except OSError:
        raise MigrationError("LEGACY_MIGRATION_ARCHIVE_INVALID") from None
    if not names <= _ARCHIVE_NAMES:
        raise MigrationError("LEGACY_MIGRATION_ARCHIVE_INVALID")
    return names


def _prepare_migration_core(
    root: Path, *,
    _worktrees: Callable[[Path], tuple[Path, ...]] = observer._known_worktree_roots,
    _repository_root: Path = observer.REPOSITORY_ROOT,
    _filesystem_validator: Callable[[Path], bool] = observer._filesystem_is_local,
) -> _MigrationPlan:
    active = archive = None
    primary = None
    try:
        active, archive = _open_stores(
            root, worktrees=_worktrees, repository_root=_repository_root,
            filesystem_validator=_filesystem_validator)
        active.acquire_session_lock(create=False)
        names = _archive_inventory(archive)
        try:
            checkpoint_name, checkpoint_raw, _checkpoint, progress_raw, _progress = (
                _read_legacy_inventory(active))
        except MigrationError as error:
            if error.code not in {
                    "LEGACY_MIGRATION_BINDING_INVALID",
                    "LEGACY_MIGRATION_PROGRESS_INVALID"}:
                raise
            raise
        if names:
            raise MigrationError("LEGACY_MIGRATION_ARCHIVE_NOT_EMPTY")
        return _MigrationPlan(
            root,
            checkpoint_digest=hashlib.sha256(checkpoint_raw).hexdigest(),
            progress_digest=(None if progress_raw is None
                             else hashlib.sha256(progress_raw).hexdigest()),
            status="LEGACY_MIGRATION_PREPARED")
    except BaseException as error:
        primary = error
        raise
    finally:
        _close_stores(active, archive, primary=primary)


def _write_exclusive(
    store: observer.PrivateReceiptStore, name: str, raw: bytes,
    fault: Callable[[str], None], stage: str,
) -> None:
    root_fd = store._check_root()
    descriptor = None
    fault(f"before_{stage}")
    try:
        descriptor = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=root_fd)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.getuid() or info.st_nlink != 1):
            raise OSError
    except OSError:
        raise MigrationError("LEGACY_MIGRATION_WRITE_FAILED") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if store._read(name, len(raw)) != raw:
        raise MigrationError("LEGACY_MIGRATION_WRITE_FAILED")
    os.fsync(root_fd)
    fault(f"after_{stage}")


def _v2_bytes(
    checkpoint: Mapping[str, Any], progress: Mapping[str, Any] | None,
) -> tuple[bytes, bytes | None]:
    lineage = observer._PRODUCTION_LINEAGE_BINDING_SHA256
    checkpoint_v2 = dict(checkpoint)
    checkpoint_v2["schema"] = CHECKPOINT_V2_SCHEMA
    checkpoint_v2["lineage_binding_sha256"] = lineage
    progress_raw = None
    if progress is not None:
        progress_v2 = dict(progress)
        progress_v2["schema"] = PROGRESS_V2_SCHEMA
        progress_v2["lineage_binding_sha256"] = lineage
        progress_raw = _canonical(progress_v2)
    return _canonical(checkpoint_v2), progress_raw


def _apply_migration_core(
    plan: _MigrationPlan, *,
    _worktrees: Callable[[Path], tuple[Path, ...]] = observer._known_worktree_roots,
    _repository_root: Path = observer.REPOSITORY_ROOT,
    _filesystem_validator: Callable[[Path], bool] = observer._filesystem_is_local,
    _fault: Callable[[str], None] = lambda _stage: None,
) -> Mapping[str, str]:
    if not isinstance(plan, _MigrationPlan):
        raise MigrationError("LEGACY_MIGRATION_PLAN_INVALID")
    root, expected_checkpoint, expected_progress, status = plan._consume()
    if status != "LEGACY_MIGRATION_PREPARED":
        raise MigrationError("LEGACY_MIGRATION_PLAN_INVALID")
    active = archive = None
    primary = None
    try:
        active, archive = _open_stores(
            root, worktrees=_worktrees, repository_root=_repository_root,
            filesystem_validator=_filesystem_validator)
        active.acquire_session_lock(create=False)
        if _archive_inventory(archive):
            raise MigrationError("LEGACY_MIGRATION_ARCHIVE_NOT_EMPTY")
        checkpoint_name, checkpoint_raw, checkpoint, progress_raw, progress = (
            _read_legacy_inventory(active))
        if (hashlib.sha256(checkpoint_raw).hexdigest() != expected_checkpoint
                or (None if progress_raw is None
                    else hashlib.sha256(progress_raw).hexdigest())
                != expected_progress):
            raise MigrationError("LEGACY_MIGRATION_TARGET_CHANGED")
        checkpoint_v2, progress_v2 = _v2_bytes(checkpoint, progress)
        checkpoint_v2_digest = hashlib.sha256(checkpoint_v2).hexdigest()
        checkpoint_v2_name = f"{checkpoint_v2_digest}.checkpoint"

        _write_exclusive(
            archive, ARCHIVE_CHECKPOINT, checkpoint_raw, _fault,
            "archive_checkpoint")
        if progress_raw is not None:
            _write_exclusive(
                archive, ARCHIVE_PROGRESS, progress_raw, _fault,
                "archive_progress")
        archive_manifest = _canonical({
            "schema": ARCHIVE_SCHEMA,
            "checkpoint_sha256": hashlib.sha256(checkpoint_raw).hexdigest(),
            "progress_sha256": (None if progress_raw is None
                                else hashlib.sha256(progress_raw).hexdigest()),
        })
        _write_exclusive(
            archive, ARCHIVE_MANIFEST, archive_manifest, _fault,
            "archive_manifest")

        marker = _canonical({
            "schema": MARKER_SCHEMA,
            "legacy_checkpoint_sha256": hashlib.sha256(checkpoint_raw).hexdigest(),
            "legacy_progress_sha256": (None if progress_raw is None
                                       else hashlib.sha256(progress_raw).hexdigest()),
            "checkpoint_v2_sha256": checkpoint_v2_digest,
            "progress_v2_sha256": (None if progress_v2 is None
                                   else hashlib.sha256(progress_v2).hexdigest()),
        })
        _write_exclusive(
            active, TRANSACTION_MARKER, marker, _fault,
            "transaction_marker")
        _write_exclusive(
            active, STAGED_CHECKPOINT, checkpoint_v2, _fault,
            "stage_checkpoint")
        if progress_v2 is not None:
            _write_exclusive(
                active, STAGED_PROGRESS, progress_v2, _fault,
                "stage_progress")

        active_fd = active._check_root()
        active._validate_artifact_file(checkpoint_name, MAX_ARTIFACT_BYTES)
        if active._read(checkpoint_name, MAX_ARTIFACT_BYTES) != checkpoint_raw:
            raise MigrationError("LEGACY_MIGRATION_TARGET_CHANGED")
        if progress_raw is not None:
            active._validate_artifact_file(
                observer.CURSOR_PROGRESS_BASENAME, MAX_ARTIFACT_BYTES)
            if (active._read(observer.CURSOR_PROGRESS_BASENAME,
                             MAX_ARTIFACT_BYTES) != progress_raw):
                raise MigrationError("LEGACY_MIGRATION_TARGET_CHANGED")
        _fault("before_switch_checkpoint")
        try:
            os.unlink(checkpoint_name, dir_fd=active_fd)
            os.rename(
                STAGED_CHECKPOINT, checkpoint_v2_name,
                src_dir_fd=active_fd, dst_dir_fd=active_fd)
            if progress_v2 is not None:
                os.rename(
                    STAGED_PROGRESS, observer.CURSOR_PROGRESS_BASENAME,
                    src_dir_fd=active_fd, dst_dir_fd=active_fd)
            os.fsync(active_fd)
        except OSError:
            raise MigrationError("LEGACY_MIGRATION_SWITCH_FAILED") from None
        _fault("after_switch_checkpoint")

        if active._read(checkpoint_v2_name, len(checkpoint_v2)) != checkpoint_v2:
            raise MigrationError("LEGACY_MIGRATION_FINAL_INVALID")
        if (progress_v2 is not None
                and active._read(observer.CURSOR_PROGRESS_BASENAME,
                                 len(progress_v2)) != progress_v2):
            raise MigrationError("LEGACY_MIGRATION_FINAL_INVALID")
        _fault("before_marker_remove")
        try:
            os.unlink(TRANSACTION_MARKER, dir_fd=active_fd)
            os.fsync(active_fd)
        except OSError:
            raise MigrationError("LEGACY_MIGRATION_COMMIT_FAILED") from None
        _fault("after_marker_remove")

        loaded = active.load_restart_checkpoint(
            request_reference_sha256=_request_reference(),
            lineage_binding_sha256=observer._PRODUCTION_LINEAGE_BINDING_SHA256)
        if (loaded is None or loaded["generation"] != checkpoint["generation"]
                or loaded["observation_started_at"]
                != checkpoint["observation_started_at"]
                or loaded["cursor"]
                != (checkpoint["cursor"] if progress is None
                    else progress["cursor"])
                or active.load()):
            raise MigrationError("LEGACY_MIGRATION_FINAL_INVALID")
        return MappingProxyType({"status": "LEGACY_MIGRATION_APPLIED"})
    except BaseException as error:
        primary = error
        raise
    finally:
        _close_stores(active, archive, primary=primary)


def _prepare_migration_at_fixed_root(root: Path) -> _MigrationPlan:
    """Internal seam; only the fixed script resolves the production root."""
    return _prepare_migration_core(root)


def _apply_prepared_migration(plan: _MigrationPlan) -> Mapping[str, str]:
    """Consume only a plan minted by the fixed read-only preparation."""
    return _apply_migration_core(plan)


def preparation_projection(plan: _MigrationPlan) -> Mapping[str, str]:
    return MappingProxyType({"status": plan.status})
