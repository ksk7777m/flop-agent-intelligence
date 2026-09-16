"""Same-process boundary between a fresh observer interval and one registration.

This module does not contain a signer or transport.  It joins the existing
GET-only supervisor to the existing durable registration handoff, and leaves
production inert until a human supplies one exact approval artifact.
"""

from __future__ import annotations

import threading
import time
import secrets
import os
import stat
import json
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping

from . import sonnet_receipt_observer as observer
from . import sonnet_receipt_supervisor as supervisor
from . import sonnet_registration as registration
from . import sonnet_registration_adapters as adapters
from . import sonnet_registration_handoff as handoff


LOCAL_REVIEWER = "local-human-operator"
MINIMUM_EXECUTION_REMAINING_SECONDS = handoff.TRANSPORT_TIMEOUT_SECONDS + 5
APPROVAL_COMMAND = "APPROVE_FIXED_SONNET2_WRITER_REGISTRATION"
APPROVAL_TTL_SECONDS = 5 * 60


class AttendedRegistrationError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class _RegistrationWindowGuard:
    """Classify every observed registration page until POST is reserved."""

    __slots__ = ("_lock", "_classification", "_post_reserved")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._classification = "REGISTRATION_WINDOW_NOT_OBSERVED"
        self._post_reserved = False

    def inspect_records(self, records: list[dict[str, Any]], generation: int) -> None:
        with self._lock:
            if self._post_reserved:
                return
            seqs = [record["seq"] for record in records]
            raw = json.dumps({
                "room": registration.ROOM,
                "count": len(records),
                "first_seq": min(seqs) if seqs else None,
                "last_seq": max(seqs) if seqs else None,
                "generation": generation,
                "messages": records,
            }, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                allow_nan=False).encode("utf-8")
            try:
                observed = adapters.classify_registration_export(
                    raw, fetched_at=datetime.now(timezone.utc),
                    receipt_classifier=(
                        registration.production_registration_service.classify_receipt))
            except Exception:
                raise observer.ReceiptObserverError(
                    "REGISTRATION_WINDOW_CLASSIFICATION_FAILED") from None
            self._classification = observed.conflict_classification
            if self._classification != adapters.NO_CONFLICT_IN_OBSERVED_WINDOW:
                raise observer.ReceiptObserverError(
                    "REGISTRATION_WINDOW_NOT_CLEAR")

    def status(self) -> str:
        with self._lock:
            return self._classification

    def reserve_post(self) -> None:
        with self._lock:
            if (self._post_reserved
                    or self._classification
                    != adapters.NO_CONFLICT_IN_OBSERVED_WINDOW):
                raise handoff.HandoffError("REGISTRATION_STATE_UNRESOLVED")
            self._post_reserved = True

    def post_attempt_recorded(self) -> None:
        with self._lock:
            if not self._post_reserved:
                raise handoff.HandoffError("REGISTRATION_STATE_UNRESOLVED")


def _interval_child_status(
    private_runtime_root: Path,
) -> str:
    try:
        capability = observer._open_receipt_child_core(
            private_runtime_root,
            repository_roots=observer._known_worktree_roots(
                observer.REPOSITORY_ROOT),
            filesystem_validator=observer._filesystem_is_local,
            _child_basename=observer.REGISTRATION_INTERVAL_CHILD_BASENAME)
    except observer.ReceiptObserverError as error:
        if error.code == "RECEIPT_CHILD_NOT_PROVISIONED":
            return "REGISTRATION_INTERVAL_PROVISIONING_REQUIRED"
        raise AttendedRegistrationError("REGISTRATION_INTERVAL_ROOT_INVALID") from None
    try:
        store = observer.PrivateReceiptStore(capability)
        try:
            names = os.listdir(store._check_root())
        finally:
            store.close()
    except observer.ReceiptObserverError:
        raise AttendedRegistrationError("REGISTRATION_INTERVAL_CHILD_INVALID") from None
    return ("REGISTRATION_INTERVAL_READY" if not names
            else "REGISTRATION_INTERVAL_ALREADY_STARTED")


def _open_validated_runtime_root(private_runtime_root: Path) -> tuple[int, os.stat_result]:
    """Open and pin the external root after repeating every location check."""
    if (type(private_runtime_root) is not type(Path())
            or not private_runtime_root.is_absolute()
            or ".." in private_runtime_root.parts):
        raise AttendedRegistrationError("REGISTRATION_INTERVAL_ROOT_INVALID")
    lexical_root = private_runtime_root.absolute()
    worktrees = observer._known_worktree_roots(observer.REPOSITORY_ROOT)
    if (observer._is_known_cloud_sync_path(lexical_root)
            or any(observer._is_within(lexical_root, boundary.absolute())
                   for boundary in worktrees)):
        raise AttendedRegistrationError("REGISTRATION_INTERVAL_ROOT_INVALID")
    current = Path(lexical_root.anchor)
    try:
        info = current.lstat()
        for component in lexical_root.parts[1:]:
            current = current / component
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise AttendedRegistrationError(
                    "REGISTRATION_INTERVAL_ROOT_INVALID")
        if (not stat.S_ISDIR(info.st_mode)
                or lexical_root.resolve(strict=True) != lexical_root
                or any(boundary.exists()
                       and observer._is_within_by_inode(lexical_root, boundary)
                       for boundary in worktrees)):
            raise AttendedRegistrationError("REGISTRATION_INTERVAL_ROOT_INVALID")
    except AttendedRegistrationError:
        raise
    except (OSError, RuntimeError):
        raise AttendedRegistrationError(
            "REGISTRATION_INTERVAL_ROOT_INVALID") from None
    flags = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
             | getattr(os, "O_NOFOLLOW", 0))
    root_fd = -1
    try:
        root_fd = os.open(lexical_root, flags)
        root_info = os.fstat(root_fd)
        named = os.stat(lexical_root, follow_symlinks=False)
        if (not stat.S_ISDIR(root_info.st_mode)
                or root_info.st_uid != os.getuid()
                or stat.S_IMODE(root_info.st_mode) != 0o700
                or (root_info.st_dev, root_info.st_ino)
                != (named.st_dev, named.st_ino)
                or not observer._filesystem_is_local(lexical_root)):
            raise AttendedRegistrationError("REGISTRATION_INTERVAL_ROOT_INVALID")
        after = os.stat(lexical_root, follow_symlinks=False)
        if ((root_info.st_dev, root_info.st_ino)
                != (after.st_dev, after.st_ino)):
            raise AttendedRegistrationError("REGISTRATION_INTERVAL_ROOT_INVALID")
        return root_fd, root_info
    except BaseException:
        if root_fd >= 0:
            os.close(root_fd)
        raise


def provision_registration_interval(
    *, private_runtime_root: Path, apply: bool = False,
) -> str:
    """Precheck or create exactly the fixed empty child; never its parent."""
    status = _interval_child_status(private_runtime_root)
    if not apply or status != "REGISTRATION_INTERVAL_PROVISIONING_REQUIRED":
        return status
    flags = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
             | getattr(os, "O_NOFOLLOW", 0))
    root_fd = child_fd = None
    created_identity: tuple[int, int] | None = None
    old_umask = os.umask(0o077)
    try:
        root_fd, root_info = _open_validated_runtime_root(private_runtime_root)
        try:
            os.stat(observer.REGISTRATION_INTERVAL_CHILD_BASENAME,
                    dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise AttendedRegistrationError("REGISTRATION_INTERVAL_RACE")
        os.mkdir(observer.REGISTRATION_INTERVAL_CHILD_BASENAME, 0o700,
                 dir_fd=root_fd)
        child_fd = os.open(
            observer.REGISTRATION_INTERVAL_CHILD_BASENAME, flags,
            dir_fd=root_fd)
        child_info = os.fstat(child_fd)
        named_child = os.stat(
            observer.REGISTRATION_INTERVAL_CHILD_BASENAME,
            dir_fd=root_fd, follow_symlinks=False)
        created_identity = (child_info.st_dev, child_info.st_ino)
        if (not stat.S_ISDIR(child_info.st_mode)
                or child_info.st_uid != os.getuid()
                or stat.S_IMODE(child_info.st_mode) != 0o700
                or created_identity != (named_child.st_dev, named_child.st_ino)
                or child_info.st_dev != root_info.st_dev
                or os.listdir(child_fd)):
            raise AttendedRegistrationError("REGISTRATION_INTERVAL_CHILD_INVALID")
        os.fsync(root_fd)
        return "REGISTRATION_INTERVAL_PROVISIONED"
    except BaseException:
        if (root_fd is not None and created_identity is not None
                and child_fd is not None):
            try:
                current = os.stat(
                    observer.REGISTRATION_INTERVAL_CHILD_BASENAME,
                    dir_fd=root_fd, follow_symlinks=False)
                if ((current.st_dev, current.st_ino) == created_identity
                        and not os.listdir(child_fd)):
                    os.rmdir(observer.REGISTRATION_INTERVAL_CHILD_BASENAME,
                             dir_fd=root_fd)
                    os.fsync(root_fd)
            except OSError:
                pass
        raise
    finally:
        if child_fd is not None:
            os.close(child_fd)
        if root_fd is not None:
            os.close(root_fd)
        os.umask(old_umask)


class _AttendedSession:
    """One-shot, non-serializable owner of one live observer and handoff."""

    __slots__ = (
        "_handle", "_handoff_factory", "_journal_inspect", "_lock",
        "_ready_seen", "_used", "_handoff", "_receipt_records", "_reconciled",
        "_registration_guard", "_stop_pending",
    )

    def __init__(
        self, handle: Any, *,
        handoff_factory: Callable[..., Any],
        journal_inspect: Callable[[], Mapping[str, Any]],
        receipt_records: Callable[[], list[Mapping[str, Any]]] | None = None,
        registration_guard: _RegistrationWindowGuard | None = None,
    ) -> None:
        self._handle = handle
        self._handoff_factory = handoff_factory
        self._journal_inspect = journal_inspect
        self._lock = threading.Lock()
        self._ready_seen = False
        self._used = False
        self._handoff = None
        self._receipt_records = receipt_records
        self._reconciled = False
        self._registration_guard = registration_guard or _RegistrationWindowGuard()
        self._stop_pending = threading.Event()

    def wait_until_ready(self, timeout: float | None = None) -> bool:
        ready = bool(self._handle.wait_until_ready(timeout))
        if ready and self._handle.is_running():
            with self._lock:
                self._ready_seen = True
            return True
        return False

    def execute_approved_registration(
        self, approval: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        with self._lock:
            if self._used:
                raise AttendedRegistrationError("REGISTRATION_SESSION_ALREADY_USED")
            if not self._ready_seen:
                raise AttendedRegistrationError("OBSERVER_NOT_READY")
            if (not self._handle.is_running()
                    or self._handle.remaining_seconds()
                    <= MINIMUM_EXECUTION_REMAINING_SECONDS):
                raise AttendedRegistrationError("OBSERVER_NOT_LIVE")
            status = self._journal_inspect()
            if status.get("state") != handoff.JournalState.NOT_STARTED.value:
                raise AttendedRegistrationError("REGISTRATION_ALREADY_STARTED")

            def live_registration_check() -> str:
                if (not self._handle.is_running()
                        or self._handle.remaining_seconds()
                        <= MINIMUM_EXECUTION_REMAINING_SECONDS):
                    return "OBSERVER_NOT_LIVE"
                return self._registration_guard.status()

            def reserve_live_post() -> None:
                if (not self._handle.is_running()
                        or self._handle.remaining_seconds()
                        <= MINIMUM_EXECUTION_REMAINING_SECONDS):
                    raise handoff.HandoffError("REGISTRATION_STATE_UNRESOLVED")
                self._registration_guard.reserve_post()

            def confirm_recorded_post_attempt() -> None:
                if not self._handle.is_running():
                    raise handoff.HandoffError("REGISTRATION_STATE_UNRESOLVED")
                self._registration_guard.post_attempt_recorded()

            service = self._handoff_factory(
                approval=MappingProxyType(dict(approval)),
                registration_checker=live_registration_check,
                pre_post_check=reserve_live_post,
                post_attempt_recorded=confirm_recorded_post_attempt)
            self._used = True
            self._handoff = service
            try:
                return service.execute(
                    registration.fixed_candidate(), approval["approval_id"])
            finally:
                if self._stop_pending.is_set():
                    self._handle.stop()

    def wait_for_terminal(self, timeout: float | None = None) -> str | None:
        status = self._handle.wait_for_terminal(timeout)
        if (status in {supervisor.ACCEPTED, supervisor.REJECTED}
                and not self._reconciled):
            if self._handoff is None or self._receipt_records is None:
                raise AttendedRegistrationError("RECEIPT_RECONCILIATION_UNAVAILABLE")
            reconciled = False
            for record in self._receipt_records():
                try:
                    self._handoff.reconcile(record)
                    reconciled = True
                    break
                except (handoff.HandoffError,
                        registration.RegistrationBoundaryError):
                    continue
            if not reconciled:
                raise AttendedRegistrationError("RECEIPT_RECONCILIATION_FAILED")
            self._reconciled = True
        return status

    def terminal_projection(self) -> Mapping[str, Any] | None:
        return self._handle.terminal_projection()

    def stop(self) -> None:
        # An explicit signal cannot end the monitored session between the last
        # liveness check and the single bounded handoff call.
        if not self._lock.acquire(blocking=False):
            self._stop_pending.set()
            return
        try:
            self._handle.stop()
        finally:
            self._lock.release()

    def is_running(self) -> bool:
        return self._handle.is_running()

    def remaining_seconds(self) -> int:
        return self._handle.remaining_seconds()

    def __repr__(self) -> str:
        return "<attended Sonnet registration session>"

    def __reduce_ex__(self, _protocol: int) -> Any:
        raise TypeError("attended registration sessions are not serializable")


def _build_production_handoff(
    *, approval: Mapping[str, Any], registration_checker: Callable[[], str],
    pre_post_check: Callable[[], None],
    post_attempt_recorded: Callable[[], None],
) -> Any:
    checked = handoff.validate_approval_artifact(
        approval, trusted_reviewers=frozenset({LOCAL_REVIEWER}),
        now=datetime.now(timezone.utc))
    def fault(point: str) -> None:
        if point == "BEFORE_POST_ATTEMPT_RECORD":
            pre_post_check()
        elif point == "AFTER_POST_ATTEMPT":
            post_attempt_recorded()

    return handoff._build_handoff(
        root=handoff.PRODUCTION_ROOT,
        approvals={checked["approval_id"]: checked},
        trusted_reviewers=frozenset({LOCAL_REVIEWER}),
        clock=lambda: datetime.now(timezone.utc),
        registration_checker=registration_checker,
        identity_signer=adapters.production_identity_signer,
        transport=handoff._production_post_transport,
        receipt_classifier=registration.production_registration_service.classify_receipt,
        fault=fault)


def _build_interval_supervisor(
    *, private_runtime_root: Path, registration_guard: _RegistrationWindowGuard,
) -> Any:
    """Assemble the existing GET-only supervisor around the fixed new child."""
    if type(private_runtime_root) is not type(Path()):
        raise observer.ReceiptObserverError("PRIVATE_ROOT_NOT_CONFIGURED")
    def guarded_observer_factory(**kwargs: Any) -> Any:
        return observer._build_guarded_production_receipt_observer(
            **kwargs, record_guard=registration_guard.inspect_records)

    return supervisor._ProductionSupervisor(
        private_runtime_root=private_runtime_root,
        transport_factory=observer.FixedReadonlyTransport,
        observer_factory=guarded_observer_factory,
        restart_factory=observer.prepare_production_registration_interval,
        clock=lambda: datetime.now(timezone.utc), monotonic=time.monotonic,
        waiter=lambda event, seconds: event.wait(seconds),
        bootstrap_inventory_guard=registration_guard.inspect_records)


def issue_local_approval(
    command: str, *, clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    token_hex: Callable[[int], str] = secrets.token_hex,
) -> Mapping[str, Any]:
    """Issue only the existing fixed approval after one exact human command."""
    if command != APPROVAL_COMMAND:
        raise AttendedRegistrationError("HUMAN_APPROVAL_REQUIRED")
    issued = clock().astimezone(timezone.utc)
    expires = issued.timestamp() + APPROVAL_TTL_SECONDS
    expires_at = datetime.fromtimestamp(expires, timezone.utc)
    approval_id = token_hex(32)
    artifact = {
        "schema": handoff.APPROVAL_SCHEMA_VERSION,
        "approval_id": approval_id,
        "decision": "APPROVED", "reviewer": LOCAL_REVIEWER,
        "action_class": registration.ACTION_CLASS,
        "participant_did": registration.PARTICIPANT_DID,
        "room": registration.ROOM, "request_id": registration.REQUEST_ID,
        "nonce": registration.NONCE,
        "packet_sha256": registration.PACKET_SHA256,
        "signing_target_sha256": registration.SIGNING_TARGET_SHA256,
        "role": registration.ROLE,
        "x_account_url": registration.X_ACCOUNT_URL,
        "referee_did": registration.REFEREE_DID,
        "manifest_sha256": registration.MANIFEST_SHA256,
        "issued_at": issued.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "journal_id": handoff.JOURNAL_ID,
    }
    return handoff.validate_approval_artifact(
        artifact, trusted_reviewers=frozenset({LOCAL_REVIEWER}), now=issued)


def _load_registration_interval_receipts(
    private_runtime_root: Path,
) -> list[Mapping[str, Any]]:
    capability = observer._open_receipt_child_core(
        private_runtime_root,
        repository_roots=observer._known_worktree_roots(observer.REPOSITORY_ROOT),
        filesystem_validator=observer._filesystem_is_local,
        _child_basename=observer.REGISTRATION_INTERVAL_CHILD_BASENAME)
    store = observer.PrivateReceiptStore(capability)
    try:
        return [record for record, _metadata, _raw in store.load()]
    finally:
        store.close()


def begin_attended_registration(
    *, private_runtime_root: Path,
) -> _AttendedSession:
    """Explicitly start one new interval; no network runs before this call."""
    inspected = handoff.production_handoff_service.inspect()
    if inspected["state"] != handoff.JournalState.NOT_STARTED.value:
        raise AttendedRegistrationError("REGISTRATION_ALREADY_STARTED")
    registration_guard = _RegistrationWindowGuard()
    unit = _build_interval_supervisor(
        private_runtime_root=private_runtime_root,
        registration_guard=registration_guard)
    handle = unit.start()
    return _AttendedSession(
        handle, handoff_factory=_build_production_handoff,
        journal_inspect=handoff.production_handoff_service.inspect,
        registration_guard=registration_guard,
        receipt_records=lambda: _load_registration_interval_receipts(
            private_runtime_root))


def _build_attended_session_for_test(
    *, handle: Any,
    handoff_factory: Callable[..., Any],
    journal_inspect: Callable[[], Mapping[str, Any]],
    receipt_records: Callable[[], list[Mapping[str, Any]]] | None = None,
    registration_guard: _RegistrationWindowGuard | None = None,
) -> _AttendedSession:
    if registration_guard is None:
        registration_guard = _RegistrationWindowGuard()
        registration_guard.inspect_records([], 1)
    return _AttendedSession(
        handle, handoff_factory=handoff_factory,
        journal_inspect=journal_inspect, receipt_records=receipt_records,
        registration_guard=registration_guard)
