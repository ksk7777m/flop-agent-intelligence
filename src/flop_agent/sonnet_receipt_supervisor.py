"""Foreground, GET-only supervision for the fixed Sonnet receipt observer."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import threading
import time
from types import MappingProxyType
from typing import Any, Callable, Mapping

from . import sonnet_receipt_observer as receipt_observer


STARTING = "OBSERVER_STARTING"
READY = "OBSERVER_READY"
ACCEPTED = "OBSERVER_ACCEPTED"
REJECTED = "OBSERVER_REJECTED"
UNCONFIRMED = "OBSERVER_UNCONFIRMED"
REVIEW_REQUIRED = "OBSERVER_REVIEW_REQUIRED"
STOPPED = "OBSERVER_STOPPED"
TIMEOUT = "OBSERVER_TIMEOUT"
TERMINAL_STATUSES = frozenset({
    ACCEPTED, REJECTED, UNCONFIRMED, REVIEW_REQUIRED, STOPPED, TIMEOUT,
})


def _parse_highwater(read: receipt_observer.HttpRead) -> tuple[int, int]:
    """Validate the unsigned deployment fields needed to begin observation."""
    expected_url = receipt_observer.FixedReadonlyTransport.highwater_url()
    if read.status_code == 400:
        raise receipt_observer._read_error(
            "READ_HTTP_400", "BOOTSTRAP", http_status=400)
    if read.status_code == 429:
        raise receipt_observer._read_error(
            "READ_HTTP_429", "BOOTSTRAP", http_status=429)
    if read.status_code != 200:
        raise receipt_observer._read_error(
            "READ_HTTP_UNEXPECTED_STATUS", "BOOTSTRAP",
            retryable=(read.status_code == 408
                       or type(read.status_code) is int
                       and 500 <= read.status_code <= 599),
            http_status=read.status_code)
    if (type(read.status_code) is not int or read.status_code != 200
            or read.redirected or read.final_url != expected_url
            or read.content_type.split(";", 1)[0].strip().lower()
            != "application/json"
            or len(read.body) > receipt_observer.MAX_PAGE_BYTES):
        if read.content_type.split(";", 1)[0].strip().lower() != "application/json":
            raise receipt_observer._read_error(
                "READ_CONTENT_TYPE_MISMATCH", "BOOTSTRAP")
        if len(read.body) > receipt_observer.MAX_PAGE_BYTES:
            raise receipt_observer._read_error(
                "READ_RESPONSE_LIMIT", "BOOTSTRAP")
        raise receipt_observer._read_error(
            "READ_MALFORMED_RESPONSE", "BOOTSTRAP")
    try:
        value = receipt_observer._json_object(
            read.body, code="HIGHWATER_JSON_INVALID")
    except receipt_observer.ReceiptObserverError:
        raise receipt_observer._read_error(
            "READ_MALFORMED_RESPONSE", "BOOTSTRAP") from None
    allowed = {
        "room", "count", "first_seq", "last_seq", "generation", "messages",
    }
    if (set(value) != allowed
            or value.get("room") != receipt_observer.ROOM
            or type(value.get("count")) is not int
            or not 0 <= value["count"] <= receipt_observer.SAFE_INTEGER_MAX
            or type(value.get("generation")) is not int
            or not 1 <= value["generation"] <= receipt_observer.SAFE_INTEGER_MAX
            or type(value.get("last_seq")) is not int
            or not 0 <= value["last_seq"] <= receipt_observer.SAFE_INTEGER_MAX
            or type(value.get("messages")) is not list
            or len(value["messages"]) > 1
            or value["count"] < len(value["messages"])):
        raise receipt_observer._read_error(
            "READ_MALFORMED_RESPONSE", "BOOTSTRAP")
    first_seq = value.get("first_seq")
    if (first_seq is not None
            and (type(first_seq) is not int
                 or not 0 <= first_seq <= value["last_seq"])):
        raise receipt_observer._read_error(
            "READ_MALFORMED_RESPONSE", "BOOTSTRAP")
    records = [receipt_observer._normalize_record(item)
               for item in value["messages"]]
    if records and records[-1]["seq"] != value["last_seq"]:
        raise receipt_observer._read_error(
            "READ_CURSOR_REGRESSION", "BOOTSTRAP")
    return value["generation"], value["last_seq"]


def _terminal_status(result: receipt_observer.ObserverResult) -> str:
    if result.status == "ACCEPTED":
        return ACCEPTED
    if result.status == "REJECTED":
        return REJECTED
    if result.review_required:
        return REVIEW_REQUIRED
    if result.error_category == "SUPERVISOR_STOPPED":
        return STOPPED
    if result.error_category == "SUPERVISOR_TIMEOUT":
        return TIMEOUT
    return UNCONFIRMED


def _terminal_projection(
    status: str, result: receipt_observer.ObserverResult,
) -> Mapping[str, Any]:
    value: dict[str, Any] = {
        "status": status,
        "failure_category": result.failure_category,
        "failure_phase": result.failure_phase,
        "retryable": result.retryable,
        "observed_at": (result.observed_at
                        or datetime.now(timezone.utc).isoformat().replace(
                            "+00:00", "Z")),
        "read_attempt_count": min(
            max(result.read_count, 0), receipt_observer.SUPERVISOR_MAX_READS),
    }
    if result.http_status is not None:
        value["http_status"] = result.http_status
    return MappingProxyType(value)


def safe_start_failure_projection(error: BaseException) -> Mapping[str, Any]:
    """Collapse all bootstrap exceptions to a fixed, path-free projection."""
    stopped = (isinstance(error, receipt_observer.ReceiptObserverError)
               and error.code == "SUPERVISOR_STOPPED")
    if isinstance(error, receipt_observer.ReceiptObserverError):
        category = ("READ_STOPPED" if stopped
                    else error.category or "READ_INTERNAL_FAILURE")
        phase = "BOOTSTRAP"
        retryable = False
        status = error.http_status
    else:
        category, phase, retryable, status = (
            "READ_INTERNAL_FAILURE", "BOOTSTRAP", False, None)
    value: dict[str, Any] = {
        "status": STOPPED if stopped else REVIEW_REQUIRED,
        "failure_category": category,
        "failure_phase": phase,
        "retryable": retryable,
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "read_attempt_count": (error.read_attempt_count
                               if isinstance(
                                   error, receipt_observer.ReceiptObserverError)
                               else 0),
    }
    if status is not None:
        value["http_status"] = status
    return MappingProxyType(value)


class SupervisorHandle:
    """Redacted, stoppable handle for exactly one observer session."""

    __slots__ = (
        "_session", "_monotonic", "_deadline", "_state_lock",
        "_explicit_stop", "_wall_timeout", "_watchdog", "_terminal",
    )

    def __init__(
        self, session: receipt_observer.ReceiptObservationSession, *,
        monotonic: Callable[[], float], started_at: float,
    ) -> None:
        self._session = session
        self._monotonic = monotonic
        self._deadline = (
            started_at + receipt_observer.SUPERVISOR_MAX_WALL_SECONDS)
        self._state_lock = threading.Lock()
        self._explicit_stop = False
        self._wall_timeout = False
        self._terminal: Mapping[str, Any] | None = None

        def enforce_wall() -> None:
            remaining = max(0.0, self._deadline - self._monotonic())
            if session.wait_for_result(remaining) is None:
                with self._state_lock:
                    if not self._explicit_stop:
                        self._wall_timeout = True
                session.stop()
                session.wait_for_result(
                    receipt_observer.HTTP_TIMEOUT_SECONDS + 1)

        self._watchdog = threading.Thread(
            target=enforce_wall, name="sonnet-receipt-wall-guard",
            daemon=False)
        self._watchdog.start()

    def wait_until_ready(self, timeout: float | None = None) -> bool:
        return self._session.wait_until_ready(timeout)

    def wait_for_terminal(self, timeout: float | None = None) -> str | None:
        result = self._session.wait_for_result(timeout)
        if result is None:
            return None
        with self._state_lock:
            wall_timeout = self._wall_timeout
        status = TIMEOUT if wall_timeout else _terminal_status(result)
        self._terminal = _terminal_projection(status, result)
        return status

    def terminal_projection(self) -> Mapping[str, Any] | None:
        return self._terminal

    def stop(self) -> None:
        with self._state_lock:
            if not self._wall_timeout:
                self._explicit_stop = True
        self._session.stop()

    def is_running(self) -> bool:
        return self._session.is_running()

    def remaining_seconds(self) -> int:
        return max(0, int(self._deadline - self._monotonic()))

    def __repr__(self) -> str:
        return "<Sonnet receipt supervisor handle>"


class _ProductionSupervisor:
    """One-shot facade whose only external capability is a fixed GET transport."""

    __slots__ = (
        "_private_runtime_root", "_transport_factory", "_observer_factory",
        "_clock", "_monotonic", "_started",
    )

    def __init__(
        self, *, private_runtime_root: Path,
        transport_factory: Callable[[], Any],
        observer_factory: Callable[..., Any],
        clock: Callable[[], datetime], monotonic: Callable[[], float],
    ) -> None:
        object.__setattr__(self, "_private_runtime_root", private_runtime_root)
        object.__setattr__(self, "_transport_factory", transport_factory)
        object.__setattr__(self, "_observer_factory", observer_factory)
        object.__setattr__(self, "_clock", clock)
        object.__setattr__(self, "_monotonic", monotonic)
        object.__setattr__(self, "_started", False)

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise AttributeError("production supervisor is immutable")

    def start(
        self, stop_requested: threading.Event | None = None,
    ) -> SupervisorHandle:
        if self._started:
            raise receipt_observer.ReceiptObserverError(
                "SUPERVISOR_ALREADY_STARTED")
        object.__setattr__(self, "_started", True)
        started_monotonic = self._monotonic()
        transport = self._transport_factory()
        primary_error: BaseException | None = None
        try:
            retries = 0
            retry_wait_total = 0
            read_attempts = 0
            while True:
                if stop_requested is not None and stop_requested.is_set():
                    raise receipt_observer.ReceiptObserverError(
                        "SUPERVISOR_STOPPED")
                remaining = (started_monotonic
                             + receipt_observer.SUPERVISOR_MAX_WALL_SECONDS
                             - self._monotonic())
                if remaining <= receipt_observer.HTTP_TIMEOUT_SECONDS:
                    raise receipt_observer._read_error(
                        "READ_NETWORK_TIMEOUT", "BOOTSTRAP")
                try:
                    read_attempts += 1
                    read = transport.read_highwater()
                    if read.status_code == 429:
                        values = read.retry_after_values()
                        if (len(values) != 1 or not values[0].isdigit()
                                or not 0 < int(values[0])
                                <= receipt_observer.MAX_RETRY_AFTER_SECONDS):
                            raise receipt_observer._read_error(
                                "READ_HTTP_429", "BOOTSTRAP", http_status=429)
                        raise receipt_observer._read_error(
                            "READ_HTTP_429", "BOOTSTRAP", retryable=True,
                            http_status=429, retry_after=int(values[0]))
                    generation, cursor = _parse_highwater(read)
                    break
                except receipt_observer.ReceiptObserverError as error:
                    if stop_requested is not None and stop_requested.is_set():
                        raise receipt_observer.ReceiptObserverError(
                            "SUPERVISOR_STOPPED") from None
                    error = receipt_observer._read_error(
                        error.category or "READ_INTERNAL_FAILURE", "BOOTSTRAP",
                        retryable=error.retryable,
                        http_status=error.http_status,
                        retry_after=error.retry_after, code=error.code)
                    delay = (error.retry_after
                             if error.retry_after is not None
                             else receipt_observer.RETRY_BACKOFF_SECONDS)
                    remaining = (started_monotonic
                                 + receipt_observer.SUPERVISOR_MAX_WALL_SECONDS
                                 - self._monotonic())
                    can_retry = (
                        error.retryable
                        and retries < receipt_observer.MAX_CONSECUTIVE_READ_RETRIES
                        and retry_wait_total + delay
                        <= receipt_observer.MAX_TOTAL_RETRY_WAIT_SECONDS
                        and remaining
                        > delay + receipt_observer.HTTP_TIMEOUT_SECONDS)
                    if not can_retry:
                        raise receipt_observer._read_error(
                            error.category or "READ_INTERNAL_FAILURE",
                            "BOOTSTRAP", retryable=False,
                            http_status=error.http_status,
                            code=error.code,
                            read_attempt_count=read_attempts) from None
                    retries += 1
                    retry_wait_total += delay
                    if stop_requested is not None:
                        if stop_requested.wait(delay):
                            raise receipt_observer.ReceiptObserverError(
                                "SUPERVISOR_STOPPED") from None
                    else:
                        time.sleep(delay)
        except BaseException as error:
            primary_error = error
            raise
        finally:
            try:
                transport.close()
            except Exception:
                if primary_error is None:
                    raise receipt_observer._read_error(
                        "READ_CLEANUP_FAILURE", "CLEANUP") from None
        started_at = self._clock()
        service = self._observer_factory(
            private_runtime_root=self._private_runtime_root,
            expected_generation=generation,
            initial_since=cursor,
            observation_started_at=started_at)
        return SupervisorHandle(
            service.start(), monotonic=self._monotonic,
            started_at=started_monotonic)

    def __repr__(self) -> str:
        return "<fixed Sonnet receipt supervisor>"


def _seal_production_factory() -> Callable[..., _ProductionSupervisor]:
    supervisor_type = _ProductionSupervisor
    transport_type = receipt_observer.FixedReadonlyTransport
    observer_factory = receipt_observer.build_production_receipt_observer
    utc_clock = lambda: datetime.now(timezone.utc)
    monotonic = time.monotonic

    def build(*, private_runtime_root: Path) -> _ProductionSupervisor:
        """Build without opening storage or contacting the network."""
        if type(private_runtime_root) is not type(Path()):
            raise receipt_observer.ReceiptObserverError(
                "PRIVATE_ROOT_NOT_CONFIGURED")
        return supervisor_type(
            private_runtime_root=private_runtime_root,
            transport_factory=transport_type,
            observer_factory=observer_factory,
            clock=utc_clock, monotonic=monotonic)

    return build


build_production_receipt_supervisor = _seal_production_factory()
del _seal_production_factory


def _build_receipt_supervisor_for_test(
    *, private_runtime_root: Path, transport_factory: Callable[[], Any],
    observer_factory: Callable[..., Any], clock: Callable[[], datetime],
    monotonic: Callable[[], float] = time.monotonic,
) -> _ProductionSupervisor:
    """Fixture-only dependency seam, separate from the production API."""
    return _ProductionSupervisor(
        private_runtime_root=private_runtime_root,
        transport_factory=transport_factory,
        observer_factory=observer_factory,
        clock=clock, monotonic=monotonic)
