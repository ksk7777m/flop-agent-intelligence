"""Foreground, GET-only supervision for the fixed Sonnet receipt observer."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import threading
import time
from typing import Any, Callable

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
    if (type(read.status_code) is not int or read.status_code != 200
            or read.redirected or read.final_url != expected_url
            or read.content_type.split(";", 1)[0].strip().lower()
            != "application/json"
            or len(read.body) > receipt_observer.MAX_PAGE_BYTES):
        raise receipt_observer.ReceiptObserverError(
            "HIGHWATER_TRANSPORT_INVALID")
    value = receipt_observer._json_object(
        read.body, code="HIGHWATER_JSON_INVALID")
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
        raise receipt_observer.ReceiptObserverError("HIGHWATER_SCHEMA_INVALID")
    first_seq = value.get("first_seq")
    if (first_seq is not None
            and (type(first_seq) is not int
                 or not 0 <= first_seq <= value["last_seq"])):
        raise receipt_observer.ReceiptObserverError("HIGHWATER_SCHEMA_INVALID")
    records = [receipt_observer._normalize_record(item)
               for item in value["messages"]]
    if records and records[-1]["seq"] != value["last_seq"]:
        raise receipt_observer.ReceiptObserverError(
            "HIGHWATER_SEQUENCE_INVALID")
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


class SupervisorHandle:
    """Redacted, stoppable handle for exactly one observer session."""

    __slots__ = (
        "_session", "_monotonic", "_deadline", "_state_lock",
        "_explicit_stop", "_wall_timeout", "_watchdog",
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
        return TIMEOUT if wall_timeout else _terminal_status(result)

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

    def start(self) -> SupervisorHandle:
        if self._started:
            raise receipt_observer.ReceiptObserverError(
                "SUPERVISOR_ALREADY_STARTED")
        object.__setattr__(self, "_started", True)
        started_monotonic = self._monotonic()
        transport = self._transport_factory()
        try:
            generation, cursor = _parse_highwater(transport.read_highwater())
        finally:
            transport.close()
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
