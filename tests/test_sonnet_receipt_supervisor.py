import importlib
import inspect
import json
import sys
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

from flop_agent import sonnet_receipt_observer as observer
from flop_agent import sonnet_receipt_supervisor as supervisor


NOW = datetime(2026, 9, 15, 4, 0, tzinfo=timezone.utc)


def highwater(**changes):
    body = {
        "room": observer.ROOM,
        "count": 1,
        "first_seq": 95927,
        "last_seq": 95927,
        "generation": 1,
        "messages": [],
    }
    body.update(changes)
    return observer.HttpRead(
        200, observer.FixedReadonlyTransport.highwater_url(),
        "application/json", json.dumps(body, separators=(",", ":")).encode(),
        {})


class FakeHighwaterTransport:
    def __init__(self, value=None):
        self.value = value or highwater()
        self.get_calls = 0
        self.close_calls = 0

    def read_highwater(self):
        self.get_calls += 1
        if isinstance(self.value, Exception):
            raise self.value
        return self.value

    def close(self):
        self.close_calls += 1


class FakeSession:
    def __init__(self, *, ready=True, terminal="OBSERVER_TIMEOUT"):
        self.ready = ready
        self.terminal = terminal
        self.running = True
        self.stop_calls = 0

    def wait_until_ready(self, _timeout=None):
        return self.ready

    def wait_for_terminal(self, _timeout=None):
        if self.terminal is None:
            return None
        self.running = False
        return self.terminal

    def wait_for_result(self, _timeout=None):
        if self.terminal is None:
            return None
        self.running = False
        mapping = {
            "OBSERVER_ACCEPTED": ("ACCEPTED", None),
            "OBSERVER_REJECTED": ("REJECTED", None),
            "OBSERVER_STOPPED": ("UNCONFIRMED", "SUPERVISOR_STOPPED"),
            "OBSERVER_TIMEOUT": ("UNCONFIRMED", "SUPERVISOR_TIMEOUT"),
        }
        status, error = mapping.get(
            self.terminal, ("UNCONFIRMED", "FIXTURE_UNCONFIRMED"))
        return observer.ObserverResult(
            status, False, False, 1, 1, False, False,
            error_category=error)

    def stop(self):
        self.stop_calls += 1
        self.terminal = "OBSERVER_STOPPED"

    def is_running(self):
        return self.running

    def remaining_seconds(self):
        return 1


class FakeService:
    def __init__(self, session):
        self.session = session
        self.start_calls = 0

    def start(self):
        self.start_calls += 1
        return self.session


class SupervisorTests(unittest.TestCase):
    def test_outer_monotonic_guard_includes_bootstrap_and_maps_timeout(self):
        class TimeoutSession:
            def __init__(self):
                self.stopped = threading.Event()

            def wait_for_result(self, _timeout=None):
                if not self.stopped.is_set():
                    return None
                return observer.ObserverResult(
                    "UNCONFIRMED", False, False, 1, 1, False, False,
                    error_category="SUPERVISOR_STOPPED")

            def stop(self):
                self.stopped.set()

            def wait_until_ready(self, _timeout=None):
                return False

            def is_running(self):
                return not self.stopped.is_set()

        clock = FakeMonotonic()
        session = TimeoutSession()
        handle = supervisor.SupervisorHandle(
            session, monotonic=clock,
            started_at=-observer.SUPERVISOR_MAX_WALL_SECONDS)
        for _ in range(100):
            if session.stopped.is_set():
                break
            time.sleep(0.001)
        self.assertTrue(session.stopped.is_set())
        self.assertEqual(handle.wait_for_terminal(1), supervisor.TIMEOUT)
        self.assertEqual(handle.remaining_seconds(), 0)

    def test_live_shaped_highwater_uses_unsigned_body_generation_and_cursor(self):
        self.assertEqual(supervisor._parse_highwater(highwater()), (1, 95927))

    def test_highwater_rejects_remote_shape_aliases_and_unsafe_integers(self):
        cases = [
            highwater(room="other"), highwater(generation=True),
            highwater(generation=0), highwater(generation="1"),
            highwater(last_seq=True), highwater(last_seq=-1),
            highwater(last_seq=observer.SAFE_INTEGER_MAX + 1),
            highwater(messages=[{"seq": 2, "ts": "t", "from": "x", "text": "x"}]),
            observer.HttpRead(
                200, observer.FixedReadonlyTransport.highwater_url(),
                "application/json",
                b'{"room":"mb-sonnet-2-registration","room":"other"}', {}),
        ]
        for candidate in cases:
            with self.subTest(body=repr(candidate)):
                with self.assertRaises(observer.ReceiptObserverError):
                    supervisor._parse_highwater(candidate)

    def test_bootstrap_get_is_closed_and_same_values_start_existing_factory(self):
        transport = FakeHighwaterTransport()
        session = FakeSession()
        service = FakeService(session)
        calls = []

        def build(**kwargs):
            calls.append(kwargs)
            return service

        unit = supervisor._build_receipt_supervisor_for_test(
            private_runtime_root=Path("/fixture/private"),
            transport_factory=lambda: transport, observer_factory=build,
            clock=lambda: NOW)
        handle = unit.start()
        self.assertEqual(transport.get_calls, 1)
        self.assertEqual(transport.close_calls, 1)
        self.assertEqual(service.start_calls, 1)
        self.assertEqual(calls[0]["expected_generation"], 1)
        self.assertEqual(calls[0]["initial_since"], 95927)
        self.assertEqual(calls[0]["observation_started_at"], NOW)
        self.assertEqual(repr(handle), "<Sonnet receipt supervisor handle>")
        self.assertNotIn("fixture", repr(handle))

    def test_constructor_failure_closes_bootstrap_transport(self):
        transport = FakeHighwaterTransport()

        def fail(**_kwargs):
            raise observer.ReceiptObserverError("FIXTURE_FAILURE")

        unit = supervisor._build_receipt_supervisor_for_test(
            private_runtime_root=Path("/fixture/private"),
            transport_factory=lambda: transport, observer_factory=fail,
            clock=lambda: NOW)
        with self.assertRaisesRegex(observer.ReceiptObserverError, "FIXTURE_FAILURE"):
            unit.start()
        self.assertEqual(transport.close_calls, 1)

    def test_supervisor_is_one_shot_and_has_no_restart_api(self):
        service = FakeService(FakeSession())
        unit = supervisor._build_receipt_supervisor_for_test(
            private_runtime_root=Path("/fixture/private"),
            transport_factory=FakeHighwaterTransport,
            observer_factory=lambda **_kwargs: service, clock=lambda: NOW)
        unit.start()
        with self.assertRaisesRegex(observer.ReceiptObserverError,
                                    "SUPERVISOR_ALREADY_STARTED"):
            unit.start()
        public = {name for name, value in inspect.getmembers(
            supervisor._ProductionSupervisor, inspect.isfunction)
            if not name.startswith("_")}
        self.assertEqual(public, {"start"})

    def test_terminal_mapping_is_fixed_and_conflict_precedes_unconfirmed(self):
        def result(status="UNCONFIRMED", review=False, error=None):
            return observer.ObserverResult(
                status, False, review, 1, 1, False, False,
                error_category=error)

        self.assertEqual(supervisor._terminal_status(result("ACCEPTED")),
                         supervisor.ACCEPTED)
        self.assertEqual(supervisor._terminal_status(result("REJECTED")),
                         supervisor.REJECTED)
        self.assertEqual(supervisor._terminal_status(
            result(review=True, error="CONFLICTING_VALID_RECEIPTS")),
            supervisor.REVIEW_REQUIRED)
        self.assertEqual(supervisor._terminal_status(
            result(error="SUPERVISOR_STOPPED")), supervisor.STOPPED)
        self.assertEqual(supervisor._terminal_status(
            result(error="SUPERVISOR_TIMEOUT")), supervisor.TIMEOUT)
        self.assertEqual(supervisor._terminal_status(
            result(error="HTTP_408")), supervisor.UNCONFIRMED)

    def test_production_factory_seals_transport_observer_and_clock(self):
        signature = inspect.signature(
            supervisor.build_production_receipt_supervisor)
        self.assertEqual(tuple(signature.parameters), ("private_runtime_root",))
        closure = inspect.getclosurevars(
            supervisor.build_production_receipt_supervisor).nonlocals
        self.assertIs(closure["transport_type"], observer.FixedReadonlyTransport)
        self.assertIs(
            closure["observer_factory"],
            observer.build_production_receipt_observer)
        unit = supervisor.build_production_receipt_supervisor(
            private_runtime_root=Path("/fixture/private"))
        for field, value in (
            ("_transport_factory", lambda: object()),
            ("_observer_factory", lambda **_kwargs: object()),
            ("_private_runtime_root", Path("/other")),
            ("_clock", lambda: NOW),
            ("_monotonic", lambda: 0.0),
        ):
            with self.subTest(field=field), self.assertRaises(AttributeError):
                setattr(unit, field, value)
        source = inspect.getsource(supervisor)
        for forbidden in (
            "sonnet_registration_adapters", "production_identity_signer",
            "production_registration", "request_id", "private_key",
            "subprocess", 'method="POST"', "urllib.request.Request",
        ):
            self.assertNotIn(forbidden, source)

    def test_production_builder_does_not_start_or_touch_filesystem(self):
        unit = supervisor.build_production_receipt_supervisor(
            private_runtime_root=Path("/definitely/not/opened"))
        self.assertEqual(repr(unit), "<fixed Sonnet receipt supervisor>")
        self.assertNotIn("definitely", repr(unit))

    def test_foreground_runner_emits_ready_and_one_terminal_status(self):
        scripts = Path(__file__).resolve().parents[1] / "scripts"
        sys.path.insert(0, str(scripts))
        self.addCleanup(lambda: sys.path.remove(str(scripts)))
        runner = importlib.import_module("run_sonnet_receipt_observer")
        statuses = []
        code = runner._run_foreground(
            FakeSession(terminal="OBSERVER_TIMEOUT"), threading.Event(),
            statuses.append)
        self.assertEqual(code, 0)
        self.assertEqual(statuses, ["OBSERVER_READY", "OBSERVER_TIMEOUT"])
        self.assertEqual(len([item for item in statuses
                              if item in supervisor.TERMINAL_STATUSES]), 1)

    def test_foreground_stop_flag_is_forwarded_without_restart(self):
        runner = importlib.import_module("run_sonnet_receipt_observer")
        session = FakeSession(ready=False, terminal=None)
        requested = threading.Event()
        requested.set()
        statuses = []
        code = runner._run_foreground(session, requested, statuses.append)
        self.assertEqual(code, 0)
        self.assertEqual(session.stop_calls, 1)
        self.assertEqual(statuses, ["OBSERVER_STOPPED"])

    def test_entrypoint_has_no_configuration_or_detachment_surface(self):
        path = (Path(__file__).resolve().parents[1] / "scripts" /
                "run_sonnet_receipt_observer.py")
        source = path.read_text(encoding="utf-8")
        for forbidden in (
            "argparse", "os.environ", "getenv", "subprocess", "Popen",
            "fork", "daemon", "request_id", "participant_did", "x_account",
            "POST", "nonce", "signer", "identity",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("signal.SIGINT", source)
        self.assertIn("signal.SIGTERM", source)
        self.assertIn("trusted_production_runtime_root", source)


class FakeMonotonic:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value

    def wait(self, event, seconds):
        self.value += seconds
        return event.is_set()


class SessionLifecycleTests(unittest.TestCase):
    class Config:
        max_reads = observer.SUPERVISOR_MAX_READS
        wait_seconds = observer.LONG_POLL_SECONDS
        deadline = observer.DEADLINE

    class Transport:
        def __init__(self):
            self.close_calls = 0

        def close(self):
            self.close_calls += 1

    class Store:
        def __init__(self):
            self.close_calls = 0

        def close(self):
            self.close_calls += 1

    class Core:
        def __init__(self, monotonic, *, terminal=None):
            self._config = SessionLifecycleTests.Config()
            self._transport = SessionLifecycleTests.Transport()
            self._store = SessionLifecycleTests.Store()
            self._clock = lambda: NOW
            self._reads = 1
            self._cursor = 1
            self._ready = True
            self.monotonic = monotonic
            self.request_times = []
            self.terminal = terminal

        def prepare(self):
            return observer.ObserverResult(
                "UNCONFIRMED", True, False, self._reads, self._cursor,
                False, False, error_category="AWAITING_RECEIPT")

        def _read(self, _wait):
            self.request_times.append(self.monotonic())
            self._reads += 1
            return self.terminal

        def _safe(self, *, error, gap=False, exported=False, review=False):
            self._ready = False
            return observer.ObserverResult(
                "UNCONFIRMED", False, review, self._reads, self._cursor,
                gap, exported, error_category=error)

    def test_monotonic_wall_timeout_and_busy_room_pacing(self):
        clock = FakeMonotonic()
        core = self.Core(clock)
        session = observer.ReceiptObservationSession(
            core, monotonic=clock, maximum_wall_seconds=30,
            minimum_poll_seconds=2, waiter=clock.wait)
        result = session.wait_for_result(2)
        self.assertIsNotNone(result)
        self.assertEqual(result.error_category, "SUPERVISOR_TIMEOUT")
        self.assertTrue(all(b - a >= 2 for a, b in zip(
            core.request_times, core.request_times[1:])))
        self.assertLess(len(core.request_times), 15)
        self.assertGreaterEqual(clock.value, 30)
        self.assertEqual(core._transport.close_calls, 1)
        self.assertEqual(core._store.close_calls, 1)

    def test_read_limit_is_hard_bounded(self):
        clock = FakeMonotonic()
        core = self.Core(clock)
        core._config.max_reads = 3
        session = observer.ReceiptObservationSession(
            core, monotonic=clock, maximum_wall_seconds=30,
            minimum_poll_seconds=0, waiter=clock.wait)
        result = session.wait_for_result(2)
        self.assertEqual(result.error_category, "SUPERVISOR_READ_LIMIT")
        self.assertEqual(core._reads, 3)

    def test_stop_during_pacing_is_interruptible_and_closes_resources(self):
        clock = FakeMonotonic()
        core = self.Core(clock)

        def stop_wait(event, _seconds):
            event.set()
            return True

        session = observer.ReceiptObservationSession(
            core, monotonic=clock, maximum_wall_seconds=30,
            minimum_poll_seconds=2, waiter=stop_wait)
        result = session.wait_for_result(2)
        self.assertEqual(result.error_category, "SUPERVISOR_STOPPED")
        self.assertEqual(core.request_times, [])
        self.assertEqual(core._transport.close_calls, 1)
        self.assertEqual(core._store.close_calls, 1)

    def test_stop_interrupts_active_read(self):
        entered = threading.Event()
        released = threading.Event()
        clock = FakeMonotonic()
        core = self.Core(clock)

        class InterruptingTransport(self.Transport):
            def close(self):
                super().close()
                released.set()

        core._transport = InterruptingTransport()

        def blocking_read(_wait):
            entered.set()
            released.wait(2)
            # CPython/macOS may surface a cross-thread response close this way.
            raise ValueError("fixture closed response")

        core._read = blocking_read
        session = observer.ReceiptObservationSession(
            core, monotonic=clock, maximum_wall_seconds=30,
            minimum_poll_seconds=0)
        self.assertTrue(session.wait_until_ready(1))
        self.assertTrue(entered.wait(1))
        session.stop()
        result = session.wait_for_result(2)
        self.assertEqual(result.error_category, "SUPERVISOR_STOPPED")
        self.assertGreaterEqual(core._transport.close_calls, 1)
        self.assertEqual(core._store.close_calls, 1)


if __name__ == "__main__":
    unittest.main()
