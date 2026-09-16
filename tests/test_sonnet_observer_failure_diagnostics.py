import importlib
import dataclasses
import json
import pickle
import ssl
import socket
import sys
import threading
import urllib.error
import unittest
from pathlib import Path
from unittest import mock

from flop_agent import sonnet_receipt_observer as observer
from flop_agent import sonnet_receipt_supervisor as supervisor
from tests.test_sonnet_receipt_observer import (
    NOW, BoundaryFixture, config, page, receipt,
)


class FakeMonotonic:
    def __init__(self):
        self.value = 0.0
        self.waits = []

    def __call__(self):
        return self.value

    def wait(self, event, seconds):
        self.waits.append(seconds)
        self.value += seconds
        return event.is_set()


class DiagnosticTests(unittest.TestCase):
    def fixture(self, pages, *, cfg=None):
        value = BoundaryFixture(pages, cfg=cfg)
        self.addCleanup(value.close)
        return value

    def session(self, fixture, clock, **kwargs):
        return observer.ReceiptObservationSession(
            fixture.service, monotonic=clock, maximum_wall_seconds=60,
            minimum_poll_seconds=0, waiter=clock.wait, **kwargs)

    def test_empty_held_wait_is_normal_and_same_cursor_continues(self):
        fixture = self.fixture([
            page(10), page(10, extra={"wait_held": True}),
            page(10, receipt()),
        ], cfg=config(max_reads=4))
        result = self.session(fixture, FakeMonotonic()).wait_for_result(2)
        self.assertEqual(result.status, "ACCEPTED")
        self.assertEqual(fixture.transport.page_calls,
                         [(10, 0), (10, 10), (10, 10)])

    def test_unheld_wait_sleeps_requested_interval_and_keeps_cursor(self):
        clock = FakeMonotonic()
        fixture = self.fixture([
            page(10), page(10, extra={"wait_held": False}),
            page(10, receipt()),
        ], cfg=config(max_reads=4))
        result = self.session(fixture, clock).wait_for_result(2)
        self.assertEqual(result.status, "ACCEPTED")
        self.assertIn(10, clock.waits)
        self.assertEqual(fixture.transport.page_calls[-2:], [(10, 10), (10, 10)])

    def test_unheld_wait_is_interruptible(self):
        fixture = self.fixture([
            page(10), page(10, extra={"wait_held": False}),
        ], cfg=config(max_reads=3))
        clock = FakeMonotonic()

        def stop_wait(event, seconds):
            clock.waits.append(seconds)
            event.set()
            return True

        session = observer.ReceiptObservationSession(
            fixture.service, monotonic=clock, maximum_wall_seconds=30,
            minimum_poll_seconds=0, waiter=stop_wait)
        result = session.wait_for_result(2)
        self.assertEqual(result.error_category, "SUPERVISOR_STOPPED")

    def test_waited_empty_without_wait_held_fails_closed(self):
        fixture = self.fixture([page(10), page(10)], cfg=config(max_reads=2))
        result = self.session(fixture, FakeMonotonic()).wait_for_result(2)
        self.assertEqual(result.failure_category, "READ_MALFORMED_RESPONSE")

    def test_429_numeric_retry_after_is_bounded(self):
        throttled = observer.HttpRead(
            429, "ignored", "", b"", {"Retry-After": "3"})
        clock = FakeMonotonic()
        fixture = self.fixture([page(10), throttled, page(10, receipt())],
                               cfg=config(max_reads=4))
        result = self.session(fixture, clock).wait_for_result(2)
        self.assertEqual(result.status, "ACCEPTED")
        self.assertIn(3, clock.waits)

    def test_invalid_retry_after_is_terminal(self):
        for raw in (
            "", "-1", "+3", " 3 ", "3e0",
            "Wed, 21 Oct 2015 07:28:00 GMT", "31", "1,2",
        ):
            with self.subTest(raw=raw):
                fixture = self.fixture([
                    page(10), observer.HttpRead(
                        429, "ignored", "", b"", {"Retry-After": raw}),
                ], cfg=config(max_reads=4))
                result = self.session(fixture, FakeMonotonic()).wait_for_result(2)
                self.assertEqual(result.failure_category, "READ_HTTP_429")
                self.assertFalse(result.retryable)

    def test_timeout_408_and_5xx_retry_only_twice(self):
        cases = [
            (observer._read_error(
                "READ_NETWORK_TIMEOUT", "POLL", retryable=True),
             "READ_NETWORK_TIMEOUT", None),
            (observer.HttpRead(408, "ignored", "", b"", {}),
             "READ_HTTP_UNEXPECTED_STATUS", 408),
            (observer.HttpRead(503, "ignored", "", b"", {}),
             "READ_HTTP_UNEXPECTED_STATUS", 503),
        ]
        for failure, category, status in cases:
            with self.subTest(category=category, status=status):
                fixture = self.fixture(
                    [page(10), failure, failure, failure],
                    cfg=config(max_reads=4))
                result = self.session(fixture, FakeMonotonic()).wait_for_result(2)
                self.assertEqual(result.failure_category, category)
                self.assertEqual(result.http_status, status)
                self.assertEqual(len(fixture.transport.page_calls), 4)

    def test_tls_failure_is_not_retried(self):
        failure = observer._read_error("READ_TLS_FAILURE", "POLL")
        fixture = self.fixture([page(10), failure], cfg=config(max_reads=4))
        result = self.session(fixture, FakeMonotonic()).wait_for_result(2)
        self.assertEqual(result.failure_category, "READ_TLS_FAILURE")
        self.assertEqual(len(fixture.transport.page_calls), 2)

    def test_response_failures_have_distinct_safe_categories(self):
        cases = [
            (observer.HttpRead(200, "ignored", "text/plain", b"{}", {}),
             "READ_CONTENT_TYPE_MISMATCH"),
            (observer.HttpRead(200, "ignored", "application/json", b"{", {}),
             "READ_MALFORMED_RESPONSE"),
            (observer.HttpRead(
                200, "ignored", "application/json",
                b"x" * (observer.MAX_PAGE_BYTES + 1), {}),
             "READ_RESPONSE_LIMIT"),
            (page(10, generation=2), "READ_GENERATION_CHANGE"),
            (page(10, last_seq=9), "READ_CURSOR_REGRESSION"),
        ]
        for candidate, category in cases:
            with self.subTest(category=category):
                fixture = self.fixture([candidate])
                result = fixture.service.prepare()
                self.assertEqual(result.failure_category, category)

    def test_checkpoint_and_export_failures_are_classified(self):
        fixture = self.fixture([page(10)])
        with mock.patch.object(
                observer.PrivateReceiptStore, "save_checkpoint",
                side_effect=RuntimeError("private path should not escape")):
            result = fixture.service.prepare()
        self.assertEqual(result.failure_category, "READ_CHECKPOINT_FAILURE")

        gap = self.fixture([page(10, receipt(seq=12))], cfg=config(max_reads=2))
        result = gap.service.prepare()
        self.assertEqual(result.failure_category, "READ_EXPORT_FAILURE")

    def test_cleanup_failure_does_not_overwrite_original(self):
        fixture = self.fixture([
            page(10), observer.HttpRead(400, "ignored", "", b"", {}),
        ], cfg=config(max_reads=2))
        with mock.patch.object(
                observer.PrivateReceiptStore, "close",
                side_effect=RuntimeError("secret path")):
            result = self.session(fixture, FakeMonotonic()).wait_for_result(2)
        self.assertEqual(result.failure_category, "READ_HTTP_400")

        accepted = self.fixture([page(10), page(10, receipt())])
        with mock.patch.object(
                observer.PrivateReceiptStore, "close",
                side_effect=RuntimeError("secret path")):
            result = self.session(accepted, FakeMonotonic()).wait_for_result(2)
        self.assertEqual(result.status, "ACCEPTED")
        self.assertIsNotNone(result.receipt_sha256)

    def test_unknown_failure_closes_to_internal_and_projection_is_redacted(self):
        secret = "did:key:z6MkSecret /private/path request-secret signature-secret"
        fixture = self.fixture([page(10)])
        fixture.transport.pages.append(RuntimeError(secret))
        result = self.session(fixture, FakeMonotonic()).wait_for_result(2)
        self.assertEqual(result.failure_category, "READ_INTERNAL_FAILURE")
        rendered = repr(result) + json.dumps(dict(result.journal_projection()))
        self.assertNotIn(secret, rendered)
        self.assertNotIn("request-secret", rendered)

    def test_storage_failure_uses_fixed_category(self):
        fixture = self.fixture([page(10)])
        result = fixture.service._safe(
            error=observer.ReceiptObserverError("EVIDENCE_WRITE_FAILED"),
            review=True)
        self.assertEqual(result.failure_category, "READ_STORAGE_FAILURE")
        self.assertEqual(set(result.journal_projection()), {
            "status", "failure_category", "failure_phase", "retryable",
            "observed_at", "read_attempt_count",
        })
        self.assertFalse(dataclasses.is_dataclass(result))
        with self.assertRaises(TypeError):
            dataclasses.asdict(result)
        with self.assertRaises(TypeError):
            vars(result)
        with self.assertRaises(TypeError):
            pickle.dumps(result)
        self.assertEqual(repr(result), "<redacted Sonnet observer result>")

        raw = observer.HttpRead(
            200, "https://private.invalid/path", "private/type",
            b"private body", {"Private": "header"})
        with self.assertRaises(TypeError):
            pickle.dumps(raw)
        self.assertNotIn("private", repr(raw).casefold())
        with self.assertRaises(TypeError):
            pickle.dumps(config())

    def test_terminal_projection_is_finite_and_emitted_once(self):
        result = observer.ObserverResult(
            "UNCONFIRMED", False, False, 3, 10, False, False,
            error_category="HTTP_STATUS", failure_category="READ_HTTP_429",
            failure_phase="POLL", retryable=False, http_status=429,
            observed_at="2026-09-15T04:00:00Z")

        class Completed:
            def wait_for_result(self, _timeout=None):
                return result
            def stop(self):
                pass
            def wait_until_ready(self, _timeout=None):
                return False
            def is_running(self):
                return False

        handle = supervisor.SupervisorHandle(
            Completed(), monotonic=lambda: 1.0, started_at=1.0)
        self.assertEqual(handle.wait_for_terminal(1), supervisor.UNCONFIRMED)
        projection = dict(handle.terminal_projection())
        self.assertEqual(projection["failure_category"], "READ_HTTP_429")
        self.assertEqual(set(projection), {
            "status", "failure_category", "failure_phase", "retryable",
            "observed_at", "read_attempt_count", "http_status",
        })
        scripts = Path(__file__).resolve().parents[1] / "scripts"
        sys.path.insert(0, str(scripts))
        self.addCleanup(lambda: sys.path.remove(str(scripts)))
        runner = importlib.import_module("run_sonnet_receipt_observer")
        emitted = []
        code = runner._run_foreground(handle, threading.Event(), emitted.append)
        self.assertEqual(code, 1)
        terminals = [item for item in emitted if isinstance(item, dict)
                     or getattr(item, "get", lambda _key: None)("status")
                     == supervisor.UNCONFIRMED]
        self.assertEqual(len(terminals), 1)

    def test_clean_supervisor_import_does_not_load_write_or_key_modules(self):
        forbidden = {
            "flop_agent.sonnet_registration_adapters",
            "flop_agent.production_identity_signer",
        }
        for name in forbidden:
            sys.modules.pop(name, None)
        importlib.reload(supervisor)
        self.assertTrue(forbidden.isdisjoint(sys.modules))

    def test_bootstrap_429_retry_is_bounded_inside_outer_wall(self):
        throttled = observer.HttpRead(
            429, observer.FixedReadonlyTransport.highwater_url(), "", b"",
            {"Retry-After": "2"})

        class Transport:
            def __init__(self):
                self.values = [throttled, throttled, throttled]
                self.close_calls = 0
            def read_highwater(self):
                return self.values.pop(0)
            def close(self):
                self.close_calls += 1

        clock = FakeMonotonic()
        transport = Transport()
        unit = supervisor._build_receipt_supervisor_for_test(
            private_runtime_root=Path("/fixture/private"),
            transport_factory=lambda: transport,
            observer_factory=lambda **_kwargs: None,
            clock=lambda: NOW, monotonic=clock)
        with mock.patch.object(
                supervisor.time, "sleep",
                side_effect=lambda seconds: setattr(
                    clock, "value", clock.value + seconds)):
            with self.assertRaises(observer.ReceiptObserverError) as caught:
                unit.start()
        self.assertEqual(caught.exception.category, "READ_HTTP_429")
        self.assertFalse(caught.exception.retryable)
        self.assertEqual(caught.exception.read_attempt_count, 3)
        self.assertEqual(clock.value, 4)
        self.assertEqual(transport.close_calls, 1)

    def test_bootstrap_stop_and_cleanup_preserve_safe_terminal_cause(self):
        stopped = observer.ReceiptObserverError("SUPERVISOR_STOPPED")
        projection = dict(supervisor.safe_start_failure_projection(stopped))
        self.assertEqual(projection["status"], supervisor.STOPPED)
        self.assertEqual(projection["failure_category"], "READ_STOPPED")

        class Transport:
            def read_highwater(self):
                raise observer._read_error("READ_TLS_FAILURE", "POLL")
            def close(self):
                raise RuntimeError("private cleanup detail")

        unit = supervisor._build_receipt_supervisor_for_test(
            private_runtime_root=Path("/fixture/private"),
            transport_factory=Transport,
            observer_factory=lambda **_kwargs: None,
            clock=lambda: NOW)
        with self.assertRaises(observer.ReceiptObserverError) as caught:
            unit.start()
        self.assertEqual(caught.exception.category, "READ_TLS_FAILURE")
        self.assertNotIn("private cleanup", repr(caught.exception))

        throttled = observer.HttpRead(
            429, observer.FixedReadonlyTransport.highwater_url(), "", b"",
            {"Retry-After": "2"})

        class ThrottledTransport:
            def read_highwater(self):
                return throttled
            def close(self):
                pass

        class StopDuringWait:
            stopped = False
            def is_set(self):
                return self.stopped
            def wait(self, _seconds):
                self.stopped = True
                return True

        unit = supervisor._build_receipt_supervisor_for_test(
            private_runtime_root=Path("/fixture/private"),
            transport_factory=ThrottledTransport,
            observer_factory=lambda **_kwargs: None,
            clock=lambda: NOW)
        with self.assertRaisesRegex(
                observer.ReceiptObserverError, "SUPERVISOR_STOPPED"):
            unit.start(stop_requested=StopDuringWait())

    def test_runner_output_failure_is_single_and_never_reemitted(self):
        result = observer.ObserverResult(
            "UNCONFIRMED", False, False, 1, 1, False, False,
            error_category="SUPERVISOR_TIMEOUT",
            failure_category="READ_WALL_TIMEOUT", failure_phase="POLL",
            observed_at="2026-09-15T04:00:00Z")

        class Completed:
            def wait_until_ready(self, _timeout=None):
                return False
            def wait_for_result(self, _timeout=None):
                return result
            def stop(self):
                pass
            def is_running(self):
                return False

        handle = supervisor.SupervisorHandle(
            Completed(), monotonic=lambda: 1.0, started_at=1.0)
        calls = []

        def failed_emit(value):
            calls.append(value)
            return False

        scripts = Path(__file__).resolve().parents[1] / "scripts"
        sys.path.insert(0, str(scripts))
        self.addCleanup(lambda: sys.path.remove(str(scripts)))
        runner = importlib.import_module("run_sonnet_receipt_observer")
        with mock.patch("builtins.print", side_effect=BrokenPipeError("detail")):
            self.assertFalse(runner._emit("OBSERVER_UNCONFIRMED"))
        self.assertEqual(
            runner._run_foreground(handle, threading.Event(), failed_emit), 1)
        self.assertEqual(len(calls), 1)

    def test_ready_terminal_paths_have_fixed_categories_and_phases(self):
        fixture = self.fixture([page(10)], cfg=config(max_reads=1))
        result = self.session(fixture, FakeMonotonic()).wait_for_result(2)
        self.assertEqual(
            (result.failure_category, result.failure_phase),
            ("READ_BOUND_EXHAUSTED", "POLL"))

    def test_session_constructor_failure_closes_transport_and_store(self):
        class Resource:
            def __init__(self):
                self.closed = 0
            def close(self):
                self.closed += 1

        core = type("Core", (), {})()
        core._transport = Resource()
        core._store = Resource()
        service = observer._ProductionReceiptObserver(
            core, lambda _core: (_ for _ in ()).throw(
                RuntimeError("private constructor detail")))
        with self.assertRaises(RuntimeError):
            service.start()
        self.assertEqual(core._transport.closed, 1)
        self.assertEqual(core._store.closed, 1)

    def test_transport_exception_repr_never_contains_underlying_message(self):
        transport = observer.FixedReadonlyTransport()
        with mock.patch.object(
                transport._opener, "open",
                side_effect=ssl.SSLError("private hostname and path")):
            with self.assertRaises(observer.ReceiptObserverError) as caught:
                transport.read_highwater()
        self.assertEqual(caught.exception.category, "READ_TLS_FAILURE")
        self.assertNotIn("hostname", repr(caught.exception))

        for raised, category in (
            (socket.timeout("private host"), "READ_NETWORK_TIMEOUT"),
            (urllib.error.URLError(ConnectionResetError("private host")),
             "READ_CONNECTION_FAILURE"),
        ):
            transport = observer.FixedReadonlyTransport()
            with mock.patch.object(transport._opener, "open", side_effect=raised):
                with self.assertRaises(observer.ReceiptObserverError) as caught:
                    transport.read_highwater()
            self.assertEqual(caught.exception.category, category)
            self.assertNotIn("private host", repr(caught.exception))


if __name__ == "__main__":
    unittest.main()
