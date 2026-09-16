import copy
import hashlib
import json
import os
import pickle
import stat
import tempfile
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flop_agent import sonnet_receipt_observer as observer
from flop_agent import sonnet_receipt_supervisor as supervisor


START_A = datetime(2026, 9, 15, 4, 0, tzinfo=timezone.utc)
START_B = START_A + timedelta(hours=3)


class RestartBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        os.chmod(self.root, 0o700)
        self.child = self.root / observer.RECEIPT_CHILD_BASENAME
        self.child.mkdir(mode=0o700)

    def prepare(self, clock=lambda: START_A):
        return observer._prepare_restart_core(
            self.root, clock=clock, create_lock=True,
            _worktrees=lambda _root: (observer.REPOSITORY_ROOT,),
            _filesystem_validator=lambda _path: True)

    def seed_checkpoint(self, *, generation=1, cursor=10):
        capability = self.prepare()
        store, mode, checkpoint, identity = capability._consume()
        self.assertEqual(mode, observer.NEW_OBSERVATION)
        self.assertIsNone(checkpoint)
        store.save_checkpoint(
            generation=generation, cursor=cursor,
            observation_started_at=identity,
            request_reference_sha256=hashlib.sha256(
                observer.registration.REQUEST_ID.encode()).hexdigest())
        store.close()
        return next(self.child.glob("*.checkpoint")).read_bytes()

    def test_new_observation_generates_identity_once_and_is_opaque(self):
        calls = []
        capability = self.prepare(lambda: calls.append(START_A) or START_A)
        self.assertEqual(capability.mode, observer.NEW_OBSERVATION)
        self.assertEqual(calls, [START_A])
        rendered = repr(capability)
        self.assertNotIn(str(self.root), rendered)
        self.assertNotIn(START_A.isoformat(), rendered)
        with self.assertRaises(TypeError):
            copy.copy(capability)
        with self.assertRaises(TypeError):
            copy.deepcopy(capability)
        with self.assertRaises(TypeError):
            pickle.dumps(capability)
        capability.close()

    def test_valid_checkpoint_resumes_without_fresh_wall_clock_match(self):
        original = self.seed_checkpoint()
        capability = self.prepare(lambda: START_B)
        store, mode, checkpoint, identity = capability._consume()
        try:
            self.assertEqual(mode, observer.RESUMING_OBSERVATION)
            self.assertEqual(identity, START_A)
            self.assertNotEqual(identity, START_B)
            self.assertIsNotNone(checkpoint)
            self.assertEqual(next(self.child.glob("*.checkpoint")).read_bytes(), original)
        finally:
            store.close()

    def test_resume_progress_preserves_lineage_and_durably_advances_cursor(self):
        original = self.seed_checkpoint(cursor=10)
        capability = self.prepare(lambda: START_B)
        store, _mode, _checkpoint, identity = capability._consume()
        try:
            store.save_checkpoint(
                generation=1, cursor=11, observation_started_at=identity,
                request_reference_sha256=hashlib.sha256(
                    observer.registration.REQUEST_ID.encode()).hexdigest())
        finally:
            store.close()
        checkpoints = list(self.child.glob("*.checkpoint"))
        self.assertEqual(len(checkpoints), 1)
        self.assertEqual(checkpoints[0].read_bytes(), original)
        resumed = self.prepare(lambda: START_B)
        resumed_store, mode, checkpoint, resumed_identity = resumed._consume()
        try:
            self.assertEqual(mode, observer.RESUMING_OBSERVATION)
            self.assertEqual(checkpoint["cursor"], 11)
            self.assertEqual(resumed_identity, identity)
        finally:
            resumed_store.close()

    def test_cursor_regression_is_rejected_and_same_cursor_is_not_rewritten(self):
        self.seed_checkpoint(cursor=10)
        capability = self.prepare(lambda: START_B)
        store, _mode, _checkpoint, identity = capability._consume()
        reference = hashlib.sha256(
            observer.registration.REQUEST_ID.encode()).hexdigest()
        try:
            store.save_checkpoint(
                generation=1, cursor=12, observation_started_at=identity,
                request_reference_sha256=reference)
            progress = self.child / observer.CURSOR_PROGRESS_BASENAME
            original = progress.read_bytes()
            store.save_checkpoint(
                generation=1, cursor=12, observation_started_at=identity,
                request_reference_sha256=reference)
            self.assertEqual(progress.read_bytes(), original)
            with self.assertRaisesRegex(
                    observer.ReceiptObserverError,
                    "CHECKPOINT_RESTART_BINDING_INVALID"):
                store.save_checkpoint(
                    generation=1, cursor=11,
                    observation_started_at=identity,
                    request_reference_sha256=reference)
        finally:
            store.close()

    def test_progress_without_lineage_and_temporary_artifact_fail_closed(self):
        progress = {
            "schema": "sonnet-registration-receipt-progress.v1",
            "request_reference_sha256": hashlib.sha256(
                observer.registration.REQUEST_ID.encode()).hexdigest(),
            "contest_id": observer.CONTEST_ID,
            "room": observer.ROOM,
            "generation": 1,
            "cursor": 11,
            "observation_started_at": START_A.isoformat().replace(
                "+00:00", "Z"),
        }
        path = self.child / observer.CURSOR_PROGRESS_BASENAME
        path.write_text(json.dumps(progress, separators=(",", ":")))
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(
                observer.ReceiptObserverError,
                "CHECKPOINT_RESTART_BINDING_INVALID"):
            self.prepare(lambda: START_B)
        path.unlink()
        self.seed_checkpoint(cursor=10)
        temporary = self.child / ".tmp-crash-artifact"
        temporary.write_bytes(b"not-a-checkpoint")
        os.chmod(temporary, 0o600)
        with self.assertRaisesRegex(
                observer.ReceiptObserverError, "EVIDENCE_UNKNOWN_ARTIFACT"):
            self.prepare(lambda: START_B)

    def test_failed_progress_rename_preserves_last_durable_cursor(self):
        self.seed_checkpoint(cursor=10)
        capability = self.prepare(lambda: START_B)
        store, _mode, _checkpoint, identity = capability._consume()
        reference = hashlib.sha256(
            observer.registration.REQUEST_ID.encode()).hexdigest()
        try:
            store.save_checkpoint(
                generation=1, cursor=11, observation_started_at=identity,
                request_reference_sha256=reference)
            with mock.patch.object(
                    observer.os, "rename", side_effect=OSError("fixture")):
                with self.assertRaisesRegex(
                        observer.ReceiptObserverError,
                        "EVIDENCE_WRITE_FAILED"):
                    store.save_checkpoint(
                        generation=1, cursor=12,
                        observation_started_at=identity,
                        request_reference_sha256=reference)
        finally:
            store.close()
        resumed = self.prepare(lambda: START_B)
        resumed_store, _mode, checkpoint, _identity = resumed._consume()
        try:
            self.assertEqual(checkpoint["cursor"], 11)
            self.assertFalse(any(
                path.name.startswith(".tmp-") for path in self.child.iterdir()))
        finally:
            resumed_store.close()

    def test_resume_factory_uses_saved_generation_cursor_and_identity(self):
        self.seed_checkpoint(generation=2, cursor=14)
        capability = self.prepare(lambda: START_B)
        service = observer.build_production_receipt_observer(
            restart_capability=capability)
        try:
            config = service._observer._config
            self.assertEqual(config.expected_generation, 2)
            self.assertEqual(config.initial_since, 14)
            self.assertEqual(config.observation_started_at, START_A)
        finally:
            service._observer._store.close()

    def test_caller_cannot_override_saved_binding(self):
        self.seed_checkpoint()
        capability = self.prepare(lambda: START_B)
        with self.assertRaisesRegex(
                observer.ReceiptObserverError, "RESTART_CAPABILITY_INVALID"):
            observer.build_production_receipt_observer(
                restart_capability=capability,
                observed_generation=9, observed_cursor=99)
        reopened = self.prepare(lambda: START_B)
        reopened.close()

    def test_duplicate_checkpoint_is_ambiguous_without_selection(self):
        self.seed_checkpoint(cursor=10)
        store = observer.PrivateReceiptStore(self.child)
        try:
            value = {
                "schema": "sonnet-registration-receipt-checkpoint.v1",
                "request_reference_sha256": hashlib.sha256(
                    observer.registration.REQUEST_ID.encode()).hexdigest(),
                "contest_id": observer.CONTEST_ID,
                "room": observer.ROOM,
                "generation": 1,
                "cursor": 11,
                "observation_started_at": START_A.isoformat().replace(
                    "+00:00", "Z"),
            }
            raw = json.dumps(
                value, sort_keys=True, separators=(",", ":")).encode()
            store._atomic_write(
                f"{hashlib.sha256(raw).hexdigest()}.checkpoint", raw)
        finally:
            store.close()
        with self.assertRaisesRegex(
                observer.ReceiptObserverError,
                "CHECKPOINT_RESTART_AMBIGUOUS"):
            self.prepare(lambda: START_B)

    def test_invalid_checkpoint_never_falls_back_to_new(self):
        self.seed_checkpoint()
        path = next(self.child.glob("*.checkpoint"))
        path.write_bytes(path.read_bytes() + b"x")
        os.chmod(path, 0o600)
        with self.assertRaises(observer.ReceiptObserverError):
            self.prepare(lambda: START_B)

    def test_lock_contention_fails_before_supervisor_transport(self):
        capability = self.prepare()
        calls = []
        unit = supervisor._build_receipt_supervisor_for_test(
            private_runtime_root=self.root,
            restart_factory=lambda **_kwargs: self.prepare(),
            transport_factory=lambda: calls.append("network"),
            observer_factory=lambda **_kwargs: None, clock=lambda: START_B)
        with self.assertRaisesRegex(
                observer.ReceiptObserverError, "EVIDENCE_LOCK_HELD"):
            unit.start()
        self.assertEqual(calls, [])
        capability.close()

    def test_read_only_validation_changes_no_bytes_and_uses_sanitized_result(self):
        original = self.seed_checkpoint()
        result = dict(observer.validate_production_restart(
            private_runtime_root=self.root))
        self.assertEqual(result, {
            "status": "RESTART_VALIDATION_PASS",
            "mode": observer.RESUMING_OBSERVATION,
        })
        self.assertEqual(next(self.child.glob("*.checkpoint")).read_bytes(), original)
        rendered = json.dumps(result)
        self.assertNotIn(str(self.root), rendered)
        self.assertNotIn(START_A.isoformat(), rendered)

    def test_read_only_validation_accepts_empty_child_without_creating_lock(self):
        before = list(self.child.iterdir())
        result = dict(observer.validate_production_restart(
            private_runtime_root=self.root))
        self.assertEqual(result["status"], "NEW_OBSERVATION_AVAILABLE")
        self.assertEqual(list(self.child.iterdir()), before)

    def test_resume_supervisor_skips_highwater_and_passes_opaque_capability(self):
        class Capability:
            mode = observer.RESUMING_OBSERVATION
            def close(self):
                pass

        class Session:
            def wait_for_result(self, _timeout=None):
                return observer.ObserverResult(
                    "UNCONFIRMED", False, False, 0, 0, False, False,
                    error_category="SUPERVISOR_STOPPED")
            def wait_until_ready(self, _timeout=None):
                return False
            def stop(self):
                pass
            def is_running(self):
                return False

        class Service:
            def start(self):
                return Session()

        network = []
        calls = []
        capability = Capability()
        unit = supervisor._build_receipt_supervisor_for_test(
            private_runtime_root=self.root,
            restart_factory=lambda **_kwargs: capability,
            transport_factory=lambda: network.append(True),
            observer_factory=lambda **kwargs: calls.append(kwargs) or Service(),
            clock=lambda: START_B)
        handle = unit.start()
        self.assertEqual(network, [])
        self.assertIs(calls[0]["restart_capability"], capability)
        self.assertEqual(set(calls[0]), {"restart_capability"})
        self.assertIsNotNone(handle.wait_for_terminal(1))

    def test_new_factory_rejects_missing_or_boolean_network_binding(self):
        capability = self.prepare()
        with self.assertRaisesRegex(
                observer.ReceiptObserverError, "RESTART_CAPABILITY_INVALID"):
            observer.build_production_receipt_observer(
                restart_capability=capability,
                observed_generation=True, observed_cursor=10)

    def test_process_budget_starts_before_storage_and_ignores_wall_clock(self):
        class Monotonic:
            value = 0.0
            def __call__(self):
                return self.value

        class Capability:
            mode = observer.NEW_OBSERVATION
            def close(self):
                pass

        class Transport:
            def read_highwater(self):
                body = {
                    "room": observer.ROOM, "count": 0, "first_seq": None,
                    "last_seq": 10, "generation": 1, "messages": [],
                }
                return observer.HttpRead(
                    200, observer.FixedReadonlyTransport.highwater_url(),
                    "application/json", json.dumps(body).encode(), {})
            def close(self):
                pass

        class Session:
            def wait_for_result(self, _timeout=None):
                return observer.ObserverResult(
                    "UNCONFIRMED", False, False, 0, 0, False, False,
                    error_category="SUPERVISOR_STOPPED")
            def wait_until_ready(self, _timeout=None):
                return False
            def stop(self):
                pass
            def is_running(self):
                return False

        class Service:
            def start(self):
                return Session()

        monotonic = Monotonic()
        def validate_storage(**_kwargs):
            monotonic.value = 100.0
            return Capability()
        unit = supervisor._build_receipt_supervisor_for_test(
            private_runtime_root=self.root,
            restart_factory=validate_storage,
            transport_factory=Transport,
            observer_factory=lambda **_kwargs: Service(),
            clock=lambda: START_B + timedelta(days=100),
            monotonic=monotonic, waiter=lambda _event, _seconds: False)
        handle = unit.start()
        self.assertEqual(handle.remaining_seconds(), 1700)

    def test_storage_validation_consumes_and_can_exhaust_process_budget(self):
        class Monotonic:
            value = 0.0
            def __call__(self):
                return self.value
        class Capability:
            mode = observer.NEW_OBSERVATION
            closed = False
            def close(self):
                self.closed = True
        monotonic = Monotonic()
        capability = Capability()
        network = []
        def slow_validation(**_kwargs):
            monotonic.value = observer.SUPERVISOR_MAX_WALL_SECONDS
            return capability
        unit = supervisor._build_receipt_supervisor_for_test(
            private_runtime_root=self.root,
            restart_factory=slow_validation,
            transport_factory=lambda: network.append(True),
            observer_factory=lambda **_kwargs: None,
            clock=lambda: START_A, monotonic=monotonic)
        with self.assertRaises(observer.ReceiptObserverError):
            unit.start()
        self.assertTrue(capability.closed)
        self.assertEqual(network, [])

    def test_checkpoint_files_remain_private_regular_single_links(self):
        self.seed_checkpoint()
        info = next(self.child.glob("*.checkpoint")).lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(info.st_uid, os.getuid())
        self.assertEqual(info.st_nlink, 1)


if __name__ == "__main__":
    unittest.main()
