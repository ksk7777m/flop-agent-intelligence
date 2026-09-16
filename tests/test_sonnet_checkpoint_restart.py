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


def lineage(**updates):
    values = {
        "contest_id": observer.CONTEST_ID,
        "origin": observer.OFFICIAL_ORIGIN,
        "room": observer.ROOM,
        "request_id": observer.registration.REQUEST_ID,
        "participant_did": observer.registration.PARTICIPANT_DID,
        "role": observer.ROLE,
        "x_account_url": observer.registration.X_ACCOUNT_URL,
        "referee_did": observer.REFEREE_DID,
        "manifest_commit": observer.MANIFEST_COMMIT,
        "manifest_sha256": observer.MANIFEST_SHA256,
    }
    values.update(updates)
    return observer._lineage_binding_sha256(**values)


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
                observer.registration.REQUEST_ID.encode()).hexdigest(),
            lineage_binding_sha256=lineage())
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
                    observer.registration.REQUEST_ID.encode()).hexdigest(),
                lineage_binding_sha256=lineage())
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
                request_reference_sha256=reference,
                lineage_binding_sha256=lineage())
            progress = self.child / observer.CURSOR_PROGRESS_BASENAME
            original = progress.read_bytes()
            store.save_checkpoint(
                generation=1, cursor=12, observation_started_at=identity,
                request_reference_sha256=reference,
                lineage_binding_sha256=lineage())
            self.assertEqual(progress.read_bytes(), original)
            with self.assertRaisesRegex(
                    observer.ReceiptObserverError,
                    "CHECKPOINT_RESTART_BINDING_INVALID"):
                store.save_checkpoint(
                    generation=1, cursor=11,
                    observation_started_at=identity,
                    request_reference_sha256=reference,
                    lineage_binding_sha256=lineage())
        finally:
            store.close()

    def test_progress_without_lineage_and_temporary_artifact_fail_closed(self):
        progress = {
            "schema": "sonnet-registration-receipt-progress.v2",
            "request_reference_sha256": hashlib.sha256(
                observer.registration.REQUEST_ID.encode()).hexdigest(),
            "lineage_binding_sha256": lineage(),
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
                request_reference_sha256=reference,
                lineage_binding_sha256=lineage())
            with mock.patch.object(
                    observer.os, "rename", side_effect=OSError("fixture")):
                with self.assertRaisesRegex(
                        observer.ReceiptObserverError,
                        "EVIDENCE_WRITE_FAILED"):
                    store.save_checkpoint(
                        generation=1, cursor=12,
                        observation_started_at=identity,
                        request_reference_sha256=reference,
                        lineage_binding_sha256=lineage())
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
        before = {
            path.name: path.read_bytes() for path in self.child.iterdir()
            if path.is_file()}
        result = dict(observer.validate_production_restart(
            private_runtime_root=self.root))
        self.assertEqual(result, {
            "status": "RESTART_VALIDATION_PASS",
            "mode": observer.RESUMING_OBSERVATION,
        })
        self.assertEqual(next(self.child.glob("*.checkpoint")).read_bytes(), original)
        self.assertEqual({
            path.name: path.read_bytes() for path in self.child.iterdir()
            if path.is_file()}, before)
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

    def test_lineage_digest_is_deterministic_and_every_binding_is_exact(self):
        baseline = lineage()
        self.assertEqual(baseline, lineage())
        changes = {
            "contest_id": "sonnet-other",
            "origin": "https://example.invalid",
            "room": "other-room",
            "request_id": "other-request",
            "participant_did": "did:key:other",
            "role": "voter",
            "x_account_url": "https://x.com/other",
            "referee_did": "did:key:referee-other",
            "manifest_commit": "0" * 40,
            "manifest_sha256": "0" * 64,
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                self.assertNotEqual(baseline, lineage(**{field: value}))
        with self.assertRaisesRegex(
                observer.ReceiptObserverError, "LINEAGE_BINDING_INVALID"):
            lineage(role=True)

    def test_same_request_id_with_changed_full_lineage_fails_before_network(self):
        self.seed_checkpoint()
        for field, value in {
            "contest_id": "sonnet-other",
            "origin": "https://example.invalid",
            "room": "other-room",
            "participant_did": "did:key:other",
            "role": "voter",
            "x_account_url": "https://x.com/other",
            "referee_did": "did:key:referee-other",
            "manifest_commit": "0" * 40,
            "manifest_sha256": "0" * 64,
        }.items():
            with self.subTest(field=field), self.assertRaisesRegex(
                    observer.ReceiptObserverError,
                    "CHECKPOINT_RESTART_BINDING_INVALID"):
                observer._prepare_restart_core(
                    self.root, clock=lambda: START_B, create_lock=True,
                    _worktrees=lambda _root: (observer.REPOSITORY_ROOT,),
                    _filesystem_validator=lambda _path: True,
                    _lineage_binding_sha256=lineage(**{field: value}))

    def test_changed_request_id_or_progress_lineage_fails_closed(self):
        self.seed_checkpoint(cursor=10)
        with self.assertRaisesRegex(
                observer.ReceiptObserverError,
                "CHECKPOINT_RESTART_BINDING_INVALID"):
            observer._prepare_restart_core(
                self.root, clock=lambda: START_B, create_lock=True,
                _worktrees=lambda _root: (observer.REPOSITORY_ROOT,),
                _filesystem_validator=lambda _path: True,
                _request_id="other-request",
                _lineage_binding_sha256=lineage(request_id="other-request"))
        capability = self.prepare(lambda: START_B)
        store, _mode, _checkpoint, identity = capability._consume()
        try:
            store.save_checkpoint(
                generation=1, cursor=11, observation_started_at=identity,
                request_reference_sha256=hashlib.sha256(
                    observer.registration.REQUEST_ID.encode()).hexdigest(),
                lineage_binding_sha256=lineage())
        finally:
            store.close()
        progress = self.child / observer.CURSOR_PROGRESS_BASENAME
        value = json.loads(progress.read_text())
        value["lineage_binding_sha256"] = lineage(role="voter")
        progress.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")))
        os.chmod(progress, 0o600)
        with self.assertRaisesRegex(
                observer.ReceiptObserverError,
                "CHECKPOINT_RESTART_BINDING_INVALID"):
            self.prepare(lambda: START_B)

    def test_legacy_checkpoint_has_fixed_category_and_is_not_rewritten(self):
        capability = self.prepare()
        store, _mode, _checkpoint, identity = capability._consume()
        reference = hashlib.sha256(
            observer.registration.REQUEST_ID.encode()).hexdigest()
        value = {
            "schema": "sonnet-registration-receipt-checkpoint.v1",
            "request_reference_sha256": reference,
            "contest_id": observer.CONTEST_ID,
            "room": observer.ROOM,
            "generation": 1,
            "cursor": 10,
            "observation_started_at": identity.isoformat().replace("+00:00", "Z"),
        }
        raw = json.dumps(
            value, sort_keys=True, separators=(",", ":")).encode()
        name = f"{hashlib.sha256(raw).hexdigest()}.checkpoint"
        store._atomic_write(name, raw)
        store.close()
        before = (self.child / name).read_bytes()
        result = dict(observer.validate_production_restart(
            private_runtime_root=self.root))
        self.assertEqual(
            result["status"], "LEGACY_CHECKPOINT_LINEAGE_UNVERIFIED")
        self.assertEqual((self.child / name).read_bytes(), before)
        self.assertFalse(any(
            path.name == observer.CURSOR_PROGRESS_BASENAME
            for path in self.child.iterdir()))
        verifier = observer.PrivateReceiptStore(self.child)
        try:
            verifier.acquire_session_lock(create=False)
        finally:
            verifier.close()

    def test_v2_checkpoint_duplicate_and_unexpected_fields_fail_closed(self):
        capability = self.prepare()
        store, _mode, _checkpoint, identity = capability._consume()
        store.close()
        base = {
            "schema": "sonnet-registration-receipt-checkpoint.v2",
            "request_reference_sha256": hashlib.sha256(
                observer.registration.REQUEST_ID.encode()).hexdigest(),
            "lineage_binding_sha256": lineage(),
            "contest_id": observer.CONTEST_ID,
            "room": observer.ROOM,
            "generation": 1,
            "cursor": 10,
            "observation_started_at": identity.isoformat().replace("+00:00", "Z"),
        }
        canonical = json.dumps(
            base, sort_keys=True, separators=(",", ":")).encode()
        variants = (
            b'{"schema":"duplicate",' + canonical[1:],
            json.dumps(
                {**base, "unexpected": "field"}, sort_keys=True,
                separators=(",", ":")).encode(),
        )
        for index, raw in enumerate(variants):
            with self.subTest(variant=index):
                name = f"{hashlib.sha256(raw).hexdigest()}.checkpoint"
                writer = observer.PrivateReceiptStore(self.child)
                try:
                    writer._atomic_write(name, raw)
                finally:
                    writer.close()
                with self.assertRaises(observer.ReceiptObserverError):
                    self.prepare(lambda: START_B)
                (self.child / name).unlink()

    def test_partial_artifact_rejects_nonregular_and_unsafe_files(self):
        self.seed_checkpoint()
        digest = "a" * 64
        target = self.child / f"{digest}.receipt"
        target.mkdir()
        with self.assertRaisesRegex(
                observer.ReceiptObserverError, "EVIDENCE_FILE_UNSAFE"):
            self.prepare(lambda: START_B)
        target.rmdir()
        target.symlink_to(self.child)
        with self.assertRaisesRegex(
                observer.ReceiptObserverError, "EVIDENCE_FILE_UNSAFE"):
            self.prepare(lambda: START_B)

    def test_partial_artifact_rejects_owner_and_size_mismatch(self):
        self.seed_checkpoint()
        target = self.child / f"{'d' * 64}.json"
        target.write_bytes(b"partial")
        os.chmod(target, 0o600)
        store = observer.PrivateReceiptStore(self.child)
        try:
            with mock.patch.object(
                    observer.PrivateReceiptStore, "_check_root",
                    return_value=store._fd), mock.patch.object(
                        observer.os, "getuid", return_value=os.getuid() + 1):
                with self.assertRaisesRegex(
                        observer.ReceiptObserverError, "EVIDENCE_FILE_UNSAFE"):
                    store._validate_artifact_file(target.name, observer.MAX_PAGE_BYTES)
        finally:
            store.close()
        target.write_bytes(b"x" * (observer.MAX_PAGE_BYTES + 1))
        os.chmod(target, 0o600)
        with self.assertRaisesRegex(
                observer.ReceiptObserverError, "EVIDENCE_FILE_UNSAFE"):
            self.prepare(lambda: START_B)
        target.unlink()
        os.mkfifo(target, 0o600)
        with self.assertRaisesRegex(
                observer.ReceiptObserverError, "EVIDENCE_FILE_UNSAFE"):
            self.prepare(lambda: START_B)
        target.unlink()
        target.write_bytes(b"partial")
        os.chmod(target, 0o644)
        with self.assertRaisesRegex(
                observer.ReceiptObserverError, "EVIDENCE_FILE_UNSAFE"):
            self.prepare(lambda: START_B)
        os.chmod(target, 0o600)
        hardlink = self.child / f"{'b' * 64}.receipt"
        os.link(target, hardlink)
        with self.assertRaisesRegex(
                observer.ReceiptObserverError, "EVIDENCE_FILE_UNSAFE"):
            self.prepare(lambda: START_B)

    def test_safe_partial_regular_file_replays_without_mutation(self):
        self.seed_checkpoint()
        target = self.child / f"{'c' * 64}.receipt"
        target.write_bytes(b"partial")
        os.chmod(target, 0o600)
        before = target.read_bytes()
        capability = self.prepare(lambda: START_B)
        capability.close()
        self.assertEqual(target.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
