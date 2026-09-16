import pickle
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType

from flop_agent import sonnet_attended_registration as attended
from flop_agent import sonnet_receipt_observer as observer
from flop_agent import sonnet_receipt_supervisor as supervisor
from flop_agent import sonnet_registration as registration
from flop_agent import sonnet_registration_handoff as handoff


APPROVAL_ID = "a" * 64


def approval():
    return {"approval_id": APPROVAL_ID}


NOW = datetime(2026, 9, 16, 9, 0, tzinfo=timezone.utc)


def full_approval():
    return {
        "schema": handoff.APPROVAL_SCHEMA_VERSION,
        "approval_id": APPROVAL_ID, "decision": "APPROVED",
        "reviewer": attended.LOCAL_REVIEWER,
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
        "issued_at": "2026-09-16T08:59:00Z",
        "expires_at": "2026-09-16T09:10:00Z",
        "journal_id": handoff.JOURNAL_ID,
    }


class FakeHandle:
    def __init__(self, *, ready=True, running=True, remaining=100, terminal=None):
        self.ready = ready
        self.running = running
        self.remaining = remaining
        self.stopped = 0
        self.terminal = terminal

    def wait_until_ready(self, _timeout=None): return self.ready
    def is_running(self): return self.running
    def remaining_seconds(self): return self.remaining
    def wait_for_terminal(self, _timeout=None):
        if self.terminal is not None:
            self.running = False
        return self.terminal
    def terminal_projection(self): return None
    def stop(self): self.stopped += 1; self.running = False


class FakeService:
    def __init__(self, effects): self.effects = effects
    def execute(self, _candidate, approval_id):
        self.effects.extend(["key", "sign", "post"])
        return MappingProxyType({"status": "AWAITING_REFEREE_RECEIPT",
                                 "approval_id": approval_id})
    def reconcile(self, record):
        self.effects.append(("reconcile", record))
        return {"status": "RECEIPT_ACCEPTED"}


class AttendedRegistrationTests(unittest.TestCase):
    def session(self, *, handle=None, state="NOT_STARTED", effects=None):
        effects = [] if effects is None else effects
        return attended._build_attended_session_for_test(
            handle=handle or FakeHandle(),
            handoff_factory=lambda **_kwargs: FakeService(effects),
            journal_inspect=lambda: {"state": state})

    def test_ready_live_session_executes_once_and_is_not_serializable(self):
        effects = []
        session = self.session(effects=effects)
        self.assertTrue(session.wait_until_ready(0))
        result = session.execute_approved_registration(approval())
        self.assertEqual(result["status"], "AWAITING_REFEREE_RECEIPT")
        self.assertEqual(effects, ["key", "sign", "post"])
        with self.assertRaises(attended.AttendedRegistrationError):
            session.execute_approved_registration(approval())
        with self.assertRaises(TypeError):
            pickle.dumps(session)

    def test_ready_before_live_after_end_and_short_budget_are_rejected(self):
        cases = (
            (FakeHandle(ready=False), False),
            (FakeHandle(running=False), True),
            (FakeHandle(remaining=attended.MINIMUM_EXECUTION_REMAINING_SECONDS), True),
        )
        for handle, call_ready in cases:
            with self.subTest(handle=handle):
                effects = []
                session = self.session(handle=handle, effects=effects)
                if call_ready:
                    session.wait_until_ready(0)
                with self.assertRaises(attended.AttendedRegistrationError):
                    session.execute_approved_registration(approval())
                self.assertEqual(effects, [])

    def test_non_not_started_journal_rejects_before_effects(self):
        effects = []
        session = self.session(state="POST_ATTEMPT_RECORDED", effects=effects)
        self.assertTrue(session.wait_until_ready(0))
        with self.assertRaisesRegex(
                attended.AttendedRegistrationError, "REGISTRATION_ALREADY_STARTED"):
            session.execute_approved_registration(approval())
        self.assertEqual(effects, [])

    def test_liveness_is_rechecked_by_handoff_checker(self):
        handle = FakeHandle()
        observed = []

        class Service:
            def execute(self, _candidate, _approval_id):
                handle.running = False
                observed.append(factory_checker())
                if observed[-1] != "NO_CONFLICT_IN_OBSERVED_WINDOW":
                    raise handoff.HandoffError("REGISTRATION_STATE_UNRESOLVED")

        factory_checker = None
        def factory(**kwargs):
            nonlocal factory_checker
            factory_checker = kwargs["registration_checker"]
            return Service()

        session = attended._build_attended_session_for_test(
            handle=handle, handoff_factory=factory,
            journal_inspect=lambda: {"state": "NOT_STARTED"})
        self.assertTrue(session.wait_until_ready(0))
        with self.assertRaises(handoff.HandoffError):
            session.execute_approved_registration(approval())
        self.assertEqual(observed, ["OBSERVER_NOT_LIVE"])

    def test_registration_window_must_be_observed_clear_and_rejects_own_request(self):
        fixed = json.loads(registration.PACKET_TEXT)
        conflicts = (
            (registration.PARTICIPANT_DID, fixed,
             attended.adapters.REQUEST_OBSERVED_RECEIPT_UNCONFIRMED),
            (registration.PARTICIPANT_DID, {**fixed, "role": "voter"},
             attended.adapters.REGISTRATION_CONFLICT),
            ("did:key:z6MkUnrelated", {**fixed, "request_id": "other"},
             attended.adapters.REGISTRATION_CONFLICT),
        )
        for sender, packet, expected in conflicts:
            with self.subTest(expected=expected):
                guard = attended._RegistrationWindowGuard()
                self.assertEqual(
                    guard.status(), "REGISTRATION_WINDOW_NOT_OBSERVED")
                guard.inspect_records([], 1)
                with self.assertRaisesRegex(
                        observer.ReceiptObserverError,
                        "REGISTRATION_WINDOW_NOT_CLEAR"):
                    guard.inspect_records([{
                        "seq": 1, "from": sender,
                        "text": json.dumps(packet, sort_keys=True,
                                           separators=(",", ":")),
                    }], 1)
                self.assertEqual(guard.status(), expected)

    def test_bootstrap_inventory_conflict_stops_before_observer_ready(self):
        guard = attended._RegistrationWindowGuard()
        record = {
            "seq": 7, "ts": "2026-09-16T09:00:00Z",
            "from": registration.PARTICIPANT_DID,
            "sig": "A" * 86, "nonce": 7,
            "text": registration.PACKET_TEXT,
        }
        highwater_body = json.dumps({
            "room": observer.ROOM, "count": 1, "first_seq": 7,
            "last_seq": 7, "generation": 1, "messages": [record],
        }, separators=(",", ":")).encode()

        class Capability:
            mode = observer.NEW_OBSERVATION
            def close(self): pass

        class Transport:
            def read_highwater(self):
                return observer.HttpRead(
                    200, observer.FixedReadonlyTransport.highwater_url(),
                    "application/json", highwater_body, MappingProxyType({}))
            def read_export(self):
                return observer.HttpRead(
                    200, observer.FixedReadonlyTransport.export_url(),
                    "application/x-ndjson",
                    json.dumps(record, separators=(",", ":")).encode() + b"\n",
                    MappingProxyType({"X-Room-Generation": "1"}))
            def close(self): pass

        called = []
        ticks = iter(range(0, 100, 10))
        unit = supervisor._ProductionSupervisor(
            private_runtime_root=Path("/fixture"),
            transport_factory=Transport,
            observer_factory=lambda **_kwargs: called.append("observer"),
            restart_factory=lambda **_kwargs: Capability(),
            clock=lambda: NOW, monotonic=lambda: next(ticks),
            waiter=lambda _event, _seconds: False,
            bootstrap_inventory_guard=guard.inspect_records)
        with self.assertRaisesRegex(
                observer.ReceiptObserverError,
                "REGISTRATION_WINDOW_NOT_CLEAR"):
            unit.start()
        self.assertEqual(called, [])

    def test_pre_post_reservation_closes_observer_conflict_race(self):
        guard = attended._RegistrationWindowGuard()
        guard.inspect_records([], 1)
        callbacks = {}
        effects = []
        test_case = self

        class Service:
            def execute(self, _candidate, _approval_id):
                self_checker = callbacks["registration_checker"]
                test_case.assertEqual(
                    self_checker(),
                    attended.adapters.NO_CONFLICT_IN_OBSERVED_WINDOW)
                callbacks["pre_post_check"]()
                callbacks["post_attempt_recorded"]()
                effects.append("post")
                return {"status": "AWAITING_REFEREE_RECEIPT"}

        def factory(**kwargs):
            callbacks.update(kwargs)
            return Service()

        session = attended._build_attended_session_for_test(
            handle=FakeHandle(), handoff_factory=factory,
            journal_inspect=lambda: {"state": "NOT_STARTED"},
            registration_guard=guard)
        self.assertTrue(session.wait_until_ready(0))
        session.execute_approved_registration(approval())
        self.assertEqual(effects, ["post"])
        guard.inspect_records([{
            "seq": 1,
            "from": registration.PARTICIPANT_DID,
            "text": registration.PACKET_TEXT,
        }], 1)

    def test_stop_during_handoff_is_deferred_without_deadlock(self):
        handle = FakeHandle()
        holder = {}

        class Service:
            def execute(self, _candidate, _approval_id):
                holder["session"].stop()
                self.assert_running = handle.is_running()
                return {"status": "AWAITING_REFEREE_RECEIPT"}

        session = attended._build_attended_session_for_test(
            handle=handle, handoff_factory=lambda **_kwargs: Service(),
            journal_inspect=lambda: {"state": "NOT_STARTED"})
        holder["session"] = session
        self.assertTrue(session.wait_until_ready(0))
        session.execute_approved_registration(approval())
        self.assertFalse(handle.is_running())
        self.assertEqual(handle.stopped, 1)

    def test_production_starts_inert_without_approval_or_provisioning(self):
        self.assertFalse(hasattr(attended, "production_approval"))
        self.assertNotEqual(
            attended.observer.RECEIPT_CHILD_BASENAME,
            attended.observer.REGISTRATION_INTERVAL_CHILD_BASENAME)

    def test_real_fixture_handoff_reaches_exactly_one_mock_post(self):
        with tempfile.TemporaryDirectory() as temp:
            effects = []
            root = Path(temp) / "journal"
            root.mkdir(mode=0o700)

            def factory(*, approval, registration_checker, **callbacks):
                def signer(target):
                    effects.extend(["key", "sign"])
                    self.assertEqual(target, registration.SIGNING_TARGET_BYTES)
                    return registration.PARTICIPANT_DID, "A" * 86
                def transport(*_args, **_kwargs):
                    effects.append("post")
                    return handoff.HandoffTransportObservation(
                        200, registration.POST_URL, b'{"ok":true}')
                def fault(point):
                    if point == "BEFORE_POST_ATTEMPT_RECORD":
                        effects.append("reserve")
                        callbacks["pre_post_check"]()
                    elif point == "AFTER_POST_ATTEMPT":
                        effects.append("recorded")
                        callbacks["post_attempt_recorded"]()
                return handoff._build_handoff_for_test(
                    root=root, approvals={APPROVAL_ID: approval},
                    trusted_reviewers=frozenset({attended.LOCAL_REVIEWER}),
                    clock=lambda: NOW,
                    registration_checker=registration_checker,
                    identity_signer=signer, transport=transport,
                    receipt_classifier=lambda _record: {}, fault=fault)

            session = attended._build_attended_session_for_test(
                handle=FakeHandle(), handoff_factory=factory,
                journal_inspect=lambda: {"state": "NOT_STARTED"})
            self.assertTrue(session.wait_until_ready(0))
            result = session.execute_approved_registration(full_approval())
            self.assertEqual(result["status"], "AWAITING_REFEREE_RECEIPT")
            self.assertEqual(
                effects, ["key", "sign", "reserve", "recorded", "post"])
            with self.assertRaises(attended.AttendedRegistrationError):
                session.execute_approved_registration(full_approval())

    def test_408_is_unknown_and_session_cannot_resend(self):
        with tempfile.TemporaryDirectory() as temp:
            effects = []
            root = Path(temp) / "journal"
            root.mkdir(mode=0o700)
            def factory(*, approval, registration_checker, **callbacks):
                def fault(point):
                    if point == "BEFORE_POST_ATTEMPT_RECORD":
                        effects.append("reserve")
                        callbacks["pre_post_check"]()
                    elif point == "AFTER_POST_ATTEMPT":
                        effects.append("recorded")
                        callbacks["post_attempt_recorded"]()
                return handoff._build_handoff_for_test(
                    root=root, approvals={APPROVAL_ID: approval},
                    trusted_reviewers=frozenset({attended.LOCAL_REVIEWER}),
                    clock=lambda: NOW,
                    registration_checker=registration_checker,
                    identity_signer=lambda _target: (
                        registration.PARTICIPANT_DID, "A" * 86),
                    transport=lambda *_args, **_kwargs: (
                        effects.append("post") or handoff.HandoffTransportObservation(
                            408, registration.POST_URL, b"")),
                    receipt_classifier=lambda _record: {}, fault=fault)
            session = attended._build_attended_session_for_test(
                handle=FakeHandle(), handoff_factory=factory,
                journal_inspect=lambda: {"state": "NOT_STARTED"})
            self.assertTrue(session.wait_until_ready(0))
            result = session.execute_approved_registration(full_approval())
            self.assertEqual(result["status"], "WRITE_OUTCOME_UNKNOWN")
            self.assertEqual(effects, ["reserve", "recorded", "post"])
            with self.assertRaises(attended.AttendedRegistrationError):
                session.execute_approved_registration(full_approval())
            self.assertEqual(effects, ["reserve", "recorded", "post"])

    def test_expired_approval_fails_before_key_sign_or_post(self):
        effects = []
        def factory(*, approval, registration_checker, **_callbacks):
            handoff.validate_approval_artifact(
                approval, trusted_reviewers=frozenset({attended.LOCAL_REVIEWER}),
                now=NOW)
            effects.append(registration_checker())
        value = full_approval()
        value["expires_at"] = "2026-09-16T08:59:30Z"
        session = attended._build_attended_session_for_test(
            handle=FakeHandle(), handoff_factory=factory,
            journal_inspect=lambda: {"state": "NOT_STARTED"})
        self.assertTrue(session.wait_until_ready(0))
        with self.assertRaises(handoff.HandoffError):
            session.execute_approved_registration(value)
        self.assertEqual(effects, [])

    def test_exact_human_command_issues_short_lived_fixed_approval(self):
        artifact = attended.issue_local_approval(
            attended.APPROVAL_COMMAND, clock=lambda: NOW,
            token_hex=lambda size: "b" * (size * 2))
        self.assertEqual(set(artifact), set(handoff.approval_schema()["required"]))
        self.assertEqual(artifact["reviewer"], attended.LOCAL_REVIEWER)
        self.assertEqual(artifact["request_id"], registration.REQUEST_ID)
        with self.assertRaises(attended.AttendedRegistrationError):
            attended.issue_local_approval(
                "APPROVE_SOMETHING_ELSE", clock=lambda: NOW)

    def test_terminal_receipt_is_reconciled_into_same_handoff(self):
        effects = []
        handle = FakeHandle(terminal="OBSERVER_ACCEPTED")
        session = attended._build_attended_session_for_test(
            handle=handle, handoff_factory=lambda **_kwargs: FakeService(effects),
            journal_inspect=lambda: {"state": "NOT_STARTED"},
            receipt_records=lambda: [{"signed": "accepted"}])
        self.assertTrue(session.wait_until_ready(0))
        session.execute_approved_registration(approval())
        self.assertEqual(session.wait_for_terminal(0), "OBSERVER_ACCEPTED")
        self.assertEqual(effects[-1], ("reconcile", {"signed": "accepted"}))

    def test_explicit_interval_uses_distinct_child_and_preserves_old_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            os.chmod(root, 0o700)
            old = root / observer.RECEIPT_CHILD_BASENAME
            new = root / observer.REGISTRATION_INTERVAL_CHILD_BASENAME
            old.mkdir(mode=0o700)
            new.mkdir(mode=0o700)
            old_marker = old / "old-evidence"
            old_marker.write_bytes(b"unchanged")
            os.chmod(old_marker, 0o600)
            original = old_marker.read_bytes()

            def open_new(value, *, repository_roots, filesystem_validator):
                return observer._open_receipt_child_core(
                    value, repository_roots=repository_roots,
                    filesystem_validator=filesystem_validator,
                    _child_basename=observer.REGISTRATION_INTERVAL_CHILD_BASENAME)

            capability = observer._prepare_restart_core(
                root, clock=lambda: NOW, create_lock=True,
                _open_child=open_new, _worktrees=lambda _root: (),
                _repository_root=Path("/repository"),
                _filesystem_validator=lambda _path: True)
            self.assertEqual(capability.mode, observer.NEW_OBSERVATION)
            capability.close()
            self.assertEqual(old_marker.read_bytes(), original)
            self.assertEqual(
                {path.name for path in new.iterdir()},
                {observer.SESSION_LOCK_BASENAME})

    def test_provisioning_creates_only_fixed_child_and_start_is_durable_one_shot(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            os.chmod(root, 0o700)
            self.assertEqual(
                attended.provision_registration_interval(
                    private_runtime_root=root, apply=False),
                "REGISTRATION_INTERVAL_PROVISIONING_REQUIRED")
            self.assertEqual(list(root.iterdir()), [])
            self.assertEqual(
                attended.provision_registration_interval(
                    private_runtime_root=root, apply=True),
                "REGISTRATION_INTERVAL_PROVISIONED")
            child = root / observer.REGISTRATION_INTERVAL_CHILD_BASENAME
            self.assertEqual({path.name for path in root.iterdir()}, {child.name})
            self.assertEqual(list(child.iterdir()), [])
            self.assertEqual(stat.S_IMODE(child.stat().st_mode), 0o700)

            capability = observer.prepare_production_registration_interval(
                private_runtime_root=root)
            capability.close()
            with self.assertRaisesRegex(
                    observer.ReceiptObserverError,
                    "REGISTRATION_INTERVAL_ALREADY_STARTED"):
                observer.prepare_production_registration_interval(
                    private_runtime_root=root)

    def test_provisioning_revalidates_root_at_creation_time(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            os.chmod(root, 0o700)
            with mock.patch.object(
                    attended, "_interval_child_status",
                    return_value="REGISTRATION_INTERVAL_PROVISIONING_REQUIRED"), \
                    mock.patch.object(
                        observer, "_filesystem_is_local", return_value=False):
                with self.assertRaisesRegex(
                        attended.AttendedRegistrationError,
                        "REGISTRATION_INTERVAL_ROOT_INVALID"):
                    attended.provision_registration_interval(
                        private_runtime_root=root, apply=True)
            self.assertEqual(list(root.iterdir()), [])

    def test_attended_runner_rejects_noninteractive_input_before_any_action(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [sys.executable, str(root / "scripts/run_sonnet_attended_registration.py")],
            input="", text=True, capture_output=True, cwd=root, timeout=5,
            check=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn("ATTENDED_REGISTRATION_INTERACTIVE_TTY_REQUIRED", result.stdout)
