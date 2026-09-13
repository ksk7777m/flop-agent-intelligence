import fcntl
import inspect
import json
import os
import ssl
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema

from flop_agent import sonnet_registration as registration
from flop_agent import sonnet_registration_handoff as handoff
from flop_agent import wire_evidence


NOW = datetime(2026, 9, 13, 8, 0, tzinfo=timezone.utc)
APPROVAL_ID = "a" * 64


def approval(**changes):
    value = {
        "schema": handoff.APPROVAL_SCHEMA_VERSION,
        "approval_id": APPROVAL_ID,
        "decision": "APPROVED",
        "reviewer": "fixture-human-reviewer",
        "action_class": registration.ACTION_CLASS,
        "participant_did": registration.PARTICIPANT_DID,
        "room": registration.ROOM,
        "request_id": registration.REQUEST_ID,
        "nonce": registration.NONCE,
        "packet_sha256": registration.PACKET_SHA256,
        "signing_target_sha256": registration.SIGNING_TARGET_SHA256,
        "role": registration.ROLE,
        "x_account_url": registration.X_ACCOUNT_URL,
        "referee_did": registration.REFEREE_DID,
        "manifest_sha256": registration.MANIFEST_SHA256,
        "issued_at": "2026-09-13T07:59:00Z",
        "expires_at": "2026-09-13T08:10:00Z",
        "journal_id": handoff.JOURNAL_ID,
    }
    value.update(changes)
    return value


def receipt_classifier(record):
    if record == {"signed": "accepted"}:
        return {"status": "ACCEPTED_VERIFIED"}
    if record == {"signed": "rejected"}:
        return {"status": "REJECTED_VERIFIED"}
    raise registration.RegistrationBoundaryError("RECEIPT_SIGNATURE_INVALID")


class Fixture:
    def __init__(self, base, *, approvals=None, transport=None, fault=None,
                 checker=None, classifier=receipt_classifier):
        self.root = Path(base) / "private" / "journal"
        self.root.parent.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.root.parent, 0o700)
        self.effects = []

        def registration_checker():
            self.effects.append("registration-check")
            return "ELIGIBLE_UNREGISTERED_CONFIRMED" if checker is None else checker()

        def key_loader():
            self.effects.append("key")
            return object(), registration.PARTICIPANT_DID

        def signer(_key, target):
            self.effects.append("sign")
            self.target = target
            return "A" * 86

        def normal_transport(url, payload, **options):
            self.effects.append("transport")
            self.transport_call = (url, bytes(payload), dict(options))
            return handoff.HandoffTransportObservation(
                200, registration.POST_URL, b'{"observed":true}')

        self.service = handoff._build_handoff_for_test(
            root=self.root,
            approvals={APPROVAL_ID: approval()} if approvals is None else approvals,
            trusted_reviewers=frozenset({"fixture-human-reviewer"}),
            clock=lambda: NOW, registration_checker=registration_checker,
            key_loader=key_loader, signer=signer,
            transport=transport or normal_transport,
            receipt_classifier=classifier, fault=fault,
        )


class ApprovalAndOrderingTests(unittest.TestCase):
    def test_closed_schema_and_exact_validator(self):
        schema = handoff.approval_schema()
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), set(approval()))
        result = handoff.validate_approval_artifact(
            approval(), trusted_reviewers=frozenset({"fixture-human-reviewer"}), now=NOW)
        self.assertEqual(result["journal_id"], handoff.JOURNAL_ID)

    def test_checked_in_schema_matches_runtime_and_is_indexed(self):
        root = Path(__file__).resolve().parents[1]
        checked_in = json.loads(
            (root / "schemas/sonnet2-registration-approval.v1.json").read_text())
        runtime = dict(handoff.approval_schema())
        runtime["$id"] = checked_in["$id"]
        runtime["title"] = checked_in["title"]
        self.assertEqual(checked_in, runtime)
        jsonschema.Draft202012Validator.check_schema(checked_in)
        index = json.loads((root / "schemas/index.json").read_text())
        self.assertIn("schemas/sonnet2-registration-approval.v1.json",
                      {item["path"] for item in index["schemas"]})

    def test_approval_missing_expired_hash_and_extra_fail_before_key(self):
        with tempfile.TemporaryDirectory() as temp:
            cases = (
                {},
                {APPROVAL_ID: approval(expires_at="2026-09-13T07:59:30Z")},
                {APPROVAL_ID: approval(packet_sha256="0" * 64)},
                {APPROVAL_ID: {**approval(), "scope": "sonnet"}},
            )
            for configured in cases:
                fixture = Fixture(temp, approvals=configured)
                with self.assertRaises((handoff.HandoffError,
                                        registration.RegistrationBoundaryError)):
                    fixture.service.execute(registration.fixed_candidate(), APPROVAL_ID)
                self.assertNotIn("key", fixture.effects)

    def test_every_public_validation_and_registration_reject_precedes_key(self):
        with tempfile.TemporaryDirectory() as temp:
            candidate = registration.fixed_candidate()
            candidate["nonce"] = "1"
            fixture = Fixture(temp)
            with self.assertRaises(registration.RegistrationBoundaryError):
                fixture.service.execute(candidate, APPROVAL_ID)
            self.assertEqual(fixture.effects, [])
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(temp, checker=lambda: "UNKNOWN")
            with self.assertRaises(handoff.HandoffError):
                fixture.service.execute(registration.fixed_candidate(), APPROVAL_ID)
            self.assertEqual(fixture.effects, ["registration-check"])

    def test_intent_is_durable_before_key_and_exact_transport_contract(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(temp)
            result = fixture.service.execute(registration.fixed_candidate(), APPROVAL_ID)
            self.assertEqual(result["status"], "AWAITING_REFEREE_RECEIPT")
            self.assertEqual(fixture.effects,
                             ["registration-check", "key", "sign", "transport"])
            self.assertEqual(fixture.target, registration.SIGNING_TARGET_BYTES)
            url, body, options = fixture.transport_call
            payload = json.loads(body)
            self.assertEqual(url, registration.POST_URL)
            self.assertEqual(set(payload), {"did", "sig", "nonce", "text"})
            self.assertEqual(len(body), handoff.REQUEST_BODY_BYTE_LENGTH)
            self.assertEqual(options, {
                "method": "POST", "timeout_seconds": 20,
                "allow_redirects": False, "allow_proxy": False,
                "credential_forwarding": False,
            })
            states = [json.loads(line)["state"] for line in
                      (fixture.root / "registration-journal.jsonl").read_text().splitlines()]
            self.assertEqual(states, [
                "INTENT_RECORDED", "LOCAL_SIGNATURE_CREATED",
                "POST_ATTEMPT_RECORDED", "POST_RESPONSE_OBSERVED",
                "AWAITING_REFEREE_RECEIPT",
            ])

    def test_production_has_no_approval_and_stops_before_key(self):
        with self.assertRaises(handoff.HandoffError) as caught:
            handoff.production_handoff_service.execute(
                registration.fixed_candidate(), APPROVAL_ID)
        self.assertEqual(caught.exception.code, "REGISTRATION_WRITE_APPROVAL_REQUIRED")


class DurabilityAndCrashTests(unittest.TestCase):
    class Crash(BaseException):
        pass

    def test_approval_and_journal_cannot_be_reused(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(temp)
            fixture.service.execute(registration.fixed_candidate(), APPROVAL_ID)
            effects = list(fixture.effects)
            with self.assertRaises(handoff.HandoffError):
                fixture.service.execute(registration.fixed_candidate(), APPROVAL_ID)
            self.assertEqual(fixture.effects, effects + ["registration-check"])
            restarted = Fixture(temp)
            with self.assertRaises(handoff.HandoffError) as caught:
                restarted.service.execute(registration.fixed_candidate(), APPROVAL_ID)
            self.assertEqual(caught.exception.code, "JOURNAL_ALREADY_USED")
            self.assertNotIn("key", restarted.effects)

    def test_crash_after_each_irreversible_boundary_blocks_restart(self):
        for point, expected_state, transport_count in (
            ("AFTER_INTENT", "INTENT_RECORDED", 0),
            ("AFTER_LOCAL_SIGNATURE", "LOCAL_SIGNATURE_CREATED", 0),
            ("BEFORE_POST_ATTEMPT_RECORD", "LOCAL_SIGNATURE_CREATED", 0),
            ("AFTER_POST_ATTEMPT", "POST_ATTEMPT_RECORDED", 0),
            ("AFTER_TRANSPORT_INVOCATION", "POST_ATTEMPT_RECORDED", 1),
        ):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as temp:
                fixture = Fixture(
                    temp, fault=lambda selected, target=point:
                    (_ for _ in ()).throw(self.Crash()) if selected == target else None)
                with self.assertRaises(self.Crash):
                    fixture.service.execute(registration.fixed_candidate(), APPROVAL_ID)
                self.assertEqual(fixture.service.inspect()["state"], expected_state)
                self.assertEqual(fixture.effects.count("transport"), transport_count)
                restarted = Fixture(temp)
                with self.assertRaises(handoff.HandoffError):
                    restarted.service.execute(registration.fixed_candidate(), APPROVAL_ID)
                self.assertNotIn("key", restarted.effects)

    def test_corruption_truncation_hash_and_state_regression_fail_closed(self):
        def regression(data):
            records = [json.loads(line) for line in data.splitlines()]
            record = dict(records[-1])
            record.update({
                "sequence": len(records), "previous_hash": records[-1]["record_hash"],
                "event": "INTENT", "state": "INTENT_RECORDED",
                "http_status": None, "receipt_status": None, "record_hash": "",
            })
            record["record_hash"] = handoff._record_hash(record)
            return data + json.dumps(
                record, sort_keys=True, separators=(",", ":")).encode() + b"\n"

        mutators = (
            lambda data: data[:-1],
            lambda data: data.replace(b'"record_hash":"', b'"record_hash":"0', 1),
            regression,
        )
        for mutate in mutators:
            with tempfile.TemporaryDirectory() as temp:
                fixture = Fixture(temp)
                fixture.service.execute(registration.fixed_candidate(), APPROVAL_ID)
                path = fixture.root / "registration-journal.jsonl"
                path.write_bytes(mutate(path.read_bytes()))
                os.chmod(path, 0o600)
                restarted = Fixture(temp)
                with self.assertRaises(handoff.HandoffError):
                    restarted.service.execute(registration.fixed_candidate(), APPROVAL_ID)
                self.assertNotIn("key", restarted.effects)

    def test_concurrent_process_lock_is_rejected_before_key(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(temp)
            fixture.root.mkdir(mode=0o700)
            lock_path = fixture.root / "registration-journal.lock"
            ready_read, ready_write = os.pipe()
            release_read, release_write = os.pipe()
            pid = os.fork()
            if pid == 0:
                try:
                    os.close(ready_read)
                    os.close(release_write)
                    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                    os.write(ready_write, b"1")
                    os.read(release_read, 1)
                    os.close(descriptor)
                finally:
                    os._exit(0)
            os.close(ready_write)
            os.close(release_read)
            try:
                self.assertEqual(os.read(ready_read, 1), b"1")
                with self.assertRaises(handoff.HandoffError) as caught:
                    fixture.service.execute(registration.fixed_candidate(), APPROVAL_ID)
                self.assertEqual(caught.exception.code, "JOURNAL_LOCKED")
                self.assertNotIn("key", fixture.effects)
            finally:
                os.write(release_write, b"1")
                os.close(release_write)
                os.close(ready_read)
                os.waitpid(pid, 0)

    def test_permissions_and_journal_exclude_secret_material(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(temp)
            fixture.service.execute(registration.fixed_candidate(), APPROVAL_ID)
            journal_path = fixture.root / "registration-journal.jsonl"
            lock_path = fixture.root / "registration-journal.lock"
            self.assertEqual(fixture.root.stat().st_mode & 0o777, 0o700)
            self.assertEqual(journal_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)
            records = [json.loads(line) for line in journal_path.read_text().splitlines()]
            keys = {key for record in records for key in record}
            self.assertTrue({"signing_target_sha256", "packet_sha256"} <= keys)
            self.assertFalse({"signature", "private_key", "seed", "raw_body"} & keys)


class TransportTests(unittest.TestCase):
    def unknown(self, response=None, error=None):
        calls = []

        def transport(*_args, **_kwargs):
            calls.append("transport")
            if error is not None:
                raise error
            return response

        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(temp, transport=transport)
            result = fixture.service.execute(registration.fixed_candidate(), APPROVAL_ID)
            self.assertEqual(result["status"], "WRITE_OUTCOME_UNKNOWN")
            self.assertEqual(result["retry_count"], 0)
            self.assertEqual(calls, ["transport"])
            with self.assertRaises(handoff.HandoffError):
                Fixture(temp, transport=transport).service.execute(
                    registration.fixed_candidate(), APPROVAL_ID)
            self.assertEqual(calls, ["transport"])

    def test_redirect_timeout_tls_and_disconnect_are_unknown(self):
        self.unknown(handoff.HandoffTransportObservation(
            302, "https://other.invalid/", b"{}", redirected=True))
        self.unknown(handoff.HandoffTransportObservation(
            200, registration.POST_URL, b"{}", tls_valid=False))
        for error in (TimeoutError(), ConnectionError(), ssl.SSLError()):
            self.unknown(error=error)

    def test_408_409_429_500_are_unknown(self):
        for status in (408, 409, 429, 500):
            self.unknown(handoff.HandoffTransportObservation(
                status, registration.POST_URL, b"{}"))

    def test_truncated_oversized_malformed_and_nonobject_are_unknown(self):
        self.unknown(handoff.HandoffTransportObservation(
            200, registration.POST_URL, b"{}", complete=False))
        self.unknown(handoff.HandoffTransportObservation(
            200, registration.POST_URL, b"x" * (handoff.MAX_RESPONSE_BYTES + 1)))
        self.unknown(handoff.HandoffTransportObservation(
            200, registration.POST_URL, b"{"))
        self.unknown(handoff.HandoffTransportObservation(
            200, registration.POST_URL, b"[]"))

    def test_http_2xx_never_means_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(temp)
            result = fixture.service.execute(registration.fixed_candidate(), APPROVAL_ID)
            self.assertEqual(result["status"], "AWAITING_REFEREE_RECEIPT")
            self.assertNotEqual(result["status"], "RECEIPT_ACCEPTED")


class ReconciliationTests(unittest.TestCase):
    def test_accepted_and_rejected_receipts_are_terminal_and_read_only(self):
        for receipt, expected in (
            ({"signed": "accepted"}, "RECEIPT_ACCEPTED"),
            ({"signed": "rejected"}, "RECEIPT_REJECTED"),
        ):
            with tempfile.TemporaryDirectory() as temp:
                fixture = Fixture(temp)
                fixture.service.execute(registration.fixed_candidate(), APPROVAL_ID)
                before = fixture.effects.count("transport")
                result = fixture.service.reconcile(receipt)
                self.assertEqual(result["status"], expected)
                self.assertEqual(result["transport_invocations"], 0)
                self.assertEqual(fixture.effects.count("transport"), before)

    def test_forged_wrong_referee_and_unverified_receipts_do_not_transition(self):
        for receipt in ({"accepted": True}, {"referee": "wrong"}, {}):
            with tempfile.TemporaryDirectory() as temp:
                fixture = Fixture(temp)
                fixture.service.execute(registration.fixed_candidate(), APPROVAL_ID)
                with self.assertRaises(registration.RegistrationBoundaryError):
                    fixture.service.reconcile(receipt)
                self.assertEqual(fixture.service.inspect()["state"],
                                 "AWAITING_REFEREE_RECEIPT")

    def test_unknown_outcome_allows_only_read_only_reconciliation(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(temp, transport=lambda *_args, **_kwargs:
                              handoff.HandoffTransportObservation(
                                  408, registration.POST_URL, b"{}"))
            fixture.service.execute(registration.fixed_candidate(), APPROVAL_ID)
            result = fixture.service.reconcile({"signed": "accepted"})
            self.assertEqual(result["status"], "RECEIPT_ACCEPTED")
            self.assertEqual(result["transport_invocations"], 0)
            restarted = Fixture(temp)
            with self.assertRaises(handoff.HandoffError):
                restarted.service.execute(registration.fixed_candidate(), APPROVAL_ID)
            self.assertNotIn("key", restarted.effects)

    def test_stage1_receipt_classifier_requires_fixed_signed_bindings(self):
        def verifier(did, signature, _canonical):
            if did != registration.REFEREE_DID or signature != "valid":
                raise registration.RegistrationBoundaryError("RECEIPT_SIGNATURE_INVALID")

        service, _issue = registration._build_registration_service_for_test(
            approvals={}, trusted_reviewers=frozenset(), clock=lambda: NOW,
            key_loader=lambda: (None, ""), signer=lambda *_args: "",
            transport=lambda *_args, **_kwargs: None,
            signature_verifier=verifier)

        def record(status="accepted", sender=registration.REFEREE_DID, signature="valid"):
            body = {
                "type": "sonnet.receipt.v1", "contest_id": registration.CONTEST_ID,
                "request_id": registration.REQUEST_ID,
                "participant_did": registration.PARTICIPANT_DID,
                "role": registration.ROLE,
                "x_account_url": registration.X_ACCOUNT_URL, "status": status,
            }
            return {"from": sender, "sig": signature, "nonce": "1789279013000",
                    "text": json.dumps(body, separators=(",", ":"))}

        self.assertEqual(service.classify_receipt(record())["status"], "ACCEPTED_VERIFIED")
        self.assertEqual(service.classify_receipt(record("rejected"))["status"],
                         "REJECTED_VERIFIED")
        for invalid in (
            record(sender=registration.PARTICIPANT_DID), record(signature="forged"),
        ):
            with self.assertRaises(registration.RegistrationBoundaryError):
                service.classify_receipt(invalid)


class RegressionTests(unittest.TestCase):
    def test_production_execution_closures_have_no_dynamic_module_globals(self):
        service = handoff.production_handoff_service
        for function in (service._execute, service._reconcile):
            self.assertEqual(inspect.getclosurevars(function).globals, {})

    def test_generic_mb_guard_remains_closed(self):
        for room in (registration.ROOM, "mb-sonnet-2-votes", "mb-arbitrary"):
            with self.assertRaises(wire_evidence.WireSafetyError):
                wire_evidence.build_signing_context(
                    room, registration.NONCE, registration.PACKET_TEXT)

    def test_fixed_registration_constants_are_unchanged(self):
        self.assertEqual(registration.REQUEST_ID,
                         "bf8de59d-6e06-48b3-914b-6ac75cf07f4a")
        self.assertEqual(registration.NONCE, "1789279012380")
        self.assertEqual(registration.PACKET_SHA256,
                         "d4f9c1ea2532bd267a800ac8a9ae8f10343d11cd12c93fa678c83792040a2f0c")
        self.assertEqual(registration.SIGNING_TARGET_SHA256,
                         "ace738f321cea3606f7bc4aa04d3ee86ae37b30c8f7426f5c5fdf65cba8658da")


if __name__ == "__main__":
    unittest.main()
