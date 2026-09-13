import base64
import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from flop_agent import did_key
from flop_agent import sonnet_registration as registration
from flop_agent import sonnet_registration_adapters as adapters
from flop_agent import sonnet_registration_handoff as handoff


NOW = datetime(2026, 9, 13, 8, 0, tzinfo=timezone.utc)


class FakeResponse:
    def __init__(self, body=b'{"ok":true}', *, url=registration.POST_URL,
                 status=200, content_length=True, chunk=8192, encoding=None):
        self.body = body
        self.offset = 0
        self.url = url
        self.status = status
        self.chunk = chunk
        self.headers = Message()
        if content_length:
            self.headers["Content-Length"] = str(len(body))
        if encoding:
            self.headers["Content-Encoding"] = encoding
        self.headers["X-Room-Generation"] = "1"

    def read(self, size):
        size = min(size, self.chunk)
        value = self.body[self.offset:self.offset + size]
        self.offset += len(value)
        return value

    def geturl(self):
        return self.url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class FakeOpener:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        return self.response


def receipt_classifier(record):
    packet = json.loads(record["text"])
    if (packet.get("type") == "sonnet.receipt.v1"
            and packet.get("status") == "accepted"):
        return {"status": "ACCEPTED_VERIFIED"}
    raise registration.RegistrationBoundaryError("RECEIPT_INVALID")


def export(*records):
    return json.dumps({"messages": list(records)}, separators=(",", ":")).encode()


def message(seq, packet, sender=registration.PARTICIPANT_DID):
    return {"seq": seq, "from": sender, "sig": "fixture", "nonce": "1",
            "text": json.dumps(packet, separators=(",", ":"))}


class EligibilityAndObservationTests(unittest.TestCase):
    def test_forbidden_conflated_state_is_absent(self):
        root = Path(__file__).resolve().parents[1]
        for path in (root / "src/flop_agent/sonnet_registration_handoff.py",
                     root / "src/flop_agent/sonnet_registration_adapters.py"):
            self.assertNotIn("ELIGIBLE_UNREGISTERED_CONFIRMED", path.read_text())

    def test_local_evidence_is_separate_from_official_eligibility(self):
        record = {"from": registration.PARTICIPANT_DID, "sig": "fixture",
                  "room": "lobby", "nonce": "1787674317832", "text": "proof"}
        calls = []
        result = adapters.verify_local_prestart_evidence(
            record, verifier=lambda *args: calls.append(args))
        self.assertEqual(result["local_prestart_evidence"],
                         adapters.PRESTART_EVIDENCE_LOCALLY_VERIFIED)
        self.assertEqual(result["official_archive_eligibility"],
                         adapters.OFFICIAL_ARCHIVE_ELIGIBILITY_UNCONFIRMED)
        self.assertEqual(len(calls), 1)

    def observe(self, raw):
        return adapters.classify_registration_export(
            raw, generation="generation-fixture", fetched_at=NOW,
            receipt_classifier=receipt_classifier)

    def test_incomplete_ring_only_reports_observed_window(self):
        value = self.observe(export(message(929750, {"note": "untrusted"}, "other")))
        self.assertEqual(value.conflict_classification,
                         adapters.NO_CONFLICT_IN_OBSERVED_WINDOW)
        self.assertEqual((value.first_observed_seq, value.last_observed_seq),
                         (929750, 929750))
        self.assertEqual(value.record_count, 1)
        self.assertEqual(value.response_sha256,
                         hashlib.sha256(export(message(
                             929750, {"note": "untrusted"}, "other"))).hexdigest())

    def test_identical_accepted_conflict_and_request_only(self):
        request = message(1, json.loads(registration.PACKET_TEXT))
        receipt_packet = {
            "type": "sonnet.receipt.v1", "contest_id": registration.CONTEST_ID,
            "request_id": registration.REQUEST_ID,
            "participant_did": registration.PARTICIPANT_DID,
            "role": registration.ROLE, "x_account_url": registration.X_ACCOUNT_URL,
            "status": "accepted",
        }
        accepted = self.observe(export(request, message(
            2, receipt_packet, registration.REFEREE_DID)))
        self.assertEqual(accepted.conflict_classification,
                         adapters.ALREADY_REGISTERED_IDENTICALLY)
        only_request = self.observe(export(request))
        self.assertEqual(only_request.conflict_classification,
                         adapters.REQUEST_OBSERVED_RECEIPT_UNCONFIRMED)
        conflicting = self.observe(export(message(3, {
            "type": registration.PROTOCOL_TYPE,
            "contest_id": registration.CONTEST_ID, "role": "voter",
            "x_account_url": registration.X_ACCOUNT_URL,
            "request_id": "other"})))
        self.assertEqual(conflicting.conflict_classification,
                         adapters.REGISTRATION_CONFLICT)

    def test_observation_binds_counts_and_rejects_duplicate_json(self):
        value = self.observe(export(message(4, json.loads(registration.PACKET_TEXT))))
        self.assertEqual(value.did_exact_match_count, 1)
        self.assertEqual(value.x_exact_match_count, 1)
        self.assertEqual(value.x_casefold_match_count, 1)
        self.assertEqual(value.official_origin, adapters.OFFICIAL_ORIGIN)
        with self.assertRaises(adapters.AdapterError):
            self.observe(b'{"messages":[],"messages":[]}')


class IdentitySignerTests(unittest.TestCase):
    def make_identity(self, directory, *, mode=0o600, stored_did=None):
        seed = b"f" * 32
        key = Ed25519PrivateKey.from_private_bytes(seed)
        did = did_key.did_from_public_key(key.public_key().public_bytes_raw())
        path = Path(directory) / "identity.json"
        path.write_text(json.dumps({
            "type": "Ed25519", "did": stored_did or did,
            "seed_b64": base64.urlsafe_b64encode(seed).decode().rstrip("=")}))
        os.chmod(path, mode)
        return path, did

    def test_loader_not_called_before_handoff_gates(self):
        calls = []
        signer = adapters._secure_identity_signer(
            Path("/not/opened"), opener=lambda *_args: calls.append(1))
        with tempfile.TemporaryDirectory() as temp:
            service = handoff._build_handoff_for_test(
                root=Path(temp) / "journal", approvals={},
                trusted_reviewers=frozenset(), clock=lambda: NOW,
                registration_checker=lambda: adapters.NO_CONFLICT_IN_OBSERVED_WINDOW,
                identity_signer=signer, transport=lambda *_args, **_kwargs: None,
                receipt_classifier=receipt_classifier)
            with self.assertRaises(handoff.HandoffError):
                service.execute(registration.fixed_candidate(), "missing")
        self.assertEqual(calls, [])

    def test_symlink_permission_and_wrong_did_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path, did = self.make_identity(temp)
            link = Path(temp) / "link.json"
            link.symlink_to(path)
            with self.assertRaises(adapters.AdapterError):
                adapters._secure_identity_signer(
                    link, expected_did=did)(registration.SIGNING_TARGET_BYTES)
            os.chmod(path, 0o644)
            with self.assertRaises(adapters.AdapterError):
                adapters._secure_identity_signer(
                    path, expected_did=did)(registration.SIGNING_TARGET_BYTES)
            os.chmod(path, 0o600)
            with self.assertRaises(adapters.AdapterError):
                adapters._secure_identity_signer(
                    path, expected_did="did:key:wrong")(
                        registration.SIGNING_TARGET_BYTES)

    def test_exact_target_and_single_invocation(self):
        with tempfile.TemporaryDirectory() as temp:
            path, did = self.make_identity(temp)
            signer = adapters._secure_identity_signer(path, expected_did=did)
            with self.assertRaises(adapters.AdapterError):
                signer(b"other")
            signed_did, signature = signer(registration.SIGNING_TARGET_BYTES)
            self.assertEqual(signed_did, did)
            self.assertEqual(len(signature), 86)
            self.assertNotIn("=", signature)
            with self.assertRaises(adapters.AdapterError):
                signer(registration.SIGNING_TARGET_BYTES)


class TransportTests(unittest.TestCase):
    def body(self):
        return json.dumps({
            "did": registration.PARTICIPANT_DID,
            "sig": "A" * 86, "nonce": registration.NONCE,
            "text": registration.PACKET_TEXT,
        }, sort_keys=True, separators=(",", ":")).encode()

    def factory(self, response):
        opener = FakeOpener(response)
        transport = adapters._build_post_transport(
            opener_factory=lambda: opener,
            observation_factory=handoff.HandoffTransportObservation,
            signature_verifier=lambda *_args: None)
        return transport, opener

    def test_exact_post_and_max_once(self):
        self.assertEqual(len(self.body()), adapters.REQUEST_BODY_BYTE_LENGTH)
        transport, opener = self.factory(FakeResponse())
        result = transport(
            registration.POST_URL, self.body(), method="POST",
            timeout_seconds=20, allow_redirects=False, allow_proxy=False,
            credential_forwarding=False)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(len(opener.calls), 1)
        request = opener.calls[0][0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.full_url, registration.POST_URL)
        self.assertIsNone(request.get_header("Authorization"))
        with self.assertRaises(adapters.AdapterError):
            transport(registration.POST_URL, self.body())

    def test_proxy_disabled_in_production_opener(self):
        with mock.patch("urllib.request.build_opener") as build:
            adapters._production_opener()
        handlers = build.call_args.args
        proxies = [item for item in handlers
                   if isinstance(item, __import__("urllib.request").request.ProxyHandler)]
        self.assertEqual(len(proxies), 1)
        self.assertEqual(proxies[0].proxies, {})

    def test_redirect_stream_limit_chunked_and_bad_json(self):
        cases = (
            FakeResponse(url="https://technocore.chat/other"),
            FakeResponse(b"x" * (adapters.MAX_RESPONSE_BYTES + 1),
                         content_length=False, chunk=17),
            FakeResponse(b"{"),
            FakeResponse(b'{"a":1,"a":2}'),
        )
        for response in cases:
            transport, _ = self.factory(response)
            with self.assertRaises(adapters.AdapterError):
                transport(
                    registration.POST_URL, self.body(), method="POST",
                    timeout_seconds=20, allow_redirects=False, allow_proxy=False,
                    credential_forwarding=False)

    def test_production_signature_check_precedes_socket(self):
        opener = FakeOpener(FakeResponse())
        transport = adapters._build_post_transport(
            opener_factory=lambda: opener,
            observation_factory=handoff.HandoffTransportObservation)
        with self.assertRaises(adapters.AdapterError):
            transport(
                registration.POST_URL, self.body(), method="POST",
                timeout_seconds=20, allow_redirects=False, allow_proxy=False,
                credential_forwarding=False)
        self.assertEqual(opener.calls, [])


class ReadOnlyAndFreshnessTests(unittest.TestCase):
    def observation(self, classification=adapters.NO_CONFLICT_IN_OBSERVED_WINDOW):
        return adapters.RegistrationObservation(
            adapters.OFFICIAL_ORIGIN, registration.ROOM, "generation", 1, 2, 2,
            "2026-09-13T08:00:00Z", "0" * 64, 0, 0, 0, classification)

    def test_read_adapter_is_unsigned_fixed_get_and_bounded(self):
        response = FakeResponse(export(), url=adapters.REGISTRATION_GET_URL)
        opener = FakeOpener(response)
        read = adapters._build_readonly_registration_adapter(
            opener_factory=lambda: opener, clock=lambda: NOW,
            receipt_classifier=receipt_classifier)
        result = read()
        request = opener.calls[0][0]
        self.assertEqual(request.method, "GET")
        self.assertIsNone(request.data)
        self.assertIsNone(request.get_header("Authorization"))
        self.assertEqual(result.conflict_classification,
                         adapters.NO_CONFLICT_IN_OBSERVED_WINDOW)
        self.assertEqual(result.room_generation, "1")

    def test_reconciliation_is_bounded_and_never_posts(self):
        calls = []
        result = adapters.bounded_readonly_reconciliation(
            lambda: calls.append("GET") or self.observation(), max_attempts=3)
        self.assertEqual(calls, ["GET"] * 3)
        self.assertEqual(result["status"], adapters.AWAITING_REFEREE_RECEIPT)
        self.assertEqual(result["transport_invocations"], 0)

    def test_freshness_separates_no_conflict_from_eligibility(self):
        launch = {
            "status": "open", "contest_id": registration.CONTEST_ID,
            "rules_version": adapters.RULES_VERSION,
            "referee_did": registration.REFEREE_DID,
            "manifest_commit": registration.MANIFEST_COMMIT,
            "manifest_sha256": registration.MANIFEST_SHA256,
        }
        prestart = {
            "local_prestart_evidence": adapters.PRESTART_EVIDENCE_LOCALLY_VERIFIED,
            "official_archive_eligibility":
                adapters.OFFICIAL_ARCHIVE_ELIGIBILITY_UNCONFIRMED,
        }
        value = adapters.evaluate_freshness(
            now=NOW, launch=launch, observation=self.observation(),
            prestart=prestart, nonce_unused=True, journal_state="NOT_STARTED",
            approval_status="ABSENT", expected_generation="generation")
        self.assertEqual(value, "REGISTRATION_WRITE_APPROVAL_REQUIRED")
        self.assertEqual(adapters.evaluate_freshness(
            now=NOW, launch=launch,
            observation=self.observation(adapters.ALREADY_REGISTERED_IDENTICALLY),
            prestart=prestart, nonce_unused=True, journal_state="NOT_STARTED",
            approval_status="ABSENT", expected_generation="generation"),
            adapters.ALREADY_REGISTERED_IDENTICALLY)
        with self.assertRaises(adapters.AdapterError):
            adapters.evaluate_freshness(
                now=NOW, launch=launch,
                observation=self.observation(adapters.REGISTRATION_CONFLICT),
                prestart=prestart, nonce_unused=True, journal_state="NOT_STARTED",
                approval_status="VALID", expected_generation="generation")

    def test_production_authority_empty_and_no_live_adapter_invocation(self):
        with mock.patch.object(adapters, "_production_opener",
                               side_effect=AssertionError("network")):
            with self.assertRaises(handoff.HandoffError):
                handoff.production_handoff_service.execute(
                    registration.fixed_candidate(), "not-issued")
        self.assertEqual(handoff.production_handoff_service.inspect()["state"],
                         "NOT_STARTED")


if __name__ == "__main__":
    unittest.main()
