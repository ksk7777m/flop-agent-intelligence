import base64
import hashlib
import inspect
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


def fixed_receipt_classifier(record):
    classifier = adapters._build_fixed_receipt_classifier_for_test(
        lambda *_args: None)
    return classifier(record)


def export(*records, generation=1, room=registration.ROOM):
    seqs = [record["seq"] for record in records]
    return json.dumps({
        "room": room, "count": len(records),
        "first_seq": min(seqs) if seqs else None,
        "last_seq": max(seqs) if seqs else None,
        "generation": generation, "messages": list(records),
    }, separators=(",", ":")).encode()


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
            raw, fetched_at=NOW,
            receipt_classifier=receipt_classifier)

    def observe_with_fixed_receipts(self, raw):
        return adapters.classify_registration_export(
            raw, fetched_at=NOW,
            receipt_classifier=fixed_receipt_classifier)

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
        self.assertEqual(value.request_id_exact_match_count, 1)
        self.assertEqual(value.official_origin, adapters.OFFICIAL_ORIGIN)
        with self.assertRaises(adapters.AdapterError):
            self.observe(b'{"room":"x","count":0,"first_seq":null,'
                         b'"last_seq":null,"generation":1,"messages":[],'
                         b'"messages":[]}')

    def test_request_id_exact_match_count_is_deterministic(self):
        exact = message(1, json.loads(registration.PACKET_TEXT))
        unrelated = message(2, {
            "type": registration.PROTOCOL_TYPE,
            "contest_id": registration.CONTEST_ID, "role": "writer",
            "x_account_url": "https://x.com/unrelated", "request_id": "other",
        }, "did:key:unrelated")
        duplicate = message(3, json.loads(registration.PACKET_TEXT))
        self.assertEqual(self.observe(export()).request_id_exact_match_count, 0)
        self.assertEqual(
            self.observe(export(exact)).request_id_exact_match_count, 1)
        observed = self.observe(export(exact, unrelated, duplicate))
        self.assertEqual(observed.request_id_exact_match_count, 2)
        self.assertEqual(observed.record_count, 3)
        self.assertEqual(observed.did_exact_match_count, 2)
        self.assertEqual(observed.x_exact_match_count, 2)

    def test_request_id_near_matches_are_not_current_request(self):
        variants = (
            "other", "", registration.REQUEST_ID.upper(),
            f" {registration.REQUEST_ID}", f"{registration.REQUEST_ID} ",
            registration.REQUEST_ID[:-1], f"{registration.REQUEST_ID}x",
            registration.REQUEST_ID.replace("b", "ь", 1), None, 7,
        )
        for index, request_id in enumerate(variants, 1):
            packet = json.loads(registration.PACKET_TEXT)
            packet["request_id"] = request_id
            with self.subTest(request_id=request_id):
                observed = self.observe(export(message(index, packet)))
                self.assertEqual(observed.request_id_exact_match_count, 0)
                self.assertEqual(observed.conflict_classification,
                                 adapters.REGISTRATION_CONFLICT)

    def test_unrelated_request_id_does_not_invalidate_observed_window(self):
        unrelated = message(1, {
            "type": registration.PROTOCOL_TYPE,
            "contest_id": registration.CONTEST_ID, "role": "voter",
            "x_account_url": "https://x.com/unrelated", "request_id": "other",
        }, "did:key:unrelated")
        observed = self.observe(export(unrelated))
        self.assertEqual(observed.request_id_exact_match_count, 0)
        self.assertEqual(observed.conflict_classification,
                         adapters.NO_CONFLICT_IN_OBSERVED_WINDOW)

    def test_related_other_request_and_mutated_fixed_request_are_conflicts(self):
        related = json.loads(registration.PACKET_TEXT)
        related["request_id"] = "other"
        mutations = (
            ({"contest_id": "other-contest"}, registration.PARTICIPANT_DID),
            ({"role": "voter"}, registration.PARTICIPANT_DID),
            ({"x_account_url": "https://x.com/other"},
             registration.PARTICIPANT_DID),
            ({}, "did:key:other"),
        )
        observed = self.observe(export(message(1, related)))
        self.assertEqual(observed.conflict_classification,
                         adapters.REGISTRATION_CONFLICT)
        self.assertEqual(observed.request_id_exact_match_count, 0)
        for index, (changes, sender) in enumerate(mutations, 2):
            packet = json.loads(registration.PACKET_TEXT)
            packet.update(changes)
            with self.subTest(changes=changes, sender=sender):
                observed = self.observe(export(message(index, packet, sender)))
                self.assertEqual(observed.conflict_classification,
                                 adapters.REGISTRATION_CONFLICT)
                self.assertEqual(observed.request_id_exact_match_count, 1)

    def test_other_request_receipt_cannot_establish_acceptance(self):
        packet = {
            "type": "sonnet.receipt.v1", "contest_id": registration.CONTEST_ID,
            "request_id": "other", "participant_did": registration.PARTICIPANT_DID,
            "role": registration.ROLE, "x_account_url": registration.X_ACCOUNT_URL,
            "status": "accepted",
        }
        observed = self.observe_with_fixed_receipts(export(message(
            1, packet, registration.REFEREE_DID)))
        self.assertEqual(observed.request_id_exact_match_count, 0)
        self.assertEqual(observed.conflict_classification,
                         adapters.REGISTRATION_CONFLICT)

    def test_conflicting_fixed_request_record_overrides_identical_acceptance(self):
        receipt_packet = {
            "type": "sonnet.receipt.v1", "contest_id": registration.CONTEST_ID,
            "request_id": registration.REQUEST_ID,
            "participant_did": registration.PARTICIPANT_DID,
            "role": registration.ROLE, "x_account_url": registration.X_ACCOUNT_URL,
            "status": "accepted",
        }
        mutated = json.loads(registration.PACKET_TEXT)
        mutated["role"] = "voter"
        observed = self.observe_with_fixed_receipts(export(
            message(1, receipt_packet, registration.REFEREE_DID),
            message(2, mutated)))
        self.assertEqual(observed.request_id_exact_match_count, 2)
        self.assertEqual(observed.conflict_classification,
                         adapters.REGISTRATION_CONFLICT)

    def test_observer_captures_request_id_before_global_rebinding(self):
        raw = export(message(1, json.loads(registration.PACKET_TEXT)))
        original = registration.REQUEST_ID
        try:
            registration.REQUEST_ID = "attacker-request"
            observed = self.observe(raw)
        finally:
            registration.REQUEST_ID = original
        self.assertEqual(observed.request_id_exact_match_count, 1)
        self.assertEqual(observed.conflict_classification,
                         adapters.REQUEST_OBSERVED_RECEIPT_UNCONFIRMED)

    def test_production_classifiers_do_not_accept_binding_overrides(self):
        self.assertFalse(hasattr(adapters, "_classify_registration_export_core"))
        self.assertFalse(hasattr(adapters, "_classify_observed_receipt_core"))
        observation_signature = inspect.signature(
            adapters.classify_registration_export)
        self.assertEqual(
            tuple(observation_signature.parameters),
            ("raw", "fetched_at", "receipt_classifier"))
        raw = export(message(1, json.loads(registration.PACKET_TEXT)))
        for keyword in ("request_id", "_request_id"):
            with self.subTest(observation_keyword=keyword), self.assertRaises(
                    TypeError):
                adapters.classify_registration_export(
                    raw, fetched_at=NOW, receipt_classifier=receipt_classifier,
                    **{keyword: "other"})
        with self.assertRaises(TypeError):
            adapters.classify_registration_export(
                raw, NOW, receipt_classifier, "other")

        receipt_signature = inspect.signature(
            adapters._classify_observed_receipt)
        self.assertEqual(tuple(receipt_signature.parameters), ("record",))
        receipt = message(2, {
            "type": "sonnet.receipt.v1", "contest_id": registration.CONTEST_ID,
            "request_id": registration.REQUEST_ID,
            "participant_did": registration.PARTICIPANT_DID,
            "role": registration.ROLE, "x_account_url": registration.X_ACCOUNT_URL,
            "status": "accepted",
        }, registration.REFEREE_DID)
        for keyword in ("request_id", "_request_id"):
            with self.subTest(receipt_keyword=keyword), self.assertRaises(TypeError):
                adapters._classify_observed_receipt(
                    receipt, **{keyword: "other"})
        with self.assertRaises(TypeError):
            adapters._classify_observed_receipt(receipt, "other")
        self.assertEqual(
            tuple(inspect.signature(
                adapters._build_fixed_receipt_classifier_for_test).parameters),
            ("signature_verifier",))
        with self.assertRaises(TypeError):
            adapters._build_fixed_receipt_classifier_for_test(
                lambda *_args: None, request_id="other")

    def test_production_closures_share_immutable_request_id_binding(self):
        observed_binding = inspect.getclosurevars(
            adapters.classify_registration_export).nonlocals["request_id"]
        receipt_binding = inspect.getclosurevars(
            adapters._classify_observed_receipt).nonlocals["request_id"]
        self.assertEqual(observed_binding, registration.REQUEST_ID)
        self.assertEqual(receipt_binding, registration.REQUEST_ID)
        original = registration.REQUEST_ID
        try:
            registration.REQUEST_ID = "attacker-request"
            self.assertEqual(inspect.getclosurevars(
                adapters.classify_registration_export).nonlocals["request_id"],
                original)
            self.assertEqual(inspect.getclosurevars(
                adapters._classify_observed_receipt).nonlocals["request_id"],
                original)
        finally:
            registration.REQUEST_ID = original

    def test_generation_and_room_are_body_bound_and_fail_closed(self):
        for generation in (None, "1", 1.0, True, 0, -1,
                           adapters.SAFE_INTEGER_MAX + 1):
            with self.subTest(generation=generation), self.assertRaises(
                    adapters.AdapterError):
                self.observe(export(generation=generation))
        with self.assertRaises(adapters.AdapterError):
            self.observe(export(room="mb-other"))
        missing = json.loads(export())
        del missing["generation"]
        with self.assertRaises(adapters.AdapterError):
            self.observe(json.dumps(missing, separators=(",", ":")).encode())
        with self.assertRaises(adapters.AdapterError):
            self.observe(
                b'{"room":"mb-sonnet-2-registration","count":0,'
                b'"first_seq":null,"last_seq":null,"generation":1,'
                b'"generation":2,"messages":[]}')

    def test_live_shape_without_generation_header_is_accepted(self):
        raw = export(message(95927, {"note": "untrusted"}, "other"))
        observed = self.observe(raw)
        self.assertEqual(observed.room_generation, 1)
        self.assertEqual(observed.generation_trust,
                         "OBSERVED_DEPLOYMENT_FIELD")
        self.assertEqual(observed.response_byte_length, len(raw))


class ReceiptRequestIdBindingTests(unittest.TestCase):
    def receipt(self, payload_request_id=registration.REQUEST_ID, **outer):
        packet = {
            "type": "sonnet.receipt.v1", "contest_id": registration.CONTEST_ID,
            "request_id": payload_request_id,
            "participant_did": registration.PARTICIPANT_DID,
            "role": registration.ROLE, "x_account_url": registration.X_ACCOUNT_URL,
            "status": "accepted",
        }
        return {
            "from": registration.REFEREE_DID, "sig": "fixture", "nonce": "1",
            "text": json.dumps(packet, separators=(",", ":")), **outer,
        }

    def classify(self, record):
        classifier = adapters._build_fixed_receipt_classifier_for_test(
            lambda *_args: None)
        return classifier(record)

    def test_exact_request_id_accepts_terminal_receipt_statuses(self):
        accepted = self.receipt()
        self.assertEqual(self.classify(accepted)["status"], "ACCEPTED_VERIFIED")
        rejected = self.receipt()
        packet = json.loads(rejected["text"])
        packet["status"] = "rejected"
        rejected["text"] = json.dumps(packet, separators=(",", ":"))
        self.assertEqual(self.classify(rejected)["status"], "REJECTED_VERIFIED")

    def test_nonexact_request_ids_are_rejected_after_signature_verification(self):
        variants = (
            "other", "", registration.REQUEST_ID[:-1],
            f"{registration.REQUEST_ID}x", registration.REQUEST_ID.upper(),
            f" {registration.REQUEST_ID}", f"{registration.REQUEST_ID} ",
            registration.REQUEST_ID.replace("b", "ь", 1), None, 7,
        )
        for request_id in variants:
            with self.subTest(request_id=request_id), self.assertRaisesRegex(
                    adapters.AdapterError, "RECEIPT_REQUEST_ID_MISMATCH"):
                self.classify(self.receipt(request_id))
        missing = self.receipt()
        packet = json.loads(missing["text"])
        del packet["request_id"]
        missing["text"] = json.dumps(packet, separators=(",", ":"))
        with self.assertRaisesRegex(adapters.AdapterError,
                                    "RECEIPT_BINDING_MISMATCH"):
            self.classify(missing)

    def test_outer_request_id_is_never_used_as_authenticated_binding(self):
        wrong_payload = self.receipt("other", request_id=registration.REQUEST_ID)
        with self.assertRaisesRegex(adapters.AdapterError,
                                    "RECEIPT_REQUEST_ID_MISMATCH"):
            self.classify(wrong_payload)
        mismatched_outer = self.receipt(request_id="other")
        with self.assertRaisesRegex(adapters.AdapterError,
                                    "RECEIPT_OUTER_METADATA_MISMATCH"):
            self.classify(mismatched_outer)
        self.assertEqual(
            self.classify(self.receipt(request_id=registration.REQUEST_ID))["status"],
            "ACCEPTED_VERIFIED")

    def test_duplicate_request_id_and_single_character_change_are_rejected(self):
        record = self.receipt()
        record["text"] = record["text"].replace(
            f'"request_id":"{registration.REQUEST_ID}"',
            f'"request_id":"{registration.REQUEST_ID}","request_id":"other"')
        with self.assertRaisesRegex(adapters.AdapterError, "DUPLICATE_JSON_KEY"):
            self.classify(record)
        changed = self.receipt(registration.REQUEST_ID[:-1] + "b")
        with self.assertRaisesRegex(adapters.AdapterError,
                                    "RECEIPT_REQUEST_ID_MISMATCH"):
            self.classify(changed)

    def test_request_id_mismatch_has_no_effect_capability_calls(self):
        calls = {"identity": 0, "signer": 0, "transport": 0}
        packet = json.loads(self.receipt("other")["text"])
        observed = adapters.classify_registration_export(
            export(message(1, packet, registration.REFEREE_DID)),
            fetched_at=NOW, receipt_classifier=fixed_receipt_classifier)

        def identity_signer(_target):
            calls["identity"] += 1
            calls["signer"] += 1
            return registration.PARTICIPANT_DID, "A" * 86

        def transport(*_args, **_kwargs):
            calls["transport"] += 1
            return None

        with tempfile.TemporaryDirectory() as temp:
            service = handoff._build_handoff_for_test(
                root=Path(temp) / "journal", approvals={},
                trusted_reviewers=frozenset(), clock=lambda: NOW,
                registration_checker=lambda: observed.conflict_classification,
                identity_signer=identity_signer, transport=transport,
                receipt_classifier=fixed_receipt_classifier)
            with self.assertRaisesRegex(handoff.HandoffError,
                                        "REGISTRATION_STATE_UNRESOLVED"):
                service.execute(registration.fixed_candidate(), "not-issued")
        self.assertEqual(calls, {"identity": 0, "signer": 0, "transport": 0})


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

    def test_fd_must_still_match_fixed_path_after_open(self):
        with tempfile.TemporaryDirectory() as temp:
            path, did = self.make_identity(temp)
            other = Path(temp) / "other.json"
            other.write_bytes(b"other")
            os.chmod(other, 0o600)
            signer = adapters._secure_identity_signer(
                path, expected_did=did,
                path_stat=lambda *_args, **_kwargs: other.stat())
            with self.assertRaisesRegex(adapters.AdapterError,
                                        "IDENTITY_PATH_CHANGED"):
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
            adapters._production_opener(_build_opener=build)
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

    def test_built_transport_ignores_late_registration_global_rebinding(self):
        body = self.body()
        transport, opener = self.factory(FakeResponse())
        originals = (registration.POST_URL, registration.PARTICIPANT_DID,
                     registration.NONCE, registration.PACKET_TEXT,
                     registration.ROOM)
        try:
            registration.POST_URL = "https://attacker.invalid/"
            registration.PARTICIPANT_DID = "did:key:attacker"
            registration.NONCE = "1"
            registration.PACKET_TEXT = "{}"
            registration.ROOM = "mb-attacker"
            result = transport(
                originals[0], body, method="POST", timeout_seconds=20,
                allow_redirects=False, allow_proxy=False,
                credential_forwarding=False)
            self.assertEqual(result.final_url, originals[0])
            self.assertEqual(len(opener.calls), 1)
        finally:
            (registration.POST_URL, registration.PARTICIPANT_DID,
             registration.NONCE, registration.PACKET_TEXT,
             registration.ROOM) = originals


class ReadOnlyAndFreshnessTests(unittest.TestCase):
    def observation(self, classification=adapters.NO_CONFLICT_IN_OBSERVED_WINDOW):
        return adapters.RegistrationObservation(
            adapters.OFFICIAL_ORIGIN, registration.ROOM, 1,
            "OBSERVED_DEPLOYMENT_FIELD", 1, 2, 2,
            "2026-09-13T08:00:00Z", "0" * 64, 100, 0, 0, 0, 0,
            classification)

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
        self.assertEqual(result.room_generation, 1)
        self.assertEqual(result.generation_trust, "OBSERVED_DEPLOYMENT_FIELD")

    def test_built_read_adapter_ignores_classifier_global_rebinding(self):
        response = FakeResponse(export(), url=adapters.REGISTRATION_GET_URL)
        opener = FakeOpener(response)
        read = adapters._build_readonly_registration_adapter(
            opener_factory=lambda: opener, clock=lambda: NOW,
            receipt_classifier=receipt_classifier)
        with mock.patch.object(
                adapters, "classify_registration_export",
                side_effect=AssertionError("late classifier replacement")):
            result = read()
        self.assertEqual(result.conflict_classification,
                         adapters.NO_CONFLICT_IN_OBSERVED_WINDOW)

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
            approval_status="ABSENT", expected_generation=1)
        self.assertEqual(value, "REGISTRATION_WRITE_APPROVAL_REQUIRED")
        self.assertEqual(adapters.evaluate_freshness(
            now=NOW, launch=launch,
            observation=self.observation(adapters.ALREADY_REGISTERED_IDENTICALLY),
            prestart=prestart, nonce_unused=True, journal_state="NOT_STARTED",
            approval_status="ABSENT", expected_generation=1),
            adapters.ALREADY_REGISTERED_IDENTICALLY)
        with self.assertRaises(adapters.AdapterError):
            adapters.evaluate_freshness(
                now=NOW, launch=launch,
                observation=self.observation(adapters.REGISTRATION_CONFLICT),
                prestart=prestart, nonce_unused=True, journal_state="NOT_STARTED",
                approval_status="VALID", expected_generation=1)
        with self.assertRaisesRegex(adapters.AdapterError,
                                    "OBSERVATION_BINDING_MISMATCH"):
            adapters.evaluate_freshness(
                now=NOW, launch=launch, observation=self.observation(),
                prestart=prestart, nonce_unused=True,
                journal_state="NOT_STARTED", approval_status="VALID",
                expected_generation=2)

        invalid_count = self.observation()
        object.__setattr__(invalid_count, "request_id_exact_match_count", True)
        with self.assertRaisesRegex(adapters.AdapterError,
                                    "OBSERVATION_BINDING_MISMATCH"):
            adapters.evaluate_freshness(
                now=NOW, launch=launch, observation=invalid_count,
                prestart=prestart, nonce_unused=True,
                journal_state="NOT_STARTED", approval_status="ABSENT",
                expected_generation=1)

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
