import dataclasses
import hashlib
import inspect
import json
import os
import stat
import tempfile
import threading
import types
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flop_agent import sonnet_receipt_observer as observer


NOW = datetime(2026, 9, 15, 4, 0, tzinfo=timezone.utc)
REQUEST_ID = "fixture-request-1"
PARTICIPANT_DID = "did:key:z6MkFixtureParticipantPublicKey11111111111111111111"
X_URL = "https://x.com/fixture_writer"


def config(**changes):
    values = {
        "origin": observer.OFFICIAL_ORIGIN,
        "room": observer.ROOM,
        "contest_id": observer.CONTEST_ID,
        "request_id": REQUEST_ID,
        "participant_did": PARTICIPANT_DID,
        "role": observer.ROLE,
        "x_account_url": X_URL,
        "referee_did": observer.REFEREE_DID,
        "manifest_commit": observer.MANIFEST_COMMIT,
        "manifest_sha256": observer.MANIFEST_SHA256,
        "expected_generation": 1,
        "initial_since": 10,
        "observation_started_at": NOW,
        "deadline": observer.DEADLINE,
        "max_reads": 3,
        "wait_seconds": 10,
    }
    values.update(changes)
    return observer._Config(**values)


def receipt(status="accepted", **changes):
    packet = {
        "type": "sonnet.receipt.v1",
        "contest_id": observer.CONTEST_ID,
        "request_id": REQUEST_ID,
        "participant_did": PARTICIPANT_DID,
        "role": observer.ROLE,
        "x_account_url": X_URL,
        "status": status,
    }
    packet.update(changes.pop("packet_changes", {}))
    value = {
        "seq": changes.pop("seq", 11),
        "ts": "2026-09-15T04:00:01.000000Z",
        "from": changes.pop("sender", observer.REFEREE_DID),
        "text": json.dumps(packet, separators=(",", ":")),
        "nonce": changes.pop("nonce", 1789444801000),
        "sig": changes.pop("sig", "A" * 86),
    }
    value.update(changes)
    return value


def message(seq, text="untrusted data"):
    return {
        "seq": seq,
        "ts": "2026-09-15T04:00:00.000000Z",
        "from": "stranger",
        "text": text,
    }


def page(since, *records, generation=1, status=200, redirected=False,
         content_type="application/json", extra=None, last_seq=None):
    body = {
        "room": observer.ROOM,
        "count": len(records),
        "first_seq": records[0]["seq"] if records else None,
        "last_seq": records[-1]["seq"] if records else (
            since if last_seq is None else last_seq),
        "generation": generation,
        "messages": list(records),
    }
    if extra:
        body.update(extra)
    url = observer.FixedReadonlyTransport.page_url(since, 0)
    return observer.HttpRead(
        status, url + ("&redirected=1" if redirected else ""), content_type,
        json.dumps(body, separators=(",", ":")).encode(), {}, redirected)


def export(*records, generation=1, status=200, redirected=False,
           content_type="application/x-ndjson"):
    raw = b"\n".join(json.dumps(record, separators=(",", ":")).encode()
                       for record in records)
    return observer.HttpRead(
        status, observer.FixedReadonlyTransport.export_url(), content_type, raw,
        {"X-Room-Generation": str(generation)}, redirected)


class FakeTransport:
    def __init__(self, pages, exports=()):
        self.pages = list(pages)
        self.exports = list(exports)
        self.page_calls = []
        self.export_calls = 0
        self.post_calls = 0

    def read_page(self, since, wait_seconds):
        self.page_calls.append((since, wait_seconds))
        value = self.pages.pop(0)
        if isinstance(value, Exception):
            raise value
        expected = observer.FixedReadonlyTransport.page_url(since, wait_seconds)
        return observer.HttpRead(
            value.status_code, expected if not value.redirected else value.final_url,
            value.content_type, value.body, value.headers, value.redirected)

    def read_export(self):
        self.export_calls += 1
        value = self.exports.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


class BoundaryFixture:
    def __init__(self, pages, exports=(), *, cfg=None, verifier=None):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve() / "receipts"
        self.root.mkdir(mode=0o700)
        self.store = observer.PrivateReceiptStore(self.root)
        self.transport = FakeTransport(pages, exports)
        self.calls = []

        def valid(did, signature, room, nonce, text):
            self.calls.append((did, len(signature), room, nonce, len(text)))
            if signature != "A" * 86:
                raise ValueError("invalid")

        self.service = observer._build_receipt_observer_for_test(
            config=cfg or config(), transport=self.transport, store=self.store,
            signature_verifier=verifier or valid, clock=lambda: NOW)

    def close(self):
        self.store.close()
        self.temporary.cleanup()


class ReceiptObserverTests(unittest.TestCase):
    def fixture(self, pages, exports=(), **kwargs):
        fixture = BoundaryFixture(pages, exports, **kwargs)
        self.addCleanup(fixture.close)
        return fixture

    def test_prepare_establishes_ready_then_observes_target_receipt(self):
        fixture = self.fixture([page(10), page(10, receipt())])
        prepared = fixture.service.prepare()
        self.assertTrue(prepared.observer_ready)
        self.assertEqual(prepared.status, "UNCONFIRMED")
        result = fixture.service.observe()
        self.assertEqual(result.status, "ACCEPTED")
        self.assertTrue(result.receipt_sha256)
        self.assertEqual(fixture.transport.page_calls, [(10, 0), (10, 10)])

    def test_continuous_session_keeps_polling_after_ready_signal(self):
        entered_poll = threading.Event()
        release_poll = threading.Event()

        class BlockingTransport(FakeTransport):
            def read_page(self, since, wait_seconds):
                if self.page_calls:
                    entered_poll.set()
                    if not release_poll.wait(2):
                        raise observer.ReceiptObserverError("FIXTURE_TIMEOUT")
                return super().read_page(since, wait_seconds)

        fixture = self.fixture([])
        fixture.transport = BlockingTransport([page(10), page(10, receipt())])
        core = observer._build_receipt_observer_for_test(
            config=config(), transport=fixture.transport, store=fixture.store,
            signature_verifier=lambda *_args: None, clock=lambda: NOW)
        production = observer._ProductionReceiptObserver(core)
        session = production.start()
        self.assertTrue(session.wait_until_ready(2))
        self.assertTrue(entered_poll.wait(2))
        self.assertIsNone(session.wait_for_result(0))
        release_poll.set()
        result = session.wait_for_result(2)
        self.assertIsNotNone(result)
        self.assertEqual(result.status, "ACCEPTED")
        self.assertEqual(fixture.transport.page_calls, [(10, 0), (10, 10)])

    def test_external_runner_can_stop_before_ready(self):
        fixture = self.fixture([page(10, status=408)])
        self.assertFalse(fixture.service.ready)
        self.assertEqual(fixture.service.observe().error_category, "OBSERVER_NOT_READY")
        self.assertFalse(fixture.service.prepare().observer_ready)
        self.assertEqual(fixture.transport.post_calls, 0)

    def test_high_frequency_page_filters_only_exact_request(self):
        records = [message(seq) for seq in range(11, 199)]
        records.append(receipt(seq=199, packet_changes={"request_id": "other"}))
        records.append(receipt(seq=200))
        fixture = self.fixture([page(10), page(10, *records)])
        fixture.service.prepare()
        self.assertEqual(fixture.service.observe().status, "ACCEPTED")

    def test_since_cursor_continues_monotonically(self):
        fixture = self.fixture([page(10, message(11)), page(11, message(12)), page(12)])
        self.assertTrue(fixture.service.prepare().observer_ready)
        result = fixture.service.observe()
        self.assertEqual(result.status, "UNCONFIRMED")
        self.assertEqual(fixture.transport.page_calls, [(10, 0), (11, 10), (12, 10)])

    def test_same_sequence_is_rejected_without_becoming_a_gap(self):
        fixture = self.fixture([page(10, message(10))])
        result = fixture.service.prepare()
        self.assertEqual(result.status, "UNCONFIRMED")
        self.assertEqual(result.error_category, "PAGE_SEQUENCE_INVALID")
        self.assertFalse(result.gap_detected)
        self.assertEqual(fixture.transport.export_calls, 0)

    def test_restart_uses_durable_cursor_checkpoint_without_guessing(self):
        fixture = self.fixture([page(10, message(11))])
        self.assertTrue(fixture.service.prepare().observer_ready)
        checkpoint = fixture.store.load_checkpoint(
            generation=1, initial_since=10, observation_started_at=NOW,
            request_reference_sha256=hashlib.sha256(
                REQUEST_ID.encode("utf-8")).hexdigest())
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint["cursor"], 11)
        checkpoint_path = next(fixture.root.glob("*.checkpoint"))
        self.assertEqual(stat.S_IMODE(checkpoint_path.stat().st_mode), 0o600)
        restarted_transport = FakeTransport([page(11, receipt(seq=12))])
        restarted = observer._build_receipt_observer_for_test(
            config=config(initial_since=10), transport=restarted_transport,
            store=fixture.store, signature_verifier=lambda *_args: None,
            clock=lambda: NOW)
        self.assertEqual(restarted.prepare().status, "ACCEPTED")
        self.assertEqual(restarted_transport.page_calls, [(11, 0)])

    def test_checkpoint_binding_mismatch_fails_closed_without_network(self):
        fixture = self.fixture([page(10, message(11))])
        fixture.service.prepare()
        restarted_transport = FakeTransport([])
        restarted = observer._build_receipt_observer_for_test(
            config=config(expected_generation=2), transport=restarted_transport,
            store=fixture.store, signature_verifier=lambda *_args: None,
            clock=lambda: NOW)
        result = restarted.prepare()
        self.assertTrue(result.review_required)
        self.assertEqual(
            result.error_category, "SAVED_CHECKPOINT_BINDING_MISMATCH")
        self.assertEqual(restarted_transport.page_calls, [])

    def test_cursor_gap_uses_export_and_finds_receipt(self):
        fixture = self.fixture(
            [page(10, message(13))], [export(message(11), message(12), receipt(seq=13))])
        result = fixture.service.prepare()
        self.assertEqual(result.status, "ACCEPTED")
        self.assertTrue(result.gap_detected)
        self.assertTrue(result.export_fallback_used)
        self.assertEqual(fixture.transport.export_calls, 1)

    def test_gap_without_receipt_is_unconfirmed(self):
        fixture = self.fixture([page(10, message(13))], [export(message(11), message(12), message(13))])
        result = fixture.service.prepare()
        self.assertEqual(result.status, "UNCONFIRMED")
        self.assertEqual(result.error_category, "CURSOR_GAP_UNRESOLVED")
        self.assertEqual(list(fixture.root.glob("*.checkpoint")), [])

    def test_generation_change_fails_closed_without_export(self):
        fixture = self.fixture([page(10, generation=2)])
        result = fixture.service.prepare()
        self.assertTrue(result.review_required)
        self.assertEqual(result.error_category, "GENERATION_CHANGED")
        self.assertEqual(fixture.transport.export_calls, 0)

    def test_no_gap_never_calls_export(self):
        fixture = self.fixture([page(10), page(10), page(10)])
        fixture.service.prepare()
        fixture.service.observe()
        self.assertEqual(fixture.transport.export_calls, 0)

    def test_urls_are_fixed_to_official_origin_and_room(self):
        self.assertEqual(
            observer.FixedReadonlyTransport.export_url(),
            "https://technocore.chat/r/mb-sonnet-2-registration/export")
        page_url = observer.FixedReadonlyTransport.page_url(10, 10)
        self.assertTrue(page_url.startswith(
            "https://technocore.chat/r/mb-sonnet-2-registration?"))
        self.assertNotIn("say", page_url)

    def test_redirect_oversize_and_record_bound_fail_closed(self):
        redirected = page(10, redirected=True)
        oversized = observer.HttpRead(
            200, observer.FixedReadonlyTransport.page_url(10, 0),
            "application/json", b"x" * (observer.MAX_PAGE_BYTES + 1), {})
        too_many = page(10)
        decoded = json.loads(too_many.body)
        decoded["count"] = observer.MAX_PAGE_RECORDS + 1
        too_many = observer.HttpRead(
            200, too_many.final_url, too_many.content_type,
            json.dumps(decoded).encode(), {})
        for read, code in ((redirected, "PAGE_TRANSPORT_INVALID"),
                           (oversized, "PAGE_TRANSPORT_INVALID"),
                           (too_many, "PAGE_SCHEMA_INVALID")):
            with self.subTest(code=code):
                fixture = self.fixture([read])
                self.assertEqual(fixture.service.prepare().error_category, code)

    def test_export_redirect_size_record_and_generation_bounds_fail_closed(self):
        expected = observer.FixedReadonlyTransport.export_url()
        cases = [
            observer.HttpRead(200, expected, "application/x-ndjson", b"", {"X-Room-Generation": "1"}, True),
            observer.HttpRead(200, expected, "application/x-ndjson",
                              b"x" * (observer.MAX_EXPORT_BYTES + 1), {"X-Room-Generation": "1"}),
            observer.HttpRead(200, expected, "application/x-ndjson",
                              b"{}\n" * (observer.MAX_EXPORT_RECORDS + 1), {"X-Room-Generation": "1"}),
            export(generation=2),
        ]
        for read in cases:
            with self.subTest(length=len(read.body)):
                fixture = self.fixture([page(10, message(13))], [read])
                self.assertEqual(fixture.service.prepare().status, "UNCONFIRMED")

    def test_receipt_binding_and_signature_failures_remain_unconfirmed(self):
        duplicate = receipt()
        duplicate["text"] = duplicate["text"][:-1] + ',"status":"accepted"}'
        cases = [
            receipt(sender="did:key:z6MkForgedReferee11111111111111111111111111111111"),
            receipt(sig="B" * 86),
            receipt(packet_changes={"contest_id": "other"}),
            receipt(packet_changes={"request_id": "other"}),
            receipt(packet_changes={"participant_did": "did:key:z6MkOther"}),
            receipt(packet_changes={"role": "voter"}),
            receipt(packet_changes={"unexpected": {"raw": "data"}}),
            duplicate,
        ]
        for candidate in cases:
            with self.subTest(candidate=candidate["seq"]):
                fixture = self.fixture(
                    [page(10), page(10, candidate)], cfg=config(max_reads=2))
                fixture.service.prepare()
                self.assertEqual(fixture.service.observe().status, "UNCONFIRMED")

    def test_room_and_generation_are_transport_bound(self):
        wrong_room = json.loads(page(10).body)
        wrong_room["room"] = "mb-other"
        read = observer.HttpRead(
            200, observer.FixedReadonlyTransport.page_url(10, 0),
            "application/json", json.dumps(wrong_room).encode(), {})
        fixture = self.fixture([read])
        self.assertEqual(fixture.service.prepare().error_category, "PAGE_SCHEMA_INVALID")

    def test_malformed_duplicate_key_and_bool_generation_fail_closed(self):
        reads = [
            observer.HttpRead(200, observer.FixedReadonlyTransport.page_url(10, 0),
                              "application/json", b"{", {}),
            observer.HttpRead(200, observer.FixedReadonlyTransport.page_url(10, 0),
                              "application/json", b'{"room":"mb-sonnet-2-registration","room":"x"}', {}),
            page(10, generation=True),
        ]
        for read in reads:
            fixture = self.fixture([read])
            self.assertFalse(fixture.service.prepare().observer_ready)

    def test_duplicate_and_replayed_receipt_are_idempotent(self):
        same = receipt()
        fixture = self.fixture([page(10), page(10, same, {**same, "seq": 12})])
        fixture.service.prepare()
        result = fixture.service.observe()
        self.assertEqual(result.status, "ACCEPTED")
        files = [path for path in fixture.root.iterdir() if path.suffix == ".receipt"]
        self.assertEqual(len(files), 1)
        restarted = observer._build_receipt_observer_for_test(
            config=config(), transport=FakeTransport([]), store=fixture.store,
            signature_verifier=lambda *_args: None, clock=lambda: NOW)
        self.assertEqual(restarted.prepare().status, "ACCEPTED")

    def test_conflicting_valid_receipts_fail_closed_and_both_are_preserved(self):
        fixture = self.fixture([page(10), page(10, receipt(), receipt("rejected", seq=12))])
        fixture.service.prepare()
        result = fixture.service.observe()
        self.assertEqual(result.status, "UNCONFIRMED")
        self.assertTrue(result.review_required)
        self.assertEqual(result.error_category, "CONFLICTING_VALID_RECEIPTS")
        self.assertEqual(len(list(fixture.root.glob("*.receipt"))), 2)
        self.assertEqual(len(list(fixture.root.glob("*.conflict"))), 1)
        restarted = observer._build_receipt_observer_for_test(
            config=config(), transport=FakeTransport([]), store=fixture.store,
            signature_verifier=lambda *_args: None, clock=lambda: NOW)
        self.assertEqual(
            restarted.prepare().error_category, "CONFLICTING_VALID_RECEIPTS")

    def test_only_formal_accept_and_reject_become_terminal(self):
        for status, expected in (("accepted", "ACCEPTED"), ("rejected", "REJECTED")):
            fixture = self.fixture([page(10), page(10, receipt(status))])
            fixture.service.prepare()
            self.assertEqual(fixture.service.observe().status, expected)

    def test_missing_timeout_network_408_and_export_absence_are_unconfirmed(self):
        scenarios = [
            self.fixture([page(10), page(10), page(10)]),
            self.fixture([page(10), observer.ReceiptObserverError("NETWORK_FAILURE")]),
            self.fixture([page(10), page(10, status=408)]),
            self.fixture([page(10, message(13))], [export(message(11), message(12), message(13))]),
        ]
        for fixture in scenarios:
            prepared = fixture.service.prepare()
            result = prepared if not prepared.observer_ready else fixture.service.observe()
            self.assertEqual(result.status, "UNCONFIRMED")

    def test_store_permissions_digest_and_separate_metadata(self):
        fixture = self.fixture([page(10), page(10, receipt())])
        fixture.service.prepare()
        result = fixture.service.observe()
        raw_path = next(fixture.root.glob("*.receipt"))
        metadata_path = next(fixture.root.glob("*.json"))
        self.assertEqual(stat.S_IMODE(raw_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(metadata_path.stat().st_mode), 0o600)
        self.assertEqual(hashlib.sha256(raw_path.read_bytes()).hexdigest(), result.receipt_sha256)
        self.assertNotIn(b"sig", metadata_path.read_bytes())

    def test_unsafe_root_symlink_and_path_traversal_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "unsafe"
            root.mkdir(mode=0o755)
            with self.assertRaisesRegex(observer.ReceiptObserverError, "EVIDENCE_ROOT_UNSAFE"):
                observer.PrivateReceiptStore(root)
            safe = base / "safe"
            safe.mkdir(mode=0o700)
            link = base / "link"
            link.symlink_to(safe, target_is_directory=True)
            with self.assertRaisesRegex(observer.ReceiptObserverError, "EVIDENCE_ROOT_UNSAFE"):
                observer.PrivateReceiptStore(link)
            store = observer.PrivateReceiptStore(safe)
            self.addCleanup(store.close)
            with self.assertRaisesRegex(observer.ReceiptObserverError, "EVIDENCE_NAME_INVALID"):
                store._read("../secret", 10)
            target = base / "target"
            target.write_bytes(b"outside")
            (safe / "fixed.receipt").symlink_to(target)
            with self.assertRaisesRegex(observer.ReceiptObserverError, "EVIDENCE_EXISTING_UNSAFE"):
                store._atomic_write("fixed.receipt", b"evidence")

    def test_orphan_temporary_file_is_not_formal_evidence(self):
        fixture = self.fixture([page(10)])
        orphan = fixture.root / ".tmp-interrupted"
        orphan.write_bytes(b"partial")
        os.chmod(orphan, 0o600)
        self.assertEqual(fixture.store.load(), [])

    def test_production_factory_requires_preprovisioned_fixed_root(self):
        source = inspect.getsource(observer.build_production_receipt_observer)
        self.assertNotIn("mkdir", source)
        self.assertNotIn("provision", source)
        self.assertNotIn("chmod", source)
        self.assertNotIn("chown", source)
        closure = inspect.getclosurevars(
            observer.build_production_receipt_observer).nonlocals
        self.assertNotIn("evidence_root", closure)
        self.assertEqual(
            observer.RECEIPT_CHILD_BASENAME, "sonnet-registration-receipts")

    def test_tampered_saved_receipt_and_metadata_fail_closed(self):
        fixture = self.fixture([page(10), page(10, receipt())])
        fixture.service.prepare()
        fixture.service.observe()
        raw_path = next(fixture.root.glob("*.receipt"))
        raw_path.write_bytes(raw_path.read_bytes() + b"x")
        os.chmod(raw_path, 0o600)
        restarted = observer._build_receipt_observer_for_test(
            config=config(), transport=FakeTransport([]), store=fixture.store,
            signature_verifier=lambda *_args: None, clock=lambda: NOW)
        result = restarted.prepare()
        self.assertEqual(result.status, "UNCONFIRMED")
        self.assertTrue(result.review_required)

    def test_journal_and_errors_are_redacted(self):
        fixture = self.fixture([page(10), page(10, receipt())])
        fixture.service.prepare()
        result = fixture.service.observe()
        rendered = json.dumps(dict(result.journal_projection()))
        self.assertNotIn("signature", rendered.lower())
        self.assertNotIn(str(fixture.root), rendered)
        self.assertNotIn(REQUEST_ID, rendered)
        self.assertNotIn(PARTICIPANT_DID, rendered)
        self.assertNotIn(X_URL, rendered)
        self.assertNotIn("A" * 20, rendered)
        self.assertEqual(str(observer.ReceiptObserverError("FIXED_ERROR")), "FIXED_ERROR")

    def test_raw_transport_and_private_config_are_not_repr_or_dataclass_serializable(self):
        raw = observer.HttpRead(
            200, "https://untrusted.example/private", "application/json",
            b'raw-receipt-signature-value', {"Authorization": "secret-token"})
        rendered = repr(raw)
        self.assertNotIn("untrusted.example", rendered)
        self.assertNotIn("raw-receipt", rendered)
        self.assertNotIn("Authorization", rendered)
        self.assertNotIn("secret-token", rendered)
        cfg = config()
        self.assertEqual(repr(cfg), "<sealed receipt observer config>")
        self.assertNotIn(REQUEST_ID, repr(cfg))
        self.assertFalse(dataclasses.is_dataclass(raw))
        self.assertFalse(dataclasses.is_dataclass(cfg))
        with self.assertRaises(TypeError):
            dataclasses.asdict(raw)
        with self.assertRaises(TypeError):
            dataclasses.asdict(cfg)

    def test_restart_after_deadline_can_verify_saved_receipt(self):
        fixture = self.fixture([page(10), page(10, receipt())])
        fixture.service.prepare()
        fixture.service.observe()
        restarted = observer._build_receipt_observer_for_test(
            config=config(), transport=FakeTransport([]), store=fixture.store,
            signature_verifier=lambda *_args: None,
            clock=lambda: observer.DEADLINE + timedelta(days=1))
        self.assertEqual(restarted.prepare().status, "ACCEPTED")

    def test_observer_has_no_write_signer_identity_nonce_or_request_id_generation_api(self):
        public = {name for name, _ in inspect.getmembers(
            observer.ReceiptObserver, predicate=inspect.isfunction) if not name.startswith("_")}
        self.assertEqual(public, {"prepare", "observe", "reconcile_saved"})
        transport_public = {name for name, _ in inspect.getmembers(
            observer.FixedReadonlyTransport, predicate=inspect.isfunction)
            if not name.startswith("_")}
        self.assertEqual(transport_public, {"page_url", "export_url", "read_page", "read_export"})
        self.assertNotIn("POST", inspect.getsource(observer.FixedReadonlyTransport))
        self.assertNotIn("identity", inspect.getsource(observer.ReceiptObserver).lower())
        self.assertNotIn("signer", inspect.getsource(observer.ReceiptObserver).lower())
        production_public = {name for name, _ in inspect.getmembers(
            observer._ProductionReceiptObserver, predicate=inspect.isfunction)
            if not name.startswith("_")}
        self.assertEqual(production_public, {"start", "reconcile_saved"})
        session_public = {name for name, _ in inspect.getmembers(
            observer.ReceiptObservationSession, predicate=inspect.isfunction)
            if not name.startswith("_")}
        self.assertEqual(
            session_public, {"wait_until_ready", "wait_for_result"})

    def test_production_factory_seals_protocol_and_request_bindings(self):
        signature = inspect.signature(observer.build_production_receipt_observer)
        self.assertEqual(
            tuple(signature.parameters),
            ("private_runtime_root", "expected_generation", "initial_since",
             "observation_started_at"))
        self.assertFalse(hasattr(observer, "_production_config"))
        closure = inspect.getclosurevars(
            observer.build_production_receipt_observer).nonlocals
        config_factory = closure["production_config"]
        cfg = config_factory(
            expected_generation=1, initial_since=10, observation_started_at=NOW)
        self.assertEqual(cfg.request_id, observer.registration.REQUEST_ID)
        self.assertEqual(cfg.participant_did, observer.registration.PARTICIPANT_DID)
        self.assertEqual(cfg.origin, observer.OFFICIAL_ORIGIN)
        self.assertEqual(cfg.room, observer.ROOM)
        self.assertIs(
            closure["trusted_classifier"],
            observer.registration_adapters._classify_observed_receipt)
        with mock.patch.object(observer.registration, "REQUEST_ID", "changed"), \
                mock.patch.object(observer.registration, "PARTICIPANT_DID", "changed"), \
                mock.patch.object(observer, "OFFICIAL_ORIGIN", "https://invalid.example"), \
                mock.patch.object(observer, "ROOM", "mb-other"):
            rebound = config_factory(
                expected_generation=1, initial_since=10,
                observation_started_at=NOW)
            self.assertEqual(rebound.request_id, cfg.request_id)
            self.assertEqual(rebound.participant_did, cfg.participant_did)
            self.assertEqual(rebound.origin, cfg.origin)
            self.assertEqual(rebound.room, cfg.room)


class ReceiptPathBoundaryTests(unittest.TestCase):
    def temporary_root(self, *, child=True, mode=0o700):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(mode)
        if child:
            (root / observer.RECEIPT_CHILD_BASENAME).mkdir(mode=0o700)
        return root

    def open_child(self, root, *, repository_roots=(), filesystem=lambda _path: True):
        return observer._open_receipt_child_core(
            root, repository_roots=tuple(repository_roots),
            filesystem_validator=filesystem)

    def assert_error(self, code, value, **kwargs):
        with self.assertRaises(observer.ReceiptObserverError) as raised:
            self.open_child(value, **kwargs)
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(str(raised.exception), code)

    def test_missing_empty_relative_and_non_path_roots_fail_closed(self):
        self.assert_error("PRIVATE_ROOT_NOT_CONFIGURED", None)
        self.assert_error("PRIVATE_ROOT_NOT_CONFIGURED", "")
        self.assert_error("PRIVATE_ROOT_NOT_ABSOLUTE", Path("relative"))
        self.assert_error("PRIVATE_ROOT_NOT_CONFIGURED", "/absolute/string")

    def test_repository_git_current_and_linked_worktrees_are_rejected(self):
        repository = self.temporary_root()
        candidates = (
            repository,
            repository / "nested",
            repository / ".git",
        )
        for candidate in candidates:
            with self.subTest(kind=candidate.name):
                self.assert_error(
                    "PRIVATE_ROOT_INSIDE_REPOSITORY", candidate,
                    repository_roots=(repository,))
        linked = self.temporary_root()
        self.assert_error(
            "PRIVATE_ROOT_INSIDE_REPOSITORY", linked,
            repository_roots=(repository, linked))

    def test_repository_comparison_is_component_aware_not_string_prefix(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder).resolve()
            repository = base / "repo"
            repository.mkdir(mode=0o700)
            candidate = base / "repo2"
            candidate.mkdir(mode=0o700)
            (candidate / observer.RECEIPT_CHILD_BASENAME).mkdir(mode=0o700)
            capability = self.open_child(
                candidate, repository_roots=(repository,))
            self.assertEqual(repr(capability), "<private directory capability>")
            capability.close()

    def test_known_cloud_sync_location_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve() / "CloudStorage" / "private"
            root.mkdir(parents=True, mode=0o700)
            (root / observer.RECEIPT_CHILD_BASENAME).mkdir(mode=0o700)
            self.assert_error("PRIVATE_ROOT_UNSAFE_LOCATION", root)

    def test_lexical_traversal_is_rejected_before_normalization(self):
        root = self.temporary_root()
        candidate = root / "nested" / ".."
        self.assertIn("..", candidate.parts)
        self.assert_error("PRIVATE_ROOT_PATH_TRAVERSAL", candidate)

    def test_root_and_intermediate_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder).resolve()
            real = base / "real"
            real.mkdir(mode=0o700)
            (real / observer.RECEIPT_CHILD_BASENAME).mkdir(mode=0o700)
            alias = base / "alias"
            alias.symlink_to(real, target_is_directory=True)
            self.assert_error("PRIVATE_ROOT_SYMLINK", alias)
            parent = base / "parent"
            parent.mkdir(mode=0o700)
            intermediate = parent / "linked"
            intermediate.symlink_to(real, target_is_directory=True)
            nested = real / "nested"
            nested.mkdir(mode=0o700)
            (nested / observer.RECEIPT_CHILD_BASENAME).mkdir(mode=0o700)
            self.assert_error("PRIVATE_ROOT_SYMLINK", intermediate / "nested")

    def test_missing_nondirectory_wrong_owner_mode_and_filesystem_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder).resolve()
            missing = base / "missing"
            self.assert_error("PRIVATE_ROOT_NOT_CONFIGURED", missing)
            self.assertFalse(missing.exists())
            regular = base / "regular"
            regular.write_bytes(b"")
            self.assert_error("PRIVATE_ROOT_NOT_DIRECTORY", regular)
        wrong_mode = self.temporary_root(mode=0o755)
        self.assert_error("PRIVATE_ROOT_UNSAFE_MODE", wrong_mode)
        root = self.temporary_root()
        with mock.patch.object(observer.os, "getuid", return_value=os.getuid() + 1):
            self.assert_error("PRIVATE_ROOT_UNSAFE_OWNER", root)
        self.assert_error(
            "PRIVATE_ROOT_UNSAFE_FILESYSTEM", root,
            filesystem=lambda _path: False)

    def test_child_is_fixed_direct_existing_and_never_auto_created(self):
        root = self.temporary_root(child=False)
        nested = root / "execution-journal"
        nested.mkdir(mode=0o700)
        (nested / observer.RECEIPT_CHILD_BASENAME).mkdir(mode=0o700)
        before = sorted(path.name for path in root.iterdir())
        self.assert_error("RECEIPT_CHILD_NOT_PROVISIONED", root)
        self.assertEqual(before, sorted(path.name for path in root.iterdir()))
        self.assertFalse((root / observer.RECEIPT_CHILD_BASENAME).exists())
        signature = inspect.signature(observer.build_production_receipt_observer)
        self.assertFalse(any("child" in name for name in signature.parameters))

    def test_child_mode_symlink_owner_and_inode_type_are_rejected(self):
        wrong_mode = self.temporary_root()
        (wrong_mode / observer.RECEIPT_CHILD_BASENAME).chmod(0o755)
        self.assert_error("RECEIPT_CHILD_UNSAFE", wrong_mode)
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder).resolve()
            base.chmod(0o700)
            target = base / "target"
            target.mkdir(mode=0o700)
            (base / observer.RECEIPT_CHILD_BASENAME).symlink_to(
                target, target_is_directory=True)
            self.assert_error("RECEIPT_CHILD_UNSAFE", base)
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder).resolve()
            base.chmod(0o700)
            (base / observer.RECEIPT_CHILD_BASENAME).write_bytes(b"")
            self.assert_error("RECEIPT_CHILD_UNSAFE", base)
        root = self.temporary_root()
        real_fstat = observer.os.fstat
        calls = 0

        def wrong_child_owner(fd):
            nonlocal calls
            calls += 1
            value = real_fstat(fd)
            if calls == 2:
                return types.SimpleNamespace(
                    st_mode=value.st_mode, st_uid=value.st_uid + 1,
                    st_dev=value.st_dev, st_ino=value.st_ino)
            return value

        with mock.patch.object(observer.os, "fstat", side_effect=wrong_child_owner):
            self.assert_error("RECEIPT_CHILD_UNSAFE", root)

    def test_safe_root_yields_path_free_single_use_capability(self):
        root = self.temporary_root()
        capability = self.open_child(root)
        self.assertNotIn(str(root), repr(capability))
        self.assertFalse(dataclasses.is_dataclass(capability))
        with self.assertRaises(TypeError):
            dataclasses.asdict(capability)
        store = observer.PrivateReceiptStore(capability)
        with self.assertRaisesRegex(
                observer.ReceiptObserverError, "RECEIPT_CHILD_UNSAFE"):
            capability.take()
        store.close()

    def test_production_factory_has_no_legacy_fallback_or_filesystem_mutation(self):
        signature = inspect.signature(observer.build_production_receipt_observer)
        parameter = signature.parameters["private_runtime_root"]
        self.assertIs(parameter.default, inspect.Parameter.empty)
        closure = inspect.getclosurevars(
            observer.build_production_receipt_observer).nonlocals
        self.assertNotIn("evidence_root", closure)
        self.assertNotIn("handoff", inspect.getsource(observer))
        with tempfile.TemporaryDirectory() as folder:
            missing = Path(folder).resolve() / "missing"
            with mock.patch.object(observer.os, "mkdir") as mkdir, \
                    mock.patch.object(observer.os, "chmod") as chmod, \
                    mock.patch.object(observer.os, "chown") as chown:
                with self.assertRaisesRegex(
                        observer.ReceiptObserverError,
                        "PRIVATE_ROOT_NOT_CONFIGURED"):
                    observer.build_production_receipt_observer(
                        private_runtime_root=missing, expected_generation=1,
                        initial_since=10, observation_started_at=NOW)
                mkdir.assert_not_called()
                chmod.assert_not_called()
                chown.assert_not_called()
            self.assertFalse(missing.exists())

    def test_factory_build_does_not_start_network_or_ready_state(self):
        root = self.temporary_root()
        with mock.patch.object(
                observer.FixedReadonlyTransport, "_get") as network:
            service = observer.build_production_receipt_observer(
                private_runtime_root=root, expected_generation=1,
                initial_since=10, observation_started_at=NOW)
            network.assert_not_called()
            self.assertFalse(service._started)
            self.assertEqual(repr(service), "<fixed Sonnet receipt observer>")
            service._observer._store.close()

    def test_production_path_policy_is_sealed_against_module_rebinding(self):
        root = self.temporary_root()
        actual_repository = observer.REPOSITORY_ROOT
        with mock.patch.object(observer, "REPOSITORY_ROOT", root), \
                mock.patch.object(observer, "RECEIPT_CHILD_BASENAME", "attacker"), \
                mock.patch.object(observer, "_open_receipt_child_core") as rebound:
            service = observer.build_production_receipt_observer(
                private_runtime_root=root, expected_generation=1,
                initial_since=10, observation_started_at=NOW)
            rebound.assert_not_called()
            service._observer._store.close()
        with mock.patch.object(observer, "REPOSITORY_ROOT", root.parent), \
                mock.patch.object(observer, "_is_within", return_value=False), \
                self.assertRaisesRegex(
                    observer.ReceiptObserverError,
                    "PRIVATE_ROOT_INSIDE_REPOSITORY"):
            observer.build_production_receipt_observer(
                private_runtime_root=actual_repository,
                expected_generation=1, initial_since=10,
                observation_started_at=NOW)

    def test_errors_and_public_projection_never_include_private_path(self):
        root = self.temporary_root(child=False)
        try:
            self.open_child(root)
        except observer.ReceiptObserverError as error:
            rendered = repr(error) + str(error)
        else:
            self.fail("missing child unexpectedly accepted")
        self.assertNotIn(str(root), rendered)
        result = observer.ObserverResult(
            "UNCONFIRMED", False, False, 0, 0, False, False,
            error_category="RECEIPT_CHILD_NOT_PROVISIONED")
        projection = json.dumps(dict(result.journal_projection()))
        self.assertNotIn(str(root), projection)

    def test_existing_handoff_root_definition_is_unchanged(self):
        from flop_agent import sonnet_registration_handoff as handoff
        expected = (
            Path(handoff.__file__).resolve().parents[2] / "runtime" / "sonnet-2"
            / "registration-bf8de59d-6e06-48b3-914b-6ac75cf07f4a"
            / "execution-journal")
        self.assertEqual(handoff.PRODUCTION_ROOT, expected)


if __name__ == "__main__":
    unittest.main()
