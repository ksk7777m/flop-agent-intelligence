import base64
import sqlite3
import tempfile
import subprocess
import sys
import os
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from flop_agent.did_key import did_from_public_key
from flop_agent.technocore import _build_technocore_client
from flop_agent.remote_content_policy import SafeRemoteError
from flop_agent.wire_evidence import ReadBackStage, parse_nonce
from flop_agent.write_effect import WriteAttemptJournal, WriteEffectError


class WriteCertaintyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "journal"
        # Deterministic public TEST fixture, never a configured identity.
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.did = did_from_public_key(self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        self.calls = []

    def client(self, failure=None, mutation=None, signing_text=None):
        record = {}
        def signer(key, room, nonce, text):
            signature = base64.urlsafe_b64encode(key.sign(
                f"{room}|{nonce}|{signing_text or text}".encode())).decode().rstrip("=")
            record.update({"from": self.did, "nonce": nonce, "text": text, "sig": signature})
            return signature, text
        def transport(_url, request):
            self.calls.append(request.method)
            if request.method == "POST":
                # Evidence must be committed BEFORE the first send invocation.
                with sqlite3.connect(self.root / "attempts.sqlite3") as con:
                    self.assertEqual(con.execute("SELECT count(*) FROM attempts").fetchone()[0], 1)
                if failure:
                    raise failure
                return {"ok": True}
            value = dict(record)
            if mutation:
                mutation(value)
            return {"messages": [value]}
        return _build_technocore_client(
            lambda _: None, lambda *a, **k: None, lambda _: (self.key, self.did),
            signer, transport, attempt_recorder=WriteAttemptJournal(self.root).reserve)[3]

    def post(self, client, nonce="9007199254740992"):
        return client(Path("unused"), "lobby", "fixture", intent=None, revision="a" * 40,
                      config_version="test", context="test", nonce=nonce)

    def test_verified_readback_is_required_and_scope_is_limited(self):
        result = self.post(self.client())
        self.assertEqual(result["write_effect"], "EVIDENCE_CONFIRMED")
        self.assertEqual(result["effect_scope"], "SIGNED_ROOM_RECORD_ONLY")
        self.assertEqual(result["nonce"], "9007199254740992")
        self.assertEqual(self.calls, ["POST", "GET"])

    def test_timeout_unknown_and_restart_never_resends_even_with_new_nonce(self):
        with self.assertRaises(WriteEffectError) as error:
            self.post(self.client(failure=TimeoutError("PRIVATE_SENTINEL")))
        self.assertEqual(error.exception.stage, ReadBackStage.EFFECT_UNKNOWN)
        self.assertNotIn("PRIVATE_SENTINEL", str(error.exception))
        for nonce in ("9007199254740992", "9007199254740993"):
            with self.assertRaises(WriteEffectError) as error:
                self.post(self.client(), nonce)
            self.assertEqual(error.exception.stage, ReadBackStage.DUPLICATE_SUPPRESSED)
        self.assertEqual(self.calls, ["POST"])

    def test_redirect_rejected_without_readback_or_retry(self):
        with self.assertRaises(WriteEffectError) as error:
            self.post(self.client(failure=SafeRemoteError("HTTP_ERROR", status=307)))
        self.assertEqual(error.exception.stage, ReadBackStage.REDIRECT_REJECTED)
        self.assertEqual(self.calls, ["POST"])

    def test_mismatch_and_invalid_signature_do_not_confirm(self):
        for field, expected in (("text", ReadBackStage.READBACK_MISMATCH),
                                 ("sig", ReadBackStage.SIGNATURE_INVALID)):
            with self.subTest(field=field):
                self.root = self.root.parent / field
                with self.assertRaises(WriteEffectError) as error:
                    self.post(self.client(mutation=lambda r: r.update({field: "invalid"})))
                self.assertEqual(error.exception.stage, expected)

    def test_same_returned_signature_still_requires_cryptographic_verification(self):
        with self.assertRaises(WriteEffectError) as error:
            self.post(self.client(signing_text="wrong signed bytes"))
        self.assertEqual(error.exception.stage, ReadBackStage.SIGNATURE_INVALID)

    def test_process_exit_after_recording_fences_a_restart(self):
        code = ("import os,sys; from pathlib import Path; "
                "from flop_agent.write_effect import WriteAttemptJournal; "
                "WriteAttemptJournal(Path(sys.argv[1])).reserve('a'*64,'b'*64); os._exit(0)")
        run = subprocess.run([sys.executable, "-c", code, str(self.root)],
                             env={**os.environ, "PYTHONPATH": "src"}, capture_output=True)
        self.assertEqual(run.returncode, 0)
        with self.assertRaises(WriteEffectError) as error:
            WriteAttemptJournal(self.root).reserve("a" * 64, "b" * 64)
        self.assertEqual(error.exception.stage, ReadBackStage.DUPLICATE_SUPPRESSED)

    def test_corruption_and_symlink_fail_before_transport(self):
        self.root.mkdir(mode=0o700)
        target = self.root.parent / "untouched"
        target.write_text("sentinel")
        (self.root / "attempts.sqlite3").symlink_to(target)
        with self.assertRaises(WriteEffectError):
            self.post(self.client())
        self.assertEqual(target.read_text(), "sentinel")
        self.assertEqual(self.calls, [])

    def test_concurrent_reservation_is_unique_and_crash_stays_consumed(self):
        self.root.mkdir(mode=0o700)
        def reserve(_):
            try:
                WriteAttemptJournal(self.root).reserve("a" * 64, "b" * 64)
                return True
            except WriteEffectError:
                return False
        with ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(sum(pool.map(reserve, range(4))), 1)
        self.assertFalse(reserve(0))  # new object, same durable fence, no send took place
        raw = (self.root / "attempts.sqlite3").read_bytes()
        self.assertNotIn(self.did.encode(), raw)

    def test_nonce_policy(self):
        for value in ("1", str(2**53-1), str(2**53), str(2**63-1)):
            self.assertEqual(parse_nonce(value).decimal, value)
        for value in ("0", "01", "-1", "1.0", "1e3", "9" * 100, 2**53, 1.0, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_nonce(value)

    def test_unsigned_note_cas_never_claims_verified_effect(self):
        calls = []
        update = _build_technocore_client(
            lambda _: None, lambda *a, **k: None, lambda _: None, lambda *a: None,
            lambda url, req: calls.append(req.method) or "untrusted note",
            attempt_recorder=WriteAttemptJournal(self.root).reserve)[2]
        args = dict(intent=None, revision="a" * 40, config_version="test", context="test")
        result = update("prior", "replacement", **args)
        self.assertEqual(result["write_effect"], "EFFECT_UNKNOWN")
        self.assertFalse(result["retry_allowed"])
        self.assertEqual(calls, ["POST", "GET"])
        with self.assertRaises(WriteEffectError):
            update("prior", "replacement", **args)
        self.assertEqual(calls, ["POST", "GET"])
