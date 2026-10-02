import base64
import hashlib
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from flop_agent import close_call as close
from flop_agent.did_key import did_from_public_key

ROOT = Path(__file__).resolve().parents[1] / "vendor/official_sources/2026-10-02/close-call"


class CloseCallTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((ROOT / "contest.json").read_text())
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.did = did_from_public_key(self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    def signed_seed(self, **changes):
        body = {"t": "seed", "season": "close-1", "price": "180.00",
                "trade": {"time": self.config["opening"], "tid": "fixture"},
                "package": hashlib.sha256((ROOT / "manifest.json").read_bytes()).hexdigest(),
                "rooms": self.config["rooms"]["referee"]}
        body.update(changes)
        text = json.dumps(body, separators=(",", ":"))
        room, nonce = "d-close1-price", "9007199254740992"
        sig = base64.urlsafe_b64encode(self.key.sign(f"{room}|{nonce}|{text}".encode())).decode().rstrip("=")
        return dict(room=room, nonce=nonce, text=text, sig=sig, **{"from": self.did})

    def test_package_and_official_fold_vector(self):
        result = close.replay_draft((ROOT / "examples/sample-season.jsonl").read_bytes())
        expected = json.loads((ROOT / "examples/sample-season.expected.json").read_text())
        self.assertEqual({k: result[k] for k in ("sweeps", "final")}, expected)
        self.assertEqual(result["final"]["zero_sum"], "0.0000")
        self.assertTrue(result["positions"])
        self.assertTrue(result["balances"])
        self.assertEqual(result["status"], "UNAUTHENTICATED_DRAFT_REPLAY")
        self.assertEqual(result["live_write"], "DISABLED")

    def test_launch_never_accepts_self_asserted_authority(self):
        for record in (None, {}, {"official_launch_verified": True}, {"sig": "invalid", "referee": self.did}):
            result = close.activation_status(launch_record=record,
                now=datetime(2026, 10, 2, tzinfo=timezone.utc))
            self.assertFalse(result["official_launch_verified"])
            self.assertEqual(result["live_write"], "DISABLED")
            self.assertTrue(result["dry_run"])
            self.assertTrue(result["time_window_open"])
        self.assertFalse(close.activation_status(now=datetime(2026, 10, 5, tzinfo=timezone.utc))["time_window_open"])

    def test_candidate_signature_is_not_official_launch(self):
        result = close.verify_candidate_records([self.signed_seed()], expected_referee=self.did)
        self.assertEqual(result["signatures"], "VERIFIED_FOR_CANDIDATE_KEY")
        self.assertFalse(result["official_launch_verified"])
        self.assertFalse(result["history_complete"])

    def test_rejects_wrong_seed_bindings(self):
        for changes in ({"season": "other"}, {"package": "0" * 64}, {"rooms": ["lobby"]}):
            with self.subTest(changes=changes), self.assertRaises(close.CloseCallError):
                close.verify_candidate_records([self.signed_seed(**changes)], expected_referee=self.did)

    def test_wrong_referee_bad_signature_replay_and_room(self):
        record = self.signed_seed()
        with self.assertRaises(close.CloseCallError):
            close.verify_candidate_records([record], expected_referee="did:key:wrong")
        for changes in ({"sig": "invalid"}, {"room": "close1"}, {"nonce": 2**53}):
            with self.subTest(changes=changes), self.assertRaises(close.CloseCallError):
                close.verify_candidate_records([{**record, **changes}], expected_referee=self.did)
        with self.assertRaisesRegex(close.CloseCallError, "REPLAYED_RECORD"):
            close.verify_candidate_records([record, record], expected_referee=self.did)

    def test_wrong_contest_rules_hash_and_malformed_fold(self):
        manifest, rules = ((ROOT / name).read_bytes() for name in ("manifest.json", "close-call-game.md"))
        for config, rule in ((b'{"contest_id":"wrong"}', rules),
                             ((ROOT / "contest.json").read_bytes(), rules + b"changed")):
            with self.assertRaises(close.CloseCallError):
                close.verify_package(config, manifest, rule)
        for raw in (b'{}', b'{"t":"seed","t":"final"}', b'{"t":"final","px":"1"}'):
            with self.assertRaises(close.CloseCallError):
                close.replay_draft(raw)

    def test_signed_archive_hash_output_and_redaction_boundaries(self):
        events = [json.loads(line) for line in (ROOT / "examples/sample-season.jsonl").read_text().splitlines()]
        expected = json.loads((ROOT / "examples/sample-season.expected.json").read_text())
        raw = json.dumps({"input": events[1], "output": expected["sweeps"][0]},
                         sort_keys=True, separators=(",", ":")).encode()
        def signed_flow(blob):
            body = {"t": "flow", "n": 1, "file": hashlib.sha256(blob).hexdigest()}
            text = json.dumps(body, separators=(",", ":"))
            sig = base64.urlsafe_b64encode(self.key.sign(f"d-close1-flow|1|{text}".encode())).decode().rstrip("=")
            return dict(room="d-close1-flow", nonce="1", text=text, sig=sig, **{"from": self.did})
        flow = signed_flow(raw)
        report = close.replay_signed_archive(self.signed_seed(), [flow], [raw], expected_referee=self.did)
        self.assertTrue(report["balances"])
        self.assertFalse(report["official_launch_verified"])
        with self.assertRaisesRegex(close.CloseCallError, "ARCHIVE_HASH"):
            close.replay_signed_archive(self.signed_seed(), [flow], [raw + b' '], expected_referee=self.did)
        bad = json.loads(raw); bad["output"]["global_price"] = "0"
        bad = json.dumps(bad).encode()
        with self.assertRaisesRegex(close.CloseCallError, "ARCHIVE_OUTPUT"):
            close.replay_signed_archive(self.signed_seed(), [signed_flow(bad)], [bad], expected_referee=self.did)
        bad = json.loads(raw); bad["input"]["trades"][0] = {"redacted": "private room"}
        bad = json.dumps(bad).encode()
        with self.assertRaisesRegex(close.CloseCallError, "ARCHIVE_REDACTED"):
            close.replay_signed_archive(self.signed_seed(), [signed_flow(bad)], [bad], expected_referee=self.did)
