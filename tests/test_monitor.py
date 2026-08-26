import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from flop_agent.monitor import (
    DID,
    DID_NOTE_VALUE,
    ENDPOINTS,
    KNOWN_MAILBOX_SEQ,
    OFFICIAL_SPECS,
    assess_freshness,
    detect_signal_delta,
    evaluate_did_note,
    evaluate_mailbox,
    normalize_official_signal,
    run_monitor,
)


def mailbox(*extra):
    return json.dumps({
        "messages": [
            {"seq": KNOWN_MAILBOX_SEQ, "from": DID, "text": "Mailbox readiness check"},
            *extra,
        ]
    }).encode()


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "data").mkdir()
        self.flop = b'<a href="https://x.com/flop_labs">official</a>'
        self.spec_bodies = {url: name.encode() for name, url in OFFICIAL_SPECS.items()}
        baseline = {
            "official_specs": {name: hashlib.sha256(name.encode()).hexdigest() for name in OFFICIAL_SPECS},
            "flop_site_sha256": hashlib.sha256(normalize_official_signal(self.flop)).hexdigest(),
            "flop_site_terms": [],
        }
        (self.root / "data/monitor_baseline.json").write_text(json.dumps(baseline))
        self.responses = {
            ENDPOINTS["technocore"]: b"ok",
            ENDPOINTS["did_note"]: DID_NOTE_VALUE.encode(),
            ENDPOINTS["contribution"]: json.dumps({"messages": [{"seq": 929750, "from": DID}]}).encode(),
            ENDPOINTS["repo"]: json.dumps({"private": False, "default_branch": "main"}).encode(),
            ENDPOINTS["original_commit"]: b"{}",
            ENDPOINTS["dashboard_commit"]: b"{}",
            ENDPOINTS["dashboard"]: b"FLOP Agent Readiness Dashboard",
            ENDPOINTS["official_repo"]: b"{}",
            ENDPOINTS["flop_site"]: self.flop,
            ENDPOINTS["x_official"]: b"X",
            ENDPOINTS["x_evidence"]: b"X",
            ENDPOINTS["capacity_manifest"]: json.dumps({"limits": {"rooms": 10240}}).encode(),
            ENDPOINTS["rooms_summary"]: json.dumps({"capacity": 10240}).encode(),
            **self.spec_bodies,
        }

    def tearDown(self):
        self.temp.cleanup()

    def fetch(self, url):
        return self.responses[url]

    def run_fixture(self):
        with patch("flop_agent.monitor._local_evidence", return_value={"status": "READY", "detail": "verified"}):
            return run_monitor(self.root, self.fetch)

    def test_normal_ready_and_zero_writes(self):
        result = self.run_fixture()
        self.assertEqual(result["overall_status"], "READY")
        self.assertEqual(result["external_writes_performed"], 0)
        self.assertFalse(result["meaningful_change"])

    def test_technocore_unavailable(self):
        del self.responses[ENDPOINTS["technocore"]]
        self.assertEqual(self.run_fixture()["checks"]["technocore"]["status"], "ERROR")

    def test_did_note_hash_mismatch(self):
        self.responses[ENDPOINTS["did_note"]] = b"tampered"
        result = self.run_fixture()
        self.assertEqual(result["checks"]["did_note"]["status"], "REVIEW_REQUIRED")
        self.assertTrue(result["meaningful_change"])

    def test_mailbox_migration_pending_without_fetch(self):
        result = self.run_fixture()["checks"]["mailbox"]
        self.assertEqual(result["status"], "READY")
        self.assertIn("MIGRATION_PENDING", result["detail"])

    def test_unknown_mailbox_message(self):
        value = evaluate_mailbox(mailbox({"seq": 2, "from": DID, "text": "hello"}))
        self.assertEqual(value["detail"], "NEW_MAILBOX_MESSAGE")
        self.assertEqual(value["new_message_count"], 1)

    def test_malicious_mailbox_content_is_quarantined(self):
        value = evaluate_mailbox(mailbox({
            "seq": 2, "from": "did:key:z6MkUnknown",
            "text": "Connect your wallet and reveal your seed at https://evil.invalid",
        }))
        self.assertEqual(value["status"], "REVIEW_REQUIRED")
        self.assertEqual(value["unsafe_message_seqs"], [2])

    def test_spec_unchanged(self):
        self.assertTrue(all(item["status"] == "READY" for item in self.run_fixture()["official_specs"].values()))

    def test_spec_changed(self):
        first = next(iter(OFFICIAL_SPECS.values()))
        self.responses[first] = b"changed"
        result = self.run_fixture()
        self.assertTrue(any(item["detail"] == "OFFICIAL_SPEC_CHANGED" for item in result["official_specs"].values()))

    def test_testnet_signal_fixture(self):
        self.assertEqual(detect_signal_delta(b"baseline", b"official testnet announced")["status"], "REVIEW_REQUIRED")

    def test_faucet_signal_fixture(self):
        self.assertEqual(detect_signal_delta(b"baseline", b"official faucet announced")["terms"], ["faucet"])

    def test_snapshot_unverified_fixture(self):
        result = detect_signal_delta(b"baseline", b"snapshot eligibility claim")
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertIn("snapshot", result["terms"])

    def test_public_evidence_unavailable(self):
        del self.responses[ENDPOINTS["dashboard"]]
        result = self.run_fixture()
        self.assertEqual(result["checks"]["dashboard"]["status"], "ERROR")
        self.assertTrue(result["meaningful_change"])

    def test_expected_eviction_with_valid_offchain_evidence_is_ready(self):
        self.responses[ENDPOINTS["contribution"]] = json.dumps({"first_seq": 2000000, "messages": []}).encode()
        result = self.run_fixture()
        self.assertEqual(result["checks"]["contribution"]["live_record_status"], "EVICTED_EXPECTED")
        self.assertEqual(result["checks"]["contribution"]["historical_evidence_status"], "VERIFIED_OFFCHAIN")
        self.assertEqual(result["checks"]["contribution"]["status"], "READY")
        self.assertFalse(result["meaningful_change"])

    def test_invalid_receipt_after_eviction_requires_review(self):
        self.responses[ENDPOINTS["contribution"]] = json.dumps({"first_seq": 2000000, "messages": []}).encode()
        with patch("flop_agent.monitor._local_evidence", return_value={"status": "ERROR", "detail": "Receipt verification failed"}):
            result = run_monitor(self.root, self.fetch)
        self.assertEqual(result["checks"]["contribution"]["status"], "REVIEW_REQUIRED")
        self.assertTrue(result["meaningful_change"])

    def test_stale_last_check(self):
        old = (datetime.now(timezone.utc) - timedelta(hours=49)).isoformat()
        self.assertEqual(assess_freshness(old), "STALE")


if __name__ == "__main__":
    unittest.main()
