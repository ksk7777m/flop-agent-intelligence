import json
import unittest
from pathlib import Path

from flop_agent.monitor import (
    DID_NOTE_VALUE,
    classify_live_record,
    evaluate_capacity_contract,
)
from flop_agent.technocore import conditional_note_payload


ROOT = Path(__file__).resolve().parents[1]


class PhaseATests(unittest.TestCase):
    def test_nonexistent_mailbox_is_not_advertised(self):
        self.assertNotIn("mailbox:", DID_NOTE_VALUE)

    def test_did_note_cas_payload(self):
        payload = conditional_note_payload("current exact value", DID_NOTE_VALUE)
        self.assertEqual(payload["if"], "current exact value")
        self.assertEqual(payload["value"], DID_NOTE_VALUE)

    def test_expected_eviction(self):
        body = json.dumps({"first_seq": 2077267, "messages": []}).encode()
        result = classify_live_record(body)
        self.assertEqual(result["status"], "EVICTED_EXPECTED")

    def test_ring_boundary_missing_is_unexpected(self):
        body = json.dumps({"first_seq": 929750, "messages": []}).encode()
        self.assertEqual(classify_live_record(body)["status"], "UNEXPECTED_MISSING")

    def test_capacity_contract_consistent(self):
        manifest = json.dumps({"limits": {"rooms": 10240}}).encode()
        rooms = json.dumps({"capacity": 10240}).encode()
        result = evaluate_capacity_contract(manifest, rooms)
        self.assertEqual(result["status"], "CONSISTENT")

    def test_capacity_contract_diverged(self):
        manifest = json.dumps({"limits": {"rooms": 10240}}).encode()
        rooms = json.dumps({"capacity": 5120}).encode()
        result = evaluate_capacity_contract(manifest, rooms)
        self.assertEqual(result["status"], "DIVERGED")
        self.assertEqual(result["classification"], "REVIEW_REQUIRED")

    def test_capacity_change_is_consistent_when_manifest_matches_runtime(self):
        manifest = json.dumps({"limits": {"rooms": 20480}}).encode()
        rooms = json.dumps({"capacity": 20480}).encode()
        result = evaluate_capacity_contract(manifest, rooms)
        self.assertEqual(result["status"], "CONSISTENT")
        self.assertTrue(result["runtime_changed_since_observation"])

    def test_no_new_room_probe_or_room_write(self):
        source = (ROOT / "src/flop_agent/monitor.py").read_text(encoding="utf-8")
        self.assertNotIn("post_signed", source)
        self.assertNotIn("/say/", source)
        self.assertNotIn("mb-flop-agent", source)

    def test_legacy_locator_absent_from_current_artifacts(self):
        legacy = "mb-p-" + "87d20323b91af58f3b79f342c1265210"
        excluded = {".git", "secrets", "receipts", "runtime", "__pycache__"}
        for path in ROOT.rglob("*"):
            if not path.is_file() or any(part in excluded for part in path.parts):
                continue
            try:
                content = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            self.assertNotIn(legacy, content, str(path))


if __name__ == "__main__":
    unittest.main()
