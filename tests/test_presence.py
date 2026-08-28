import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from flop_agent.presence import DryRunOnly, PresenceConfig, PresenceError, apply_payload, observe

NOW = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)


def config(**overrides):
    values = {"room": "lobby", "note_path": "/kv/did-4e/public-note",
              "current_note_value": "current", "minimum_update_seconds": 3600,
              "enabled": True, "dry_run": True}
    values.update(overrides)
    return PresenceConfig(**values)


def rooms(seq=10):
    return {"rooms": [{"room": "lobby", "last_seq": seq}]}


class PresenceAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.state = Path(self.temporary.name) / "presence.json"

    def tearDown(self):
        self.temporary.cleanup()

    def observe(self, seq, **kwargs):
        return observe(config(**kwargs), self.state, reader=lambda path: rooms(seq), now=NOW)

    def test_unchanged_seq(self):
        self.observe(10)
        result = self.observe(10)
        self.assertEqual(result["status"], "UNCHANGED")
        self.assertIsNone(result["payload"])

    def test_advanced_seq_prepares_official_payload(self):
        self.observe(10)
        result = self.observe(11)
        self.assertEqual(result["status"], "PAYLOAD_PREPARED")
        self.assertEqual(result["payload"]["body"]["if"], "current")
        note = json.loads(result["payload"]["body"]["value"])
        self.assertEqual(note["observation"]["last_seq"], 11)
        self.assertFalse(result["write_performed"])

    def test_rate_limit(self):
        self.observe(10)
        self.observe(11)
        result = observe(config(), self.state, reader=lambda path: rooms(12),
                         now=datetime(2026, 8, 28, 12, 30, tzinfo=timezone.utc))
        self.assertEqual(result["status"], "RATE_LIMITED")
        self.assertIsNone(result["payload"])
        self.assertEqual(json.loads(self.state.read_text())["last_seen_seq"], 12)

    def test_missing_room(self):
        with self.assertRaisesRegex(PresenceError, "missing"):
            observe(config(), self.state, reader=lambda path: {"rooms": []}, now=NOW)

    def test_malformed_response(self):
        bad = (None, [], {}, {"rooms": "nope"}, {"rooms": [{"room": "lobby", "last_seq": "10"}]})
        for response in bad:
            with self.subTest(response=response), self.assertRaises(PresenceError):
                observe(config(), self.state, reader=lambda path, value=response: value, now=NOW)

    def test_kill_switch_prevents_read_and_state_change(self):
        def forbidden_reader(path):
            raise AssertionError(f"reader called for {path}")
        result = observe(config(enabled=False), self.state, reader=forbidden_reader, now=NOW)
        self.assertEqual(result["status"], "KILL_SWITCHED")
        self.assertFalse(self.state.exists())

    def test_dry_run_enforcement(self):
        with self.assertRaises(DryRunOnly):
            observe(config(dry_run=False), self.state, reader=lambda path: rooms(), now=NOW)
        with self.assertRaises(DryRunOnly):
            apply_payload({"body": {"value": "x", "if": "y"}}, confirm=True)


if __name__ == "__main__":
    unittest.main()
