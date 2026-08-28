import json
import unittest
from pathlib import Path

from flop_agent.observatory import (
    build_snapshot,
    eviction_state,
    filter_rooms,
    normalize_room,
    safe_text,
    sort_rooms,
)


ROOT = Path(__file__).resolve().parents[1]


class ObservatoryTests(unittest.TestCase):
    def setUp(self):
        self.raw = {
            "rooms": [
                {"room": "active", "topic": "hello", "last_seq": 9, "idle_seconds": 10, "bytes": 90, "window": 4, "zero_response_share": 0.25, "nick_diversity": 0.5},
                {"room": "idle", "topic": "<script>alert(1)</script>", "last_seq": 3, "idle_seconds": 90000, "bytes": 20, "window": 1, "zero_response_share": None, "nick_diversity": None},
            ],
            "total": 2, "capacity": 5120, "bytes": 110, "bytes_capacity": 1000,
            "engagement": {"zero_response_share": 0.3, "nick_diversity": 0.4, "windowed_note_to_message_ratio": 0.1, "windowed_messages": 5},
        }

    def test_official_room_parsing_and_schema(self):
        built = build_snapshot(self.raw, fetched_at="2026-08-27T00:00:00Z", lobby_metadata={"first_seq": 8}, spec_version="0.10.0")
        self.assertEqual(built["rooms"]["schema"], "technocore-observatory-rooms-v1")
        self.assertEqual(built["status"]["current_first_seq"], 8)
        self.assertEqual(built["observatory"]["source_status"], "official")

    def test_missing_metric_remains_null(self):
        room = normalize_room(self.raw["rooms"][1], 2)
        self.assertIsNone(room["nick_diversity"])

    def test_unknown_room_filter_is_empty(self):
        rooms = build_snapshot(self.raw)["rooms"]["rooms"]
        self.assertEqual(filter_rooms(rooms, "missing-room"), [])

    def test_filter_and_sort(self):
        rooms = build_snapshot(self.raw)["rooms"]["rooms"]
        self.assertEqual(filter_rooms(rooms, activity="ACTIVE")[0]["room"], "active")
        self.assertEqual(sort_rooms(rooms, "diversity")[0]["room"], "active")
        self.assertEqual(sort_rooms(list(reversed(rooms)), "activity")[0]["room"], "active")

    def test_eviction_calculation(self):
        self.assertEqual(eviction_state(2, 9), "EVICTION_ACTIVE")
        self.assertEqual(eviction_state(1, 9), "NO_GAP_OBSERVED")
        self.assertEqual(eviction_state(None, 9), "UNKNOWN")

    def test_derived_fields_are_explicit(self):
        room = normalize_room(self.raw["rooms"][0], 1)
        self.assertTrue(room["derived"])
        self.assertIn("activity", room["derived_fields"])

    def test_untrusted_html_is_inert_and_bounded(self):
        value = safe_text("<script>go()</script>\nnext", 120)
        self.assertEqual(value, "<script>go()</script> next")
        js = (ROOT / "dashboard.js").read_text(encoding="utf-8")
        self.assertIn("textContent", js)
        self.assertNotIn("innerHTML", js)

    def test_public_api_files_and_openapi(self):
        schemas = {
            "rooms": "technocore-observatory-rooms-v1",
            "engagement": "technocore-observatory-engagement-v1",
            "status": "technocore-observatory-status-v1",
            "observatory": "technocore-observatory-v1",
        }
        for name, schema in schemas.items():
            self.assertEqual(json.loads((ROOT / f"api/{name}.json").read_text())["schema"], schema)
        self.assertEqual(json.loads((ROOT / "openapi.json").read_text())["openapi"], "3.1.0")
        self.assertEqual(json.loads((ROOT / "schemas/observatory.schema.json").read_text())["type"], "object")

    def test_agent_files_prompt_pack_and_chinese(self):
        for path in ("llms.txt", "AGENTS.md", "SKILL.md", "AI_ONBOARDING.md", "ai-onboarding.json", "README.zh-CN.md"):
            self.assertTrue((ROOT / path).is_file())
        expected = {"chatgpt.md", "codex.md", "claude.md", "claude-code.md", "gemini.md", "deepseek.md", "qwen.md", "kimi.md", "cursor.md", "generic-agent.md"}
        self.assertEqual({p.name for p in (ROOT / "prompts").glob("*.md")}, expected)
        self.assertIn("不可信", (ROOT / "README.zh-CN.md").read_text(encoding="utf-8"))

    def test_ai_discovery_and_prompt_contract(self):
        manifest = json.loads((ROOT / "ai-onboarding.json").read_text(encoding="utf-8"))
        labels = {"CONFIRMED", "OFFICIAL_DRAFT", "COMMUNITY", "INFERENCE"}
        self.assertEqual(set(manifest["trust_labels"]), labels)
        self.assertEqual(manifest["mode"], "read-only")
        self.assertEqual(set(manifest["prompts"]), {"chatgpt", "codex", "claude", "claude_code", "gemini", "deepseek", "qwen", "kimi", "cursor", "generic"})
        for prompt_path in manifest["prompts"].values():
            prompt = (ROOT / prompt_path.lstrip("/")).read_text(encoding="utf-8")
            self.assertIn("ai-onboarding.json", prompt)
            for label in labels:
                self.assertIn(label, prompt)

    def test_openapi_is_get_only(self):
        spec = json.loads((ROOT / "openapi.json").read_text(encoding="utf-8"))
        self.assertIn("/ai-onboarding.json", spec["paths"])
        for operations in spec["paths"].values():
            self.assertFalse(set(operations) - {"get", "parameters", "summary", "description"})

    def test_public_safety_scan(self):
        from scripts.public_safety_scan import scan

        self.assertEqual(scan(), [])

    def test_no_write_methods_or_airdrop_score_fields(self):
        source = (ROOT / "src/flop_agent/observatory.py").read_text(encoding="utf-8")
        for forbidden in ("requests.post", "urlopen", "say-signed", "/set/", "private_key"):
            self.assertNotIn(forbidden, source)
        for path in (ROOT / "api").glob("*.json"):
            payload = path.read_text(encoding="utf-8").lower()
            self.assertNotIn('"airdrop_score"', payload)
            self.assertNotIn("mb-p-", payload)

    def test_engagement_rendering_and_copy_ui(self):
        js = (ROOT / "dashboard.js").read_text(encoding="utf-8")
        html = (ROOT / "index.html").read_text(encoding="utf-8")
        self.assertIn("renderEngagement", js)
        self.assertIn('id="room-search"', html)
        self.assertIn('id="copy-prompt"', html)


if __name__ == "__main__":
    unittest.main()
