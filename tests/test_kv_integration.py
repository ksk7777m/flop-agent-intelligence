import json
import re
import unittest
from pathlib import Path
from flop_agent.presence import load_semantic_contract

ROOT = Path(__file__).resolve().parents[1]


class KVIntegrationTests(unittest.TestCase):
    def test_presence_contract_unchanged(self):
        self.assertEqual(
            load_semantic_contract(ROOT / "data/presence_semantic_contract.json")[1],
            "1d89199c57008083bef24cc2f62a4275a8b77ab470c0a163f0e037c14e872778",
        )
        adapter = json.loads((ROOT / "data/presence_adapter.json").read_text())
        self.assertEqual(adapter["live_writes"], "DISABLED")
        self.assertEqual(adapter["writes"], 0)

    def test_discovery_preserved_and_kv_discoverable(self):
        manifest = json.loads((ROOT / "ai-onboarding.json").read_text())
        endpoints = [f"https://ksk7777m.github.io/flop-agent-intelligence/api/kv/{name}.json" for name in ("status", "namespaces", "changes", "presence")]
        for endpoint in endpoints:
            self.assertIn(endpoint, manifest["read_only_data"])
            self.assertIn(endpoint, (ROOT / "llms.txt").read_text())
        self.assertIn("LIVE READY — DISABLED", (ROOT / "index.html").read_text())
        self.assertIn("publish --confirm", (ROOT / "llms.txt").read_text())

    def test_openapi_get_only_and_schema_registered(self):
        spec = json.loads((ROOT / "openapi.json").read_text())
        for operations in spec["paths"].values():
            self.assertFalse(set(operations) & {"post", "put", "patch", "delete"})
        for name in ("status", "namespaces", "changes", "presence"):
            self.assertIn(f"/api/kv/{name}.json", spec["paths"])
        index = json.loads((ROOT / "schemas/index.json").read_text())
        self.assertTrue(any(s["path"] == "schemas/kv-observatory.schema.json" for s in index["schemas"]))

    def test_static_generation_consistency_and_empty_warning(self):
        payloads = [json.loads((ROOT / "api/kv" / f"{n}.json").read_text()) for n in ("status", "namespaces", "changes", "presence")]
        self.assertEqual(len({p["snapshot_id"] for p in payloads}), 1)
        self.assertEqual(len({p["generated_at"] for p in payloads}), 1)
        self.assertEqual(payloads[0]["observation_status"], "NO REVIEWED LIVE OBSERVATION YET")
        self.assertEqual(payloads[0]["namespaces_successfully_observed"], 0)

    def test_gitignore_database_artifacts(self):
        text = (ROOT / ".gitignore").read_text()
        for pattern in ("*.sqlite", "*.sqlite3", "*.db", "*.db-wal", "*.db-shm", "*.sqlite-wal", "*.sqlite-shm", "*-wal", "*-shm"):
            self.assertIn(pattern, text)

    def test_dashboard_separates_presence_and_kv_and_uses_inert_text(self):
        html = (ROOT / "index.html").read_text()
        js = (ROOT / "dashboard.js").read_text()
        self.assertIn('id="presence-adapter"', html)
        self.assertIn('id="kv-observatory"', html)
        self.assertIn("textContent", js)
        self.assertNotIn("innerHTML", js)
        ids = re.findall(r'\bid="([^"]+)"', html)
        self.assertEqual(len(ids), len(set(ids)))


if __name__ == "__main__":
    unittest.main()
