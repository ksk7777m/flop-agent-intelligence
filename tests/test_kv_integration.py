import json
import copy
import importlib.util
import re
import unittest
from pathlib import Path
from flop_agent.presence import load_semantic_contract
import jsonschema

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
        self.assertEqual(payloads[0]["namespaces_ever_successfully_observed"], 0)
        self.assertEqual(payloads[0]["namespaces_successfully_observed_in_latest_cycle"], 0)

    def test_gitignore_database_artifacts(self):
        text = (ROOT / ".gitignore").read_text()
        for pattern in ("/runtime/**/*.sqlite", "/runtime/**/*.sqlite3", "/runtime/**/*.db", "/runtime/**/*-wal", "/runtime/**/*-shm"):
            self.assertIn(pattern, text)
        self.assertNotIn("\n*.db\n", text)

    def test_dashboard_separates_presence_and_kv_and_uses_inert_text(self):
        html = (ROOT / "index.html").read_text()
        js = (ROOT / "dashboard.js").read_text()
        self.assertIn('id="presence-adapter"', html)
        self.assertIn('id="kv-observatory"', html)
        self.assertIn("textContent", js)
        self.assertNotIn("innerHTML", js)
        ids = re.findall(r'\bid="([^"]+)"', html)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertRegex(js, r"loadData\(\)\.then[\s\S]+loadKvData\(\)\.then")
        self.assertIn(".catch(() => renderKvError())", js)
        self.assertIn("KV DATA UNAVAILABLE", js)
        self.assertIn("loadPresenceData().then(renderPresenceAdapter).catch(() => renderPresenceError())", js)
        self.assertLess(js.index("loadPresenceData().then"), js.index("loadKvData().then"))

    def test_kv_schema_strict_shapes_and_negative_cases(self):
        schema = json.loads((ROOT / "schemas/kv-observatory.schema.json").read_text())
        validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
        payloads = {p.stem: json.loads(p.read_text()) for p in (ROOT / "api/kv").glob("*.json")}
        for payload in payloads.values():
            validator.validate(payload)
        for name, field in (("status", "coverage_claim"), ("namespaces", "namespaces"),
                            ("changes", "changes"), ("presence", "presence")):
            bad = copy.deepcopy(payloads[name]); bad.pop(field)
            self.assertFalse(validator.is_valid(bad))
        for forbidden in ("raw_value", "value_raw", "note_value", "response_body",
                          "message_body", "raw_body", "content", "body"):
            bad = copy.deepcopy(payloads["changes"]); bad[forbidden] = "secret"
            self.assertFalse(validator.is_valid(bad))
        bad = copy.deepcopy(payloads["changes"]); bad["unexpected"] = True
        self.assertFalse(validator.is_valid(bad))
        nonce = copy.deepcopy(payloads["changes"]); nonce["room_nonce"]["key"] = "forbidden"
        self.assertFalse(validator.is_valid(nonce))
        invalid_hash = copy.deepcopy(payloads["changes"])
        invalid_hash["changes"] = [{"namespace":"lobby","key":"hb-x","first_seen_at":"2026-01-01T00:00:00Z","last_observed_at":"2026-01-01T00:00:00Z","last_changed_at":"2026-01-01T00:00:00Z","value_sha256":"bad","previous_value_sha256":None,"observation_count":1,"existence_state":"OBSERVED","note_class":"PRESENCE","trust_class":"ORDINARY_UNAUTHENTICATED","observer_version":"kv-observatory-v0"}]
        self.assertFalse(validator.is_valid(invalid_hash))
        invalid_hash["changes"][0]["value_sha256"] = "a" * 64
        validator.validate(invalid_hash)

    def test_public_scanner_precision_and_surface_coverage(self):
        spec = importlib.util.spec_from_file_location("public_safety_scan", ROOT / "scripts/public_safety_scan.py")
        scanner = importlib.util.module_from_spec(spec); spec.loader.exec_module(scanner)
        names = {p.relative_to(ROOT).as_posix() for p in scanner.public_files()}
        for expected in ("README.md", "README.ja.md", "README.zh-CN.md", "docs/KV_OBSERVATORY.md",
                         "schemas/kv-observatory.schema.json", "api/kv/status.json",
                         "examples/kv-observer.example.json"):
            self.assertIn(expected, names)
        positives = ["/Users/alice/secret", "/private/tmp/operator", "/var/folders/x/y",
                     "file:///tmp/key", "https://u:p@example.invalid/x",
                     "mb-p-secret", "prefix-mb-p-secret", "https://technocore.chat/set-signed/x",
                     "wallet_secret=abcd"]
        for value in positives:
            self.assertTrue(scanner.scan_text(value), value)
        for harmless in ("keep-private-key material out", "step-by-step", "~/Library/<placeholder>",
                         "https://technocore.chat/openapi.json", "value_sha256"):
            self.assertFalse(scanner.scan_text(harmless), harmless)
        for name in ("state.sqlite", "state.sqlite3", "state.db", "state.db-wal", "state.sqlite-shm"):
            self.assertTrue(scanner.is_database_artifact(name))
        for name in ("deps/pkg.whl","runtime/python-wheelhouse/x","runtime/wheelhouse/x",
                     "runtime/wheel-house/x","runtime/wheels/README.inventory",
                     "runtime/venv/bin/python","runtime/.venv/bin/python","runtime/venv/pyvenv.cfg",
                     "runtime/generations/sha/production-runtime.json",
                     "logs/launcher-preflight.jsonl","logs/launcher-preflight.jsonl.2",
                     "logs/launcher-preflight-2026.jsonl.bak","venv/site-packages/jsonschema/__init__.py",
                     "pip-cache/http/item",".cache/pip/http/item","runtime/scheduler-state.lock",
                     "runtime/history.jsonl","runtime/history.jsonl.lock","private-wheel-inventory.json"):
            self.assertTrue(scanner.is_private_runtime_artifact(name),name)
        for name in ("docs/ENGAGEMENT_RUNTIME_MIGRATION.md","requirements-engagement-production.txt"):
            self.assertFalse(scanner.is_private_runtime_artifact(name),name)
        self.assertTrue(scanner.is_generated_private_plist(
            "staging/com.example.plist","""<?xml version="1.0"?><plist version="1.0"><dict>
            <key>Label</key><string>com.flop-agent-intelligence.engagement-scheduler</string>
            <key>ProgramArguments</key><array><string>/Users/alice/private/python3</string></array>
            </dict></plist>"""))
        self.assertTrue(scanner.is_generated_private_plist(
            "staging/renamed.xml","""<?xml version="1.0"?><plist version="1.0"><dict>
            <key>Label</key><string>com.flop-agent-intelligence.engagement-scheduler</string>
            <key>ProgramArguments</key><array><string>/private/tmp/runtime/python3</string></array>
            </dict></plist>"""))
        self.assertFalse(scanner.is_generated_private_plist(
            "launchd/com.example.plist.template","<string>&lt;PRIVATE_RUNTIME_ROOT&gt;</string>"))
        runtime_manifest=json.dumps({"schema":"engagement-production-runtime-v1",
            "interpreter_realpath":"/Library/Developer/CommandLineTools/python3",
            "project_revision":"a"*40,"dependency_lock_sha256":"b"*64,
            "wheels":{"attrs.whl":"c"*64},"readiness":"READY"})
        readiness=json.dumps({"interpreter_realpath":"/Library/Developer/CommandLineTools/python3",
            "project_revision":"a"*40,"dependency_lock_sha256":"b"*64,
            "wheels":{},"readiness":"READY"})
        prelog=json.dumps({"timestamp":"2026-09-03T00:00:00Z","stage":"RUNTIME",
            "error_class":"PRODUCTION_RUNTIME_NOT_READY","approved_revision":"a"*40,
            "runtime_version":"0.1.0"})
        history=json.dumps({"collector_version":"0.1.0","git_revision":"a"*40,
            "source_sha256":"b"*64,"per_room":[],"fetched_at":"2026-09-03T00:00:00Z"})
        for name,text in (("misc/renamed.json",runtime_manifest),("misc/ready.tmp",readiness),
                          ("logs/diagnostic-20260903.bak",prelog),("misc/archive.jsonl",history)):
            self.assertTrue(scanner.is_structured_private_artifact(name,text),name)
        self.assertFalse(scanner.is_structured_private_artifact(
            "api/capabilities.json",json.dumps({"schema":"capabilities-v1","status":"READY"})))


if __name__ == "__main__":
    unittest.main()
