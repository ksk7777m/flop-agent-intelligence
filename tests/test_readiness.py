import json
import tempfile
import unittest
from pathlib import Path

from flop_agent.readiness import OFFICIAL_SPECS, compare_spec_hashes, validate_dashboard_data


ROOT = Path(__file__).resolve().parents[1]


class ReadinessTests(unittest.TestCase):
    def test_dashboard_schema_and_public_urls(self):
        validate_dashboard_data(ROOT / "data")

    def test_spec_hash_unchanged(self):
        bodies = {url: name.encode() for name, url in OFFICIAL_SPECS.items()}
        import hashlib
        expected = {name: hashlib.sha256(name.encode()).hexdigest() for name in OFFICIAL_SPECS}
        result = compare_spec_hashes(expected, lambda url: bodies[url])
        self.assertTrue(all(item["status"] == "UNCHANGED" for item in result.values()))

    def test_spec_hash_change_requires_review(self):
        expected = {name: "0" * 64 for name in OFFICIAL_SPECS}
        result = compare_spec_hashes(expected, lambda _: b"changed")
        self.assertTrue(all(item["status"] == "OFFICIAL_SPEC_CHANGED" for item in result.values()))
        self.assertTrue(all(item["review"] == "REVIEW_REQUIRED" for item in result.values()))

    def test_dashboard_build_inputs_exist(self):
        for filename in ("index.html", "dashboard.css", "dashboard.js"):
            self.assertTrue((ROOT / filename).is_file())
        script = (ROOT / "dashboard.js").read_text(encoding="utf-8")
        self.assertIn('"UNKNOWN"', script)
        self.assertNotIn("innerHTML", script)

    def test_offline_fixture_has_no_private_material(self):
        rendered = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "data").glob("*.json"))
        for forbidden in ("/Users/", "private_key_b64url", "seed_b64", "BEGIN PRIVATE KEY"):
            self.assertNotIn(forbidden, rendered)


if __name__ == "__main__":
    unittest.main()
