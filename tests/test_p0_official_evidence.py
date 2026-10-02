import hashlib
import json
import unittest
from pathlib import Path

from flop_agent.source_policy import AuthorityState
from flop_agent.technocore_runtime_observation import describe_runtime_limits, ObservationError
from flop_agent.yellowpaper_wire import decode_policy_hash, task_hash

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "vendor/official_sources/2026-10-02"


class OfficialEvidenceTests(unittest.TestCase):
    def test_every_retained_source_matches_its_evidence_hash(self):
        evidence = json.loads((ROOT / "data/official_baseline/2026-10-02/manifest.json").read_text())
        self.assertFalse(evidence["live_action_enabled"])
        for item in evidence["documents"]:
            with self.subTest(path=item["path"]):
                path = ROOT / item["path"]
                self.assertIn(ROOT, path.resolve().parents)
                self.assertFalse(path.is_symlink())
                raw = path.read_bytes()
                self.assertEqual(len(raw), item["bytes"])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), item["sha256"])
                AuthorityState(item["authority"])
                self.assertTrue(item["url"].startswith("https://"))
        with self.assertRaises(ValueError):
            AuthorityState("OFFICIAL_BUT_UNKNOWN")

    def test_runtime_values_do_not_become_operational_constants(self):
        raws = [(RAW / "technocore" / name).read_bytes() for name in ("config.json", "agent.json", "openapi.json")]
        defaults = dict(max_rooms=5120, max_notes_per_ns=5120, max_notes_total=163840, rate_read=120, rate_write=30)
        result = describe_runtime_limits(*raws, spec_defaults=defaults, observed_at="2026-10-02T09:11:00Z")
        self.assertEqual(result["limits"]["max_rooms"]["runtime_observed"], 300000)
        self.assertEqual(result["limits"]["max_rooms"]["spec_default"], 5120)
        self.assertIsNone(result["limits"]["max_rooms"]["effective_value"])
        self.assertFalse(result["live_action_enabled"])
        changed = json.loads(raws[0]); changed["version"] = "99.0.0"
        result = describe_runtime_limits(json.dumps(changed).encode(), *raws[1:],
            spec_defaults=defaults, observed_at="2026-10-02T09:11:00Z")
        self.assertEqual(result["compatibility_verdict"], "CONFLICT")
        for malformed in (b'{}', b'{"version":"1","version":"2"}', b'{"value":NaN}'):
            with self.assertRaises(ObservationError):
                describe_runtime_limits(malformed, *raws[1:], spec_defaults=defaults,
                                        observed_at="2026-10-02T09:11:00Z")

    def test_official_decode_policy_and_direct_replay_domain_vectors(self):
        vectors = json.loads((RAW / "yellowpaper/evidence/wire-format-v1.json").read_text())
        v = vectors["decode_policy_v1"]
        raw = bytes.fromhex(v["scale_bytes_hex"])
        self.assertEqual(decode_policy_hash(raw).hex(), v["sha256_hex"])
        for bad in (raw + b'\0', raw[:-1], b'\2' + raw[1:], raw[:2] + b'\xff' + raw[3:]):
            with self.assertRaises(ValueError):
                decode_policy_hash(bad)
        v = vectors["direct_rail_v1"]["task_hash"]; inp = v["inputs"]
        value = task_hash(bytes.fromhex(inp["genesis_hash_hex"]), bytes.fromhex(inp["agent_account_id32_hex"]),
                          inp["nonce"], *[bytes.fromhex(inp[k]) for k in ("model_hash_hex", "payload_hash_hex", "commit_hash_hex")])
        self.assertEqual(value.hex(), v["hash_hex"])
