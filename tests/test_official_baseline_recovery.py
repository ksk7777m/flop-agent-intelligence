import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]


class OfficialBaselineRecoveryTests(unittest.TestCase):
    def load(self, relative):
        return json.loads((ROOT / relative).read_text(encoding="utf-8"))

    def test_yellow_paper_parameter_baseline_is_exact_and_safe(self):
        value = self.load("data/yellow_paper.json")
        schema = self.load("schemas/yellow-paper-baseline.v1.json")
        Draft202012Validator(schema).validate(value)
        self.assertEqual(value["source"]["version"], "0.5.0 (draft)")
        self.assertEqual(value["source"]["updated"], "2026-09-05")
        self.assertEqual(value["parameters"], {
            "genesis_supply": 4_400_000_000,
            "genesis_miner_airdrop": 1_200_000_000,
            "genesis_validator_airdrop": 1_200_000_000,
            "genesis_agent_airdrop": 1_200_000_000,
            "genesis_reserve": 800_000_000,
            "initial_block_reward": 96,
            "miner_share_ppt": 750,
            "validator_share_ppt": 100,
            "agent_share_ppt": 100,
            "staker_share_ppt": 50,
            "max_halvings": 5,
            "floor_reward": 3,
            "subsidy_per_block_per_recipient": 8,
        })
        self.assertEqual(value["semantic_diff_review"]["previous_reported_genesis_pool"], 2_483_460_000)
        self.assertEqual(value["semantic_diff_review"]["previous_validator_airdrop"], 305_505_000)
        self.assertFalse(value["safety"]["ready_to_act"])
        self.assertFalse(value["safety"]["authorized_to_act"])
        self.assertEqual(value["safety"]["production_authorities"], 0)
        self.assertEqual(value["safety"]["external_writes"], 0)

    def test_release_main_and_live_are_distinct_reviewed_facts(self):
        value = self.load("data/technocore_compatibility.json")
        schema = self.load("schemas/technocore-compatibility.v1.json")
        Draft202012Validator(schema).validate(value)
        tracking = value["release_tracking"]
        self.assertEqual(tracking["latest_released_tag"], "v0.13.0")
        self.assertEqual(tracking["live_openapi_version"], "0.13.0")
        self.assertNotEqual(tracking["tag_commit"], tracking["upstream_main_head"])
        self.assertEqual(tracking["unreleased_main_delta"], "DOCUMENTATION_ONLY_OPERATOR_MEASUREMENT_PROBE")
        self.assertEqual(tracking["action"], "NO_LIVE_ACTION")

    def test_observatory_payload_is_historical_not_current_room_state(self):
        observatory = self.load("api/observatory.json")
        Draft202012Validator(self.load("schemas/observatory.schema.json")).validate(observatory)
        for relative in ("api/status.json", "api/rooms.json", "api/engagement.json", "api/observatory.json"):
            value = self.load(relative)
            self.assertEqual(value["snapshot_classification"], "HISTORICAL_SNAPSHOT")
            self.assertEqual(value["compatibility"]["live_openapi_version"], "0.13.0")
            self.assertNotEqual(value["compatibility"]["currentness"], "READY")
        status = self.load("api/status.json")
        self.assertEqual(status["official_spec_status"], "HISTORICAL_SNAPSHOT_NOT_CURRENT")
        self.assertEqual(status["generated_at"], status["source"]["fetched_at"])
        self.assertNotEqual(status["generated_at"], status["reviewed_at"])

    def test_dashboard_and_api_expose_same_boundaries(self):
        html = (ROOT / "index.html").read_text(encoding="utf-8")
        js = (ROOT / "dashboard.js").read_text(encoding="utf-8")
        self.assertIn('"yellow_paper"', js)
        self.assertIn("FLOP_YELLOW_PAPER", js)
        self.assertIn('id="yellow-paper"', html)
        self.assertIn("snapshot_classification", js)
        self.assertNotIn("innerHTML", js)

    def test_current_program_and_activation_boundaries_remain_closed(self):
        compatibility = self.load("data/technocore_compatibility.json")
        kol = compatibility["flop_kol_referral_readiness"]
        testnet = compatibility["flop_testnet_readiness"]
        self.assertEqual(kol["program"], "ANNOUNCED_DETAILS_PENDING")
        self.assertEqual(kol["referral"], "NOT_ISSUED_CONFIRMED")
        self.assertEqual(kol["leaderboard"], "NOT_PUBLISHED_CONFIRMED")
        self.assertEqual(testnet["faucet"], "NOT_LIVE_CONFIRMED")
        self.assertEqual(testnet["claim_endpoint"], "NONE_CONFIRMED")
        self.assertEqual(testnet["scoring"], "UNRESOLVED")
        self.assertEqual(testnet["action"], "NO_LIVE_ACTION")


if __name__ == "__main__":
    unittest.main()
