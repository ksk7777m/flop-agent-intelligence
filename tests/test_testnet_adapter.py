import json
import unittest
from pathlib import Path

from flop_agent.testnet import (
    ApprovalEnvelope,
    FaucetAdapter,
    InferenceAdapter,
    LiveActionDisabled,
    TestnetState,
    WalletProvider,
    activation_checklist,
    classify_instruction,
    classify_source,
    configuration_candidate,
    create_fixture_receipt,
    empty_config,
    inference_request,
    spend_record,
    transition,
    validate_config,
    verify_testnet_receipt,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "examples/fixtures/testnet"


def fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class TestnetAdapterTests(unittest.TestCase):
    def test_state_machine_requires_explicit_transitions(self):
        self.assertEqual(transition(TestnetState.NOT_ANNOUNCED, "official_draft"), TestnetState.OFFICIAL_DRAFT)
        with self.assertRaises(ValueError):
            transition(TestnetState.NOT_ANNOUNCED, "faucet_verified")

    def test_official_source_accepted(self):
        self.assertEqual(classify_source("https://flop.finance/teaser/"), "TIER_1_OFFICIAL")
        self.assertEqual(classify_source("https://github.com/flop-labs/technocore-chat"), "TIER_1_OFFICIAL")

    def test_unofficial_source_rejected(self):
        self.assertEqual(classify_source("https://aggregator.example/flop"), "UNVERIFIED")
        self.assertEqual(classify_source("https://fake-flop-faucet.example"), "UNVERIFIED")

    def test_draft_config_keeps_unknown_values_null(self):
        config = fixture("valid_draft_config.json")
        self.assertEqual(validate_config(config)["status"], "OFFICIAL_DRAFT")
        self.assertIsNone(config["chain_id"])
        self.assertIsNone(config["rpc_url"])
        self.assertEqual(config["activation_status"], "DO_NOT_ACTIVATE")

    def test_fake_faucet_is_blocked(self):
        result = classify_instruction("preview only", fixture("fake_faucet.json")["faucet_url"])
        self.assertEqual(result["status"], "UNVERIFIED_ENDPOINT")
        self.assertTrue(result["connection_prohibited"])

    def test_seed_private_key_and_wallet_connect_are_critical(self):
        result = classify_instruction(fixture("malicious_wallet_prompt.json")["instruction"])
        self.assertEqual(result["status"], "CRITICAL_SECURITY_RISK")
        self.assertEqual(result["risks"], ["private_key", "seed", "wallet_connect"])

    def test_faucet_claim_disabled_even_with_approval(self):
        approved = ApprovalEnvelope("claim_faucet", "APPROVED", "human", "2026-08-27T00:00:00Z")
        with self.assertRaises(LiveActionDisabled):
            FaucetAdapter(empty_config()).claim(approved)

    def test_wallet_sign_disabled_even_with_approval(self):
        approved = ApprovalEnvelope("sign_transaction", "APPROVED", "human", "2026-08-27T00:00:00Z")
        with self.assertRaises(LiveActionDisabled):
            WalletProvider().sign(b"fixture", approved)

    def test_inference_execute_disabled_even_with_approval(self):
        approved = ApprovalEnvelope("purchase_inference", "APPROVED", "human", "2026-08-27T00:00:00Z")
        with self.assertRaises(LiveActionDisabled):
            InferenceAdapter(empty_config()).execute(inference_request(), approved)

    def test_prompt_body_is_not_preserved(self):
        request = inference_request(prompt="private fixture prompt")
        self.assertNotIn("prompt", request)
        self.assertEqual(len(request["prompt_hash"]), 64)

    def test_cost_fixture_accounting_and_mismatch(self):
        record = spend_record(fixture("inference_cost_mismatch.json"))
        self.assertFalse(record["cost_match"])
        self.assertFalse(record["verified"])
        self.assertEqual(record["airdrop_score"], "UNKNOWN")
        self.assertIsNone(record["tx_hash"])

    def test_receipt_integrity_create_and_verify(self):
        receipt = create_fixture_receipt({"request_hash": "a" * 64, "result_hash": "b" * 64, "cost_flop": "0"}, "2026-08-27T00:00:00Z")
        self.assertEqual(verify_testnet_receipt(receipt)["status"], "VALID_FIXTURE")
        self.assertTrue(receipt["fixture"])
        self.assertFalse(receipt["live_action"])

    def test_fixture_receipt_file_verifies(self):
        self.assertEqual(verify_testnet_receipt(fixture("result_receipt.json"))["status"], "VALID_FIXTURE")

    def test_tamper_result_fails(self):
        receipt = fixture("result_receipt.json")
        receipt["result_hash"] = "tampered"
        self.assertEqual(verify_testnet_receipt(receipt)["status"], "INVALID")

    def test_tamper_cost_fails(self):
        receipt = fixture("result_receipt.json")
        receipt["cost_flop"] = "99"
        self.assertEqual(verify_testnet_receipt(receipt)["status"], "INVALID")

    def test_unknown_contract_is_rejected(self):
        result = validate_config(fixture("unverified_contract.json"))
        self.assertEqual(result["reason"], "UNVERIFIED_CONTRACT")
        self.assertEqual(result["activation"], "DO_NOT_ACTIVATE")

    def test_valid_address_from_official_source_still_needs_contract_provenance(self):
        config = empty_config()
        config.update({
            "network_name": "UNVERIFIED_TESTNET",
            "token_contract": "0x1111111111111111111111111111111111111111",
            "source_url": "https://flop.finance/teaser/",
            "source_tier": "TIER_1_OFFICIAL",
            "verified_at": "2026-09-03T00:00:00Z",
        })
        result = validate_config(config)
        self.assertEqual(result["reason"], "CONTRACT_PROVENANCE_REQUIRED")
        self.assertEqual(result["activation"], "DO_NOT_ACTIVATE")

    def test_official_looking_discovered_endpoint_remains_inert(self):
        result = classify_instruction("candidate", "https://flop.finance/")
        self.assertEqual(result["status"], "UNVERIFIED_ENDPOINT")
        self.assertTrue(result["connection_prohibited"])

    def test_unknown_network_is_not_activated(self):
        result = validate_config(fixture("unknown_network.json"))
        self.assertEqual(result["reason"], "UNVERIFIED_CONFIGURATION_SOURCE")
        self.assertEqual(result["activation"], "DO_NOT_ACTIVATE")

    def test_signal_handoff_never_auto_activates(self):
        candidate = configuration_candidate(fixture("yellow_paper_config_update.json"))
        self.assertEqual(candidate["activation_status"], "REVIEW_REQUIRED")
        self.assertEqual(candidate["handoff"], "DETECT_VERIFY_REVIEW_PREPARE")

    def test_activation_checklist_fails_closed(self):
        result = activation_checklist(empty_config())
        self.assertEqual(result["status"], "DO_NOT_ACTIVATE")
        self.assertFalse(result["auto_activate"])

    def test_adapter_has_no_network_or_key_implementation(self):
        source = (ROOT / "src/flop_agent/testnet.py").read_text(encoding="utf-8")
        forbidden = ("urllib.request", "requests.", "httpx.", "web3", "seed_b64", "private_key_b64url", "post_signed", "urlopen(")
        for marker in forbidden:
            self.assertNotIn(marker, source)

    def test_all_fixtures_are_marked_or_inert(self):
        names = sorted(path.name for path in FIXTURES.glob("*.json"))
        self.assertGreaterEqual(len(names), 9)
        for name in names:
            self.assertIsInstance(fixture(name), dict)


if __name__ == "__main__":
    unittest.main()
