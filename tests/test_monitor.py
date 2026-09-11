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
    evaluate_engagement_aggregates,
    evaluate_teaser,
    evaluate_yellow_paper,
    extract_teaser_snapshot,
    extract_yellow_paper_snapshot,
    classify_source_failure,
    evaluate_did_note,
    evaluate_mailbox,
    normalize_official_signal,
    _build_monitor_service,
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
        self.teaser = b'''<html><head><meta name="description" content="Figures are provisional"></head><body>
        <h2>04 Testnet and Airdrop</h2><p>Flop Testnet is planned for Q4 2026, with mainnet to follow in Q1 2027.</p>
        <p>Agents claim a test-token faucet and spend it on inference with prizes. Every 3 FLOP spent unlocks 1 airdropped FLOP.</p>
        <p>Refer to the yet to be finalised Yellow Paper.</p></body></html>'''
        rows = "".join(
            f'<tr><td><a id="param-{name}"></a><code>{name}</code></td><td>{value:_} {unit}</td></tr>'
            for name, unit, value in (
                ("genesis_supply", "FLOP", 4_400_000_000),
                ("genesis_miner_airdrop", "FLOP", 1_200_000_000),
                ("genesis_validator_airdrop", "FLOP", 1_200_000_000),
                ("genesis_agent_airdrop", "FLOP", 1_200_000_000),
                ("genesis_reserve", "FLOP", 800_000_000),
                ("initial_block_reward", "FLOP", 96),
                ("miner_share_ppt", "parts-per-thousand", 750),
                ("validator_share_ppt", "parts-per-thousand", 100),
                ("agent_share_ppt", "parts-per-thousand", 100),
                ("staker_share_ppt", "parts-per-thousand", 50),
                ("max_halvings", "count", 5),
                ("floor_reward", "FLOP", 3),
                ("subsidy_per_block_per_recipient", "FLOP", 8),
            )
        )
        self.yellow_paper = (
            '<html><body><div class="meta"><span>Version<b>0.5.0 (draft)</b></span>'
            '<span>Status<b>Implementation spec — iterating</b></span>'
            '<span>Updated<b>2026-09-05</b></span></div><table>' + rows +
            '</table><h2>E.38 — Genesis allocation &amp; airdrop vesting</h2>'
            '<h2>E.40 — Agent &amp; staker leg distribution</h2>'
            '<a href="https://untrusted.example/claim">remote text</a></body></html>'
        ).encode()
        teaser_baseline = extract_teaser_snapshot(self.teaser)
        yellow_baseline = extract_yellow_paper_snapshot(self.yellow_paper)
        self.spec_bodies = {url: name.encode() for name, url in OFFICIAL_SPECS.items()}
        baseline = {
            "official_specs": {name: hashlib.sha256(name.encode()).hexdigest() for name in OFFICIAL_SPECS},
            "flop_site_sha256": hashlib.sha256(normalize_official_signal(self.flop)).hexdigest(),
            "flop_site_terms": [],
            "teaser": teaser_baseline,
            "yellow_paper": yellow_baseline,
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
            ENDPOINTS["public_evidence"]: b"{}",
            ENDPOINTS["official_repo"]: b"{}",
            ENDPOINTS["flop_site"]: self.flop,
            ENDPOINTS["teaser"]: self.teaser,
            ENDPOINTS["yellow_paper"]: self.yellow_paper,
            ENDPOINTS["x_official"]: b"X",
            ENDPOINTS["x_evidence"]: b"X",
            ENDPOINTS["capacity_manifest"]: json.dumps({"limits": {"rooms": 10240}}).encode(),
            ENDPOINTS["rooms_summary"]: json.dumps({
                "capacity": 10240, "total": 9000,
                "engagement": {"zero_response_share": 0.2, "nick_diversity": 0.4, "windowed_note_to_message_ratio": 0.1},
            }).encode(),
            **self.spec_bodies,
        }

    def tearDown(self):
        self.temp.cleanup()

    def fetch(self, url):
        return self.responses[url]

    def run_fixture(self):
        _, run_monitor = _build_monitor_service(self.fetch, self.root)
        with patch("flop_agent.monitor._local_evidence", return_value={"status": "READY", "detail": "verified"}):
            return run_monitor()

    def test_normal_ready_and_zero_writes(self):
        result = self.run_fixture()
        self.assertEqual(result["overall_status"], "READY")
        self.assertEqual(result["external_writes_performed"], 0)
        self.assertFalse(result["meaningful_change"])

    def test_technocore_unavailable(self):
        del self.responses[ENDPOINTS["technocore"]]
        result = self.run_fixture()
        self.assertEqual(result["checks"]["technocore"]["status"], "UNKNOWN")
        self.assertEqual(result["overall_status"], "DEGRADED")
        self.assertFalse(result["meaningful_change"])

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

    def test_teaser_unchanged_and_draft_wording(self):
        result = evaluate_teaser(self.teaser, extract_teaser_snapshot(self.teaser))
        self.assertEqual(result["status"], "READY")
        self.assertEqual(result["spec_status"], "OFFICIAL_DRAFT")
        self.assertEqual(result["signals"]["testnet"], "q4 2026")
        self.assertEqual(result["signals"]["faucet"], "OFFICIAL_DRAFT_MENTION")

    def test_teaser_changed_requires_review(self):
        baseline = extract_teaser_snapshot(self.teaser)
        changed = self.teaser.replace(b"Q4 2026", b"Q3 2026")
        result = evaluate_teaser(changed, baseline)
        self.assertEqual(result["detail"], "OFFICIAL_TEASER_CHANGED")
        self.assertEqual(result["status"], "REVIEW_REQUIRED")

    def test_yellow_paper_reviewed_semantics_are_ready(self):
        snapshot = extract_yellow_paper_snapshot(self.yellow_paper)
        result = evaluate_yellow_paper(self.yellow_paper, snapshot)
        self.assertEqual(result["status"], "READY")
        self.assertEqual(result["metadata"], {
            "version": "0.5.0 (draft)",
            "status": "Implementation spec — iterating",
            "updated": "2026-09-05",
        })
        self.assertEqual(result["parameters"]["genesis_supply"], 4_400_000_000)
        self.assertEqual(result["parameters"]["genesis_validator_airdrop"], 1_200_000_000)
        self.assertEqual(result["parameters"]["genesis_reserve"], 800_000_000)
        self.assertEqual(result["parameters"]["initial_block_reward"], 96)
        self.assertEqual(result["parameters"]["miner_share_ppt"], 750)
        self.assertEqual(result["parameters"]["floor_reward"], 3)
        self.assertEqual(result["discovered_links"]["navigation"], "INERT")
        self.assertFalse(result["authorized_to_act"])

    def test_yellow_paper_parameter_change_is_semantic_review(self):
        baseline = extract_yellow_paper_snapshot(self.yellow_paper)
        changed = self.yellow_paper.replace(b"4_400_000_000 FLOP", b"2_483_460_000 FLOP")
        result = evaluate_yellow_paper(changed, baseline)
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertEqual(result["detail"], "YELLOW_PAPER_SEMANTIC_CHANGED")
        self.assertEqual(result["semantic_diff"][0]["field"], "genesis_supply")

    def test_yellow_paper_malformed_missing_duplicate_and_unknown_version_fail_closed(self):
        baseline = extract_yellow_paper_snapshot(self.yellow_paper)
        cases = (
            self.yellow_paper.replace(b"4_400_000_000 FLOP", b"4.4 billion FLOP"),
            self.yellow_paper.replace(b'id="param-genesis_supply"', b'id="missing-genesis_supply"'),
            self.yellow_paper.replace(b"</table>", b'<tr><td><a id="param-genesis_supply"></a><code>genesis_supply</code></td><td>4_400_000_000 FLOP</td></tr></table>'),
        )
        for value in cases:
            with self.subTest(value=len(value)):
                self.assertEqual(evaluate_yellow_paper(value, baseline)["detail"], "YELLOW_PAPER_PARSE_FAILED")
        unknown = self.yellow_paper.replace(b"0.5.0 (draft)", b"0.6.0 (draft)")
        self.assertEqual(evaluate_yellow_paper(unknown, baseline)["detail"], "YELLOW_PAPER_VERSION_UNREVIEWED")

    def test_yellow_paper_source_unavailable_is_not_ready(self):
        del self.responses[ENDPOINTS["yellow_paper"]]
        result = self.run_fixture()
        self.assertEqual(result["checks"]["yellow_paper"]["status"], "UNKNOWN")
        self.assertEqual(result["overall_status"], "DEGRADED")

    def test_testnet_launch_and_faucet_endpoint(self):
        baseline = extract_teaser_snapshot(self.teaser)
        live = self.teaser.replace(
            b"</body>", b'<a href="https://flop.finance/faucet/">Faucet</a><p>Testnet live RPC explorer.</p></body>'
        )
        result = evaluate_teaser(live, baseline)
        self.assertEqual(result["signals"]["faucet"], "CONFIRMED_ENDPOINT")
        self.assertEqual(result["status"], "REVIEW_REQUIRED")

    def test_inference_endpoint_and_yellow_paper_link(self):
        baseline = extract_teaser_snapshot(self.teaser)
        changed = self.teaser.replace(
            b"</body>",
            b'<a href="https://flop.finance/inference/">Inference endpoint</a>'
            b'<a href="https://flop.finance/yellow-paper.pdf">Yellow Paper</a></body>',
        )
        result = evaluate_teaser(changed, baseline)
        self.assertEqual(result["signals"]["inference"], "CONFIRMED_ENDPOINT")
        self.assertEqual(result["detail"], "CRITICAL_NEW_OFFICIAL_SPEC")

    def test_contract_address_requires_review(self):
        baseline = extract_teaser_snapshot(self.teaser)
        changed = self.teaser.replace(b"</body>", b"<p>Contract 0x1111111111111111111111111111111111111111</p></body>")
        result = evaluate_teaser(changed, baseline)
        self.assertEqual(result["signals"]["contract_address"], ["0x1111111111111111111111111111111111111111"])
        self.assertEqual(result["status"], "REVIEW_REQUIRED")

    def test_unofficial_community_claim_is_not_a_teaser_input(self):
        snapshot = extract_teaser_snapshot(self.teaser)
        self.assertEqual(snapshot["signals"]["snapshot"], "NOT_ANNOUNCED")
        self.assertEqual(snapshot["signals"]["eligibility"], "NOT_ANNOUNCED")

    def test_engagement_metrics_are_informational(self):
        result = evaluate_engagement_aggregates(self.responses[ENDPOINTS["rooms_summary"]])
        self.assertEqual(result["status"], "READY")
        self.assertIn("not confirmed FLOP airdrop scoring", result["detail"])

    def test_network_failure_escalates_only_after_two(self):
        self.assertEqual(classify_source_failure(1)["status"], "UNKNOWN")
        self.assertEqual(classify_source_failure(2)["status"], "REVIEW_REQUIRED")

    def test_public_evidence_unavailable(self):
        del self.responses[ENDPOINTS["dashboard"]]
        result = self.run_fixture()
        self.assertEqual(result["checks"]["dashboard"]["status"], "UNKNOWN")
        self.assertEqual(result["overall_status"], "DEGRADED")
        self.assertFalse(result["meaningful_change"])

    def test_expected_eviction_with_valid_offchain_evidence_is_ready(self):
        self.responses[ENDPOINTS["contribution"]] = json.dumps({"first_seq": 2000000, "messages": []}).encode()
        result = self.run_fixture()
        self.assertEqual(result["checks"]["contribution"]["live_record_status"], "EVICTED_EXPECTED")
        self.assertEqual(result["checks"]["contribution"]["historical_evidence_status"], "VERIFIED_OFFCHAIN")
        self.assertEqual(result["checks"]["contribution"]["status"], "READY")
        self.assertFalse(result["meaningful_change"])

    def test_invalid_receipt_after_eviction_requires_review(self):
        self.responses[ENDPOINTS["contribution"]] = json.dumps({"first_seq": 2000000, "messages": []}).encode()
        _, run_monitor = _build_monitor_service(self.fetch, self.root)
        with patch("flop_agent.monitor._local_evidence", return_value={"status": "ERROR", "detail": "Receipt verification failed"}):
            result = run_monitor()
        self.assertEqual(result["checks"]["contribution"]["status"], "REVIEW_REQUIRED")
        self.assertTrue(result["meaningful_change"])

    def test_stale_last_check(self):
        old = (datetime.now(timezone.utc) - timedelta(hours=49)).isoformat()
        self.assertEqual(assess_freshness(old), "STALE")


if __name__ == "__main__":
    unittest.main()
