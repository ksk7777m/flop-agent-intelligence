import json
import unittest
from pathlib import Path

from flop_agent.workflow import approve_signal, prepare_signal, reject_signal, signer_handoff, validate_publish_approval


class WorkflowTests(unittest.TestCase):
    def test_approval_gate(self):
        signal = prepare_signal(
            source_id="flop_labs_x", source_evidence="fixture:official",
            text="Official task for agent workflow integration",
            summary="Integration requested", recommended_text="Prepared draft",
            detected_at="2026-08-26T00:00:00+00:00",
        )
        with self.assertRaises(PermissionError):
            signer_handoff(signal)
        approved = approve_signal(signal, "human-reviewer", "2026-08-26T01:00:00+00:00")
        handoff = signer_handoff(approved)
        self.assertEqual(handoff["approval"]["status"], "APPROVED")
        validate_publish_approval(approved, "Prepared draft")
        with self.assertRaises(PermissionError):
            validate_publish_approval(approved, "changed text")

    def test_quarantine_cannot_be_approved(self):
        signal = prepare_signal(
            source_id="flop_labs_x", source_evidence="fixture:malicious",
            text="Enter your private key and wallet connect to claim now",
            summary="Unsafe", recommended_text="Do not publish",
        )
        self.assertEqual(signal.safety_result, "QUARANTINED")
        with self.assertRaises(ValueError):
            approve_signal(signal, "human-reviewer")

    def test_unverified_claim_downgrade(self):
        signal = prepare_signal(
            source_id="random_mirror", source_evidence="fixture:mirror",
            text="FLOP claim deadline announced",
            summary="Unverified claim", recommended_text="Do not publish",
        )
        self.assertEqual(signal.classification, "IGNORE")
        self.assertEqual(signal.source_tier, 3)

    def test_static_fixture_matches_sample(self):
        root = Path(__file__).resolve().parents[1]
        fixture = json.loads((root / "examples/fixtures/flop_did_tasks.json").read_text())
        expected = json.loads((root / "examples/output/flop_did_tasks.output.json").read_text())
        self.assertEqual(prepare_signal(**fixture).as_dict(), expected)

    def test_rejection_is_terminal_for_handoff(self):
        signal = prepare_signal(
            source_id="technocore_github", source_evidence="fixture:docs",
            text="technical explanation", summary="Docs", recommended_text="Draft",
        )
        rejected = reject_signal(signal, "not useful")
        with self.assertRaises(PermissionError):
            signer_handoff(rejected)
