import base64
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from flop_agent.collaboration import (
    EVIDENCE_DOMAIN, CollaborationEvent, CollaborationState, EventKind, HumanApproval,
    Phase, Provenance, SignedEvidence, apply_event, canonical_json, digest,
    evidence_payload, readiness_manifest,
)
from flop_agent.identity import did_from_public_key


NOW = "2026-08-28T00:00:00Z"


def provenance(classification="CONFIRMED"):
    return Provenance("official-fixture", "fixture:official", NOW, "a" * 64, classification)


def signed(key, did, case_id, kind, subject, idem):
    payload = evidence_payload(case_id, kind, subject, idem)
    signature = base64.urlsafe_b64encode(key.sign(EVIDENCE_DOMAIN + canonical_json(payload))).decode().rstrip("=")
    return SignedEvidence(did, payload, signature)


class CollaborationTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.did = did_from_public_key(self.key.public_key().public_bytes_raw())
        self.case_id = "case-001"
        self.state = CollaborationState(self.case_id)

    def event(self, kind, subject, approval=None, evidence=None, idem=None):
        return CollaborationEvent(
            self.case_id, self.state.next_sequence, kind.value, NOW, subject, provenance(),
            self.state.last_event_sha256, approval, evidence, idem,
        )

    def apply(self, event):
        self.state = apply_event(self.state, event)

    def test_full_lifecycle_is_hash_chained_and_gated(self):
        task = {"task_id": "official-task-1", "summary": "fixture only"}
        self.apply(self.event(EventKind.DISCOVER, task))
        task_hash = digest(task)
        subject = {"task_sha256": task_hash, "claim": "bounded work"}
        approval = HumanApproval("human", NOW, EventKind.APPROVE_CLAIM.value, digest(subject))
        self.apply(self.event(EventKind.APPROVE_CLAIM, subject, approval=approval))

        for approval_kind, record_kind, extra in (
            (None, EventKind.RECORD_CLAIM, {"claim_receipt": "local-fixture"}),
            (EventKind.APPROVE_HANDOFF, EventKind.RECORD_HANDOFF, {"recipient": self.did}),
            (None, EventKind.RECORD_ACK, {"ack": "accepted"}),
            (EventKind.APPROVE_COMPLETION, EventKind.RECORD_COMPLETION, {"result_sha256": "b" * 64}),
        ):
            subject = {"task_sha256": task_hash, **extra}
            if approval_kind:
                approval = HumanApproval("human", NOW, approval_kind.value, digest(subject))
                self.apply(self.event(approval_kind, subject, approval=approval))
            idem = f"idem-{record_kind.value.lower()}"
            proof = signed(self.key, self.did, self.case_id, record_kind, subject, idem)
            self.apply(self.event(record_kind, subject, evidence=proof, idem=idem))
        self.assertEqual(self.state.phase, Phase.COMPLETED)
        self.assertEqual(self.state.next_sequence, 9)

    def test_missing_approval_fails_closed(self):
        task = {"task_id": "task"}
        self.apply(self.event(EventKind.DISCOVER, task))
        with self.assertRaises(PermissionError):
            apply_event(self.state, self.event(EventKind.APPROVE_CLAIM, {"task_sha256": digest(task)}))

    def test_tampered_signed_evidence_fails_closed(self):
        task = {"task_id": "task"}
        self.apply(self.event(EventKind.DISCOVER, task))
        subject = {"task_sha256": digest(task), "claim": "x"}
        approval = HumanApproval("human", NOW, EventKind.APPROVE_CLAIM.value, digest(subject))
        self.apply(self.event(EventKind.APPROVE_CLAIM, subject, approval=approval))
        proof = signed(self.key, self.did, self.case_id, EventKind.RECORD_CLAIM, subject, "idem")
        bad_subject = {**subject, "claim": "changed"}
        with self.assertRaises(ValueError):
            apply_event(self.state, self.event(EventKind.RECORD_CLAIM, bad_subject, evidence=proof, idem="idem"))

    def test_gap_replay_and_duplicate_are_rejected(self):
        task = {"task_id": "task"}
        event = self.event(EventKind.DISCOVER, task)
        self.apply(event)
        with self.assertRaises(ValueError):
            apply_event(self.state, event)

    def test_partial_failure_requires_explicit_recovery(self):
        task = {"task_id": "task"}
        self.apply(self.event(EventKind.DISCOVER, task))
        subject = {"task_sha256": digest(task), "failure": "outcome unknown"}
        self.apply(self.event(EventKind.REQUIRE_RECOVERY, subject))
        self.assertEqual(self.state.phase, Phase.RECOVERY_REQUIRED)
        approval = HumanApproval("human", NOW, EventKind.APPROVE_COMPLETION.value, digest(subject))
        with self.assertRaises(ValueError):
            apply_event(self.state, self.event(EventKind.APPROVE_COMPLETION, subject, approval=approval))

    def test_manifest_cannot_enable_external_effects(self):
        manifest = readiness_manifest()
        self.assertFalse(manifest["external_writes_supported"])
        self.assertFalse(manifest["wallet_operations_supported"])

    def test_provenance_classification_is_closed_enum(self):
        bad = provenance("OFFICIALISH")
        task = {"task_id": "task"}
        event = CollaborationEvent(self.case_id, 1, "DISCOVER", NOW, task, bad, None)
        with self.assertRaises(ValueError):
            apply_event(self.state, event)


if __name__ == "__main__":
    unittest.main()
