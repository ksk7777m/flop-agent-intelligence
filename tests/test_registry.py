import unittest

from flop_agent.registry import contribution_note_plan, did_fingerprint, did_profile_plan


class RegistryPlanTests(unittest.TestCase):
    DID = "did:key:z6MkkTuFggpkYcZ61zGxej2Ae7Lf6MHk3AbsYASULYTqiqXy"

    def test_profile_uses_current_sharded_convention(self):
        fingerprint = did_fingerprint(self.DID)
        plan = did_profile_plan(self.DID)
        self.assertEqual(plan["registry_key"], f"/kv/did-{fingerprint[:2]}/{fingerprint[2:]}")
        self.assertTrue(plan["dry_run"])
        self.assertTrue(plan["manual_approval_required"])

    def test_contribution_is_labeled_community_practice(self):
        plan = contribution_note_plan(self.DID, "monitor")
        self.assertEqual(plan["official_status"], "COMMUNITY_PRACTICE")
        self.assertEqual(plan["namespace"], "contrib")

