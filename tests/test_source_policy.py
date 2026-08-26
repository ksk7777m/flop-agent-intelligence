import unittest

from flop_agent.source_policy import assess_source


class SourcePolicyTests(unittest.TestCase):
    def test_official_source_upgrade(self):
        result = assess_source("flop_labs_x")
        self.assertTrue(result.authoritative)
        self.assertTrue(result.can_confirm_sensitive_claims)
        self.assertEqual(result.tier, 1)

    def test_unknown_source_stays_tier_three(self):
        result = assess_source("lookalike_flop_account")
        self.assertFalse(result.authoritative)
        self.assertFalse(result.can_confirm_sensitive_claims)
        self.assertEqual(result.tier, 3)

