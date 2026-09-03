import unittest

from flop_agent.remote_content_policy import ContractProvenance, SourceTrustTier
from flop_agent.source_policy import assess_source, assess_source_v2


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

    def test_v2_official_source_does_not_verify_contract(self):
        result = assess_source_v2("flop_finance")
        self.assertEqual(result.source_trust_tier, SourceTrustTier.TIER_0_OFFICIAL)
        self.assertEqual(result.contract_provenance, ContractProvenance.UNVERIFIED)

    def test_v2_signed_community_is_not_official(self):
        result = assess_source_v2("community", signed_community=True)
        self.assertEqual(result.source_trust_tier, SourceTrustTier.TIER_1_SIGNED_COMMUNITY)

    def test_linked_target_does_not_inherit_official_trust(self):
        result = assess_source("new-linked-target", directly_linked_by_tier1=True)
        self.assertFalse(result.authoritative)
        self.assertFalse(result.can_confirm_sensitive_claims)
