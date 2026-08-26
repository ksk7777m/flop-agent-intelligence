import unittest

from flop_agent.classifier import classify


class ClassifierTests(unittest.TestCase):
    def test_unofficial_critical_claim_is_ignored(self):
        self.assertEqual(classify("airdrop snapshot tomorrow", official=False).category, "IGNORE")

    def test_wallet_language_is_quarantined_even_if_official(self):
        result = classify("wallet connect and claim now", official=True)
        self.assertEqual(result.category, "SECURITY_REVIEW_REQUIRED")
        self.assertTrue(result.security_review_required)

    def test_official_testnet_is_critical(self):
        self.assertEqual(classify("testnet launch", official=True).category, "CRITICAL")
