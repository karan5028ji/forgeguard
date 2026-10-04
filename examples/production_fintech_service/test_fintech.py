"""
Integration Test for Production Fintech Wallet Service
"""
import unittest
import json
from examples.production_fintech_service.wallet_service import WalletService

class TestFintechWalletService(unittest.TestCase):
    def setUp(self):
        self.service = WalletService()

    def test_account_balance_lookup(self):
        bal = self.service.get_account_balance("acc_user1")
        self.assertEqual(bal, 1250.0)

    def test_hash_api_secret(self):
        hashed = self.service.hash_api_secret("api_secret_sample_key")
        self.assertTrue(len(hashed) > 10)

    def test_generate_mfa_otp(self):
        otp = self.service.generate_mfa_otp()
        self.assertEqual(len(otp), 6)
        self.assertTrue(otp.isdigit())

    def test_dynamic_pricing_rule(self):
        result = self.service.execute_dynamic_pricing_rule("100 * 1.18")
        self.assertAlmostEqual(result, 118.0)

if __name__ == "__main__":
    unittest.main()
