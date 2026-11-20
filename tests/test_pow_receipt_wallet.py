import tempfile
import unittest
from pathlib import Path

from src.mining.sha256d import scan_nonce_range
from src.mining.receipt_wallet import (
    append_to_wallet,
    create_receipt,
    verify_receipt,
    verify_wallet,
)


class ReceiptWalletTests(unittest.TestCase):
    def setUp(self):
        self.header = bytes(range(80))
        result = scan_nonce_range(self.header, (1 << 256) - 1, 9, 10)
        self.candidate = result.candidates[0]

    def make_receipt(self, **overrides):
        args = {
            "header": self.header,
            "candidate": self.candidate,
            "wallet_id": "local:architect-wallet",
            "ruleset_id": "cryptic-local-regtest-v1",
            "window_start": 100,
            "window_end": 200,
            "accepted_at": 150,
        }
        args.update(overrides)
        return create_receipt(**args)

    def test_receipt_is_reproducible_and_verifiable(self):
        receipt = self.make_receipt()
        self.assertTrue(verify_receipt(receipt))
        self.assertEqual(receipt["verification"]["status"], "locally_verified")
        self.assertEqual(receipt["network"]["status"], "not_submitted")

    def test_out_of_window_receipt_is_rejected(self):
        with self.assertRaises(ValueError):
            self.make_receipt(accepted_at=200)

    def test_tampering_invalidates_receipt(self):
        receipt = self.make_receipt()
        receipt["work"]["nonce"] += 1
        self.assertFalse(verify_receipt(receipt))

    def test_wallet_append_and_audit(self):
        receipt = self.make_receipt()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wallet.jsonl"
            append_to_wallet(receipt, path)
            audit = verify_wallet(path)
            self.assertTrue(audit["valid"])
            self.assertEqual(audit["checked"], 1)

    def test_wallet_rejects_invalid_receipt(self):
        receipt = self.make_receipt()
        receipt["wallet_id"] = "tampered"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                append_to_wallet(receipt, Path(directory) / "wallet.jsonl")


if __name__ == "__main__":
    unittest.main()
