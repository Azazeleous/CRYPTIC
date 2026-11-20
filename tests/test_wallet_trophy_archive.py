import json
import tempfile
import unittest
from pathlib import Path

from src.mining.sha256d import scan_nonce_range
from src.mining.receipt_wallet import append_to_wallet, create_receipt
from src.mining.trophy_manifest import create_manifest, export_manifest
from src.mining.wallet_trophy_archive import reconcile_wallet


class WalletTrophyArchiveTests(unittest.TestCase):
    def setUp(self):
        header = bytes(range(80))
        result = scan_nonce_range(header, (1 << 256) - 1, 9, 10)
        self.receipt = create_receipt(
            header=header,
            candidate=result.candidates[0],
            wallet_id="local:archive-test",
            ruleset_id="cryptic-local-test-v1",
            window_start=100,
            window_end=200,
            accepted_at=150,
        )

    def test_generates_manifest_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wallet = root / "wallet.jsonl"
            manifests = root / "trophies"
            append_to_wallet(self.receipt, wallet)

            first = reconcile_wallet(wallet, manifests)
            second = reconcile_wallet(wallet, manifests)

            self.assertEqual(len(first["generated_manifests"]), 1)
            self.assertEqual(len(second["already_present_manifests"]), 1)
            self.assertTrue(first["valid"])
            self.assertTrue(second["valid"])

    def test_duplicate_receipts_are_exported_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wallet = root / "wallet.jsonl"
            append_to_wallet(self.receipt, wallet)
            append_to_wallet(self.receipt, wallet)

            report = reconcile_wallet(wallet, root / "trophies")
            self.assertEqual(len(report["generated_manifests"]), 1)
            self.assertEqual(len(report["duplicate_receipts"]), 1)

    def test_invalid_receipt_is_not_exported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wallet = root / "wallet.jsonl"
            invalid = dict(self.receipt)
            invalid["wallet_id"] = "tampered"
            wallet.write_text(json.dumps(invalid) + "\n", encoding="utf-8")

            report = reconcile_wallet(wallet, root / "trophies")
            self.assertEqual(report["unique_valid_receipts"], 0)
            self.assertEqual(len(report["invalid_receipts"]), 1)
            self.assertEqual(list((root / "trophies").glob("*.json")), [])

    def test_malformed_wallet_line_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wallet = root / "wallet.jsonl"
            wallet.write_text("{broken json\n", encoding="utf-8")

            report = reconcile_wallet(wallet, root / "trophies")
            self.assertEqual(report["malformed_wallet_lines"], [1])
            self.assertFalse(report["valid"])

    def test_conflicting_existing_manifest_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wallet = root / "wallet.jsonl"
            append_to_wallet(self.receipt, wallet)
            manifest_dir = root / "trophies"
            manifest_dir.mkdir()
            target = manifest_dir / f"{self.receipt['receipt_id']}.json"
            target.write_text('{"tampered":true}\n', encoding="utf-8")

            report = reconcile_wallet(wallet, manifest_dir)
            self.assertEqual(len(report["manifest_conflicts"]), 1)
            self.assertEqual(target.read_text(encoding="utf-8"), '{"tampered":true}\n')

    def test_unreferenced_manifest_is_reported_as_orphan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wallet = root / "wallet.jsonl"
            manifest_dir = root / "trophies"
            manifest_dir.mkdir()
            manifest = create_manifest(self.receipt)
            export_manifest(manifest, manifest_dir / "orphan.json")

            report = reconcile_wallet(wallet, manifest_dir)
            self.assertEqual(report["orphaned_manifests"], ["orphan.json"])
            self.assertFalse(report["valid"])


if __name__ == "__main__":
    unittest.main()
