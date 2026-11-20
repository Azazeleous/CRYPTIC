import json
import tempfile
import unittest
from pathlib import Path

from src.mining.sha256d import scan_nonce_range
from src.mining.receipt_wallet import append_to_wallet, create_receipt
from src.mining.trophy_manifest import create_manifest, export_manifest
from src.mining.provenance_index import (
    audit_index_file, build_index, export_index, verify_index,
)


class ProvenanceIndexTests(unittest.TestCase):
    def setUp(self):
        header = bytes(range(80))
        result = scan_nonce_range(header, (1 << 256) - 1, 17, 18)
        self.receipt = create_receipt(
            header=header,
            candidate=result.candidates[0],
            wallet_id="local:provenance-index-test",
            ruleset_id="cryptic-local-test-v1",
            window_start=100,
            window_end=200,
            accepted_at=150,
        )

    def _archive(self, root):
        wallet = root / "wallet.jsonl"
        manifests = root / "trophies"
        append_to_wallet(self.receipt, wallet)
        manifests.mkdir()
        manifest = create_manifest(self.receipt)
        export_manifest(manifest, manifests / f"{self.receipt['receipt_id']}.json")
        return wallet, manifests

    def test_index_is_deterministic_and_connects_receipt_to_trophy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wallet, manifests = self._archive(root)
            first = build_index(wallet, manifests)
            second = build_index(wallet, manifests)
            self.assertEqual(first, second)
            self.assertTrue(first["summary"]["valid"])
            self.assertEqual(first["summary"]["indexed_records"], 1)
            record = first["records"][0]
            self.assertEqual(record["receipt_id"], self.receipt["receipt_id"])
            self.assertEqual(record["network_acceptance"], "not_claimed")
            self.assertEqual(len(record["work_id"]), 64)
            self.assertEqual(len(record["trophy_id"]), 64)

    def test_duplicate_receipt_is_reported_but_indexed_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wallet, manifests = self._archive(root)
            append_to_wallet(self.receipt, wallet)
            index = build_index(wallet, manifests)
            self.assertEqual(index["summary"]["indexed_records"], 1)
            self.assertEqual(len(index["issues"]["duplicate_receipts"]), 1)
            self.assertFalse(index["summary"]["valid"])

    def test_missing_and_orphan_manifests_are_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wallet = root / "wallet.jsonl"
            append_to_wallet(self.receipt, wallet)
            manifests = root / "trophies"
            manifests.mkdir()
            index = build_index(wallet, manifests)
            self.assertEqual(index["issues"]["missing_manifests"], [self.receipt["receipt_id"]])
            self.assertFalse(index["summary"]["valid"])

            orphan = create_manifest(self.receipt)
            export_manifest(orphan, manifests / "orphan.json")
            index = build_index(wallet, manifests)
            self.assertIn("orphan.json", index["issues"]["orphaned_manifests"])

    def test_tampered_manifest_is_a_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wallet, manifests = self._archive(root)
            path = manifests / f"{self.receipt['receipt_id']}.json"
            item = json.loads(path.read_text(encoding="utf-8"))
            item["identity"]["trophy_id"] = "0" * 64
            path.write_text(json.dumps(item), encoding="utf-8")
            index = build_index(wallet, manifests)
            self.assertEqual(index["issues"]["manifest_conflicts"], [path.name])
            self.assertEqual(index["summary"]["indexed_records"], 0)

    def test_checkpoint_changes_when_indexed_evidence_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wallet, manifests = self._archive(root)
            index = build_index(wallet, manifests)
            altered = dict(index)
            altered["records"] = []
            self.assertFalse(verify_index(altered, wallet, manifests))
            self.assertNotEqual(index["checkpoint"]["archive_root"], "0" * 64)

    def test_export_is_no_overwrite_and_audit_rebuilds_from_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wallet, manifests = self._archive(root)
            index = build_index(wallet, manifests)
            target = root / "index.json"
            export_index(index, target)
            self.assertTrue(verify_index(json.loads(target.read_text()), wallet, manifests))
            self.assertTrue(audit_index_file(target, wallet, manifests)["valid"])
            with self.assertRaises(FileExistsError):
                export_index(index, target)

    def test_malformed_wallet_line_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wallet = root / "wallet.jsonl"
            wallet.write_bytes(b"\xff\xfe\n")
            index = build_index(wallet, root / "trophies")
            self.assertEqual(index["issues"]["malformed_wallet_lines"], [1])
            self.assertFalse(index["summary"]["valid"])

    def test_malformed_index_structure_fails_audit_without_crashing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wallet = root / "wallet.jsonl"
            manifests = root / "trophies"
            target = root / "bad-index.json"
            target.write_text(json.dumps({
                "schema": "cryptic.provenance-index.v1",
                "summary": [],
                "checkpoint": "not-an-object",
            }), encoding="utf-8")
            report = audit_index_file(target, wallet, manifests)
            self.assertFalse(report["valid"])
            self.assertIsNone(report["indexed_records"])
            self.assertIsNone(report["archive_root"])


if __name__ == "__main__":
    unittest.main()
