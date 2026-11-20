import json
import tempfile
import unittest
from pathlib import Path

from src.mining.sha256d import scan_nonce_range
from src.mining.receipt_wallet import append_to_wallet, create_receipt
from src.mining.trophy_manifest import create_manifest, export_manifest
from src.mining.provenance_index import build_index
from src.mining.provenance_federation import (
    audit_federation_file,
    build_federation,
    export_federation,
    verify_federation,
)


class ProvenanceFederationTests(unittest.TestCase):
    def setUp(self):
        header = bytes(range(80))
        result = scan_nonce_range(header, (1 << 256) - 1, 17, 18)
        self.receipt = create_receipt(
            header=header,
            candidate=result.candidates[0],
            wallet_id="local:federation-test",
            ruleset_id="cryptic-local-test-v1",
            window_start=100,
            window_end=200,
            accepted_at=150,
        )

    def _archive(self, root, name, receipt=None):
        receipt = receipt or self.receipt
        folder = root / name
        folder.mkdir()
        wallet = folder / "wallet.jsonl"
        manifests = folder / "trophies"
        append_to_wallet(receipt, wallet)
        manifests.mkdir()
        manifest = create_manifest(receipt)
        export_manifest(manifest, manifests / f"{receipt['receipt_id']}.json")
        return wallet, manifests

    def _source(self, source_id, archive, expected=None):
        wallet, manifests = archive
        result = {
            "source_id": source_id,
            "wallet_file": str(wallet),
            "manifest_dir": str(manifests),
        }
        if expected is not None:
            result["expected_archive_root"] = expected
        return result

    def test_federation_is_deterministic_and_rebuild_verifiable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self._archive(root, "device-a")
            sources = [self._source("device-a", archive)]
            first = build_federation(sources)
            second = build_federation(sources)
            self.assertEqual(first, second)
            self.assertTrue(first["summary"]["valid"])
            self.assertEqual(first["summary"]["source_count"], 1)
            self.assertEqual(first["summary"]["indexed_occurrences"], 1)
            self.assertTrue(verify_federation(first, sources))

    def test_cross_archive_duplicate_is_preserved_and_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            a = self._archive(root, "device-a")
            b = self._archive(root, "device-b")
            sources = [
                self._source("device-a", a),
                self._source("device-b", b),
            ]
            result = build_federation(sources)
            self.assertEqual(result["summary"]["indexed_occurrences"], 2)
            self.assertEqual(result["summary"]["unique_receipt_ids"], 1)
            self.assertEqual(result["summary"]["duplicate_receipt_ids"], 1)
            duplicate = result["issues"]["cross_archive_duplicates"][0]
            self.assertEqual(duplicate["receipt_id"], self.receipt["receipt_id"])
            self.assertEqual(duplicate["source_ids"], ["device-a", "device-b"])
            self.assertFalse(result["summary"]["valid"])

    def test_expected_checkpoint_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self._archive(root, "device-a")
            sources = [self._source("device-a", archive, "0" * 64)]
            result = build_federation(sources)
            self.assertFalse(result["summary"]["valid"])
            self.assertEqual(len(result["issues"]["checkpoint_mismatches"]), 1)

    def test_source_archive_issues_are_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self._archive(root, "device-a")
            with archive[0].open("ab") as stream:
                stream.write(b"not-json\n")
            result = build_federation([self._source("device-a", archive)])
            self.assertFalse(result["summary"]["valid"])
            self.assertEqual(
                result["issues"]["source_archive_issues"][0]["kind"],
                "source_archive_has_issues",
            )

    def test_unreadable_source_is_reported_without_dropping_other_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            good = self._archive(root, "device-a")
            missing = (root / "missing-wallet.jsonl", root / "missing-trophies")
            result = build_federation([
                self._source("device-a", good),
                self._source("device-b", missing),
            ])
            self.assertEqual(result["summary"]["source_count"], 2)
            self.assertEqual(result["summary"]["readable_sources"], 1)
            self.assertFalse(result["summary"]["valid"])
            self.assertEqual(
                result["issues"]["source_archive_issues"][0]["kind"],
                "source_unreadable",
            )

    def test_export_and_audit_are_no_overwrite_and_source_rebuilt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self._archive(root, "device-a")
            sources = [self._source("device-a", archive)]
            federation = build_federation(sources)
            destination = root / "federation.json"
            export_federation(federation, destination)
            self.assertTrue(audit_federation_file(destination, sources)["valid"])
            with self.assertRaises(FileExistsError):
                export_federation(federation, destination)
            loaded = json.loads(destination.read_text(encoding="utf-8"))
            self.assertTrue(verify_federation(loaded, sources))

    def test_export_refuses_duplicates_and_checkpoint_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            a = self._archive(root, "device-a")
            b = self._archive(root, "device-b")
            duplicate = build_federation([
                self._source("device-a", a),
                self._source("device-b", b),
            ])
            with self.assertRaises(ValueError):
                export_federation(duplicate, root / "duplicate.json")

            clean = build_federation([self._source("device-a", a)])
            tampered = dict(clean)
            tampered["checkpoint"] = dict(clean["checkpoint"])
            tampered["checkpoint"]["federation_root"] = "0" * 64
            with self.assertRaises(ValueError):
                export_federation(tampered, root / "tampered.json")
            self.assertFalse((root / "tampered.json").exists())

    def test_duplicate_source_ids_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self._archive(root, "device-a")
            source = self._source("device-a", archive)
            with self.assertRaises(ValueError):
                build_federation([source, source])


if __name__ == "__main__":
    unittest.main()
