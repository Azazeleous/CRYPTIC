import json
import tempfile
import unittest
from pathlib import Path

from src.mining.sha256d import scan_nonce_range
from src.mining.receipt_wallet import create_receipt
from src.mining.trophy_manifest import (
    audit_manifest_file,
    canonicalize_manifest,
    compute_manifest_hash,
    create_manifest,
    export_manifest,
    verify_manifest,
)


class TrophyManifestTests(unittest.TestCase):
    def setUp(self):
        self.header = bytes(range(80))
        result = scan_nonce_range(self.header, (1 << 256) - 1, 9, 10)
        candidate = result.candidates[0]
        self.receipt = create_receipt(
            header=self.header,
            candidate=candidate,
            wallet_id="local:test-wallet",
            ruleset_id="cryptic-local-test-v1",
            window_start=100,
            window_end=200,
            accepted_at=150,
        )

    def test_manifest_is_deterministic_and_verifiable(self):
        first = create_manifest(self.receipt)
        second = create_manifest(self.receipt)
        self.assertEqual(first, second)
        self.assertEqual(canonicalize_manifest(first), canonicalize_manifest(second))
        self.assertEqual(first["integrity"]["manifest_hash"], compute_manifest_hash(first))
        self.assertTrue(verify_manifest(first, self.receipt))

    def test_manifest_does_not_claim_network_acceptance(self):
        manifest = create_manifest(self.receipt)
        self.assertEqual(manifest["verification"]["network_acceptance"], "not_claimed")
        self.assertEqual(manifest["representation"]["asset_type"], "proof_trophy")
        self.assertIsNone(manifest["representation"]["valuation"])

    def test_tampered_manifest_is_rejected(self):
        manifest = create_manifest(self.receipt)
        manifest["provenance"]["ruleset_id"] = "changed"
        self.assertFalse(verify_manifest(manifest, self.receipt))

    def test_manifest_bound_to_exact_receipt(self):
        manifest = create_manifest(self.receipt)
        other = dict(self.receipt)
        other["receipt_id"] = "0" * 64
        self.assertFalse(verify_manifest(manifest, other))

    def test_unknown_fields_are_rejected(self):
        manifest = create_manifest(self.receipt)
        manifest["unrecognized"] = True
        manifest["integrity"]["manifest_hash"] = compute_manifest_hash(manifest)
        self.assertFalse(verify_manifest(manifest, self.receipt))

    def test_export_and_full_audit(self):
        manifest = create_manifest(self.receipt)
        with tempfile.TemporaryDirectory() as directory:
            path = export_manifest(manifest, Path(directory) / "trophy.json")
            audit = audit_manifest_file(path, self.receipt)
            self.assertTrue(audit["valid"])
            self.assertEqual(audit["receipt_hash"], self.receipt["receipt_id"])
            with self.assertRaises(FileExistsError):
                export_manifest(manifest, path)

    def test_export_rejects_bad_manifest_hash(self):
        manifest = create_manifest(self.receipt)
        manifest["integrity"]["manifest_hash"] = "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                export_manifest(manifest, Path(directory) / "bad.json")

    def test_audit_detects_modified_export(self):
        manifest = create_manifest(self.receipt)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trophy.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            stored = json.loads(path.read_text(encoding="utf-8"))
            stored["identity"]["issuer"] = "OTHER"
            path.write_text(json.dumps(stored), encoding="utf-8")
            self.assertFalse(audit_manifest_file(path, self.receipt)["valid"])


if __name__ == "__main__":
    unittest.main()
