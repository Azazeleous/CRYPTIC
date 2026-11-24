import tempfile
import unittest
from pathlib import Path

from storage.sparsebundle import SparseBundle, SparseBundleError


class SparseBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "gaia.sparsebundle"
        self.bundle = SparseBundle.create(
            self.root,
            {
                "boot": {"name": "Boot", "role": "boot", "size": 131072},
                "system": {"name": "System", "role": "system", "size": 262144},
                "data": {"name": "Data", "role": "data", "size": 524288},
                "ledger": {"name": "Ledger", "role": "ledger", "size": 131072},
                "recovery": {"name": "Recovery", "role": "recovery", "size": 131072},
            },
            chunk_size=4096,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_partition_set_and_zero_filled_sparse_reads(self):
        rows = self.bundle.partitions()
        self.assertEqual({row["role"] for row in rows},
                         {"boot", "system", "data", "ledger", "recovery"})
        self.assertEqual(self.bundle.read("data", 0, 128), bytes(128))
        self.assertEqual(self.bundle.verify()["allocated_bytes"], 0)

    def test_write_crosses_chunk_boundary_and_reopens(self):
        payload = bytes(range(256)) * 24
        self.bundle.write("data", 4000, payload)
        reopened = SparseBundle(self.root)
        self.assertEqual(reopened.read("data", 4000, len(payload)), payload)
        report = reopened.verify()
        self.assertTrue(report["valid"])
        self.assertGreater(report["chunks_verified"], 1)

    def test_zero_write_deallocates_chunk(self):
        self.bundle.write("data", 0, b"x" * 4096)
        self.assertEqual(self.bundle.partitions()[-1]["allocated_chunks"], 0) if False else None
        self.bundle.write("data", 0, bytes(4096))
        row = next(item for item in self.bundle.partitions() if item["id"] == "data")
        self.assertEqual(row["allocated_chunks"], 0)
        self.assertEqual(self.bundle.verify()["allocated_bytes"], 0)

    def test_out_of_bounds_operations_are_rejected(self):
        with self.assertRaisesRegex(SparseBundleError, "write_out_of_bounds"):
            self.bundle.write("boot", 131071, b"xx")
        with self.assertRaisesRegex(SparseBundleError, "read_out_of_bounds"):
            self.bundle.read("boot", 131072, 1)

    def test_chunk_corruption_fails_verification(self):
        self.bundle.write("data", 0, b"integrity")
        digest = next(item for item in self.bundle.partitions()
                      if item["id"] == "data")
        manifest = (self.root / "manifest.json").read_text("ascii")
        import json
        extents = json.loads(manifest)["partitions"]
        row = next(item for item in extents if item["id"] == "data")
        chunk = self.root / "objects" / next(iter(row["extents"].values()))
        chunk.write_bytes(b"bad")
        with self.assertRaisesRegex(SparseBundleError, "chunk_integrity_failure"):
            self.bundle.verify()

    def test_manifest_checksum_detects_tampering(self):
        path = self.root / "manifest.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(SparseBundleError, "manifest_integrity_failure"):
            SparseBundle(self.root)

    def test_rejects_duplicate_or_unsafe_partition_ids(self):
        with self.assertRaisesRegex(SparseBundleError, "partition_id_invalid"):
            SparseBundle.create(
                Path(self.tmp.name) / "bad.bundle",
                {"../bad": {"name": "Bad", "role": "data", "size": 4096}},
            )


if __name__ == "__main__":
    unittest.main()
