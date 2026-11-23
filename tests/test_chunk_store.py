import tempfile
import unittest
from pathlib import Path

from src.error_correction.storage import ChunkStore, ChunkStoreError


class ChunkStoreTests(unittest.TestCase):
    def test_chunked_round_trip_and_manifest_deduplication(self):
        payload = bytes((i * 19) & 0xFF for i in range(257))
        with tempfile.TemporaryDirectory() as directory:
            store = ChunkStore(directory)
            first = store.put(payload, chunk_size=64)
            second = store.put(payload, chunk_size=64)
            self.assertEqual(first.manifest_id, second.manifest_id)
            self.assertEqual(first.chunk_count, 5)
            self.assertEqual(store.get(first.manifest_id), payload)
            self.assertTrue(store.verify(first.manifest_id))

    def test_empty_payload_has_a_valid_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ChunkStore(directory)
            receipt = store.put(b"", chunk_size=32)
            self.assertEqual(receipt.chunk_count, 0)
            self.assertEqual(store.get(receipt.manifest_id), b"")

    def test_corrupted_chunk_is_rejected(self):
        payload = b"chunk integrity" * 20
        with tempfile.TemporaryDirectory() as directory:
            store = ChunkStore(directory)
            receipt = store.put(payload, chunk_size=32)
            manifest_path = store.manifests / (receipt.manifest_id + ".json")
            import json
            manifest = json.loads(manifest_path.read_text("ascii"))
            digest = manifest["chunks"][0]["sha256"]
            object_path = store.objects / digest[:2] / digest[2:]
            object_path.write_bytes(b"tampered")
            self.assertFalse(store.verify(receipt.manifest_id))
            with self.assertRaises(ChunkStoreError):
                store.get(receipt.manifest_id)

    def test_corrupted_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ChunkStore(directory)
            receipt = store.put(b"manifest integrity", chunk_size=8)
            path = store.manifests / (receipt.manifest_id + ".json")
            path.write_bytes(path.read_bytes() + b" ")
            self.assertFalse(store.verify(receipt.manifest_id))
            with self.assertRaises(ChunkStoreError):
                store.get(receipt.manifest_id)

    def test_invalid_chunk_size_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ChunkStore(directory)
            for invalid in (True, 0, -1, 4 * 1024 * 1024 + 1, 1.5):
                with self.subTest(invalid=invalid):
                    with self.assertRaises(ChunkStoreError):
                        store.put(b"data", chunk_size=invalid)


if __name__ == "__main__":
    unittest.main()
