"""Tests for canonical experiment commitments and header binding."""
import unittest

from src.ingestion.research_commitment import (
    bind_commitment_to_header_prefix,
    canonical_experiment_bytes,
    compute_experiment_commitment,
    verify_header_commitment,
)


class ResearchCommitmentTests(unittest.TestCase):
    def test_canonical_serialization_ignores_mapping_insertion_order(self):
        left = {"algorithm": "FGR-ICE", "parameters": {"q": 3329, "n": 256}}
        right = {"parameters": {"n": 256, "q": 3329}, "algorithm": "FGR-ICE"}
        self.assertEqual(canonical_experiment_bytes(left), canonical_experiment_bytes(right))
        self.assertEqual(compute_experiment_commitment(left), compute_experiment_commitment(right))

    def test_commitment_is_domain_separated_and_stable(self):
        document = {"algorithm": "FGR-ICE", "revision": 1}
        first = compute_experiment_commitment(document)
        self.assertEqual(len(first), 64)
        self.assertEqual(first, compute_experiment_commitment(document))
        self.assertNotEqual(first, compute_experiment_commitment({"algorithm": "other", "revision": 1}))

    def test_nan_and_non_json_values_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsupported_canonical_value"):
            canonical_experiment_bytes({"value": float("nan")})
        with self.assertRaisesRegex(ValueError, "finite_json"):
            canonical_experiment_bytes({"value": object()})

    def test_canonical_metadata_rejects_floats_and_unsafe_integers(self):
        with self.assertRaisesRegex(ValueError, "unsupported_canonical_value"):
            canonical_experiment_bytes({"value": 1.25})
        with self.assertRaisesRegex(ValueError, "unsafe_integer"):
            canonical_experiment_bytes({"value": 1 << 60})
        with self.assertRaisesRegex(ValueError, "ascii_strings"):
            canonical_experiment_bytes({"é": "value"})

    def test_commitment_binds_header_root_slot(self):
        prefix = bytes(range(76))
        commitment = compute_experiment_commitment({"ring": {"q": 3329, "n": 256}})
        bound = bind_commitment_to_header_prefix(prefix, commitment)
        self.assertEqual(len(bound), 76)
        self.assertEqual(bound[:36], prefix[:36])
        self.assertEqual(bound[36:68], bytes.fromhex(commitment))
        self.assertEqual(bound[68:], prefix[68:])
        self.assertTrue(verify_header_commitment(bound, commitment))
        self.assertFalse(verify_header_commitment(prefix, commitment))

    def test_invalid_header_or_commitment_rejected(self):
        with self.assertRaisesRegex(ValueError, "76_bytes"):
            bind_commitment_to_header_prefix(b"short", "00" * 32)
        with self.assertRaisesRegex(ValueError, "64_hex"):
            bind_commitment_to_header_prefix(bytes(76), "not-a-hash")


if __name__ == "__main__":
    unittest.main()
