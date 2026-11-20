import unittest

from src.mining.sha256d import (
    Candidate,
    double_sha256,
    scan_nonce_range,
    serialize_header_with_nonce,
    verify_candidate,
)


class Sha256dMinerTests(unittest.TestCase):
    def setUp(self):
        self.header = bytes(range(80))

    def test_double_sha256_known_answer_empty(self):
        self.assertEqual(
            double_sha256(b"").hex(),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
        )

    def test_nonce_serialization_is_little_endian(self):
        encoded = serialize_header_with_nonce(self.header, 0x12345678)
        self.assertEqual(encoded[76:80], bytes.fromhex("78563412"))
        self.assertEqual(encoded[:76], self.header[:76])

    def test_optimized_and_reference_kernels_match(self):
        target = (1 << 256) - 1
        optimized = scan_nonce_range(self.header, target, 17, 29, optimized=True)
        reference = scan_nonce_range(self.header, target, 17, 29, optimized=False)
        self.assertEqual(
            [(x.nonce, x.digest_hex, x.hash_value) for x in optimized.candidates],
            [(x.nonce, x.digest_hex, x.hash_value) for x in reference.candidates],
        )
        self.assertEqual(optimized.attempts, 12)

    def test_candidate_is_independently_verified(self):
        target = (1 << 256) - 1
        result = scan_nonce_range(self.header, target, 7, 8)
        self.assertEqual(len(result.candidates), 1)
        self.assertTrue(verify_candidate(self.header, result.candidates[0]))
        altered = Candidate(result.candidates[0].nonce, "00" * 32,
                            result.candidates[0].hash_value, target)
        self.assertFalse(verify_candidate(self.header, altered))

    def test_empty_range_is_valid(self):
        result = scan_nonce_range(self.header, 0, 4, 4)
        self.assertEqual(result.attempts, 0)
        self.assertEqual(result.candidates, ())

    def test_rejects_wrong_header_size(self):
        with self.assertRaises(ValueError):
            scan_nonce_range(b"short", 0, 0, 1)

    def test_rejects_out_of_range_nonce_interval(self):
        with self.assertRaises(ValueError):
            scan_nonce_range(self.header, 0, 10, 1)


if __name__ == "__main__":
    unittest.main()
