"""Tests for canonical transport encoding and strict decoding."""
import unittest

from src.ingestion.transport_codec import (
    TransportCodecError,
    canonical_json_bytes,
    decode_json_document,
)


class TransportCodecTests(unittest.TestCase):
    def test_canonical_encoding_is_deterministic_and_key_order_independent(self):
        left = {"z": 1, "a": {"y": 2, "x": 3}}
        right = {"a": {"x": 3, "y": 2}, "z": 1}
        self.assertEqual(canonical_json_bytes(left), canonical_json_bytes(right))

    def test_round_trip_preserves_absent_null_zero_false_and_empty_values(self):
        value = {"null": None, "zero": 0, "false": False, "empty": "", "array": [], "object": {}}
        encoded = canonical_json_bytes(value)
        self.assertEqual(decode_json_document(encoded, max_bytes=1024), value)
        self.assertNotIn("absent", decode_json_document(encoded, max_bytes=1024))

    def test_utf8_length_is_measured_in_bytes(self):
        with self.assertRaisesRegex(TransportCodecError, "encoded_payload_too_large"):
            canonical_json_bytes({"x": "🌐"}, max_bytes=5)

    def test_non_finite_numbers_are_rejected(self):
        with self.assertRaises(TransportCodecError):
            canonical_json_bytes({"x": float("nan")})

    def test_non_string_object_keys_are_rejected(self):
        with self.assertRaisesRegex(TransportCodecError, "object_key_must_be_string"):
            canonical_json_bytes({1: "x"})

    def test_cyclic_values_are_rejected(self):
        value = []
        value.append(value)
        with self.assertRaisesRegex(TransportCodecError, "cyclic_value"):
            canonical_json_bytes(value)

    def test_duplicate_response_keys_are_rejected(self):
        with self.assertRaisesRegex(TransportCodecError, "duplicate_object_key"):
            decode_json_document(b'{"jsonrpc":"2.0","id":1,"id":2}', max_bytes=128)

    def test_invalid_utf8_and_non_object_roots_are_rejected(self):
        with self.assertRaises(TransportCodecError):
            decode_json_document(b"\xff", max_bytes=128)
        with self.assertRaisesRegex(TransportCodecError, "json_root_must_be_object"):
            decode_json_document(b"[]", max_bytes=128)

    def test_response_size_is_rejected_before_decode(self):
        with self.assertRaisesRegex(TransportCodecError, "payload_too_large"):
            decode_json_document(b'{"x":1}', max_bytes=2)


if __name__ == "__main__":
    unittest.main()
