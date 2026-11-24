import hashlib
import unittest

from src.error_correction import (
    BerlekampWelchError,
    CorrectionStack,
    CorrectionStackError,
    QCParityCheck,
    ReedSolomonCode,
    ReedSolomonError,
    decode_evaluations,
)
from src.error_correction.gf256 import alpha_power, div, inv, mul, poly_eval


class GF256Tests(unittest.TestCase):
    def test_nonzero_elements_have_multiplicative_inverses(self):
        for value in range(1, 256):
            self.assertEqual(mul(value, inv(value)), 1)
            self.assertEqual(div(value, value), 1)

    def test_primitive_element_cycles_through_nonzero_field(self):
        values = [alpha_power(i) for i in range(255)]
        self.assertEqual(len(set(values)), 255)
        self.assertNotIn(0, values)

    def test_polynomial_evaluation_uses_ascending_coefficients(self):
        self.assertEqual(poly_eval([7, 3, 2], 5), 7 ^ mul(3, 5) ^ mul(2, mul(5, 5)))


class BerlekampWelchTests(unittest.TestCase):
    def test_recovers_polynomial_with_two_corrupted_evaluations(self):
        points = [alpha_power(i) for i in range(12)]
        coefficients = [17, 29, 41, 53]
        values = [poly_eval(coefficients, x) for x in points]
        values[2] ^= 0x55
        values[9] ^= 0xA7
        result = decode_evaluations(points, values, degree=4, max_errors=2)
        self.assertEqual(result.coefficients, tuple(coefficients))
        self.assertEqual(result.error_positions, (2, 9))

    def test_rejects_duplicate_evaluation_points(self):
        with self.assertRaises(BerlekampWelchError):
            decode_evaluations([1, 1, 2], [3, 4, 5], degree=2, max_errors=0)


class ReedSolomonTests(unittest.TestCase):
    def test_round_trip(self):
        codec = ReedSolomonCode(n=15, k=9)
        message = bytes([3, 9, 27, 81, 12, 34, 56, 78, 90])
        self.assertEqual(codec.decode(codec.encode(message)).message, message)

    def test_corrects_maximum_supported_symbol_errors(self):
        codec = ReedSolomonCode(n=15, k=9)
        message = bytes(range(9))
        encoded = bytearray(codec.encode(message))
        for position, mask in ((1, 0xA5), (7, 0x3C), (13, 0xF1)):
            encoded[position] ^= mask
        result = codec.decode(encoded)
        self.assertEqual(result.message, message)
        self.assertEqual(result.error_positions, (1, 7, 13))
        self.assertEqual(result.corrected_codeword, codec.encode(message))

    def test_rejects_wrong_dimensions_and_word_length(self):
        with self.assertRaises(ReedSolomonError):
            ReedSolomonCode(n=256, k=200)
        codec = ReedSolomonCode(n=8, k=4)
        with self.assertRaises(ReedSolomonError):
            codec.decode(b"short")


class QCLDPCTests(unittest.TestCase):
    def test_systematic_encoder_produces_zero_syndrome(self):
        code = QCParityCheck.default(lift=8)
        message = tuple((i * 7 + 3) & 1 for i in range(code.message_bits))
        encoded = code.encode(message)
        self.assertEqual(encoded[:code.message_bits], message)
        self.assertFalse(any(code.syndrome(encoded)))

    def test_min_sum_corrects_a_single_flipped_bit(self):
        code = QCParityCheck.default(lift=8)
        message = tuple((i * 5 + 1) & 1 for i in range(code.message_bits))
        encoded = code.encode(message)
        llr = [10.0 if bit == 0 else -10.0 for bit in encoded]
        llr[0] *= -1
        result = code.decode(llr, max_iterations=20)
        self.assertTrue(result.converged)
        self.assertEqual(result.bits, encoded)
        self.assertEqual(result.syndrome_weight, 0)

    def test_rejects_nonbinary_message_bits(self):
        code = QCParityCheck.default(lift=8)
        with self.assertRaises(ValueError):
            code.encode([False] + [0] * (code.message_bits - 1))


class CorrectionStackTests(unittest.TestCase):
    def test_layered_encode_decode_and_reverification(self):
        rs = ReedSolomonCode(n=32, k=24)
        qc = QCParityCheck.default(lift=64)
        stack = CorrectionStack(qc, rs)
        payload = bytes(range(24))
        encoded = stack.encode(payload)
        llr = [10.0 if bit == 0 else -10.0 for bit in encoded]
        llr[0] *= -1
        receipt = stack.decode(llr, max_iterations=30)
        self.assertTrue(receipt.verified)
        self.assertEqual(receipt.message, payload)
        self.assertEqual(receipt.output_sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(receipt.qc_syndrome_weight, 0)

    def test_rejects_invalid_decoder_budget(self):
        rs = ReedSolomonCode(n=32, k=24)
        qc = QCParityCheck.default(lift=64)
        stack = CorrectionStack(qc, rs)
        with self.assertRaises(CorrectionStackError):
            stack.decode([10.0] * qc.codeword_bits, max_iterations=0)


if __name__ == "__main__":
    unittest.main()
