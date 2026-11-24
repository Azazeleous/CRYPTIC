import random
import unittest

from src.error_correction import (
    CorrectionStack,
    CorrectionStackError,
    QCParityCheck,
    ReedSolomonCode,
    ThreeLaneCorrection,
    ThreeLaneCorrectionError,
)
from src.error_correction.reference_rs import (
    ReferenceReedSolomonError,
    decode_evaluations_reference,
    encode_evaluations_reference,
)


def make_stack():
    codec = ReedSolomonCode(n=32, k=24)
    qc = QCParityCheck.default(lift=64)
    return CorrectionStack(qc, codec)


class FaultInjectedLayeredStack(CorrectionStack):
    """Test-only fault injection for the layered lane boundary."""

    def decode(self, channel_llr, *, max_iterations=30, normalization=0.8):
        raise CorrectionStackError("injected_layered_lane_unavailable")


class IndependentReferenceTests(unittest.TestCase):
    def test_reference_decoder_matches_production_over_deterministic_error_sweep(self):
        codec = ReedSolomonCode(n=32, k=24)
        random_source = random.Random(0xC0FFEE)
        for case in range(30):
            message = bytes(random_source.randrange(256) for _ in range(codec.k))
            encoded = bytearray(codec.encode(message))
            error_count = case % (codec.max_errors + 1)
            positions = random_source.sample(range(codec.n), error_count)
            for position in positions:
                encoded[position] ^= random_source.randrange(1, 256)
            production = codec.decode(encoded)
            reference = decode_evaluations_reference(
                codec.points, encoded, degree=codec.k,
                max_errors=codec.max_errors,
            )
            self.assertEqual(bytes(reference.coefficients), production.message)
            self.assertEqual(reference.corrected_values, production.corrected_codeword)
            self.assertEqual(reference.error_positions, production.error_positions)
            self.assertEqual(
                encode_evaluations_reference(reference.coefficients, codec.points),
                production.corrected_codeword,
            )

    def test_reference_decoder_rejects_more_than_the_error_bound(self):
        codec = ReedSolomonCode(n=32, k=24)
        message = bytes(range(codec.k))
        damaged = bytearray(codec.encode(message))
        for position in range(codec.max_errors + 1):
            damaged[position] ^= 0x5A + position
        with self.assertRaises(ReferenceReedSolomonError):
            decode_evaluations_reference(
                codec.points, damaged, degree=codec.k,
                max_errors=codec.max_errors,
            )


class ThreeLaneCorrectionTests(unittest.TestCase):
    def test_all_three_lanes_agree_after_single_bit_channel_error(self):
        stack = make_stack()
        correction = ThreeLaneCorrection(stack)
        message = bytes(range(stack.reed_solomon.k))
        encoded = stack.encode(message)
        llr = [12.0 if bit == 0 else -12.0 for bit in encoded]
        llr[0] *= -1
        receipt = correction.decode(llr)
        self.assertTrue(receipt.verified)
        self.assertEqual(receipt.message, message)
        self.assertEqual(len(receipt.agreeing_lanes), 3)
        self.assertEqual(receipt.failed_lanes, ())

    def test_two_independent_rs_lanes_can_recover_when_layered_lane_fails(self):
        base = make_stack()
        stack = FaultInjectedLayeredStack(base.qc, base.reed_solomon)
        correction = ThreeLaneCorrection(stack)
        message = bytes((i * 13 + 7) & 0xFF for i in range(stack.reed_solomon.k))
        encoded = stack.encode(message)
        llr = [10.0 if bit == 0 else -10.0 for bit in encoded]
        llr[0] *= -1
        receipt = correction.decode(llr)
        self.assertEqual(receipt.message, message)
        self.assertEqual(
            receipt.agreeing_lanes,
            ("direct_rs", "independent_reference_rs"),
        )
        self.assertEqual(receipt.failed_lanes[0][0], "layered_qc_rs")

    def test_no_two_lane_agreement_fails_closed(self):
        base = make_stack()
        stack = FaultInjectedLayeredStack(base.qc, base.reed_solomon)
        correction = ThreeLaneCorrection(stack)
        message = bytes((i * 17 + 11) & 0xFF for i in range(stack.reed_solomon.k))
        encoded = stack.encode(message)
        llr = [10.0 if bit == 0 else -10.0 for bit in encoded]
        for symbol in range(stack.reed_solomon.max_errors + 1):
            llr[symbol * 8] *= -1
        with self.assertRaisesRegex(ThreeLaneCorrectionError, "no_two_lane_agreement"):
            correction.decode(llr)

    def test_shared_decoder_configuration_is_validated_before_any_lane(self):
        stack = make_stack()
        correction = ThreeLaneCorrection(FaultInjectedLayeredStack(
            stack.qc, stack.reed_solomon
        ))
        message = bytes(range(stack.reed_solomon.k))
        encoded = stack.encode(message)
        llr = [10.0 if bit == 0 else -10.0 for bit in encoded]
        with self.assertRaisesRegex(ThreeLaneCorrectionError, "max_iterations_invalid"):
            correction.decode(llr, max_iterations=0)
        with self.assertRaisesRegex(ThreeLaneCorrectionError, "normalization_invalid"):
            correction.decode(llr, normalization=0.0)

    def test_nonfinite_llr_fails_closed(self):
        stack = make_stack()
        correction = ThreeLaneCorrection(stack)
        encoded = stack.encode(bytes(range(stack.reed_solomon.k)))
        llr = [10.0 if bit == 0 else -10.0 for bit in encoded]
        llr[0] = float("nan")
        with self.assertRaisesRegex(
            ThreeLaneCorrectionError, "llr_values_must_be_finite_numbers",
        ):
            correction.decode(llr)


if __name__ == "__main__":
    unittest.main()
