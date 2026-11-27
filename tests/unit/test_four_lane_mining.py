import hashlib
import unittest

from mining.barrel_roll import (
    roll_frame, unroll_frame, rotl, rotr, deinterleave_lanes,
)
from mining.miner import candidate_digest, mine_four_lane, verify_candidate, _mine_lane
from mining.scheduler import PROFILE_MODULUS, lane_ordinals, nonce_for_ordinal, traversal_index


class BarrelRollTests(unittest.TestCase):
    def test_bit_rotation_inverse(self):
        for width in (8, 16, 32, 64):
            values = (0, 1, (1 << width) - 1, 1 << (width - 1), 0xA5 % (1 << width))
            for value in values:
                for shift in range(width + 1):
                    self.assertEqual(rotr(rotl(value, shift, width), shift, width), value)

    def test_frame_round_trip(self):
        samples = (b"", b"x", bytes(range(256)), b"CRYPTIC four lane mining" * 7)
        for data in samples:
            for bit_shift, byte_shift, lane_shift in ((0, 0, 0), (3, 5, 2), (7, 19, 3), (4, -2, -1)):
                lanes = roll_frame(data, bit_shift=bit_shift, byte_shift=byte_shift, lane_shift=lane_shift)
                self.assertEqual(unroll_frame(lanes, bit_shift=bit_shift, byte_shift=byte_shift, lane_shift=lane_shift), data)

    def test_malformed_round_robin_lane_lengths_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "lane_lengths_not_round_robin"):
            deinterleave_lanes((b"a", b"", b"b", b""))

    def test_unroll_requires_explicit_transform_metadata(self):
        lanes = roll_frame(b"metadata", bit_shift=2, byte_shift=3, lane_shift=1)
        with self.assertRaises(TypeError):
            unroll_frame(lanes)


class SchedulerTests(unittest.TestCase):
    def test_affine_profile_is_permutation(self):
        self.assertEqual(len({traversal_index(i) for i in range(PROFILE_MODULUS)}), PROFILE_MODULUS)

    def test_four_lanes_are_disjoint_and_complete(self):
        count = 1003
        ordinals = [o for lane in range(4) for o in lane_ordinals(lane, count, reverse=lane in (1, 2))]
        self.assertEqual(sorted(ordinals), list(range(count)))
        self.assertEqual(list(lane_ordinals(1, count, reverse=True)), list(reversed(list(lane_ordinals(1, count)))))
        nonces = [nonce_for_ordinal(100, o) for o in ordinals]
        self.assertEqual(len(set(nonces)), count)

    def test_scheduler_rejects_boolean_integer_arguments(self):
        for call in (
            lambda: traversal_index(True),
            lambda: nonce_for_ordinal(True, 0),
            lambda: nonce_for_ordinal(0, True),
            lambda: lane_ordinals(True, 10),
            lambda: lane_ordinals(0, True),
            lambda: lane_ordinals(0, 10, lane_count=True),
        ):
            with self.assertRaises(ValueError):
                call()
        with self.assertRaisesRegex(ValueError, "reverse must be a boolean"):
            list(lane_ordinals(0, 10, reverse=1))


class MiningTests(unittest.TestCase):
    def test_candidate_hash_known_answer(self):
        self.assertEqual(candidate_digest(b"header", 7), hashlib.sha256(b"header" + (7).to_bytes(8, "big")).digest())

    def test_boolean_nonce_and_numeric_inputs_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "uint64"):
            candidate_digest(b"header", True)
        for kwargs in (
            {"start_nonce": True, "count": 1, "target": (1 << 256) - 1},
            {"start_nonce": 0, "count": True, "target": (1 << 256) - 1},
            {"start_nonce": 0, "count": 1, "target": True},
        ):
            with self.assertRaises(ValueError):
                mine_four_lane(b"header", **kwargs)

    def test_verifier_rejects_boolean_target_and_invalid_metadata(self):
        result = mine_four_lane(b"header", 0, 1, (1 << 256) - 1)
        self.assertIsNotNone(result)
        self.assertFalse(verify_candidate(b"header", result, True))
        self.assertFalse(verify_candidate(
            b"header",
            MiningResult(result.nonce, result.digest, True, result.ordinal, result.attempts),
            (1 << 256) - 1,
        ))

    def test_easy_target_mines_and_verifies(self):
        result = mine_four_lane(b"test-header", 0, 32, (1 << 256) - 1)
        self.assertIsNotNone(result)
        self.assertEqual(result.attempts, 32)
        self.assertTrue(verify_candidate(b"test-header", result, (1 << 256) - 1))
        self.assertFalse(verify_candidate(b"tampered-header", result, (1 << 256) - 1))

    def test_lane_retains_only_earliest_hit(self):
        hit, attempts = _mine_lane(b"memory-bound-test", 0, 4096, (1 << 256) - 1, 0)
        self.assertIsNotNone(hit)
        self.assertEqual(hit.ordinal, 0)
        self.assertEqual(attempts, 1024)

    def test_zero_count_returns_none(self):
        self.assertIsNone(mine_four_lane(b"header", 0, 0, (1 << 256) - 1))

    def test_target_zero_has_no_hit_in_test_window(self):
        self.assertIsNone(mine_four_lane(b"header", 0, 64, 0))


if __name__ == "__main__":
    unittest.main()
