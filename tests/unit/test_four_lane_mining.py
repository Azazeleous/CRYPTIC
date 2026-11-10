import hashlib
import unittest

from mining.barrel_roll import roll_frame, unroll_frame, rotl, rotr
from mining.miner import candidate_digest, mine_four_lane, verify_candidate
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


class SchedulerTests(unittest.TestCase):
    def test_affine_profile_is_permutation(self):
        self.assertEqual(len({traversal_index(i) for i in range(PROFILE_MODULUS)}), PROFILE_MODULUS)

    def test_four_lanes_are_disjoint_and_complete(self):
        count = 1003
        ordinals = [o for lane in range(4) for o in lane_ordinals(lane, count)]
        self.assertEqual(sorted(ordinals), list(range(count)))
        self.assertEqual(list(lane_ordinals(1, count, reverse=True)), list(reversed(list(lane_ordinals(1, count)))))
        nonces = [nonce_for_ordinal(100, o) for o in ordinals]
        self.assertEqual(len(set(nonces)), count)


class MiningTests(unittest.TestCase):
    def test_candidate_hash_known_answer(self):
        self.assertEqual(candidate_digest(b"header", 7), hashlib.sha256(b"header" + (7).to_bytes(8, "big")).digest())

    def test_easy_target_mines_and_verifies(self):
        result = mine_four_lane(b"test-header", 0, 32, (1 << 256) - 1)
        self.assertIsNotNone(result)
        self.assertEqual(result.attempts, 32)
        self.assertTrue(verify_candidate(b"test-header", result, (1 << 256) - 1))
        self.assertFalse(verify_candidate(b"tampered-header", result, (1 << 256) - 1))

    def test_zero_count_returns_none(self):
        self.assertIsNone(mine_four_lane(b"header", 0, 0, (1 << 256) - 1))

    def test_target_zero_has_no_hit_in_test_window(self):
        self.assertIsNone(mine_four_lane(b"header", 0, 64, 0))


if __name__ == "__main__":
    unittest.main()
