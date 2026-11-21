"""Tests for the four-lane FGR-ICE SHA-256d regtest."""
import unittest

from src.ingestion.four_lane_regtest import (
    LANE_COUNT,
    RegtestError,
    run_four_lane_regtest,
    sha256d,
)


class FourLaneRegtestTests(unittest.TestCase):
    def setUp(self):
        self.header_prefix = bytes(range(76))

    def test_sha256d_header_nonce_serialization(self):
        digest = sha256d(self.header_prefix, 7)
        self.assertEqual(len(digest), 32)
        self.assertEqual(digest, sha256d(self.header_prefix, 7))
        self.assertNotEqual(digest, sha256d(self.header_prefix, 8))

    def test_four_lanes_find_and_center_verify_one_winner(self):
        expected_nonce = 1337
        expected = sha256d(self.header_prefix, expected_nonce)
        target = int.from_bytes(expected, "little")
        report = run_four_lane_regtest(
            self.header_prefix,
            nonce_start=0,
            nonce_end=5000,
            target=target,
            time_budget_seconds=5.0,
        )
        self.assertEqual(report["status"], "accepted")
        self.assertEqual(report["lane_count"], LANE_COUNT)
        self.assertEqual(report["winner_count"], 1)
        self.assertIsNotNone(report["receipt"])
        nonce = report["winner"]["nonce"]
        digest = sha256d(self.header_prefix, nonce)
        self.assertEqual(report["winner"]["digest"], digest.hex())
        self.assertLessEqual(int.from_bytes(digest, "little"), target)
        self.assertEqual(report["process"], ["REDUCE", "SOLVE", "CONVERGE"])
        self.assertTrue(report["metrics"]["hccgn_timer"]["deadline_enforced"])

    def test_zero_target_exhausts_small_domain_without_false_winner(self):
        report = run_four_lane_regtest(
            self.header_prefix,
            nonce_start=0,
            nonce_end=31,
            target=0,
            time_budget_seconds=5.0,
        )
        self.assertEqual(report["status"], "exhausted")
        self.assertEqual(report["winner_count"], 0)
        self.assertIsNone(report["receipt"])
        self.assertEqual(report["metrics"]["candidates_checked"], 32)

    def test_invalid_header_and_bounds_rejected(self):
        with self.assertRaisesRegex(RegtestError, "76_bytes"):
            run_four_lane_regtest(b"short", nonce_start=0, nonce_end=1, target=0)
        with self.assertRaisesRegex(RegtestError, "reversed"):
            run_four_lane_regtest(self.header_prefix, nonce_start=2, nonce_end=1, target=0)
        with self.assertRaisesRegex(RegtestError, "uint256"):
            run_four_lane_regtest(self.header_prefix, nonce_start=0, nonce_end=1, target=1 << 256)


if __name__ == "__main__":
    unittest.main()
