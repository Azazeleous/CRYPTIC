"""Tests for the four-lane FGR-ICE SHA-256d regtest."""
import unittest
from unittest.mock import patch

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

    def test_successfully_cancelled_lanes_still_receive_reports(self):
        from src.ingestion.four_lane_regtest import LaneReport

        report_digest = sha256d(self.header_prefix, 0).hex()

        class FakeFuture:
            def __init__(self, lane):
                self.lane = lane
                self._cancelled = False

            def done(self):
                return self.lane == 0

            def result(self, timeout=None):
                return LaneReport(
                    0, "partition-0", 1, 1, 1000.0,
                    "candidate", 0, report_digest,
                )

            def cancel(self):
                self._cancelled = True
                return True

            def cancelled(self):
                return self._cancelled

        class FakeExecutor:
            def __init__(self, max_workers, thread_name_prefix):
                self.futures = []

            def submit(self, fn, lane, *args, **kwargs):
                future = FakeFuture(lane)
                self.futures.append(future)
                return future

            def shutdown(self, wait=True, cancel_futures=False):
                pass

        def fake_wait(pending, timeout=None, return_when=None):
            completed = next(future for future in pending if future.lane == 0)
            return {completed}, set(pending) - {completed}

        with (
            patch("src.ingestion.four_lane_regtest.ThreadPoolExecutor", FakeExecutor),
            patch("src.ingestion.four_lane_regtest.wait", fake_wait),
        ):
            report = run_four_lane_regtest(
                self.header_prefix,
                nonce_start=0,
                nonce_end=100,
                target=(1 << 256) - 1,
                time_budget_seconds=5.0,
            )

        self.assertEqual(report["status"], "accepted")
        self.assertEqual(
            sorted(row["lane_id"] for row in report["lanes"]),
            list(range(LANE_COUNT)),
        )
        self.assertEqual(
            {row["lane_id"]: row["status"] for row in report["lanes"]},
            {0: "candidate", 1: "cancelled", 2: "cancelled", 3: "cancelled"},
        )

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

    def test_experiment_commitment_is_bound_to_header_root_and_receipt(self):
        from src.ingestion.research_commitment import (
            bind_commitment_to_header_prefix,
            compute_experiment_commitment,
        )

        metadata = {"algorithm": "FGR-ICE", "ring": {"n": 256, "q": 3329}}
        commitment = compute_experiment_commitment(metadata)
        prefix = bind_commitment_to_header_prefix(bytes(76), commitment)
        report = run_four_lane_regtest(
            prefix,
            nonce_start=0,
            nonce_end=16,
            target=(1 << 256) - 1,
            time_budget_seconds=5.0,
            experiment_commitment=commitment,
        )
        self.assertEqual(report["status"], "accepted")
        self.assertEqual(report["receipt"]["experiment_commitment"], commitment)
        self.assertEqual(
            report["receipt"]["header_prefix_sha256"],
            __import__("hashlib").sha256(prefix).hexdigest(),
        )

    def test_experiment_commitment_mismatch_is_rejected(self):
        from src.ingestion.research_commitment import compute_experiment_commitment

        commitment = compute_experiment_commitment({"ring": {"n": 256, "q": 3329}})
        with self.assertRaisesRegex(RegtestError, "header_binding_mismatch"):
            run_four_lane_regtest(
                bytes(76),
                nonce_start=0,
                nonce_end=1,
                target=0,
                experiment_commitment=commitment,
            )

    def test_invalid_header_and_bounds_rejected(self):
        with self.assertRaisesRegex(RegtestError, "76_bytes"):
            run_four_lane_regtest(b"short", nonce_start=0, nonce_end=1, target=0)
        with self.assertRaisesRegex(RegtestError, "reversed"):
            run_four_lane_regtest(self.header_prefix, nonce_start=2, nonce_end=1, target=0)
        with self.assertRaisesRegex(RegtestError, "uint256"):
            run_four_lane_regtest(self.header_prefix, nonce_start=0, nonce_end=1, target=1 << 256)


if __name__ == "__main__":
    unittest.main()
