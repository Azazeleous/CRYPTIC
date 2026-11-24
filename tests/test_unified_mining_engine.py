import unittest

from src.consensus.hccgn_work import HCCGNWorkHeader, network_hash
from src.mining.unified_engine import (
    PROFILE_FOUR_LANE_SHA256,
    PROFILE_HCCGN_WORK,
    PROFILE_SHA256D_80,
    MiningEngineError,
    UnifiedMiningEngine,
)


class UnifiedMiningEngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = UnifiedMiningEngine()

    def test_registry_exposes_explicit_noninterchangeable_profiles(self):
        self.assertEqual(
            self.engine.profiles(),
            (PROFILE_SHA256D_80, PROFILE_FOUR_LANE_SHA256, PROFILE_HCCGN_WORK),
        )

    def test_sha256d_profile_uses_adaptive_bounded_kernel_and_reverifies(self):
        receipt = self.engine.mine(
            PROFILE_SHA256D_80,
            header=bytes(range(80)),
            target=(1 << 256) - 1,
            start_nonce=0,
            max_attempts=32,
            workers=2,
            chunk_size=8,
        )
        self.assertEqual(receipt.status, "verified_candidate")
        self.assertTrue(receipt.verified)
        self.assertEqual(receipt.attempts, 32)
        self.assertEqual(receipt.metrics["nonce_range"], [0, 32])
        self.assertEqual(receipt.metrics["retained_candidate_count"], 1)
        self.assertEqual(receipt.candidate["nonce"], 0)
        self.assertEqual(receipt.verification["method"], "independent_full_header_sha256d")

    def test_four_lane_profile_uses_disjoint_lane_scheduler_and_reverifies(self):
        receipt = self.engine.mine(
            PROFILE_FOUR_LANE_SHA256,
            header=b"CRYPTIC unified miner",
            target=(1 << 256) - 1,
            start_nonce=100,
            max_attempts=64,
        )
        self.assertEqual(receipt.status, "verified_candidate")
        self.assertTrue(receipt.verified)
        self.assertEqual(receipt.attempts, 64)
        self.assertEqual(receipt.candidate["lane_id"], 0)
        self.assertEqual(receipt.verification["method"], "independent_four_lane_candidate_recompute")

    def test_hccgn_profile_builds_and_independently_verifies_canonical_proof(self):
        network_id = "cryptic-unified-testnet"
        header = HCCGNWorkHeader(
            network_id_hash=network_hash(network_id),
            height=1,
            sequence=1,
            timestamp=1_800_000_000,
            parent_hash=b"\x00" * 32,
            payload_hash=b"\x11" * 32,
            primary_stride=3037,
            compact_stride=5,
            nonce=0,
            target=b"\xff" * 32,
        )
        receipt = self.engine.mine(
            PROFILE_HCCGN_WORK,
            header=header,
            network_id=network_id,
            start_nonce=0,
            max_attempts=8,
        )
        self.assertEqual(receipt.status, "verified_candidate")
        self.assertTrue(receipt.verified)
        self.assertEqual(receipt.attempts, 1)
        self.assertEqual(receipt.verification["method"], "canonical_hccgn_work_v1_proof_verifier")
        self.assertEqual(len(receipt.candidate["proof_hash"]), 64)
        self.assertEqual(receipt.candidate["nonce"], 0)


    def test_hccgn_symplectic_schedule_is_exposed_and_receipted(self):
        network_id = "cryptic-unified-testnet"
        header = HCCGNWorkHeader(
            network_id_hash=network_hash(network_id), height=1, sequence=1,
            timestamp=1_800_000_000, parent_hash=b"\\x00" * 32,
            payload_hash=b"\\x11" * 32, primary_stride=3037,
            compact_stride=5, nonce=0, target=b"\\xff" * 32,
        )
        receipt = self.engine.mine(
            PROFILE_HCCGN_WORK, header=header, network_id=network_id,
            start_nonce=900, max_attempts=17,
            schedule_profile="symplectic-phase-space-v1",
        )
        self.assertTrue(receipt.verified)
        self.assertEqual(receipt.candidate["nonce"], 900)
        self.assertEqual(receipt.metrics["schedule_profile"], "symplectic-phase-space-v1")
        self.assertEqual(receipt.metrics["nonce_end_exclusive"], 917)
        self.assertEqual(receipt.metrics["phase_space"]["candidate_window"], 17)

    def test_symplectic_schedule_rejected_for_other_profiles_and_oversized_windows(self):
        with self.assertRaisesRegex(MiningEngineError, "not_supported_for_mining_profile"):
            self.engine.mine(
                PROFILE_FOUR_LANE_SHA256, header=b"x", target=(1 << 256) - 1,
                max_attempts=1, schedule_profile="symplectic-phase-space-v1",
            )
        network_id = "cryptic-unified-testnet"
        header = HCCGNWorkHeader(
            network_id_hash=network_hash(network_id), height=1, sequence=1,
            timestamp=1_800_000_000, parent_hash=b"\\x00" * 32,
            payload_hash=b"\\x11" * 32, primary_stride=3037,
            compact_stride=5, nonce=0, target=b"\\xff" * 32,
        )
        with self.assertRaisesRegex(MiningEngineError, "symplectic_schedule_parameters_invalid"):
            self.engine.mine(
                PROFILE_HCCGN_WORK, header=header, network_id=network_id,
                max_attempts=10_000_001, schedule_profile="symplectic-phase-space-v1",
            )

    def test_hccgn_exhausted_budget_returns_verified_no_candidate_receipt(self):
        network_id = "cryptic-unified-testnet"
        header = HCCGNWorkHeader(
            network_id_hash=network_hash(network_id),
            height=1,
            sequence=1,
            timestamp=1_800_000_000,
            parent_hash=b"\x00" * 32,
            payload_hash=b"\x11" * 32,
            primary_stride=3037,
            compact_stride=5,
            nonce=0,
            target=b"\x00" * 32,
        )
        receipt = self.engine.mine(
            PROFILE_HCCGN_WORK,
            header=header,
            network_id=network_id,
            start_nonce=0,
            max_attempts=8,
            schedule_profile="symplectic-phase-space-v1",
        )
        self.assertEqual(receipt.status, "no_candidate")
        self.assertTrue(receipt.verified)
        self.assertIsNone(receipt.candidate)
        self.assertEqual(receipt.attempts, 8)
        self.assertEqual(receipt.metrics["termination"], "attempt_budget_exhausted")
        self.assertEqual(receipt.metrics["schedule_profile"], "symplectic-phase-space-v1")

    def test_profile_mismatch_and_unknown_profile_fail_closed(self):
        with self.assertRaises(MiningEngineError):
            self.engine.mine("auto", header=b"ambiguous")
        with self.assertRaises(MiningEngineError):
            self.engine.mine(
                PROFILE_HCCGN_WORK,
                header=b"not-an-hccgn-header",
                network_id="test",
                max_attempts=1,
            )

    def test_attempt_budget_is_mandatory_and_bounded(self):
        with self.assertRaises(MiningEngineError):
            self.engine.mine(
                PROFILE_FOUR_LANE_SHA256,
                header=b"header",
                target=(1 << 256) - 1,
                max_attempts=0,
            )
        with self.assertRaises(MiningEngineError):
            self.engine.mine(
                PROFILE_FOUR_LANE_SHA256,
                header=b"header",
                target=(1 << 256) - 1,
                max_attempts=100_000_001,
            )


if __name__ == "__main__":
    unittest.main()
