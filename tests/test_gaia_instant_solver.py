import json
import math
import tempfile
import unittest
from pathlib import Path

from src.mining.gaia_fabric import (
    CAYLEY_MODULUS,
    PRIMARY_TOTIENT,
    build_lane_plan,
    cayley_position,
    compute_difficulty_stratified_guarantees,
    discrete_divergence,
    hodge_star_sign,
    inverse_route,
    reduced_residues,
    route_ordinal,
    schlafli_cycle,
    select_coprime_stride,
    v5_coordinates,
    verify_arithmetic_fabric,
)
from src.mining.receipt_wallet import verify_wallet
from src.mining.trophy_solver import (
    attempts_for_confidence,
    build_trophy_header,
    mine_trophy_ladder,
    scan_reverse_nonce_range,
    target_for_difficulty,
)
from src.mining.trophy_manifest import audit_manifest_file


class GaiaFabricTests(unittest.TestCase):
    def test_project_modulus_totients(self):
        result = verify_arithmetic_fabric()
        self.assertTrue(result["primary_valid"])
        self.assertTrue(result["compact_valid"])
        self.assertEqual(result["primary_totient_actual"], 28_160)
        self.assertEqual(result["compact_totient_actual"], 440)

    def test_coprime_route_round_trip(self):
        stride = select_coprime_stride(PRIMARY_TOTIENT, "test-seed")
        self.assertEqual(math.gcd(stride, PRIMARY_TOTIENT), 1)
        for ordinal in (0, 1, 2, 439, 28_159, 28_160, 56_321):
            anchor = 1729
            route = route_ordinal(ordinal, anchor, stride)
            self.assertEqual(inverse_route(route, anchor, stride), ordinal)

    def test_cayley_799_visits_all_residues(self):
        positions = {cayley_position(i) for i in range(CAYLEY_MODULUS)}
        self.assertEqual(len(positions), CAYLEY_MODULUS)
        self.assertEqual(cayley_position(CAYLEY_MODULUS), 0)

    def test_v5_origin_and_boundaries(self):
        self.assertEqual(v5_coordinates(312), (0, 0, 0, 0))
        self.assertEqual(v5_coordinates(0), (-2, -2, -2, -2))
        self.assertEqual(v5_coordinates(624), (2, 2, 2, 2))

    def test_schlafli_cycle_and_uniform_zero_divergence(self):
        self.assertEqual(schlafli_cycle(5, 2), (0, 2, 4, 1, 3))
        self.assertEqual(discrete_divergence(5, 2, [1, 1, 1, 1, 1]), (0, 0, 0, 0, 0))

    def test_nonuniform_cycle_divergence_conserves_total_flow(self):
        divergence = discrete_divergence(5, 2, [1, 2, 3, 4, 5])
        self.assertAlmostEqual(sum(divergence), 0.0)
        self.assertNotEqual(divergence, (0, 0, 0, 0, 0))

    def test_hodge_star_sign(self):
        self.assertEqual(hodge_star_sign(4, 1), -1)
        self.assertEqual(hodge_star_sign(4, 2), 1)
        self.assertEqual(hodge_star_sign(3, 1), 1)

    def test_difficulty_bounds_are_labeled_and_consistent(self):
        result = compute_difficulty_stratified_guarantees(4, attempts=32, tail_multiplier=2)
        self.assertEqual(result["expected_trials"], 16)
        self.assertAlmostEqual(result["single_trial_success_probability"], 1 / 16)
        self.assertAlmostEqual(result["geometric_exponential_bound_at_multiplier"], math.exp(-2))
        self.assertEqual(result["regime"], "low")
        self.assertIn("heuristic", result["spectral_bound_status"])
        self.assertGreaterEqual(result["exact_probability_of_at_least_one_solution"], 0.0)

    def test_lane_plan_partitions_without_overlap(self):
        plan = build_lane_plan(100, 200, "lane-seed")
        l1 = plan["lanes"]["L1"]
        l3 = plan["lanes"]["L3"]
        self.assertEqual((l1["start_nonce"], l1["stop_nonce"]), (100, 150))
        self.assertEqual((l3["start_nonce"], l3["stop_nonce"]), (150, 200))
        self.assertEqual(l1["stop_nonce"], l3["start_nonce"])
        self.assertEqual(plan["routing_effect"], "metadata_only_no_nonce_candidates_are_skipped")


class TrophySolverTests(unittest.TestCase):
    def test_difficulty_target_has_exact_probability(self):
        for difficulty in (4, 8, 16):
            target = target_for_difficulty(difficulty)
            self.assertEqual(target + 1, 1 << (256 - difficulty))

    def test_attempt_budget(self):
        self.assertEqual(attempts_for_confidence(4, 0.5), 11)

    def test_trophy_header_is_80_bytes_and_binds_challenge(self):
        first = build_trophy_header("challenge-a", "public-seed", "rules-v1", 1000, "run-a")
        same = build_trophy_header("challenge-a", "public-seed", "rules-v1", 1000, "run-a")
        changed = build_trophy_header("challenge-b", "public-seed", "rules-v1", 1000, "run-a")
        self.assertEqual(len(first), 80)
        self.assertEqual(first, same)
        self.assertNotEqual(first, changed)

    def test_reverse_scanner_returns_independently_valid_candidates(self):
        header = bytes(range(80))
        target = (1 << 256) - 1
        result = scan_reverse_nonce_range(header, target, 10, 20, workers=1, chunk_size=3)
        self.assertEqual(result["attempts"], 10)
        self.assertEqual([c.nonce for c in result["candidates"]], list(range(10, 20)))
        self.assertEqual(result["direction"], "reverse")

    def test_mine_ladder_creates_verified_local_trophies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = mine_trophy_ladder(
                challenge_id="unit-test-challenge",
                seed="public-unit-test-seed",
                min_difficulty=4,
                max_difficulty=5,
                confidence=0.99,
                start_nonce=0,
                max_attempts=3_000,
                workers=1,
                chunk_size=500,
                wallet_id="local:test-wallet",
                ruleset_id="test-ruleset",
                wallet_file=root / "wallet.jsonl",
                manifest_dir=root / "manifests",
                window_seconds=3600,
            )
            self.assertEqual(report["status"], "complete")
            self.assertEqual(report["trophy_count"], 2)
            self.assertTrue(report["shadow_verification"]["L2"])
            self.assertTrue(report["shadow_verification"]["L4"])
            self.assertEqual(report["network_acceptance"], "not_claimed_local_proof_trophies_only")
            wallet_audit = verify_wallet(root / "wallet.jsonl")
            self.assertTrue(wallet_audit["valid"])
            self.assertEqual(wallet_audit["checked"], 2)
            manifests = sorted((root / "manifests").glob("*.json"))
            self.assertEqual(len(manifests), 2)
            self.assertTrue(all(json.loads(path.read_text())["verification"]["network_acceptance"] == "not_claimed" for path in manifests))


if __name__ == "__main__":
    unittest.main()
