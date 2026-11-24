import unittest
from src.mining.gaia_fabric import (
    COMPACT_MODULUS, COMPACT_TOTIENT, PRIMARY_MODULUS, PRIMARY_TOTIENT,
    reduced_residues, verify_arithmetic_fabric, v5_coordinates,
    v5_lattice_summary, v5_neighbors, v5_node_id, verify_lane_plan, build_lane_plan,
)


class GaiaFabricExtensionTests(unittest.TestCase):
    def test_primary_and_compact_reduced_residue_counts(self):
        self.assertEqual(len(reduced_residues(PRIMARY_MODULUS)), PRIMARY_TOTIENT)
        self.assertEqual(len(reduced_residues(COMPACT_MODULUS)), COMPACT_TOTIENT)
        result = verify_arithmetic_fabric()
        self.assertTrue(result["primary_valid"])
        self.assertTrue(result["compact_valid"])

    def test_v5_node_id_and_coordinates_round_trip_all_nodes(self):
        for node_id in range(625):
            self.assertEqual(v5_node_id(v5_coordinates(node_id)), node_id)

    def test_v5_neighbors_are_symmetric_and_exactly_2000_edges(self):
        directed = 0
        for node_id in range(625):
            neighbors = v5_neighbors(node_id)
            self.assertEqual(len(neighbors), len(set(neighbors)))
            directed += len(neighbors)
            for neighbor in neighbors:
                self.assertIn(node_id, v5_neighbors(neighbor))
        self.assertEqual(directed // 2, 2000)

    def test_v5_lattice_summary_matches_source(self):
        summary = v5_lattice_summary()
        self.assertTrue(summary["verified"])
        self.assertEqual(summary["node_count"], 625)
        self.assertEqual(summary["undirected_edge_count"], 2000)
        self.assertEqual(summary["origin_node_id"], 312)
        self.assertEqual(summary["degree_distribution"],
            {"4": 16, "5": 96, "6": 216, "7": 216, "8": 81})

    def test_four_lane_plan_has_independent_ticket_and_route_verification(self):
        plan = build_lane_plan(100, 1000, "lane-seed-01")
        self.assertTrue(verify_lane_plan(plan, start=100, stop=1000, seed="lane-seed-01")["valid"])
        self.assertEqual(plan["lanes"]["L1"]["start_nonce"], plan["lanes"]["L2"]["start_nonce"])
        self.assertEqual(plan["lanes"]["L3"]["stop_nonce"], plan["lanes"]["L4"]["stop_nonce"])
        damaged = {**plan, "lanes": {key: dict(value) for key, value in plan["lanes"].items()}}
        damaged["lanes"]["L2"]["ticket"] = "0" * 64
        result = verify_lane_plan(damaged, start=100, stop=1000, seed="lane-seed-01")
        self.assertFalse(result["valid"])
        self.assertIn("L2_ticket_or_metadata_mismatch", result["failures"])

    def test_lane_plan_rejects_boolean_bounds_and_empty_seed(self):
        with self.assertRaises(ValueError):
            build_lane_plan(True, 100, "seed")
        with self.assertRaises(ValueError):
            build_lane_plan(0, 100, "")

    def test_invalid_lattice_values_are_rejected(self):
        for value in (-1, 625, True, 1.5):
            with self.assertRaises(ValueError):
                v5_coordinates(value)
        for value in ((0, 0, 0), (0, 0, 0, 3), (0, 0, False, 0)):
            with self.assertRaises(ValueError):
                v5_node_id(value)


if __name__ == "__main__":
    unittest.main()
