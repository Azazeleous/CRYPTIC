import unittest
from src.mining.gaia_fabric import (
    COMPACT_MODULUS, COMPACT_TOTIENT, PRIMARY_MODULUS, PRIMARY_TOTIENT,
    reduced_residues, verify_arithmetic_fabric, v5_coordinates,
    v5_lattice_summary, v5_neighbors, v5_node_id,
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

    def test_invalid_lattice_values_are_rejected(self):
        for value in (-1, 625, True, 1.5):
            with self.assertRaises(ValueError):
                v5_coordinates(value)
        for value in ((0, 0, 0), (0, 0, 0, 3), (0, 0, False, 0)):
            with self.assertRaises(ValueError):
                v5_node_id(value)


if __name__ == "__main__":
    unittest.main()
