"""Tests for canonical chain normalization and source discrepancy reports."""
import copy
import unittest

from src.ingestion.normalization import (
    NormalizationError,
    compare_chain_heads,
    normalize_chain_observation,
    normalize_journal_record,
)


EVM_GENESIS = "0x" + "a" * 64
EVM_HEAD_A = "0x" + "b" * 64
EVM_HEAD_B = "0x" + "c" * 64
SOLANA_GENESIS = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"


def evm(source_id, *, height=100, head_hash=EVM_HEAD_A, genesis=EVM_GENESIS, observed_at=1000):
    return normalize_chain_observation(
        source_id,
        "cryptic.evm-chain-observation.v1",
        observed_at,
        {
            "chain_id": 1,
            "genesis_hash": genesis,
            "block_number": height,
            "block_hash": head_hash,
        },
    )


def solana(source_id, *, height=200, observed_at=1000, genesis=SOLANA_GENESIS):
    return normalize_chain_observation(
        source_id,
        "cryptic.solana-chain-observation.v1",
        observed_at,
        {"genesis_hash": genesis, "slot": 250, "block_height": height},
    )


class ChainNormalizationTests(unittest.TestCase):
    def test_evm_identity_uses_chain_id_and_genesis_hash(self):
        first = evm("provider-a")
        same_network = evm("provider-b", height=101)
        reused_chain_id = evm("provider-c", genesis="0x" + "d" * 64)
        self.assertEqual(first["network_identity"], same_network["network_identity"])
        self.assertNotEqual(first["network_identity"], reused_chain_id["network_identity"])
        self.assertEqual(first["network_family"], "evm")
        self.assertEqual(first["height"], 100)

    def test_solana_identity_uses_genesis_hash(self):
        first = solana("provider-a")
        second = solana("provider-b", height=201)
        different_cluster = solana(
            "provider-c", genesis="4Nd1m7x8vYk8qP2mL9sT6uW3aBcDeFgHjKpQrStUvWxY"
        )
        self.assertEqual(first["network_identity"], second["network_identity"])
        self.assertNotEqual(first["network_identity"], different_cluster["network_identity"])
        self.assertIsNone(first["head_hash"])

    def test_unsupported_schema_and_malformed_identity_fail_closed(self):
        with self.assertRaisesRegex(NormalizationError, "unsupported source schema"):
            normalize_chain_observation("provider-a", "other.schema", 100, {})
        with self.assertRaisesRegex(NormalizationError, "genesis_hash"):
            normalize_chain_observation(
                "provider-a", "cryptic.evm-chain-observation.v1", 100,
                {"chain_id": 1, "block_number": 1, "genesis_hash": "bad", "block_hash": EVM_HEAD_A},
            )

    def test_journal_record_normalizes_one_observation(self):
        record = {
            "schema": "cryptic.raw-observation.v1",
            "source_id": "provider-a",
            "source_schema": "cryptic.evm-chain-observation.v1",
            "observed_at": 1000,
            "items": [{
                "chain_id": 1, "genesis_hash": EVM_GENESIS,
                "block_number": 100, "block_hash": EVM_HEAD_A,
            }],
        }
        normalized = normalize_journal_record(record)
        self.assertEqual(normalized["source_id"], "provider-a")
        self.assertEqual(normalized["height"], 100)

    def test_journal_record_requires_exactly_one_object_item(self):
        record = {
            "schema": "cryptic.raw-observation.v1",
            "source_id": "provider-a",
            "source_schema": "cryptic.evm-chain-observation.v1",
            "observed_at": 1000,
            "items": [],
        }
        with self.assertRaisesRegex(NormalizationError, "exactly one"):
            normalize_journal_record(record)

    def test_height_lag_is_reported_for_same_network(self):
        report = compare_chain_heads([
            evm("provider-a", height=100),
            evm("provider-b", height=104),
        ], max_height_delta=1)
        self.assertTrue(report["valid"])
        self.assertFalse(report["summary"]["consistent"])
        self.assertEqual(report["discrepancies"][0]["kind"], "height_lag")
        self.assertEqual(report["discrepancies"][0]["height_delta"], 4)

    def test_same_height_hash_conflict_is_reported(self):
        report = compare_chain_heads([
            evm("provider-a", height=100, head_hash=EVM_HEAD_A),
            evm("provider-b", height=100, head_hash=EVM_HEAD_B),
        ])
        kinds = [item["kind"] for item in report["discrepancies"]]
        self.assertIn("head_hash_conflict", kinds)

    def test_observation_skew_is_reported_as_skipped_not_disagreement(self):
        report = compare_chain_heads([
            evm("provider-a", observed_at=1000),
            evm("provider-b", observed_at=1100),
        ], max_observation_skew_seconds=10)
        self.assertTrue(report["summary"]["consistent"])
        self.assertEqual(report["summary"]["compared_groups"], 0)
        self.assertEqual(report["skipped_groups"][0]["reason"], "observation_skew_exceeded")

    def test_distinct_networks_are_never_compared(self):
        report = compare_chain_heads([
            evm("provider-a"),
            evm("provider-b", genesis="0x" + "d" * 64, height=1),
        ])
        self.assertEqual(report["summary"]["compared_groups"], 0)
        self.assertEqual(report["summary"]["skipped_group_count"], 2)

    def test_duplicate_source_in_same_network_is_rejected(self):
        with self.assertRaisesRegex(NormalizationError, "duplicate source_id"):
            compare_chain_heads([evm("provider-a"), evm("provider-a", height=101)])

    def test_tampered_normalized_network_identity_is_rejected(self):
        observation = copy.deepcopy(evm("provider-a"))
        observation["network_identity"] = "0" * 64
        with self.assertRaisesRegex(NormalizationError, "does not match genesis"):
            compare_chain_heads([observation, evm("provider-b")])

    def test_comparison_report_is_deterministic(self):
        left = [evm("provider-b", height=102), evm("provider-a", height=100)]
        right = list(reversed(left))
        first = compare_chain_heads(left)
        second = compare_chain_heads(right)
        self.assertEqual(first, second)
        self.assertEqual(len(first["report_digest"]), 64)

    def test_solana_sources_compare_only_with_same_genesis(self):
        report = compare_chain_heads([
            solana("provider-a", height=100),
            solana("provider-b", height=103),
        ], max_height_delta=1)
        self.assertEqual(report["discrepancies"][0]["kind"], "height_lag")


if __name__ == "__main__":
    unittest.main()
