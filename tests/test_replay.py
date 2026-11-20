"""Tests for deterministic replay and data-quality reports."""
import json
import tempfile
import unittest
from pathlib import Path

from src.ingestion.observation_log import append_page
from src.ingestion.replay import replay_journal
from src.ingestion.source_registry import SourceDescriptor, SourcePage


GENESIS = "0x" + "a" * 64
HEAD_A = "0x" + "b" * 64
HEAD_B = "0x" + "c" * 64


def descriptor(source_id, schema="cryptic.evm-chain-observation.v1"):
    return SourceDescriptor(
        source_id=source_id,
        source_kind="chain_rpc",
        endpoint=f"https://{source_id}.example.org",
        auth_mode="none",
        rate_limit_per_minute=30,
        max_page_size=1,
        pagination_mode="none",
        schema_id=schema,
    )


def evm_page(source, observed_at, height, head_hash=HEAD_A):
    return SourcePage(
        source_id=source,
        schema_id="cryptic.evm-chain-observation.v1",
        observed_at=observed_at,
        items=({
            "chain_id": 1,
            "genesis_hash": GENESIS,
            "block_number": height,
            "block_hash": head_hash,
        },),
    )


class DeterministicReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.journal = self.root / "observations.jsonl"

    def tearDown(self):
        self.temp.cleanup()

    def test_replay_is_deterministic_and_read_only(self):
        append_page(self.journal, descriptor("provider-a"), evm_page("provider-a", 1000, 100))
        append_page(self.journal, descriptor("provider-b"), evm_page("provider-b", 1001, 100))
        before = self.journal.read_bytes()

        first = replay_journal(self.journal)
        second = replay_journal(self.journal)

        self.assertEqual(first, second)
        self.assertTrue(first["valid"])
        self.assertTrue(first["quality_ok"])
        self.assertEqual(first["summary"]["normalized_count"], 2)
        self.assertTrue(first["summary"]["evidence_sufficient"])
        self.assertEqual(before, self.journal.read_bytes())

    def test_cross_source_height_discrepancy_survives_replay(self):
        append_page(self.journal, descriptor("provider-a"), evm_page("provider-a", 1000, 100))
        append_page(self.journal, descriptor("provider-b"), evm_page("provider-b", 1002, 106))
        report = replay_journal(self.journal, max_height_delta=1)
        self.assertTrue(report["valid"])
        self.assertFalse(report["quality_ok"])
        self.assertEqual(report["summary"]["discrepancy_count"], 1)
        self.assertEqual(report["discrepancy_report"]["discrepancies"][0]["kind"], "height_lag")

    def test_latest_observation_per_source_is_used_for_comparison(self):
        append_page(self.journal, descriptor("provider-a"), evm_page("provider-a", 1000, 100))
        append_page(self.journal, descriptor("provider-a"), evm_page("provider-a", 1001, 105))
        append_page(self.journal, descriptor("provider-b"), evm_page("provider-b", 1002, 105))
        report = replay_journal(self.journal)
        self.assertEqual(report["summary"]["normalized_count"], 3)
        self.assertEqual(report["summary"]["comparison_count"], 2)
        self.assertEqual(report["summary"]["discrepancy_count"], 0)

    def test_duplicate_observations_are_warnings_not_deleted(self):
        page = evm_page("provider-a", 1000, 100)
        append_page(self.journal, descriptor("provider-a"), page)
        append_page(self.journal, descriptor("provider-a"), page)
        report = replay_journal(self.journal)
        self.assertTrue(report["valid"])
        self.assertFalse(report["quality_ok"])
        self.assertEqual(report["summary"]["record_count"], 2)
        self.assertEqual(report["summary"]["warning_count"], 1)
        self.assertEqual(report["warnings"][0]["kind"], "duplicate_observation")

    def test_source_timestamp_regression_is_reported(self):
        append_page(self.journal, descriptor("provider-a"), evm_page("provider-a", 1001, 100))
        append_page(self.journal, descriptor("provider-a"), evm_page("provider-a", 999, 101))
        report = replay_journal(self.journal)
        self.assertTrue(report["valid"])
        self.assertEqual(report["warnings"][0]["kind"], "source_timestamp_regression")

    def test_unsupported_source_schema_is_an_issue_not_silently_dropped(self):
        custom = descriptor("custom-source", "custom.observation.v1")
        page = SourcePage(
            source_id="custom-source",
            schema_id="custom.observation.v1",
            observed_at=1000,
            items=({"value": "preserved"},),
        )
        append_page(self.journal, custom, page)
        report = replay_journal(self.journal)
        self.assertFalse(report["valid"])
        self.assertFalse(report["quality_ok"])
        self.assertEqual(report["summary"]["record_count"], 1)
        self.assertEqual(report["summary"]["normalized_count"], 0)
        self.assertEqual(report["issues"][0]["kind"], "normalization_error")

    def test_tampered_journal_fails_closed(self):
        append_page(self.journal, descriptor("provider-a"), evm_page("provider-a", 1000, 100))
        record = json.loads(self.journal.read_text(encoding="utf-8"))
        record["items"][0]["block_number"] = 999
        self.journal.write_text(json.dumps(record) + "\n", encoding="utf-8")
        report = replay_journal(self.journal)
        self.assertFalse(report["valid"])
        self.assertFalse(report["quality_ok"])
        self.assertEqual(report["summary"]["issue_count"], 1)
        self.assertEqual(report["issues"][0]["kind"], "journal_integrity_failure")
        self.assertIsNone(report["discrepancy_report"])

    def test_empty_journal_reports_insufficient_evidence(self):
        report = replay_journal(self.journal)
        self.assertTrue(report["valid"])
        self.assertFalse(report["quality_ok"])
        self.assertFalse(report["summary"]["evidence_sufficient"])
        self.assertEqual(report["summary"]["record_count"], 0)


if __name__ == "__main__":
    unittest.main()
