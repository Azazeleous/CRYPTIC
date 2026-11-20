"""Tests for the append-only raw observation journal."""
import json
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from src.ingestion.observation_log import (
    ObservationJournalError,
    append_page,
    audit_journal,
    read_records,
)
from src.ingestion.source_registry import SourceAdapterError, SourceDescriptor, SourcePage


class ObservationJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "observations.jsonl"
        self.descriptor = SourceDescriptor(
            source_id="public-chain-rpc",
            source_kind="chain_rpc",
            endpoint="https://rpc.example.org",
            auth_mode="none",
            rate_limit_per_minute=30,
            max_page_size=10,
            pagination_mode="cursor",
            schema_id="cryptic.chain-observation.v1",
        )

    def tearDown(self):
        self.temp.cleanup()

    def _page(self, observed_at, value, cursor=None):
        return SourcePage(
            source_id=self.descriptor.source_id,
            schema_id=self.descriptor.schema_id,
            observed_at=observed_at,
            items=({"height": value, "status": "observed"},),
            next_cursor=cursor,
        )

    def test_append_and_verify_hash_chain(self):
        first = append_page(self.path, self.descriptor, self._page(100, 12, "opaque-cursor"))
        second = append_page(self.path, self.descriptor, self._page(101, 13))
        report = audit_journal(self.path)
        records = read_records(self.path)

        self.assertTrue(report["valid"])
        self.assertEqual(report["record_count"], 2)
        self.assertEqual(second["sequence"], 2)
        self.assertEqual(records[1]["previous_digest"], first["record_digest"])
        self.assertEqual(report["journal_root"], second["record_digest"])
        self.assertEqual(records[0]["next_cursor_sha256"], __import__("hashlib").sha256(
            b"opaque-cursor"
        ).hexdigest())
        self.assertNotIn("opaque-cursor", self.path.read_text(encoding="utf-8"))

    def test_duplicate_observations_are_preserved_as_distinct_events(self):
        page = self._page(100, 12)
        append_page(self.path, self.descriptor, page)
        append_page(self.path, self.descriptor, page)
        records = read_records(self.path)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["observation_id"], records[1]["observation_id"])
        self.assertNotEqual(records[0]["record_digest"], records[1]["record_digest"])

    def test_tampering_is_detected_and_blocks_future_append(self):
        append_page(self.path, self.descriptor, self._page(100, 12))
        record = json.loads(self.path.read_text(encoding="utf-8"))
        record["items"][0]["height"] = 999
        self.path.write_text(json.dumps(record) + "\n", encoding="utf-8")

        report = audit_journal(self.path)
        self.assertFalse(report["valid"])
        self.assertIn("noncanonical_record", report["error"])
        with self.assertRaisesRegex(ObservationJournalError, "invalid journal"):
            append_page(self.path, self.descriptor, self._page(101, 13))
        with self.assertRaises(ObservationJournalError):
            read_records(self.path)

    def test_truncated_line_fails_closed(self):
        self.path.write_bytes(b'{"partial":true}')
        report = audit_journal(self.path)
        self.assertFalse(report["valid"])
        self.assertIn("missing_newline", report["error"])

    def test_schema_mismatch_is_rejected_before_append(self):
        wrong = SourcePage(
            source_id=self.descriptor.source_id,
            schema_id="other.schema.v1",
            observed_at=100,
            items=({"value": 1},),
        )
        with self.assertRaises(SourceAdapterError):
            append_page(self.path, self.descriptor, wrong)
        self.assertFalse(self.path.exists())

    def test_non_json_payload_is_rejected(self):
        bad = SourcePage(
            source_id=self.descriptor.source_id,
            schema_id=self.descriptor.schema_id,
            observed_at=100,
            items=({"value": float("nan")},),
        )
        with self.assertRaisesRegex(ObservationJournalError, "non-finite"):
            append_page(self.path, self.descriptor, bad)
        self.assertFalse(self.path.exists())

    def test_record_size_limit_is_enforced(self):
        large = SourcePage(
            source_id=self.descriptor.source_id,
            schema_id=self.descriptor.schema_id,
            observed_at=100,
            items=({"payload": "x" * 3000},),
        )
        with self.assertRaisesRegex(ObservationJournalError, "byte limit"):
            append_page(self.path, self.descriptor, large, max_record_bytes=1024)
        self.assertFalse(self.path.exists())

    def test_threaded_writers_produce_contiguous_valid_chain(self):
        pages = [self._page(1000 + index, index) for index in range(8)]
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(
                lambda page: append_page(self.path, self.descriptor, page),
                pages,
            ))
        report = audit_journal(self.path)
        records = read_records(self.path)
        self.assertTrue(report["valid"])
        self.assertEqual(len(records), 8)
        self.assertEqual([item["sequence"] for item in records], list(range(1, 9)))
        self.assertEqual(sorted(item["sequence"] for item in results), list(range(1, 9)))

    def test_private_file_permissions_on_posix(self):
        append_page(self.path, self.descriptor, self._page(100, 12))
        if os.name != "nt":
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
