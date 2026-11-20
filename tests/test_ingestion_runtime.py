"""Tests for bounded ingestion coordination and deterministic journal writes."""
import tempfile
import threading
import time
import unittest
from pathlib import Path

from src.ingestion.observation_log import audit_journal
from src.ingestion.runtime import BoundedIngestionRuntime, IngestionPolicy, IngestionRuntimeError
from src.ingestion.source_registry import HealthReport, SourceDescriptor, SourcePage, SourceRegistry


class DeadlineAdapter:
    deadline_enforced = True

    def __init__(self, source_id, *, delay=0.0, pages=1):
        self.descriptor = SourceDescriptor(
            source_id=source_id, source_kind="public_registry",
            endpoint=f"https://{source_id}.example.org", auth_mode="none",
            rate_limit_per_minute=60, max_page_size=5,
            pagination_mode="cursor" if pages > 1 else "none",
            schema_id="test.record.v1",
        )
        self.delay, self.pages = delay, pages

    def _wait(self, deadline):
        if time.monotonic() + self.delay >= deadline:
            raise TimeoutError("deadline")
        if self.delay:
            time.sleep(self.delay)

    def health_check_until(self, *, deadline_monotonic):
        self._wait(deadline_monotonic)
        return HealthReport(self.descriptor.source_id, True, 1, 1)

    def fetch_page_until(self, *, limit, cursor=None, filters=None, deadline_monotonic):
        self._wait(deadline_monotonic)
        index = int(cursor or "0")
        next_cursor = str(index + 1) if index + 1 < self.pages else None
        return SourcePage(self.descriptor.source_id, self.descriptor.schema_id, 1,
                          ({"source": self.descriptor.source_id, "index": index},), next_cursor)


class LegacyAdapter:
    def __init__(self, source_id):
        self.descriptor = SourceDescriptor(
            source_id=source_id, source_kind="public_registry",
            endpoint=f"https://{source_id}.example.org", auth_mode="none",
            rate_limit_per_minute=60, max_page_size=5, pagination_mode="none",
            schema_id="test.record.v1",
        )

    def health_check(self):
        return HealthReport(self.descriptor.source_id, True, 1)

    def fetch_page(self, *, limit, cursor=None, filters=None):
        return SourcePage(self.descriptor.source_id, self.descriptor.schema_id, 1, ())


class BoundedRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.journal = Path(self.temp.name) / "observations.jsonl"
        self.registry = SourceRegistry()

    def tearDown(self):
        self.temp.cleanup()

    def test_legacy_adapter_is_rejected(self):
        self.registry.register(LegacyAdapter("legacy"))
        with BoundedIngestionRuntime(self.registry) as runtime:
            with self.assertRaisesRegex(IngestionRuntimeError, "deadline capability"):
                runtime.run(self.journal, ["legacy"])

    def test_pagination_and_single_writer_order(self):
        self.registry.register(DeadlineAdapter("beta", pages=2))
        self.registry.register(DeadlineAdapter("alpha", pages=2))
        policy = IngestionPolicy(max_workers=2, max_queue_size=2, max_pages=4,
                                 max_observations=8, max_page_size=2)
        with BoundedIngestionRuntime(self.registry, policy) as runtime:
            report = runtime.run(self.journal, ["beta", "alpha"], page_size=1)
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["journal"]["record_count"], 4)
        self.assertTrue(report["replay_valid"])
        self.assertEqual([row["source_id"] for row in report["appended"]],
                         ["alpha", "alpha", "beta", "beta"])
        self.assertTrue(audit_journal(self.journal)["valid"])

    def test_worker_concurrency_is_bounded(self):
        active, maximum = 0, 0
        lock = threading.Lock()

        class TrackingAdapter(DeadlineAdapter):
            def _wait(self, deadline):
                nonlocal active, maximum
                with lock:
                    active += 1
                    maximum = max(maximum, active)
                try:
                    time.sleep(0.02)
                    if time.monotonic() >= deadline:
                        raise TimeoutError("deadline")
                finally:
                    with lock:
                        active -= 1

        for name in ("a", "b", "c", "d"):
            self.registry.register(TrackingAdapter(name))
        policy = IngestionPolicy(max_workers=2, max_queue_size=2, max_pages=4,
                                 max_observations=4, max_page_size=1)
        with BoundedIngestionRuntime(self.registry, policy) as runtime:
            runtime.run(self.journal, ["a", "b", "c", "d"])
        self.assertLessEqual(maximum, 2)

    def test_page_and_observation_budgets_are_respected(self):
        self.registry.register(DeadlineAdapter("alpha", pages=20))
        policy = IngestionPolicy(max_workers=1, max_queue_size=0, max_pages=2,
                                 max_observations=2, max_page_size=1)
        with BoundedIngestionRuntime(self.registry, policy) as runtime:
            report = runtime.run(self.journal, ["alpha"])
        self.assertLessEqual(report["journal"]["record_count"], 2)
        self.assertLessEqual(report["sources"][0]["observation_count"], 2)

    def test_credential_filters_are_rejected_before_adapter_dispatch(self):
        self.registry.register(DeadlineAdapter("alpha"))
        with BoundedIngestionRuntime(self.registry) as runtime:
            with self.assertRaisesRegex(IngestionRuntimeError, "credential"):
                runtime.run(self.journal, ["alpha"], filters_by_source={"alpha": {"api_key": "x"}})

    def test_duplicate_source_selection_is_rejected(self):
        self.registry.register(DeadlineAdapter("alpha"))
        with BoundedIngestionRuntime(self.registry) as runtime:
            with self.assertRaisesRegex(IngestionRuntimeError, "unique"):
                runtime.run(self.journal, ["alpha", "alpha"])

    def test_session_digest_is_stable_for_identical_source_data(self):
        class StableAdapter(DeadlineAdapter):
            def health_check_until(self, *, deadline_monotonic):
                return HealthReport(self.descriptor.source_id, True, 1, 1)

            def fetch_page_until(self, *, limit, cursor=None, filters=None, deadline_monotonic):
                return SourcePage(self.descriptor.source_id, self.descriptor.schema_id, 1,
                                  ({"value": 7},), None)
        first_registry, second_registry = SourceRegistry(), SourceRegistry()
        first_registry.register(StableAdapter("stable"))
        second_registry.register(StableAdapter("stable"))
        policy = IngestionPolicy(max_workers=1, max_queue_size=0, max_pages=1,
                                 max_observations=1, max_page_size=1)
        with BoundedIngestionRuntime(first_registry, policy) as runtime:
            first = runtime.run(self.journal, ["stable"])
        second_path = Path(self.temp.name) / "second.jsonl"
        with BoundedIngestionRuntime(second_registry, policy) as runtime:
            second = runtime.run(second_path, ["stable"])
        self.assertEqual(first["session_digest"], second["session_digest"])

    def test_policy_rejects_unbounded_values(self):
        with self.assertRaisesRegex(IngestionRuntimeError, "max_workers"):
            IngestionPolicy(max_workers=0).validate()
        with self.assertRaisesRegex(IngestionRuntimeError, "max_duration_seconds"):
            IngestionPolicy(max_duration_seconds=float("inf")).validate()


if __name__ == "__main__":
    unittest.main()
