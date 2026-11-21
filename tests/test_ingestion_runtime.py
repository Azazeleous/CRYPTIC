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
            schema_id="cryptic.evm-chain-observation.v1",
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
                          ({
                              "chain_id": 1,
                              "genesis_hash": "0x" + "a" * 64,
                              "block_number": index,
                              "block_hash": "0x" + "b" * 64,
                          },), next_cursor)


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

    def test_adapter_preparation_precedes_collection_deadline(self):
        class PreparedAdapter(DeadlineAdapter):
            def __init__(self, source_id):
                super().__init__(source_id)
                self.prepared_at = None
                self.prepared_before_collection = False

            def prepare(self):
                self.prepared_at = time.monotonic()

            def health_check_until(self, *, deadline_monotonic):
                collection_started = deadline_monotonic - 5.0
                self.prepared_before_collection = self.prepared_at is not None and self.prepared_at < collection_started
                if not self.prepared_before_collection:
                    raise RuntimeError("adapter_not_prepared_before_collection")
                return HealthReport(self.descriptor.source_id, True, 1, 1)

        adapter = PreparedAdapter("prepared")
        self.registry.register(adapter)
        policy = IngestionPolicy(max_workers=1, max_queue_size=0, max_pages=1,
                                 max_observations=1, max_page_size=1,
                                 max_duration_seconds=5.0)
        with BoundedIngestionRuntime(self.registry, policy) as runtime:
            report = runtime.run(self.journal, ["prepared"])
        self.assertEqual(report["status"], "complete")
        self.assertTrue(adapter.prepared_before_collection)

    def test_non_waiting_shutdown_closes_adapter_transport(self):
        class ClosableAdapter(DeadlineAdapter):
            def __init__(self, source_id):
                super().__init__(source_id)
                self.closed = False

            def close(self):
                self.closed = True

        adapter = ClosableAdapter("closable")
        self.registry.register(adapter)
        runtime = BoundedIngestionRuntime(self.registry)
        runtime.run(self.journal, ["closable"])
        runtime.close(wait_for_workers=False)
        self.assertTrue(adapter.closed)

    def test_prepared_adapter_count_is_capped_by_submission_window(self):
        class PreparedAdapter(DeadlineAdapter):
            def __init__(self, source_id):
                super().__init__(source_id)
                self.prepare_count = 0
            def prepare(self):
                self.prepare_count += 1
        first, second = PreparedAdapter("first"), PreparedAdapter("second")
        self.registry.register(first)
        self.registry.register(second)
        policy = IngestionPolicy(max_workers=1, max_queue_size=0)
        with BoundedIngestionRuntime(self.registry, policy) as runtime:
            with self.assertRaisesRegex(IngestionRuntimeError, "bounded worker window"):
                runtime.run(self.journal, ["first", "second"])
        self.assertEqual(first.prepare_count, 0)
        self.assertEqual(second.prepare_count, 0)

    def test_prepared_adapter_cap_applies_across_runtime_reuse(self):
        class PreparedAdapter(DeadlineAdapter):
            def __init__(self, source_id):
                super().__init__(source_id)
                self.prepare_count = 0
            def prepare(self):
                self.prepare_count += 1

        first = PreparedAdapter("first-lifetime")
        second = PreparedAdapter("second-lifetime")
        self.registry.register(first)
        self.registry.register(second)
        policy = IngestionPolicy(max_workers=1, max_queue_size=0, max_pages=2,
                                 max_observations=2, max_page_size=1)
        with BoundedIngestionRuntime(self.registry, policy) as runtime:
            runtime.run(self.journal, ["first-lifetime"])
            with self.assertRaisesRegex(IngestionRuntimeError, "prepared adapter leases"):
                runtime.run(self.journal, ["second-lifetime"])
        self.assertEqual(first.prepare_count, 1)
        self.assertEqual(second.prepare_count, 0)

    def test_shared_adapter_is_closed_only_after_last_runtime_releases_it(self):
        class SharedAdapter(DeadlineAdapter):
            def __init__(self, source_id):
                super().__init__(source_id)
                self.closed = False
                self.prepare_count = 0
            def prepare(self):
                self.prepare_count += 1
            def close(self):
                self.closed = True
        adapter = SharedAdapter("shared")
        self.registry.register(adapter)
        first = BoundedIngestionRuntime(self.registry)
        second = BoundedIngestionRuntime(self.registry)
        first.run(self.journal, ["shared"])
        second.run(self.journal, ["shared"])
        self.assertEqual(adapter.prepare_count, 1)
        first.close()
        self.assertFalse(adapter.closed)
        second.close()
        self.assertTrue(adapter.closed)

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
        self.assertEqual(report["sources"][0]["status"], "budget_exhausted")

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


    def test_adapter_timeout_is_reported_as_timed_out(self):
        class TimeoutAdapter(DeadlineAdapter):
            def health_check_until(self, *, deadline_monotonic):
                raise TimeoutError("bounded adapter call timed out")
        self.registry.register(TimeoutAdapter("timeout-source"))
        with BoundedIngestionRuntime(self.registry) as runtime:
            report = runtime.run(self.journal, ["timeout-source"])
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["sources"][0]["status"], "timed_out")
        self.assertEqual(report["sources"][0]["error_kind"], "adapter_timeout")

    def test_rpc_deadline_signal_marks_session_timed_out_not_partial(self):
        class RpcDeadline(TimeoutError):
            deadline_exceeded = True
        class DeadlineSignalingAdapter(DeadlineAdapter):
            def health_check_until(self, *, deadline_monotonic):
                raise RpcDeadline("rpc_deadline_exceeded")
        self.registry.register(DeadlineSignalingAdapter("rpc-deadline"))
        with BoundedIngestionRuntime(self.registry) as runtime:
            report = runtime.run(self.journal, ["rpc-deadline"])
            self.assertEqual(report["status"], "timed_out")
            self.assertEqual(report["sources"][0]["error_kind"], "deadline_exceeded")
            with self.assertRaises(IngestionRuntimeError):
                runtime.run(self.journal, ["rpc-deadline"])

    def test_report_discloses_deadline_scope_and_bounded_submission(self):
        for name in ("a", "b", "c"):
            self.registry.register(DeadlineAdapter(name, delay=0.005))
        policy = IngestionPolicy(max_workers=1, max_queue_size=1, max_pages=3,
                                 max_observations=3, max_page_size=1)
        with BoundedIngestionRuntime(self.registry, policy) as runtime:
            report = runtime.run(self.journal, ["a", "b", "c"])
        self.assertEqual(report["deadline_scope"], "source_collection_only")
        self.assertLessEqual(report["max_in_flight"], policy.max_workers + policy.max_queue_size)
        self.assertIn("collection_elapsed_ms", report)
        self.assertIn("finalization_elapsed_ms", report)
        self.assertIn("total_elapsed_ms", report)


if __name__ == "__main__":
    unittest.main()
