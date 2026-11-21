"""Bounded, deadline-aware read-only ingestion coordination."""
from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
import hashlib
import json
import math
import re
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol

_ADAPTER_LEASE_LOCK = threading.Lock()
_ADAPTER_LEASES: dict[int, tuple[object, int]] = {}


def _lease_adapter(adapter: object) -> None:
    """Prepare an adapter once and reference-count runtimes sharing it."""
    key = id(adapter)
    with _ADAPTER_LEASE_LOCK:
        current = _ADAPTER_LEASES.get(key)
        prepare = getattr(adapter, "prepare", None)
        if callable(prepare):
            prepare()
        _ADAPTER_LEASES[key] = (adapter, (current[1] + 1) if current and current[0] is adapter else 1)


def _release_adapter(adapter: object) -> None:
    key = id(adapter)
    with _ADAPTER_LEASE_LOCK:
        current = _ADAPTER_LEASES.get(key)
        if current is None or current[0] is not adapter:
            return
        if current[1] > 1:
            _ADAPTER_LEASES[key] = (adapter, current[1] - 1)
            return
        del _ADAPTER_LEASES[key]
        close = getattr(adapter, "close", None)
        if callable(close):
            close()

from .observation_log import append_page, audit_journal
from .replay import replay_journal
from .source_registry import HealthReport, SourceAdapterError, SourceDescriptor, SourcePage, SourceRegistry

_FORBIDDEN_FILTER_KEY = re.compile(r"(secret|password|authorization|api[_-]?key|access[_-]?token)", re.IGNORECASE)


class IngestionRuntimeError(ValueError):
    """Invalid runtime policy, source selection, or session state."""


class IngestionDeadlineExceeded(TimeoutError):
    """A cooperative adapter reached the session deadline."""


class DeadlineAwareAdapter(Protocol):
    """Adapter must bound every blocking operation by the supplied deadline."""
    descriptor: SourceDescriptor
    deadline_enforced: bool

    def health_check_until(self, *, deadline_monotonic: float) -> HealthReport: ...

    def fetch_page_until(
        self, *, limit: int, cursor: str | None = None,
        filters: Mapping[str, object] | None = None,
        deadline_monotonic: float,
    ) -> SourcePage: ...


@dataclass(frozen=True, slots=True)
class IngestionPolicy:
    max_workers: int = 4
    max_queue_size: int = 4
    max_pages: int = 16
    max_observations: int = 256
    max_page_size: int = 32
    max_duration_seconds: float = 30.0
    max_cursor_repeats: int = 1

    def validate(self) -> None:
        bounds = {
            "max_workers": (1, 32), "max_queue_size": (0, 256),
            "max_pages": (1, 4096), "max_observations": (1, 100_000),
            "max_page_size": (1, 10_000), "max_cursor_repeats": (0, 3),
        }
        for field, (low, high) in bounds.items():
            value = getattr(self, field)
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise IngestionRuntimeError(f"{field} must be between {low} and {high}")
        duration = self.max_duration_seconds
        if isinstance(duration, bool) or not isinstance(duration, (int, float)) or not math.isfinite(duration) or not 0.1 <= duration <= 300:
            raise IngestionRuntimeError("max_duration_seconds must be finite and between 0.1 and 300")


@dataclass(frozen=True, slots=True)
class _WorkerResult:
    source_id: str
    health: dict[str, object]
    pages: tuple[SourcePage, ...]
    status: str
    error_kind: str | None
    elapsed_ms: int


def _remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    if value <= 0:
        raise IngestionDeadlineExceeded("session_deadline_exceeded")
    return value


def _worker(adapter: DeadlineAwareAdapter, *, page_quota: int, observation_quota: int,
            page_size: int, filters: Mapping[str, object] | None, deadline: float,
            max_cursor_repeats: int) -> _WorkerResult:
    started = time.monotonic()
    source_id = adapter.descriptor.source_id
    pages: list[SourcePage] = []
    try:
        health = adapter.health_check_until(deadline_monotonic=deadline)
        if not isinstance(health, HealthReport):
            raise SourceAdapterError("invalid_health_report")
        health.validate()
        if health.source_id != source_id:
            raise SourceAdapterError("health_source_mismatch")
        health_data: dict[str, object] = {
            "healthy": health.healthy, "checked_at": health.checked_at,
            "latency_ms": health.latency_ms, "reason": health.reason,
        }
        if not health.healthy:
            return _WorkerResult(source_id, health_data, (), "unhealthy", "health_check_failed",
                                 max(0, int((time.monotonic() - started) * 1000)))
        cursor: str | None = None
        seen: dict[str, int] = {}
        observations = 0
        budget_exhausted = False
        for _ in range(page_quota):
            _remaining(deadline)
            remaining_observations = observation_quota - observations
            if remaining_observations <= 0:
                budget_exhausted = True
                break
            limit = min(page_size, adapter.descriptor.max_page_size, remaining_observations)
            page = adapter.fetch_page_until(
                limit=limit, cursor=cursor, filters=filters,
                deadline_monotonic=deadline,
            )
            _remaining(deadline)
            if not isinstance(page, SourcePage):
                raise SourceAdapterError("invalid_source_page")
            page.validate(adapter.descriptor, limit)
            pages.append(page)
            observations += len(page.items)
            if page.next_cursor is None or not page.items:
                cursor = None
                break
            if adapter.descriptor.pagination_mode == "none":
                raise SourceAdapterError("cursor_not_supported")
            if adapter.descriptor.pagination_mode == "cursor" and len(page.next_cursor) > 4096:
                raise SourceAdapterError("cursor_too_large")
            if adapter.descriptor.pagination_mode == "offset":
                if not page.next_cursor.isdecimal() or int(page.next_cursor) > 2**63 - 1:
                    raise SourceAdapterError("offset_cursor_invalid")
            seen[page.next_cursor] = seen.get(page.next_cursor, 0) + 1
            if seen[page.next_cursor] > max_cursor_repeats:
                raise SourceAdapterError("pagination_cursor_repeated")
            cursor = page.next_cursor
        if cursor is not None:
            budget_exhausted = True
        return _WorkerResult(
            source_id, health_data, tuple(pages),
            "budget_exhausted" if budget_exhausted else "complete",
            "page_or_observation_budget_exhausted" if budget_exhausted else None,
            max(0, int((time.monotonic() - started) * 1000)),
        )
    except IngestionDeadlineExceeded:
        return _WorkerResult(source_id, {"healthy": False, "reason": "deadline_exceeded"},
                             tuple(pages), "timed_out", "deadline_exceeded",
                             max(0, int((time.monotonic() - started) * 1000)))
    except TimeoutError as exc:
        deadline_signal = getattr(exc, "deadline_exceeded", False) is True
        reason = "deadline_exceeded" if deadline_signal else "adapter_timeout"
        return _WorkerResult(source_id, {"healthy": False, "reason": reason},
                             tuple(pages), "timed_out", reason,
                             max(0, int((time.monotonic() - started) * 1000)))
    except Exception as exc:
        return _WorkerResult(source_id, {"healthy": False, "reason": "worker_failed"},
                             tuple(pages), "failed", type(exc).__name__,
                             max(0, int((time.monotonic() - started) * 1000)))


class BoundedIngestionRuntime:
    """Bounded worker coordinator; only its caller thread writes the journal.

    Python cannot forcibly terminate a blocked thread. Network adapters must
    prepare a supervised transport before collection and enforce the shared
    deadline at a process boundary for every blocking network operation.
    """
    def __init__(self, registry: SourceRegistry, policy: IngestionPolicy | None = None) -> None:
        if not isinstance(registry, SourceRegistry):
            raise IngestionRuntimeError("registry must be a SourceRegistry")
        self.registry = registry
        self.policy = policy or IngestionPolicy()
        self.policy.validate()
        self._executor = ThreadPoolExecutor(max_workers=self.policy.max_workers,
                                            thread_name_prefix="cryptic-ingest")
        self._session_lock = threading.Lock()
        self._closed = False
        self._poisoned = False
        self._leased_adapters: dict[int, object] = {}

    def close(self, *, wait_for_workers: bool = True) -> None:
        if not self._closed:
            self._closed = True
            self._executor.shutdown(wait=wait_for_workers, cancel_futures=True)
            # Release only adapters this runtime selected. Shared adapters remain
            # alive until the final runtime releases its lease.
            for adapter in tuple(self._leased_adapters.values()):
                _release_adapter(adapter)
            self._leased_adapters.clear()

    def __enter__(self) -> "BoundedIngestionRuntime":
        if self._closed:
            raise IngestionRuntimeError("runtime is closed")
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close(wait_for_workers=True)

    def _resolve(self, source_ids: Sequence[str]) -> list[DeadlineAwareAdapter]:
        if not isinstance(source_ids, Sequence) or isinstance(source_ids, (str, bytes)):
            raise IngestionRuntimeError("source_ids must be a sequence")
        if not source_ids or len(source_ids) > self.policy.max_pages:
            raise IngestionRuntimeError("source count must be between 1 and max_pages")
        if any(not isinstance(value, str) or not value for value in source_ids):
            raise IngestionRuntimeError("source_ids must contain non-empty strings")
        if len(set(source_ids)) != len(source_ids):
            raise IngestionRuntimeError("source_ids must be unique")
        adapters = []
        for source_id in sorted(source_ids):
            adapter = self.registry.get_adapter(source_id)
            if getattr(adapter, "deadline_enforced", False) is not True:
                raise IngestionRuntimeError(f"source {source_id} lacks enforced deadline capability")
            if not callable(getattr(adapter, "health_check_until", None)) or not callable(
                getattr(adapter, "fetch_page_until", None)
            ):
                raise IngestionRuntimeError(f"source {source_id} lacks deadline-aware adapter methods")
            adapters.append(adapter)

        # Each prepared RPC adapter owns a process and a fixed shared-memory
        # allocation. Cap those resources by the same submission window.
        capacity = self.policy.max_workers + self.policy.max_queue_size
        prepared = [item for item in adapters if callable(getattr(item, "prepare", None))]
        if len(prepared) > capacity:
            raise IngestionRuntimeError("selected prepared adapters exceed bounded worker window")

        # Lease every adapter with lifecycle hooks. Some adapters need cleanup
        # without a separate preparation step; omitting those would leak their
        # transport resources on both waiting and non-waiting shutdown.
        managed = [
            item for item in adapters
            if callable(getattr(item, "prepare", None))
            or callable(getattr(item, "close", None))
        ]
        newly_leased: list[object] = []
        try:
            for adapter in managed:
                key = id(adapter)
                if key not in self._leased_adapters:
                    _lease_adapter(adapter)  # Startup remains before collection_started.
                    self._leased_adapters[key] = adapter
                    newly_leased.append(adapter)
        except Exception:
            for adapter in reversed(newly_leased):
                self._leased_adapters.pop(id(adapter), None)
                _release_adapter(adapter)
            raise
        return adapters

    def run(self, journal_path: str | Path, source_ids: Sequence[str], *,
            page_size: int = 1,
            filters_by_source: Mapping[str, Mapping[str, object]] | None = None) -> dict[str, object]:
        if self._closed:
            raise IngestionRuntimeError("runtime is closed")
        if self._poisoned:
            raise IngestionRuntimeError("runtime cannot be reused after an unresolved deadline timeout")
        if not self._session_lock.acquire(blocking=False):
            raise IngestionRuntimeError("another ingestion session is active")
        try:
            run_started = time.monotonic()
            if isinstance(page_size, bool) or not isinstance(page_size, int) or not 1 <= page_size <= self.policy.max_page_size:
                raise IngestionRuntimeError("page_size exceeds policy bounds")
            adapters = self._resolve(source_ids)
            filters_by_source = filters_by_source or {}
            if not isinstance(filters_by_source, Mapping):
                raise IngestionRuntimeError("filters_by_source must be an object")
            selected = {item.descriptor.source_id for item in adapters}
            if set(filters_by_source) - selected:
                raise IngestionRuntimeError("filters supplied for an unselected source")
            if any(not isinstance(value, Mapping) for value in filters_by_source.values()):
                raise IngestionRuntimeError("each source filter must be an object")
            for source_filters in filters_by_source.values():
                if any(not isinstance(key, str) or _FORBIDDEN_FILTER_KEY.search(key) for key in source_filters):
                    raise IngestionRuntimeError("filters must not contain credential fields")
            before = audit_journal(journal_path)
            if not before["valid"]:
                raise IngestionRuntimeError("refusing to ingest into an invalid journal")

            collection_started = time.monotonic()
            deadline = collection_started + self.policy.max_duration_seconds
            count = len(adapters)
            page_quotas = [self.policy.max_pages // count] * count
            observation_quotas = [self.policy.max_observations // count] * count
            for index in range(self.policy.max_pages % count):
                page_quotas[index] += 1
            for index in range(self.policy.max_observations % count):
                observation_quotas[index] += 1

            capacity = self.policy.max_workers + self.policy.max_queue_size
            submitted: dict[Future[_WorkerResult], str] = {}
            results: dict[str, _WorkerResult] = {}
            next_index = 0
            timed_out = False
            max_in_flight = 0
            while next_index < count or submitted:
                while next_index < count and len(submitted) < capacity:
                    adapter = adapters[next_index]
                    source_id = adapter.descriptor.source_id
                    future = self._executor.submit(
                        _worker, adapter, page_quota=page_quotas[next_index],
                        observation_quota=observation_quotas[next_index], page_size=page_size,
                        filters=filters_by_source.get(source_id), deadline=deadline,
                        max_cursor_repeats=self.policy.max_cursor_repeats,
                    )
                    submitted[future] = source_id
                    max_in_flight = max(max_in_flight, len(submitted))
                    next_index += 1
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                done, _ = wait(tuple(submitted), timeout=remaining, return_when=FIRST_COMPLETED)
                if not done:
                    timed_out = True
                    break
                for future in done:
                    source_id = submitted.pop(future)
                    try:
                        results[source_id] = future.result()
                    except Exception as exc:
                        results[source_id] = _WorkerResult(
                            source_id, {"healthy": False, "reason": "worker_failed"},
                            (), "failed", type(exc).__name__, 0,
                        )
            if any(result.error_kind == "deadline_exceeded" for result in results.values()):
                timed_out = True
            if timed_out:
                if submitted:
                    self._poisoned = True
                for future, source_id in submitted.items():
                    future.cancel()
                    results.setdefault(source_id, _WorkerResult(
                        source_id, {"healthy": False, "reason": "deadline_exceeded"},
                        (), "timed_out", "deadline_exceeded", 0,
                    ))

            collection_finished = time.monotonic()
            finalization_started = collection_finished
            appended: list[dict[str, object]] = []
            for source_id in sorted(results):
                result = results[source_id]
                descriptor = self.registry.get_descriptor(source_id)
                for page_index, page in enumerate(result.pages):
                    if time.monotonic() >= deadline:
                        timed_out = True
                        break
                    position = append_page(journal_path, descriptor, page)
                    appended.append({
                        "source_id": source_id, "page_index": page_index,
                        "sequence": position["sequence"],
                        "observation_id": position["observation_id"],
                        "record_digest": position["record_digest"],
                    })
            after = audit_journal(journal_path)
            replay = replay_journal(journal_path) if after["valid"] else None
            finalization_finished = time.monotonic()
            source_reports = []
            for adapter in adapters:
                source_id = adapter.descriptor.source_id
                result = results.get(source_id)
                source_reports.append({
                    "source_id": source_id,
                    "status": result.status if result else ("timed_out" if timed_out else "not_started"),
                    "health": result.health if result else {"healthy": False, "reason": "not_started"},
                    "page_count": len(result.pages) if result else 0,
                    "observation_count": sum(len(page.items) for page in result.pages) if result else 0,
                    "elapsed_ms": result.elapsed_ms if result else 0,
                    "error_kind": result.error_kind if result else ("deadline_exceeded" if timed_out else None),
                })
            body: dict[str, object] = {
                "schema": "cryptic.ingestion-session.v2",
                "status": "timed_out" if timed_out else (
                    "complete" if all(row["status"] == "complete" for row in source_reports) else "partial"
                ),
                "policy": {
                    "max_workers": self.policy.max_workers, "max_queue_size": self.policy.max_queue_size,
                    "max_pages": self.policy.max_pages, "max_observations": self.policy.max_observations,
                    "max_page_size": self.policy.max_page_size,
                    "max_duration_seconds": self.policy.max_duration_seconds,
                },
                "deadline_scope": "source_collection_only",
                "max_in_flight": max_in_flight,
                "collection_elapsed_ms": max(0, int((collection_finished - collection_started) * 1000)),
                "finalization_elapsed_ms": max(0, int((finalization_finished - finalization_started) * 1000)),
                "total_elapsed_ms": max(0, int((finalization_finished - run_started) * 1000)),
                "sources": source_reports, "appended": appended, "journal": after,
                "replay_digest": replay["replay_digest"] if replay else None,
                "replay_valid": replay["valid"] if replay else False,
                "replay_quality_ok": replay["quality_ok"] if replay else False,
            }
            stable = dict(body)
            stable["sources"] = [
                {key: value for key, value in row.items() if key != "elapsed_ms"}
                for row in source_reports
            ]
            for timing_field in ("collection_elapsed_ms", "finalization_elapsed_ms", "total_elapsed_ms"):
                stable.pop(timing_field, None)
            stable.pop("max_in_flight", None)
            digest = hashlib.sha256(json.dumps(
                stable, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False,
            ).encode("utf-8")).hexdigest()
            return {**body, "session_digest": digest}
        finally:
            self._session_lock.release()
