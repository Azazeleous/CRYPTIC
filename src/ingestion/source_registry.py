"""Read-only source registry and bounded adapter contract.

This module defines local contracts only. It does not configure credentials,
open network connections, or grant write capabilities to registered sources.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from threading import RLock
from typing import Any, Protocol
from urllib.parse import urlsplit


_SOURCE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_ALLOWED_SCHEMES = {"http", "https", "ws", "wss", "file"}
_FORBIDDEN_FILTER_KEY = re.compile(
    r"(secret|password|authorization|api[_-]?key|access[_-]?token)",
    re.IGNORECASE,
)
_AUTH_MODES = {"none", "api_key", "oauth", "device_identity"}
_PAGINATION_MODES = {"none", "cursor", "offset"}
_SOURCE_KINDS = {
    "market_data", "chain_rpc", "exchange", "public_registry",
    "local_file", "device",
}


class SourceRegistryError(ValueError):
    """Invalid source metadata or registry operation."""


class SourceAdapterError(RuntimeError):
    """A registered read-only adapter failed its contract."""


@dataclass(frozen=True, slots=True)
class SourceDescriptor:
    source_id: str
    source_kind: str
    endpoint: str
    auth_mode: str
    rate_limit_per_minute: int
    max_page_size: int
    pagination_mode: str
    schema_id: str
    read_only: bool = True
    enabled: bool = True

    def validate(self) -> None:
        if not isinstance(self.source_id, str) or not _SOURCE_ID.fullmatch(self.source_id):
            raise SourceRegistryError("source_id must be lowercase and URL-safe")
        if self.source_kind not in _SOURCE_KINDS:
            raise SourceRegistryError("unsupported source_kind")
        if not isinstance(self.endpoint, str) or not self.endpoint.strip():
            raise SourceRegistryError("endpoint is required")
        parsed = urlsplit(self.endpoint)
        if parsed.scheme not in _ALLOWED_SCHEMES:
            raise SourceRegistryError("endpoint scheme is not supported")
        if parsed.username is not None or parsed.password is not None:
            raise SourceRegistryError("endpoint must not embed credentials")
        if parsed.query or parsed.fragment:
            raise SourceRegistryError("endpoint must not contain query strings or fragments")
        if parsed.scheme == "file":
            if not parsed.path:
                raise SourceRegistryError("file endpoint requires a path")
        elif not parsed.netloc:
            raise SourceRegistryError("network endpoint requires a host")
        if self.auth_mode not in _AUTH_MODES:
            raise SourceRegistryError("unsupported auth_mode")
        if self.pagination_mode not in _PAGINATION_MODES:
            raise SourceRegistryError("unsupported pagination_mode")
        if isinstance(self.rate_limit_per_minute, bool) or not isinstance(
            self.rate_limit_per_minute, int
        ) or self.rate_limit_per_minute < 1:
            raise SourceRegistryError("rate_limit_per_minute must be a positive integer")
        if isinstance(self.max_page_size, bool) or not isinstance(
            self.max_page_size, int
        ) or not 1 <= self.max_page_size <= 10000:
            raise SourceRegistryError("max_page_size must be between 1 and 10000")
        if not isinstance(self.schema_id, str) or not self.schema_id.strip():
            raise SourceRegistryError("schema_id is required")
        if self.read_only is not True:
            raise SourceRegistryError("only read-only sources may be registered")
        if not isinstance(self.enabled, bool):
            raise SourceRegistryError("enabled must be boolean")


@dataclass(frozen=True, slots=True)
class HealthReport:
    source_id: str
    healthy: bool
    checked_at: int
    latency_ms: int | None = None
    reason: str = "ok"

    def validate(self) -> None:
        if not isinstance(self.source_id, str) or not _SOURCE_ID.fullmatch(self.source_id):
            raise SourceAdapterError("health report source_id is invalid")
        if not isinstance(self.healthy, bool):
            raise SourceAdapterError("health report healthy must be boolean")
        if isinstance(self.checked_at, bool) or not isinstance(self.checked_at, int) or self.checked_at < 0:
            raise SourceAdapterError("health report checked_at must be a non-negative integer")
        if self.latency_ms is not None and (
            isinstance(self.latency_ms, bool) or not isinstance(self.latency_ms, int)
            or self.latency_ms < 0
        ):
            raise SourceAdapterError("health report latency_ms must be non-negative")
        if not isinstance(self.reason, str) or not self.reason:
            raise SourceAdapterError("health report reason is required")


@dataclass(frozen=True, slots=True)
class SourcePage:
    source_id: str
    schema_id: str
    observed_at: int
    items: tuple[Mapping[str, Any], ...]
    next_cursor: str | None = None

    def validate(self, descriptor: SourceDescriptor, requested_limit: int) -> None:
        if self.source_id != descriptor.source_id:
            raise SourceAdapterError("page source_id does not match registered source")
        if self.schema_id != descriptor.schema_id:
            raise SourceAdapterError("page schema_id does not match registered schema")
        if isinstance(self.observed_at, bool) or not isinstance(self.observed_at, int) or self.observed_at < 0:
            raise SourceAdapterError("observed_at must be a non-negative integer")
        if not isinstance(self.items, (tuple, list)) or len(self.items) > requested_limit:
            raise SourceAdapterError("page exceeds requested item bound")
        if any(not isinstance(item, Mapping) for item in self.items):
            raise SourceAdapterError("every page item must be an object")
        if self.next_cursor is not None and (
            not isinstance(self.next_cursor, str) or len(self.next_cursor) > 4096
        ):
            raise SourceAdapterError("next_cursor must be at most 4096 characters")


class SourceAdapter(Protocol):
    """Required adapter surface; implementations must perform reads only."""

    descriptor: SourceDescriptor

    def health_check(self) -> HealthReport:
        """Return a source health observation."""

    def fetch_page(
        self,
        *,
        limit: int,
        cursor: str | None = None,
        filters: Mapping[str, Any] | None = None,
    ) -> SourcePage:
        """Fetch one bounded page without mutating the source."""


class SourceRegistry:
    """Thread-safe in-memory registry for explicitly supplied read-only adapters."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._adapters: dict[str, SourceAdapter] = {}

    def register(self, adapter: SourceAdapter, *, replace: bool = False) -> SourceDescriptor:
        descriptor = getattr(adapter, "descriptor", None)
        if not isinstance(descriptor, SourceDescriptor):
            raise SourceRegistryError("adapter must expose a SourceDescriptor")
        descriptor.validate()
        if not callable(getattr(adapter, "health_check", None)) or not callable(
            getattr(adapter, "fetch_page", None)
        ):
            raise SourceRegistryError("adapter does not implement the read-only contract")
        if not isinstance(replace, bool):
            raise SourceRegistryError("replace must be boolean")
        with self._lock:
            if descriptor.source_id in self._adapters and not replace:
                raise SourceRegistryError("source_id is already registered")
            self._adapters[descriptor.source_id] = adapter
        return descriptor

    def unregister(self, source_id: str) -> bool:
        with self._lock:
            return self._adapters.pop(source_id, None) is not None

    def get_descriptor(self, source_id: str) -> SourceDescriptor:
        with self._lock:
            adapter = self._adapters.get(source_id)
        if adapter is None:
            raise SourceRegistryError("source_id is not registered")
        return adapter.descriptor

    def list_sources(self, *, enabled_only: bool = False) -> tuple[SourceDescriptor, ...]:
        if not isinstance(enabled_only, bool):
            raise SourceRegistryError("enabled_only must be boolean")
        with self._lock:
            descriptors = [item.descriptor for item in self._adapters.values()]
        selected = [item for item in descriptors if not enabled_only or item.enabled]
        return tuple(sorted(selected, key=lambda item: item.source_id))

    def health_check(self, source_id: str) -> HealthReport:
        descriptor = self.get_descriptor(source_id)
        with self._lock:
            adapter = self._adapters[source_id]
        if not descriptor.enabled:
            return HealthReport(source_id, False, 0, reason="source_disabled")
        try:
            report = adapter.health_check()
            if not isinstance(report, HealthReport):
                raise SourceAdapterError("adapter returned an invalid health report")
            report.validate()
            if report.source_id != source_id:
                raise SourceAdapterError("health report source_id mismatch")
            return report
        except Exception as exc:
            if isinstance(exc, SourceAdapterError):
                reason = "adapter_contract_violation"
            else:
                reason = "adapter_health_check_failed"
            return HealthReport(source_id, False, 0, reason=reason)

    def fetch_page(
        self,
        source_id: str,
        *,
        limit: int,
        cursor: str | None = None,
        filters: Mapping[str, Any] | None = None,
    ) -> SourcePage:
        descriptor = self.get_descriptor(source_id)
        if not descriptor.enabled:
            raise SourceRegistryError("source is disabled")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= descriptor.max_page_size:
            raise SourceRegistryError("limit exceeds the registered page-size boundary")
        if descriptor.pagination_mode == "none" and cursor is not None:
            raise SourceRegistryError("cursor is not supported by this source")
        if descriptor.pagination_mode == "cursor" and cursor is not None and (
            not isinstance(cursor, str) or len(cursor) > 4096
        ):
            raise SourceRegistryError("cursor must be at most 4096 characters")
        if descriptor.pagination_mode == "offset":
            raise SourceRegistryError("offset pagination requires an explicit adapter extension")
        if filters is not None:
            if not isinstance(filters, Mapping):
                raise SourceRegistryError("filters must be an object")
            if any(
                not isinstance(key, str) or _FORBIDDEN_FILTER_KEY.search(key)
                for key in filters
            ):
                raise SourceRegistryError("filters must not contain credential fields")
        with self._lock:
            adapter = self._adapters[source_id]
        try:
            page = adapter.fetch_page(limit=limit, cursor=cursor, filters=filters)
        except Exception as exc:
            raise SourceAdapterError("adapter page retrieval failed") from exc
        if not isinstance(page, SourcePage):
            raise SourceAdapterError("adapter returned an invalid page")
        page.validate(descriptor, limit)
        return page
