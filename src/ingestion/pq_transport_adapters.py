"""Capability-gated transport adapter registry for PQ-ready CRYPTIC routes.

This module defines the integration boundary only. It deliberately does not
implement ML-KEM, ML-DSA, TLS, or an HTTP/WebRTC client. Production adapters
must delegate cryptography to a vetted implementation of the named standard.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import threading
import time
from typing import Protocol


class AdapterError(RuntimeError):
    """Base class for adapter selection and exchange failures."""


class NoCompatibleAdapter(AdapterError):
    """No registered adapter satisfies every requested security capability."""


class AdapterDeadlineExceeded(AdapterError):
    """The adapter did not complete within the caller's absolute deadline."""


class AdapterProtocolError(AdapterError):
    """The adapter returned an invalid or oversized response."""


@dataclass(frozen=True, slots=True)
class AdapterCapabilities:
    protocols: frozenset[str]
    kem_algorithms: frozenset[str]
    max_request_bytes: int
    max_response_bytes: int
    authenticated: bool
    deadline_enforced: bool
    signature_algorithms: frozenset[str] = frozenset({"ML-DSA-65"})

    def __post_init__(self) -> None:
        if not self.protocols or any(not isinstance(item, str) or not item for item in self.protocols):
            raise ValueError("protocols_must_be_nonempty")
        if (isinstance(self.max_request_bytes, bool) or not isinstance(self.max_request_bytes, int)
                or isinstance(self.max_response_bytes, bool) or not isinstance(self.max_response_bytes, int)
                or self.max_request_bytes <= 0 or self.max_response_bytes <= 0):
            raise ValueError("byte_limits_must_be_positive")
        if not isinstance(self.authenticated, bool) or not isinstance(self.deadline_enforced, bool):
            raise ValueError("security_capabilities_must_be_boolean")
        if any(item not in {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"} for item in self.kem_algorithms):
            raise ValueError("unsupported_kem_identifier")
        if any(item not in {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} for item in self.signature_algorithms):
            raise ValueError("unsupported_signature_identifier")


class TransportAdapter(Protocol):
    adapter_id: str
    capabilities: AdapterCapabilities

    def prepare(self) -> None: ...
    def exchange(self, payload: bytes, *, deadline_monotonic: float) -> bytes: ...
    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class AdapterSelection:
    adapter_id: str
    protocol: str
    kem_algorithm: str
    deadline_enforced: bool
    authenticated: bool
    require_authenticated: bool = True
    require_deadline: bool = True
    signature_algorithm: str | None = "ML-DSA-65"


class AdapterRegistry:
    """Explicitly enrolled adapters; no implicit imports or security downgrade."""

    def __init__(self) -> None:
        self._adapters: dict[str, TransportAdapter] = {}
        self._prepared: set[str] = set()
        self._lock = threading.RLock()

    def register(self, adapter: TransportAdapter) -> None:
        adapter_id = getattr(adapter, "adapter_id", "")
        capabilities = getattr(adapter, "capabilities", None)
        if not isinstance(adapter_id, str) or not adapter_id.strip():
            raise ValueError("adapter_id_required")
        if not isinstance(capabilities, AdapterCapabilities):
            raise ValueError("adapter_capabilities_required")
        with self._lock:
            if adapter_id in self._adapters:
                raise ValueError("adapter_id_already_registered")
            self._adapters[adapter_id] = adapter

    def register_verified(self, adapter: TransportAdapter, signed_manifest: object,
                          trust_store: object) -> None:
        """Enroll only an adapter whose ML-DSA manifest chains to a pinned key."""
        from src.ingestion.pq_adapter_manifest import (
            manifest_matches_adapter,
            verify_signed_adapter_manifest,
        )

        if not verify_signed_adapter_manifest(signed_manifest, trust_store):
            raise ValueError("adapter_manifest_signature_invalid")
        if not manifest_matches_adapter(signed_manifest, adapter):
            raise ValueError("manifest_adapter_mismatch")
        self.register(adapter)

    def unregister(self, adapter_id: str) -> None:
        with self._lock:
            if adapter_id in self._prepared:
                raise AdapterError("prepared_adapter_must_be_closed_before_unregister")
            if adapter_id not in self._adapters:
                raise KeyError("adapter_not_registered")
            del self._adapters[adapter_id]

    def select(
        self,
        *,
        protocol: str,
        kem_algorithm: str = "ML-KEM-768",
        signature_algorithm: str | None = "ML-DSA-65",
        request_bytes: int = 0,
        require_authenticated: bool = True,
        require_deadline: bool = True,
        allowed_adapter_ids: tuple[str, ...] | None = None,
    ) -> AdapterSelection:
        if not protocol:
            raise ValueError("protocol_required")
        if kem_algorithm not in {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}:
            raise ValueError("unsupported_kem_identifier")
        if signature_algorithm is not None and signature_algorithm not in {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}:
            raise ValueError("unsupported_signature_identifier")
        if isinstance(request_bytes, bool) or not isinstance(request_bytes, int) or request_bytes < 0:
            raise ValueError("request_bytes_must_be_nonnegative_integer")

        with self._lock:
            allowed = set(allowed_adapter_ids) if allowed_adapter_ids is not None else None
            candidates = []
            for adapter_id, adapter in self._adapters.items():
                caps = adapter.capabilities
                if allowed is not None and adapter_id not in allowed:
                    continue
                if protocol not in caps.protocols or kem_algorithm not in caps.kem_algorithms:
                    continue
                if signature_algorithm is not None and signature_algorithm not in caps.signature_algorithms:
                    continue
                if request_bytes > caps.max_request_bytes:
                    continue
                if require_authenticated and not caps.authenticated:
                    continue
                if require_deadline and not caps.deadline_enforced:
                    continue
                candidates.append(adapter_id)
            if not candidates:
                raise NoCompatibleAdapter("no_adapter_satisfies_requested_security_profile")
            chosen = sorted(candidates)[0]
            caps = self._adapters[chosen].capabilities
            return AdapterSelection(
                chosen, protocol, kem_algorithm, caps.deadline_enforced, caps.authenticated,
                require_authenticated, require_deadline, signature_algorithm
            )

    def prepare(self, adapter_id: str) -> None:
        with self._lock:
            adapter = self._adapters.get(adapter_id)
            if adapter is None:
                raise KeyError("adapter_not_registered")
            if adapter_id in self._prepared:
                return
            adapter.prepare()
            self._prepared.add(adapter_id)

    def exchange(
        self,
        selection: AdapterSelection,
        payload: bytes,
        *,
        deadline_monotonic: float,
    ) -> bytes:
        if not isinstance(payload, bytes):
            raise TypeError("payload_must_be_bytes")
        if (isinstance(deadline_monotonic, bool)
                or not isinstance(deadline_monotonic, (int, float))
                or not math.isfinite(deadline_monotonic)
                or deadline_monotonic <= 0):
            raise ValueError("absolute_monotonic_deadline_required")
        with self._lock:
            adapter = self._adapters.get(selection.adapter_id)
            if adapter is None:
                raise KeyError("adapter_not_registered")
            caps = adapter.capabilities
            if selection.protocol not in caps.protocols or selection.kem_algorithm not in caps.kem_algorithms:
                raise NoCompatibleAdapter("selection_capabilities_changed")
            if (selection.signature_algorithm is not None
                    and selection.signature_algorithm not in caps.signature_algorithms):
                raise NoCompatibleAdapter("selection_signature_capability_changed")
            # The exchange boundary enforces the secure baseline even if a caller forges
            # an AdapterSelection with weaker optional requirements.
            if not caps.authenticated:
                raise NoCompatibleAdapter("adapter_authentication_requirement_not_met")
            if not caps.deadline_enforced:
                raise NoCompatibleAdapter("adapter_deadline_requirement_not_met")
            if len(payload) > caps.max_request_bytes:
                raise AdapterProtocolError("request_exceeds_adapter_limit")
            if time.monotonic() >= deadline_monotonic:
                raise AdapterDeadlineExceeded("deadline_expired_before_dispatch")
            if selection.adapter_id not in self._prepared:
                raise AdapterError("adapter_must_be_prepared_before_exchange")

        response = adapter.exchange(payload, deadline_monotonic=deadline_monotonic)
        if time.monotonic() >= deadline_monotonic:
            raise AdapterDeadlineExceeded("deadline_expired_during_exchange")
        if not isinstance(response, bytes):
            raise AdapterProtocolError("response_must_be_bytes")
        if len(response) > caps.max_response_bytes:
            raise AdapterProtocolError("response_exceeds_adapter_limit")
        return response

    def close(self, adapter_id: str) -> None:
        with self._lock:
            adapter = self._adapters.get(adapter_id)
            if adapter is None:
                raise KeyError("adapter_not_registered")
            if adapter_id in self._prepared:
                try:
                    adapter.close()
                finally:
                    self._prepared.discard(adapter_id)

    def close_all(self) -> None:
        errors: list[str] = []
        with self._lock:
            for adapter_id in sorted(tuple(self._prepared), reverse=True):
                try:
                    self._adapters[adapter_id].close()
                except Exception:
                    errors.append(adapter_id)
                finally:
                    self._prepared.discard(adapter_id)
        if errors:
            raise AdapterError("adapter_close_failed:" + ",".join(errors))
