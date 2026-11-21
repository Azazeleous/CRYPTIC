"""Bounded, read-only JSON-RPC transport and EVM/Solana identity adapters.

Only explicitly allowlisted read methods are exposed. This module has no
transaction signing, wallet, submission, or state-changing RPC surface.
"""
from __future__ import annotations

from dataclasses import dataclass
import itertools
import math
import re
import time
from typing import Any, Mapping
from threading import Lock
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

from .transport_codec import (
    TransportCodecError,
    canonical_json_bytes,
    decode_json_document,
)

from .supervised_http import (
    SupervisedHttpTransport,
    SupervisedTransportDeadlineExceeded,
    SupervisedTransportError,
)

from .source_registry import (
    HealthReport,
    SourceAdapterError,
    SourceDescriptor,
    SourcePage,
    SourceRegistryError,
)


class JsonRpcError(SourceAdapterError):
    """Sanitized JSON-RPC transport, protocol, or provider error."""


class JsonRpcDeadlineExceeded(TimeoutError):
    """The shared monotonic deadline expired during transport coordination."""

    deadline_exceeded = True


class JsonRpcRemoteError(JsonRpcError):
    """Provider returned a JSON-RPC error object."""

    def __init__(self, code: int, message: str) -> None:
        self.code = code
        super().__init__(f"provider_rpc_error:{code}:{message[:160]}")


@dataclass(frozen=True, slots=True)
class JsonRpcPolicy:
    timeout_seconds: float = 8.0
    max_response_bytes: int = 1_048_576
    max_retries: int = 2
    retry_base_seconds: float = 0.2
    rate_limit_per_minute: int = 30

    def validate(self) -> None:
        if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, (int, float)) or not 0.1 <= self.timeout_seconds <= 30:
            raise SourceRegistryError("timeout_seconds must be between 0.1 and 30")
        if isinstance(self.max_response_bytes, bool) or not isinstance(self.max_response_bytes, int) or not 128 <= self.max_response_bytes <= 8_388_608:
            raise SourceRegistryError("max_response_bytes must be between 128 and 8388608")
        if isinstance(self.max_retries, bool) or not isinstance(self.max_retries, int) or not 0 <= self.max_retries <= 3:
            raise SourceRegistryError("max_retries must be between 0 and 3")
        if isinstance(self.retry_base_seconds, bool) or not isinstance(self.retry_base_seconds, (int, float)) or not 0 <= self.retry_base_seconds <= 2:
            raise SourceRegistryError("retry_base_seconds must be between 0 and 2")
        if isinstance(self.rate_limit_per_minute, bool) or not isinstance(self.rate_limit_per_minute, int) or not 1 <= self.rate_limit_per_minute <= 600:
            raise SourceRegistryError("rate_limit_per_minute must be between 1 and 600")


class _RateGate:
    """Per-client monotonic request spacing; no shared/global scheduler."""

    def __init__(self, per_minute: int) -> None:
        self._interval = 60.0 / per_minute
        self._next_at = 0.0
        self._lock = Lock()

    def wait(self, *, deadline_monotonic: float | None = None) -> None:
        if deadline_monotonic is None:
            with self._lock:
                delay = self._next_at - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                self._next_at = max(time.monotonic(), self._next_at) + self._interval
            return
        remaining = deadline_monotonic - time.monotonic()
        if remaining <= 0 or not self._lock.acquire(timeout=remaining):
            raise JsonRpcDeadlineExceeded("rpc_deadline_exceeded")
        try:
            while True:
                remaining = deadline_monotonic - time.monotonic()
                if remaining <= 0:
                    raise JsonRpcDeadlineExceeded("rpc_deadline_exceeded")
                delay = self._next_at - time.monotonic()
                if delay <= 0:
                    self._next_at = time.monotonic() + self._interval
                    return
                time.sleep(min(delay, remaining))
        finally:
            self._lock.release()


class JsonRpcClient:
    """HTTP JSON-RPC 2.0 client restricted to a caller-supplied method set."""

    _ids = itertools.count(1)

    def __init__(
        self,
        endpoint: str,
        *,
        allowed_methods: frozenset[str],
        policy: JsonRpcPolicy | None = None,
    ) -> None:
        self.policy = policy or JsonRpcPolicy()
        self.policy.validate()
        if not isinstance(endpoint, str) or not endpoint.strip():
            raise SourceRegistryError("JSON-RPC endpoint is required")
        try:
            parsed = urlsplit(endpoint)
            hostname = parsed.hostname
        except ValueError as exc:
            raise SourceRegistryError("JSON-RPC endpoint is malformed") from exc
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and hostname in {"localhost", "127.0.0.1", "::1"}
        ):
            raise SourceRegistryError("JSON-RPC requires HTTPS or loopback HTTP")
        if len(endpoint) > 2_048:
            raise SourceRegistryError("JSON-RPC endpoint exceeds maximum length")
        if not hostname or parsed.username is not None or parsed.password is not None:
            raise SourceRegistryError("JSON-RPC endpoint host is invalid or embeds credentials")
        if parsed.query or parsed.fragment:
            raise SourceRegistryError("JSON-RPC endpoint must not contain query or fragment")
        if not isinstance(allowed_methods, frozenset) or not allowed_methods or any(
            not isinstance(method, str) or method not in _READ_ONLY_METHODS
            for method in allowed_methods
        ):
            raise SourceRegistryError("allowed_methods must contain only approved read-only methods")
        self.endpoint = endpoint
        self.allowed_methods = allowed_methods
        self._rate_gate = _RateGate(self.policy.rate_limit_per_minute)
        self._supervised_transport: SupervisedHttpTransport | None = None

    def prepare(self) -> None:
        """Start the whole-request worker before the collection deadline."""
        if self._supervised_transport is None:
            self._supervised_transport = SupervisedHttpTransport()
        if not self._supervised_transport.healthy:
            raise SupervisedTransportError("worker_unavailable")

    def close(self) -> None:
        if self._supervised_transport is not None:
            self._supervised_transport.close()
            self._supervised_transport = None

    @staticmethod
    def parse_response(payload: bytes, expected_id: int, max_bytes: int) -> Any:
        try:
            document = decode_json_document(payload, max_bytes=max_bytes)
        except TransportCodecError as exc:
            if str(exc) == "payload_too_large":
                raise JsonRpcError("response_size_invalid") from None
            raise JsonRpcError("response_json_invalid") from None
        if not isinstance(document, dict) or document.get("jsonrpc") != "2.0":
            raise JsonRpcError("response_envelope_invalid")
        if document.get("id") != expected_id or isinstance(document.get("id"), bool):
            raise JsonRpcError("response_id_mismatch")
        has_result = "result" in document
        has_error = "error" in document
        if has_result == has_error:
            raise JsonRpcError("response_must_contain_exactly_one_result_or_error")
        if has_error:
            error = document["error"]
            if not isinstance(error, dict):
                raise JsonRpcError("response_error_object_invalid")
            code = error.get("code")
            message = error.get("message")
            if isinstance(code, bool) or not isinstance(code, int) or not isinstance(message, str):
                raise JsonRpcError("response_error_fields_invalid")
            raise JsonRpcRemoteError(code, message)
        return document["result"]

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        # Cold worker startup has its own bounded startup timeout and occurs
        # before the direct request's timeout budget begins.
        if not isinstance(method, str) or method not in self.allowed_methods:
            raise JsonRpcError("rpc_method_not_allowlisted")
        self.prepare()
        return self._call(
            method, params,
            deadline_monotonic=time.monotonic() + self.policy.timeout_seconds,
        )

    def call_until(self, method: str, params: list[Any] | None = None, *,
                   deadline_monotonic: float) -> Any:
        """Execute against a prepared worker and caller-owned absolute deadline."""
        if (isinstance(deadline_monotonic, bool)
                or not isinstance(deadline_monotonic, (int, float))
                or not math.isfinite(deadline_monotonic)):
            raise JsonRpcError("rpc_deadline_invalid")
        if deadline_monotonic <= time.monotonic():
            raise JsonRpcDeadlineExceeded("rpc_deadline_exceeded")
        if self._supervised_transport is None:
            raise JsonRpcError("rpc_transport_not_prepared")
        return self._call(method, params, deadline_monotonic=float(deadline_monotonic))

    def _call(self, method: str, params: list[Any] | None, *,
              deadline_monotonic: float | None) -> Any:
        if deadline_monotonic is None:
            raise JsonRpcError("rpc_deadline_required")
        if not isinstance(method, str) or method not in self.allowed_methods:
            raise JsonRpcError("rpc_method_not_allowlisted")
        if params is None:
            params = []
        if not isinstance(params, list):
            raise JsonRpcError("rpc_params_must_be_array")
        request_id = next(self._ids)
        try:
            body = canonical_json_bytes(
                {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
                max_bytes=65_536,
            )
        except TransportCodecError as exc:
            if str(exc) == "encoded_payload_too_large":
                raise JsonRpcError("request_size_invalid") from None
            raise JsonRpcError("rpc_params_invalid") from None
        if self._supervised_transport is None or not self._supervised_transport.healthy:
            raise JsonRpcError("rpc_transport_not_prepared")
        for attempt in range(self.policy.max_retries + 1):
            self._rate_gate.wait(deadline_monotonic=deadline_monotonic)
            timeout = self.policy.timeout_seconds
            if deadline_monotonic is not None:
                remaining = deadline_monotonic - time.monotonic()
                if remaining <= 0:
                    raise JsonRpcDeadlineExceeded("rpc_deadline_exceeded")
                timeout = min(timeout, remaining)
            try:
                assert self._supervised_transport is not None
                status, payload = self._supervised_transport.request(
                    self.endpoint, body, timeout_seconds=timeout,
                    max_response_bytes=self.policy.max_response_bytes,
                    deadline_monotonic=deadline_monotonic,
                )
                if status != 200:
                    raise HTTPError(self.endpoint, status, "http_status", None, None)
                if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                    raise JsonRpcDeadlineExceeded("rpc_deadline_exceeded")
                return self.parse_response(payload, request_id, self.policy.max_response_bytes)
            except SupervisedTransportDeadlineExceeded:
                raise JsonRpcDeadlineExceeded("rpc_deadline_exceeded") from None
            except HTTPError as exc:
                retryable = exc.code == 429 or 500 <= exc.code <= 599
                if not retryable or attempt >= self.policy.max_retries:
                    raise JsonRpcError(f"http_status:{exc.code}") from None
            except (URLError, TimeoutError, OSError):
                if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                    raise JsonRpcDeadlineExceeded("rpc_deadline_exceeded") from None
                if attempt >= self.policy.max_retries:
                    raise JsonRpcError("transport_unavailable") from None
            if self.policy.retry_base_seconds:
                delay = self.policy.retry_base_seconds * (2 ** attempt)
                if deadline_monotonic is not None:
                    remaining = deadline_monotonic - time.monotonic()
                    if remaining <= 0 or delay >= remaining:
                        raise JsonRpcDeadlineExceeded("rpc_deadline_exceeded")
                time.sleep(delay)
        raise JsonRpcError("transport_retry_exhausted")


_EVM_METHODS = frozenset({"eth_chainId", "eth_blockNumber", "eth_getBlockByNumber"})
_SOLANA_METHODS = frozenset({"getGenesisHash", "getSlot", "getBlockHeight"})
_READ_ONLY_METHODS = _EVM_METHODS | _SOLANA_METHODS


class EvmReadOnlyAdapter:
    """EVM chain identity and finalized-head observation; no write methods."""

    # All deadline-aware calls use the supervised whole-request process.
    deadline_enforced = True

    def __init__(
        self,
        endpoint: str,
        *,
        source_id: str = "evm-rpc",
        policy: JsonRpcPolicy | None = None,
    ) -> None:
        self.descriptor = SourceDescriptor(
            source_id=source_id,
            source_kind="chain_rpc",
            endpoint=endpoint,
            auth_mode="none",
            rate_limit_per_minute=(policy or JsonRpcPolicy()).rate_limit_per_minute,
            max_page_size=1,
            pagination_mode="none",
            schema_id="cryptic.evm-chain-observation.v1",
        )
        self.descriptor.validate()
        self.client = JsonRpcClient(endpoint, allowed_methods=_EVM_METHODS, policy=policy)

    def prepare(self) -> None:
        self.client.prepare()

    def close(self) -> None:
        self.client.close()

    @staticmethod
    def _hex_quantity(value: Any, field: str) -> int:
        if not isinstance(value, str) or not value.startswith("0x") or len(value) < 3:
            raise JsonRpcError(f"{field}_quantity_invalid")
        try:
            number = int(value[2:], 16)
        except ValueError:
            raise JsonRpcError(f"{field}_quantity_invalid") from None
        if number < 0:
            raise JsonRpcError(f"{field}_quantity_invalid")
        return number

    @classmethod
    def _block_fields(cls, block: Any, field: str) -> dict[str, Any]:
        if not isinstance(block, Mapping):
            raise JsonRpcError(f"{field}_block_invalid")
        number = cls._hex_quantity(block.get("number"), f"{field}_number")
        timestamp = cls._hex_quantity(block.get("timestamp"), f"{field}_timestamp")
        block_hash = block.get("hash")
        parent_hash = block.get("parentHash")
        hash_pattern = re.compile(r"^0x[0-9a-fA-F]{64}$")
        if not isinstance(block_hash, str) or not hash_pattern.fullmatch(block_hash):
            raise JsonRpcError(f"{field}_hash_invalid")
        if not isinstance(parent_hash, str) or not hash_pattern.fullmatch(parent_hash):
            raise JsonRpcError(f"{field}_parent_hash_invalid")
        return {
            "number": number,
            "hash": block_hash.lower(),
            "parent_hash": parent_hash.lower(),
            "timestamp": timestamp,
        }

    def observe(self) -> dict[str, Any]:
        chain_id = self._hex_quantity(self.client.call("eth_chainId"), "chain_id")
        genesis = self._block_fields(
            self.client.call("eth_getBlockByNumber", ["0x0", False]),
            "genesis",
        )
        latest = self._block_fields(
            self.client.call("eth_getBlockByNumber", ["latest", False]),
            "latest",
        )
        if genesis["number"] != 0 or latest["number"] < genesis["number"]:
            raise JsonRpcError("block_height_order_invalid")
        return {
            "chain_id": chain_id,
            "genesis_hash": genesis["hash"],
            "block_number": latest["number"],
            "block_hash": latest["hash"],
            "parent_hash": latest["parent_hash"],
            "timestamp": latest["timestamp"],
        }

    def health_check(self) -> HealthReport:
        started = time.monotonic()
        try:
            chain_id = self._hex_quantity(self.client.call("eth_chainId"), "chain_id")
            return HealthReport(
                self.descriptor.source_id, True, int(time.time()),
                latency_ms=max(0, int((time.monotonic() - started) * 1000)),
                reason=f"chain_id:{chain_id}",
            )
        except Exception:
            return HealthReport(self.descriptor.source_id, False, int(time.time()),
                                reason="rpc_unavailable")

    def health_check_until(self, *, deadline_monotonic: float) -> HealthReport:
        started = time.monotonic()
        try:
            chain_id = self._hex_quantity(
                self.client.call_until("eth_chainId", deadline_monotonic=deadline_monotonic),
                "chain_id",
            )
            return HealthReport(
                self.descriptor.source_id, True, int(time.time()),
                latency_ms=max(0, int((time.monotonic() - started) * 1000)),
                reason=f"chain_id:{chain_id}",
            )
        except JsonRpcDeadlineExceeded:
            raise
        except Exception:
            return HealthReport(self.descriptor.source_id, False, int(time.time()), reason="rpc_unavailable")

    def observe_until(self, *, deadline_monotonic: float) -> dict[str, Any]:
        chain_id = self._hex_quantity(
            self.client.call_until("eth_chainId", deadline_monotonic=deadline_monotonic),
            "chain_id",
        )
        genesis = self._block_fields(
            self.client.call_until("eth_getBlockByNumber", ["0x0", False],
                                   deadline_monotonic=deadline_monotonic),
            "genesis",
        )
        latest = self._block_fields(
            self.client.call_until("eth_getBlockByNumber", ["latest", False],
                                   deadline_monotonic=deadline_monotonic),
            "latest",
        )
        if genesis["number"] != 0 or latest["number"] < genesis["number"]:
            raise JsonRpcError("block_height_order_invalid")
        return {
            "chain_id": chain_id, "genesis_hash": genesis["hash"],
            "block_number": latest["number"], "block_hash": latest["hash"],
            "parent_hash": latest["parent_hash"], "timestamp": latest["timestamp"],
        }

    def fetch_page_until(self, *, limit: int, cursor: str | None = None,
                         filters: Mapping[str, Any] | None = None,
                         deadline_monotonic: float) -> SourcePage:
        if limit != 1 or cursor is not None or filters:
            raise SourceRegistryError("EVM identity adapter accepts one unfiltered observation")
        observation = self.observe_until(deadline_monotonic=deadline_monotonic)
        return SourcePage(self.descriptor.source_id, self.descriptor.schema_id,
                          int(time.time()), (observation,), None)

    def fetch_page(self, *, limit: int, cursor: str | None = None, filters: Mapping[str, Any] | None = None) -> SourcePage:
        if limit != 1 or cursor is not None or filters:
            raise SourceRegistryError("EVM identity adapter accepts one unfiltered observation")
        observation = self.observe()
        return SourcePage(
            self.descriptor.source_id, self.descriptor.schema_id, int(time.time()),
            (observation,), None,
        )


class SolanaReadOnlyAdapter:
    """Solana genesis identity and finalized head observation; no write methods."""

    # All deadline-aware calls use the supervised whole-request process.
    deadline_enforced = True

    def __init__(
        self,
        endpoint: str,
        *,
        source_id: str = "solana-rpc",
        policy: JsonRpcPolicy | None = None,
    ) -> None:
        self.descriptor = SourceDescriptor(
            source_id=source_id,
            source_kind="chain_rpc",
            endpoint=endpoint,
            auth_mode="none",
            rate_limit_per_minute=(policy or JsonRpcPolicy()).rate_limit_per_minute,
            max_page_size=1,
            pagination_mode="none",
            schema_id="cryptic.solana-chain-observation.v1",
        )
        self.descriptor.validate()
        self.client = JsonRpcClient(endpoint, allowed_methods=_SOLANA_METHODS, policy=policy)

    def prepare(self) -> None:
        self.client.prepare()

    def close(self) -> None:
        self.client.close()

    def observe(self) -> dict[str, Any]:
        options = [{"commitment": "finalized"}]
        genesis_hash = self.client.call("getGenesisHash")
        slot = self.client.call("getSlot", options)
        block_height = self.client.call("getBlockHeight", options)
        if not isinstance(genesis_hash, str) or not genesis_hash:
            raise JsonRpcError("genesis_hash_invalid")
        for name, value in (("slot", slot), ("block_height", block_height)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise JsonRpcError(f"{name}_invalid")
        return {"genesis_hash": genesis_hash, "slot": slot, "block_height": block_height}

    def health_check(self) -> HealthReport:
        started = time.monotonic()
        try:
            genesis_hash = self.client.call("getGenesisHash")
            if not isinstance(genesis_hash, str) or not genesis_hash:
                raise JsonRpcError("genesis_hash_invalid")
            return HealthReport(
                self.descriptor.source_id, True, int(time.time()),
                latency_ms=max(0, int((time.monotonic() - started) * 1000)),
                reason="genesis_identity_verified",
            )
        except Exception:
            return HealthReport(self.descriptor.source_id, False, int(time.time()),
                                reason="rpc_unavailable")

    def health_check_until(self, *, deadline_monotonic: float) -> HealthReport:
        started = time.monotonic()
        try:
            genesis_hash = self.client.call_until("getGenesisHash",
                                                  deadline_monotonic=deadline_monotonic)
            if not isinstance(genesis_hash, str) or not genesis_hash:
                raise JsonRpcError("genesis_hash_invalid")
            return HealthReport(
                self.descriptor.source_id, True, int(time.time()),
                latency_ms=max(0, int((time.monotonic() - started) * 1000)),
                reason="genesis_identity_verified",
            )
        except JsonRpcDeadlineExceeded:
            raise
        except Exception:
            return HealthReport(self.descriptor.source_id, False, int(time.time()), reason="rpc_unavailable")

    def observe_until(self, *, deadline_monotonic: float) -> dict[str, Any]:
        options = [{"commitment": "finalized"}]
        genesis_hash = self.client.call_until("getGenesisHash",
                                              deadline_monotonic=deadline_monotonic)
        slot = self.client.call_until("getSlot", options,
                                      deadline_monotonic=deadline_monotonic)
        block_height = self.client.call_until("getBlockHeight", options,
                                              deadline_monotonic=deadline_monotonic)
        if not isinstance(genesis_hash, str) or not genesis_hash:
            raise JsonRpcError("genesis_hash_invalid")
        for name, value in (("slot", slot), ("block_height", block_height)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise JsonRpcError(f"{name}_invalid")
        return {"genesis_hash": genesis_hash, "slot": slot, "block_height": block_height}

    def fetch_page_until(self, *, limit: int, cursor: str | None = None,
                         filters: Mapping[str, Any] | None = None,
                         deadline_monotonic: float) -> SourcePage:
        if limit != 1 or cursor is not None or filters:
            raise SourceRegistryError("Solana identity adapter accepts one unfiltered observation")
        observation = self.observe_until(deadline_monotonic=deadline_monotonic)
        return SourcePage(self.descriptor.source_id, self.descriptor.schema_id,
                          int(time.time()), (observation,), None)

    def fetch_page(self, *, limit: int, cursor: str | None = None, filters: Mapping[str, Any] | None = None) -> SourcePage:
        if limit != 1 or cursor is not None or filters:
            raise SourceRegistryError("Solana identity adapter accepts one unfiltered observation")
        observation = self.observe()
        return SourcePage(
            self.descriptor.source_id, self.descriptor.schema_id, int(time.time()),
            (observation,), None,
        )
