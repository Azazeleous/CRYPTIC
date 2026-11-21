"""Capability selection, lifecycle, and fail-closed tests for PQ transport adapters."""
import time
import unittest

from src.ingestion.pq_transport_adapters import (
    AdapterCapabilities,
    AdapterDeadlineExceeded,
    AdapterError,
    AdapterProtocolError,
    AdapterRegistry,
    AdapterSelection,
    NoCompatibleAdapter,
)


class FakeAdapter:
    def __init__(self, adapter_id, *, protocols=frozenset({"https"}),
                 kem=frozenset({"ML-KEM-768"}), authenticated=True,
                 deadline_enforced=True, max_request=1024, max_response=1024,
                 delay=0.0, response=b"ok"):
        self.adapter_id = adapter_id
        self.capabilities = AdapterCapabilities(
            protocols=frozenset(protocols),
            kem_algorithms=frozenset(kem),
            max_request_bytes=max_request,
            max_response_bytes=max_response,
            authenticated=authenticated,
            deadline_enforced=deadline_enforced,
        )
        self.delay = delay
        self.response = response
        self.prepared = 0
        self.closed = 0

    def prepare(self):
        self.prepared += 1

    def exchange(self, payload, *, deadline_monotonic):
        if self.delay:
            time.sleep(self.delay)
        return self.response

    def close(self):
        self.closed += 1


class AdapterRegistryTests(unittest.TestCase):
    def test_selection_is_deterministic_and_capability_gated(self):
        registry = AdapterRegistry()
        registry.register(FakeAdapter("z-websocket"))
        registry.register(FakeAdapter("a-https"))
        selected = registry.select(protocol="https", request_bytes=12)
        self.assertEqual(selected.adapter_id, "a-https")
        self.assertEqual(selected.kem_algorithm, "ML-KEM-768")

    def test_no_pq_downgrade_when_kem_capability_is_missing(self):
        registry = AdapterRegistry()
        registry.register(FakeAdapter("classical-only", kem=frozenset()))
        with self.assertRaises(NoCompatibleAdapter):
            registry.select(protocol="https", kem_algorithm="ML-KEM-768")

    def test_authentication_and_deadline_capabilities_are_required(self):
        registry = AdapterRegistry()
        registry.register(FakeAdapter("unauth", authenticated=False))
        registry.register(FakeAdapter("unbounded", deadline_enforced=False))
        with self.assertRaises(NoCompatibleAdapter):
            registry.select(protocol="https")

    def test_explicit_allowlist_prevents_unapproved_fallback(self):
        registry = AdapterRegistry()
        registry.register(FakeAdapter("approved"))
        registry.register(FakeAdapter("other"))
        selected = registry.select(protocol="https", allowed_adapter_ids=("other",))
        self.assertEqual(selected.adapter_id, "other")

    def test_prepare_once_exchange_and_close(self):
        registry = AdapterRegistry()
        adapter = FakeAdapter("https")
        registry.register(adapter)
        selection = registry.select(protocol="https")
        registry.prepare("https")
        registry.prepare("https")
        result = registry.exchange(
            selection, b"request", deadline_monotonic=time.monotonic() + 1.0
        )
        self.assertEqual(result, b"ok")
        self.assertEqual(adapter.prepared, 1)
        registry.close("https")
        self.assertEqual(adapter.closed, 1)

    def test_exchange_requires_preparation(self):
        registry = AdapterRegistry()
        registry.register(FakeAdapter("https"))
        selection = registry.select(protocol="https")
        with self.assertRaisesRegex(AdapterError, "prepared"):
            registry.exchange(selection, b"x", deadline_monotonic=time.monotonic() + 1)

    def test_request_and_response_limits_are_enforced(self):
        registry = AdapterRegistry()
        registry.register(FakeAdapter("small", max_request=2, max_response=2, response=b"long"))
        selection = registry.select(protocol="https", request_bytes=2)
        registry.prepare("small")
        with self.assertRaisesRegex(AdapterProtocolError, "response_exceeds"):
            registry.exchange(selection, b"ok", deadline_monotonic=time.monotonic() + 1)
        with self.assertRaisesRegex(AdapterProtocolError, "request_exceeds"):
            registry.exchange(selection, b"too long", deadline_monotonic=time.monotonic() + 1)

    def test_deadline_is_checked_before_and_after_exchange(self):
        registry = AdapterRegistry()
        adapter = FakeAdapter("slow", delay=0.03)
        registry.register(adapter)
        selection = registry.select(protocol="https")
        registry.prepare("slow")
        with self.assertRaisesRegex(AdapterDeadlineExceeded, "before_dispatch"):
            registry.exchange(selection, b"x", deadline_monotonic=time.monotonic() - 1)
        with self.assertRaisesRegex(AdapterDeadlineExceeded, "during_exchange"):
            registry.exchange(selection, b"x", deadline_monotonic=time.monotonic() + 0.005)

    def test_forged_selection_cannot_bypass_required_capabilities(self):
        registry = AdapterRegistry()
        weak = FakeAdapter("weak", authenticated=False, deadline_enforced=False)
        registry.register(weak)
        registry.prepare("weak")
        forged = AdapterSelection(
            "weak", "https", "ML-KEM-768", False, False, False, False
        )
        with self.assertRaises(NoCompatibleAdapter):
            registry.exchange(
                forged, b"x", deadline_monotonic=time.monotonic() + 1
            )

    def test_prepared_adapter_cannot_be_unregistered(self):
        registry = AdapterRegistry()
        registry.register(FakeAdapter("https"))
        registry.prepare("https")
        with self.assertRaisesRegex(AdapterError, "must_be_closed"):
            registry.unregister("https")
        registry.close("https")
        registry.unregister("https")


if __name__ == "__main__":
    unittest.main()
