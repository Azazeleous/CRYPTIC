"""Tests for pinned ML-DSA-65 signed adapter manifests."""
import unittest
from dataclasses import replace

from src.ingestion.pq_security import MLDSA65
from src.ingestion.pq_transport_adapters import AdapterCapabilities, AdapterRegistry, NoCompatibleAdapter
from src.ingestion.pq_adapter_manifest import (
    AdapterTrustStore,
    manifest_matches_adapter,
    sign_adapter_manifest,
    verify_signed_adapter_manifest,
)


class Adapter:
    def __init__(self, adapter_id="https-main"):
        self.adapter_id = adapter_id
        self.closed = 0
        self.capabilities = AdapterCapabilities(
            protocols=frozenset({"https", "wss"}),
            kem_algorithms=frozenset({"ML-KEM-768"}),
            signature_algorithms=frozenset({"ML-DSA-65"}),
            max_request_bytes=65536,
            max_response_bytes=131072,
            authenticated=True,
            deadline_enforced=True,
        )

    def prepare(self):
        pass

    def exchange(self, payload, *, deadline_monotonic):
        return payload

    def close(self):
        self.closed += 1


class AdapterManifestTests(unittest.TestCase):
    def setUp(self):
        self.signer = MLDSA65.keygen()
        self.trust = AdapterTrustStore()
        self.key_id = self.trust.add(self.signer.public_key)
        self.adapter = Adapter()
        self.signed = sign_adapter_manifest(
            self.adapter,
            signing_secret_key=self.signer.secret_key,
            signer_public_key=self.signer.public_key,
        )

    def test_manifest_signature_verifies_against_pinned_trust_anchor(self):
        self.assertEqual(self.signed.signer_key_id, self.key_id)
        self.assertTrue(verify_signed_adapter_manifest(self.signed, self.trust))
        self.assertTrue(manifest_matches_adapter(self.signed, self.adapter))

    def test_untrusted_signer_is_not_implicitly_trusted(self):
        empty = AdapterTrustStore()
        self.assertFalse(verify_signed_adapter_manifest(self.signed, empty))

    def test_tampered_manifest_is_rejected(self):
        changed = dict(self.signed.manifest)
        changed["max_request_bytes"] += 1
        forged = replace(self.signed, manifest=changed)
        self.assertFalse(verify_signed_adapter_manifest(forged, self.trust))

    def test_tampered_signature_is_rejected(self):
        changed = bytearray(self.signed.signature)
        changed[0] ^= 1
        forged = replace(self.signed, signature=bytes(changed))
        self.assertFalse(verify_signed_adapter_manifest(forged, self.trust))

    def test_revoked_trust_anchor_is_rejected(self):
        self.assertTrue(self.trust.revoke(self.key_id))
        self.assertFalse(verify_signed_adapter_manifest(self.signed, self.trust))

    def test_registry_only_accepts_verified_matching_manifest(self):
        registry = AdapterRegistry()
        registry.register_verified(self.adapter, self.signed, self.trust)
        selected = registry.select(protocol="https")
        self.assertEqual(selected.adapter_id, "https-main")

    def test_registry_invalidates_prepared_adapter_after_signer_revocation(self):
        registry = AdapterRegistry()
        registry.register_verified(self.adapter, self.signed, self.trust)
        registry.prepare(self.adapter.adapter_id)
        self.assertTrue(self.trust.revoke(self.key_id))
        with self.assertRaises(NoCompatibleAdapter):
            registry.select(protocol="https")
        self.assertEqual(self.adapter.closed, 1)
        self.assertFalse(verify_signed_adapter_manifest(self.signed, self.trust))

    def test_revoked_signer_blocks_existing_selection(self):
        import time
        from src.ingestion.pq_transport_adapters import NoCompatibleAdapter

        registry = AdapterRegistry()
        registry.register_verified(self.adapter, self.signed, self.trust)
        selection = registry.select(protocol="https")
        registry.prepare(self.adapter.adapter_id)
        self.assertTrue(self.trust.revoke(self.key_id))
        with self.assertRaises(NoCompatibleAdapter):
            registry.exchange(
                selection, b"request", deadline_monotonic=time.monotonic() + 1
            )
        self.assertEqual(self.adapter.closed, 1)

    def test_registry_rejects_manifest_for_different_adapter(self):
        registry = AdapterRegistry()
        with self.assertRaisesRegex(ValueError, "manifest_adapter_mismatch"):
            registry.register_verified(Adapter("different"), self.signed, self.trust)

    def test_registry_rejects_untrusted_manifest(self):
        registry = AdapterRegistry()
        with self.assertRaisesRegex(ValueError, "manifest_signature_invalid"):
            registry.register_verified(self.adapter, self.signed, AdapterTrustStore())


if __name__ == "__main__":
    unittest.main()
