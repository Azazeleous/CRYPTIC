import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.consensus.hccgn_registry import (
    HCCGNActiveTargetPolicy, HCCGNProofStore, HCCGNRegistryError,
    POLICY_DOMAIN, POLICY_SCHEMA, _canonical,
)
from src.consensus.hccgn_work import (
    HCCGNWorkHeader, HCCGNWorkProofProvider, build_proof, network_hash,
)


class HCCGNRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.now = 1_800_000_000
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.target = bytes.fromhex("ff" * 32)
        self.policy = HCCGNActiveTargetPolicy(
            Path(self.temp.name) / "policy.sqlite3",
            trusted_public_key=self.public, trusted_signer_id="GOD-ROOT-1",
            clock=lambda: self.now,
        )
        self.store = HCCGNProofStore(Path(self.temp.name) / "proofs.sqlite3")

    def tearDown(self):
        self.temp.cleanup()

    def signed_policy(self, **overrides):
        body = {
            "schema": POLICY_SCHEMA, "profile_id": "HCCGN-WORK/1",
            "network_id": "gaia-testnet", "sequence": 1,
            "activation_height": 1, "activation_epoch": 1,
            "target": self.target.hex(), "issued_at": self.now - 10,
            "expires_at": self.now + 1000, "signer_id": "GOD-ROOT-1",
        }
        body.update(overrides)
        signature = self.private.sign(POLICY_DOMAIN + _canonical(body))
        return {**body, "signature": base64.b64encode(signature).decode("ascii")}

    def proof(self):
        header = HCCGNWorkHeader(
            network_id_hash=network_hash("gaia-testnet"), height=1, sequence=1,
            timestamp=self.now, parent_hash=bytes.fromhex("11" * 32),
            payload_hash=bytes.fromhex("22" * 32), primary_stride=5,
            compact_stride=7, nonce=42, target=self.target,
        )
        return build_proof(header)

    def test_in_memory_databases_are_rejected_as_non_durable(self):
        with self.assertRaisesRegex(HCCGNRegistryError, "persistent_database_required"):
            HCCGNProofStore(":memory:")
        with self.assertRaisesRegex(HCCGNRegistryError, "persistent_database_required"):
            HCCGNActiveTargetPolicy(":memory:", trusted_public_key=self.public,
                                    trusted_signer_id="GOD-ROOT-1", clock=lambda: self.now)

    def test_proof_store_content_addressed_round_trip_and_integrity(self):
        proof = self.proof()
        digest = self.store.put(proof, inserted_at=self.now)
        self.assertEqual(digest, hashlib.sha256(proof).hexdigest())
        self.assertEqual(self.store.get(digest), proof)
        self.assertIsNone(self.store.get("0" * 64))

    def test_proof_store_is_idempotent(self):
        proof = self.proof()
        self.assertEqual(self.store.put(proof), self.store.put(proof))

    def test_proof_store_enforces_size_bound(self):
        bounded = HCCGNProofStore(Path(self.temp.name) / "small.sqlite3", max_proof_bytes=8)
        with self.assertRaisesRegex(HCCGNRegistryError, "proof_too_large"):
            bounded.put(b"x" * 9)

    def test_signed_target_policy_installs_and_resolves(self):
        self.policy.install(self.signed_policy())
        self.assertEqual(
            self.policy.resolve({"network_id": "gaia-testnet", "height": 1,
                                  "epoch": 1, "issued_at": self.now}),
            self.target,
        )

    def test_target_policy_rejects_invalid_signature(self):
        snapshot = self.signed_policy()
        snapshot["target"] = "00" * 32
        with self.assertRaisesRegex(HCCGNRegistryError, "policy_signature_invalid"):
            self.policy.install(snapshot)

    def test_target_policy_rejects_rollback(self):
        self.policy.install(self.signed_policy(sequence=2))
        with self.assertRaisesRegex(HCCGNRegistryError, "policy_rollback_or_sequence_reuse"):
            self.policy.install(self.signed_policy(sequence=1))

    def test_target_policy_rejects_same_sequence_different_content(self):
        self.policy.install(self.signed_policy())
        altered = self.signed_policy(target="00" * 32)
        with self.assertRaisesRegex(HCCGNRegistryError, "policy_rollback_or_sequence_reuse"):
            self.policy.install(altered)

    def test_policy_does_not_activate_before_height_or_epoch(self):
        self.policy.install(self.signed_policy(activation_height=5, activation_epoch=3))
        self.assertIsNone(self.policy.resolve({
            "network_id": "gaia-testnet", "height": 4, "epoch": 3,
            "issued_at": self.now,
        }))
        self.assertIsNone(self.policy.resolve({
            "network_id": "gaia-testnet", "height": 5, "epoch": 2,
            "issued_at": self.now,
        }))

    def test_policy_expiry_fails_closed(self):
        self.policy.install(self.signed_policy())
        self.now += 2000
        self.assertIsNone(self.policy.resolve({
            "network_id": "gaia-testnet", "height": 1, "epoch": 1,
            "issued_at": self.now - 1500,
        }))

    def test_provider_connects_durable_proof_and_authenticated_target(self):
        proof = self.proof()
        digest = self.store.put(proof)
        self.policy.install(self.signed_policy())
        provider = HCCGNWorkProofProvider(self.store.get, self.policy.resolve)
        proposal = {
            "network_id": "gaia-testnet", "height": 1, "epoch": 1,
            "issued_at": self.now, "parent_hash": "11" * 32,
            "payload_hash": "22" * 32, "proof_hash": digest,
        }
        result = provider.verify_proof_hash(digest, proposal)
        self.assertTrue(result["valid"], result)


if __name__ == "__main__":
    unittest.main()
