import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.consensus.signer_guard import (
    ConsensusSigningError, ConsensusSigningGuard,
)


class ConsensusSigningGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.key = Ed25519PrivateKey.generate()
        self.private = self.key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        self.public = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ).hex()
        self.guard = ConsensusSigningGuard(
            database=Path(self.temp.name) / "signer.sqlite3",
            network_id="gaia-testnet", epoch=1,
            validator_id="validator-a", public_key_hex=self.public,
            sign_bytes=lambda message: self.key.sign(message),
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_gcf2_vote_is_signed_and_exact_retry_reuses_signature(self):
        body = {
            "schema": "GCF/2", "network_id": "gaia-testnet", "epoch": 1,
            "height": 12, "round": 0, "parent_hash": "ab" * 32,
            "vote_type": "PREVOTE", "vote_kind": "NIL",
            "candidate_digest": None, "validator_id": "validator-a",
            "approve": None, "polc_digest": None,
            "issued_at": 1_800_000_000, "expires_at": 1_800_000_060,
        }
        first = self.guard.sign_vote(body, created_at=1_800_000_000)
        second = self.guard.sign_vote(body, created_at=1_800_000_001)
        self.assertEqual(first["signature"], second["signature"])
        self.assertEqual(len(self.guard.slot_status()), 1)
        self.assertTrue(self.guard.slot_status()[0]["signed"])

    def test_gcf1_and_gcf2_cannot_consume_the_same_height_phase_slot(self):
        gcf1 = {
            "schema": "GCF/1", "network_id": "gaia-testnet", "epoch": 1,
            "height": 12, "round": 0, "candidate_digest": "cd" * 32,
            "validator_id": "validator-a", "vote_type": "PREVOTE",
            "approve": True, "polc_digest": None, "issued_at": 1_800_000_000,
        }
        self.guard.sign_vote(gcf1, created_at=1_800_000_000)
        gcf2 = {
            "schema": "GCF/2", "network_id": "gaia-testnet", "epoch": 1,
            "height": 12, "round": 0, "parent_hash": "ab" * 32,
            "vote_type": "PREVOTE", "vote_kind": "NIL",
            "candidate_digest": None, "validator_id": "validator-a",
            "approve": None, "polc_digest": None,
            "issued_at": 1_800_000_000, "expires_at": 1_800_000_060,
        }
        with self.assertRaisesRegex(
            ConsensusSigningError, "consensus_signing_slot_conflict"
        ):
            self.guard.sign_vote(gcf2, created_at=1_800_000_000)

    def test_wrong_provider_signature_is_rejected_and_slot_remains_reserved(self):
        body = {
            "schema": "GCF/1", "network_id": "gaia-testnet", "epoch": 1,
            "height": 13, "round": 0, "candidate_digest": "ef" * 32,
            "validator_id": "validator-a", "vote_type": "PREVOTE",
            "approve": True, "polc_digest": None, "issued_at": 1_800_000_000,
        }
        with self.assertRaisesRegex(
            ConsensusSigningError, "hardware_signing_provider_failed"
        ):
            bad = ConsensusSigningGuard(
                database=Path(self.temp.name) / "bad-provider.sqlite3",
                network_id="gaia-testnet", epoch=1,
                validator_id="validator-a", public_key_hex=self.public,
                sign_bytes=lambda _message: b"\\x00" * 64,
            )
            bad.sign_vote(body, created_at=1_800_000_000)
        self.assertEqual(self.guard.slot_status(), [])


if __name__ == "__main__":
    unittest.main()
