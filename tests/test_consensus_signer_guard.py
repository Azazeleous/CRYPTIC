import base64
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
        self.tmp = tempfile.TemporaryDirectory()
        self.private = Ed25519PrivateKey.generate()
        self.private_hex = self.private.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ).hex()
        self.public_hex = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ).hex()
        self.calls = []
        def provider(payload):
            self.calls.append(payload)
            return self.private.sign(payload)
        self.guard = ConsensusSigningGuard(
            database=Path(self.tmp.name) / "signer.sqlite3",
            network_id="gaia-testnet", epoch=1, validator_id="v0",
            public_key_hex=self.public_hex, sign_bytes=provider,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def vote(self, *, schema="GCF/1", round_number=0, candidate="11" * 32):
        body = {
            "schema": schema, "network_id": "gaia-testnet", "epoch": 1,
            "height": 12, "round": round_number, "vote_type": "PREVOTE",
            "validator_id": "v0", "candidate_digest": candidate,
            "approve": True, "polc_digest": None,
        }
        if schema == "GCF/2":
            body.update({
                "vote_kind": "CANDIDATE", "parent_hash": "22" * 32,
                "issued_at": 100, "expires_at": 200,
            })
        return body

    def test_same_vote_retry_returns_persisted_signature_without_resigning(self):
        first = self.guard.sign_vote(self.vote(), created_at=100)
        second = self.guard.sign_vote(self.vote(), created_at=101)
        self.assertEqual(first, second)
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(self.guard.slot_status()[0]["signed"])

    def test_cross_version_double_signing_same_logical_slot_is_rejected(self):
        self.guard.sign_vote(self.vote(schema="GCF/1"), created_at=100)
        with self.assertRaisesRegex(ConsensusSigningError, "consensus_signing_slot_conflict"):
            self.guard.sign_vote(
                self.vote(schema="GCF/2"), created_at=101,
            )

    def test_same_candidate_can_be_signed_again_in_a_higher_round(self):
        self.guard.sign_vote(self.vote(round_number=0), created_at=100)
        second = self.guard.sign_vote(
            self.vote(round_number=1), created_at=101,
        )
        self.assertEqual(second["round"], 1)
        self.assertEqual(len(self.guard.slot_status()), 2)

    def test_different_candidate_still_requires_proof_bound_transition(self):
        self.guard.sign_vote(self.vote(round_number=0), created_at=100)
        with self.assertRaisesRegex(
            ConsensusSigningError, "consensus_candidate_lock_transition_unauthorized"
        ):
            self.guard.sign_vote(
                self.vote(round_number=1, candidate="33" * 32), created_at=101,
            )

    def test_failed_hsm_attempt_reserves_exact_payload_and_blocks_equivocation(self):
        calls = 0
        def failing_provider(payload):
            nonlocal calls
            calls += 1
            raise RuntimeError("provider unavailable")
        guard = ConsensusSigningGuard(
            database=Path(self.tmp.name) / "failure.sqlite3",
            network_id="gaia-testnet", epoch=1, validator_id="v0",
            public_key_hex=self.public_hex, sign_bytes=failing_provider,
        )
        with self.assertRaisesRegex(ConsensusSigningError, "hardware_signing_provider_failed"):
            guard.sign_vote(self.vote(), created_at=100)
        with self.assertRaisesRegex(ConsensusSigningError, "consensus_signing_slot_conflict"):
            guard.sign_vote(self.vote(candidate="33" * 32), created_at=101)
        self.assertEqual(calls, 1)

    def test_provider_signature_is_cryptographically_checked(self):
        guard = ConsensusSigningGuard(
            database=Path(self.tmp.name) / "bad-provider.sqlite3",
            network_id="gaia-testnet", epoch=1, validator_id="v0",
            public_key_hex=self.public_hex, sign_bytes=lambda _payload: b"\x00" * 64,
        )
        with self.assertRaisesRegex(ConsensusSigningError, "hardware_signing_provider_failed"):
            guard.sign_vote(self.vote(), created_at=100)


if __name__ == "__main__":
    unittest.main()
