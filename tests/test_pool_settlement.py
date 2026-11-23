import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.consensus.pool_ledger import PoolShareLedger
from src.consensus.pool_settlement import (
    INTERNAL_ASSET, POLICY_DOMAIN, POLICY_SCHEMA, PoolSettlementError,
    PoolSettlementLedger, _canonical,
)


class PoolSettlementLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.now = 1_900_000_000
        self.share_ledger = PoolShareLedger(self.root / "shares.sqlite3")
        self.policy_private = Ed25519PrivateKey.generate()
        self.policy_private_hex = self.policy_private.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ).hex()
        self.policy_public_hex = self.policy_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ).hex()
        self.proposal = {
            "schema": "GCF/1", "network_id": "hccgn-test", "epoch": 4,
            "height": 27, "round": 0, "parent_hash": "11" * 32,
            "payload_hash": "22" * 32, "proof_hash": "33" * 32,
            "justice_commitment": {}, "issued_at": self.now - 30,
            "expires_at": self.now + 300, "proposer_id": "validator-a",
            "proposer_public_key": "44" * 32, "nonce": "ab" * 16,
            "signature": "fixture",
        }
        self.certificate = {
            "schema": "GCF/1", "network_id": "hccgn-test", "epoch": 4,
            "height": 27, "round": 0,
            "candidate_digest": hashlib.sha256(_canonical(self.proposal)).hexdigest(),
            "proposal": self.proposal,
        }
        self.certificate_digest = hashlib.sha256(
            b"GCF/1|FINALITY-CERTIFICATE\x00" + _canonical(self.certificate)
        ).hexdigest()
        self.finality = {
            "finalized": True, "certificate": self.certificate,
            "certificate_digest": self.certificate_digest,
        }
        self.share = {
            "accepted": True, "share_id": "55" * 32,
            "network_id": "hccgn-test", "pool_id": "gaia-pool",
            "job_id": "66" * 16, "worker_id": "worker-1",
            "proof_hash": "33" * 32, "work_digest": "77" * 32,
            "nonce": 9, "accepted_at": self.now - 5,
        }
        self.share_ledger.record_accepted_share(self.share)
        self.settlement = PoolSettlementLedger(
            database=self.root / "settlements.sqlite3",
            share_ledger=self.share_ledger,
            trusted_reward_policy_public_key_hex=self.policy_public_hex,
            verify_finality_certificate=self.verify_certificate,
            clock=lambda: self.now,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def verify_certificate(self, certificate, proposal):
        return {
            "valid": (
                certificate["schema"] == "GCF/1"
                and certificate["candidate_digest"] ==
                    hashlib.sha256(_canonical(proposal)).hexdigest()
            )
        }

    def reward_policy(self, *, reward_units=25, max_total_credits=100):
        body = {
            "schema": POLICY_SCHEMA, "policy_id": "internal-reward-v1",
            "network_id": "hccgn-test", "epoch": 4,
            "effective_height_start": 20, "effective_height_end": 40,
            "reward_units": reward_units, "max_total_credits": max_total_credits,
            "asset": INTERNAL_ASSET, "issuer_id": "governance-reward-root",
            "issued_at": self.now - 100, "expires_at": self.now + 1000,
        }
        signature = self.policy_private.sign(POLICY_DOMAIN + _canonical(body))
        return {**body, "signature": base64.b64encode(signature).decode("ascii")}

    def test_settlement_requires_verified_finality_and_exact_proof_share(self):
        result = self.settlement.settle_finalized_block(
            finality=self.finality, reward_policy=self.reward_policy(),
            pool_id="gaia-pool",
        )
        self.assertTrue(result["settled"])
        self.assertFalse(result["replayed"])
        self.assertEqual(result["worker_id"], "worker-1")
        self.assertEqual(result["credit_units"], 25)
        self.assertEqual(result["asset"], INTERNAL_ASSET)
        self.assertTrue(self.settlement.verify_chain())

    def test_exact_settlement_retry_is_idempotent(self):
        first = self.settlement.settle_finalized_block(
            finality=self.finality, reward_policy=self.reward_policy(),
            pool_id="gaia-pool",
        )
        second = self.settlement.settle_finalized_block(
            finality=self.finality, reward_policy=self.reward_policy(),
            pool_id="gaia-pool",
        )
        self.assertFalse(first["replayed"])
        self.assertTrue(second["replayed"])
        self.assertEqual(first["event_hash"], second["event_hash"])

    def test_settlement_rejects_unverified_finality(self):
        self.settlement.verify_finality_certificate = lambda *_: {"valid": False}
        with self.assertRaisesRegex(PoolSettlementError, "finality_certificate_not_verified"):
            self.settlement.settle_finalized_block(
                finality=self.finality, reward_policy=self.reward_policy(),
                pool_id="gaia-pool",
            )

    def test_settlement_rejects_policy_tampering(self):
        policy = self.reward_policy()
        policy["reward_units"] = 26
        with self.assertRaisesRegex(PoolSettlementError, "reward_policy_signature_invalid"):
            self.settlement.settle_finalized_block(
                finality=self.finality, reward_policy=policy, pool_id="gaia-pool",
            )

    def test_settlement_rejects_missing_or_different_proof_share(self):
        self.proposal["proof_hash"] = "88" * 32
        self.certificate["candidate_digest"] = hashlib.sha256(
            _canonical(self.proposal)
        ).hexdigest()
        self.certificate_digest = hashlib.sha256(
            b"GCF/1|FINALITY-CERTIFICATE\x00" + _canonical(self.certificate)
        ).hexdigest()
        finality = {
            "finalized": True, "certificate": self.certificate,
            "certificate_digest": self.certificate_digest,
        }
        with self.assertRaisesRegex(
            PoolSettlementError, "finalized_proof_has_no_unique_accepted_pool_share"
        ):
            self.settlement.settle_finalized_block(
                finality=finality, reward_policy=self.reward_policy(),
                pool_id="gaia-pool",
            )

    def test_reward_policy_credit_cap_is_enforced(self):
        policy = self.reward_policy(reward_units=25, max_total_credits=25)
        self.settlement.settle_finalized_block(
            finality=self.finality, reward_policy=policy, pool_id="gaia-pool",
        )
        second_share = {
            **self.share, "share_id": "aa" * 32,
            "proof_hash": "99" * 32, "work_digest": "bb" * 32,
            "nonce": 10,
        }
        self.share_ledger.record_accepted_share(second_share)
        self.proposal["height"] = 28
        self.proposal["proof_hash"] = "99" * 32
        self.certificate["height"] = 28
        self.certificate["candidate_digest"] = hashlib.sha256(
            _canonical(self.proposal)
        ).hexdigest()
        self.certificate["proposal"] = self.proposal
        digest = hashlib.sha256(
            b"GCF/1|FINALITY-CERTIFICATE\x00" + _canonical(self.certificate)
        ).hexdigest()
        finality = {"certificate": self.certificate, "certificate_digest": digest}
        with self.assertRaisesRegex(PoolSettlementError, "reward_policy_credit_cap_exceeded"):
            self.settlement.settle_finalized_block(
                finality=finality, reward_policy=policy, pool_id="gaia-pool",
            )

    def test_settlement_rejects_share_ledger_integrity_failure(self):
        self.share_ledger.verify_chain = lambda: False
        with self.assertRaisesRegex(PoolSettlementError, "share_ledger_integrity_failure"):
            self.settlement.settle_finalized_block(
                finality=self.finality, reward_policy=self.reward_policy(),
                pool_id="gaia-pool",
            )


if __name__ == "__main__":
    unittest.main()
