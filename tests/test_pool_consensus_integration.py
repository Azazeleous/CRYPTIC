import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.consensus.gcf import (
    CERT_DOMAIN,
    GCFEngine,
    GateResult,
    ValidatorSet,
    canonical_bytes,
    make_proposal,
    make_vote,
    sha256_hex,
)
from src.consensus.hccgn_adapter import HCCGNVerifierAdapter
from src.consensus.hccgn_work import (
    HCCGNWorkProofProvider,
    PROFILE_ID,
)
from src.consensus.pool_runtime import (
    build_adam_finalized_state_verifier,
    build_gcf1_pool_finality_verifier,
)
from src.adam.commit_store import AdamCommitStore, APEXValidator
from src.consensus.pool_settlement import (
    INTERNAL_ASSET,
    POLICY_DOMAIN,
    POLICY_SCHEMA,
    _canonical,
)
from src.consensus.pool_ledger import PoolShareLedger
from src.mining.pool_service import PoolCoordinator
from src.mining.pool_worker import execute_pool_job


def keypair():
    private = Ed25519PrivateKey.generate()
    private_hex = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()
    public_hex = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()
    return private_hex, public_hex


class PoolConsensusIntegrationTests(unittest.TestCase):
    """Real HCCGN work, real GCF signatures/quorum, and durable pool settlement."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.now = 1_800_000_000
        self.target = b"\xff" * 32
        self.state_bytes = b"canonical-pool-state-v1"
        self.payload_hash = hashlib.sha256(self.state_bytes).hexdigest()

        issuer_private, issuer_public = keypair()
        self.reward_private, self.reward_public = keypair()
        self.share_ledger = PoolShareLedger(self.root / "shares.sqlite3")
        self.pool = PoolCoordinator(
            database=self.root / "jobs.sqlite3",
            share_ledger=self.share_ledger,
            issuer_private_key_hex=issuer_private,
            issuer_id="pool-issuer",
            pool_id="gaia-pool",
            network_id="hccgn-test",
            trusted_issuer_public_key_hex=issuer_public,
            resolve_active_target=lambda _boundary: self.target,
            clock=lambda: self.now,
        )

        self.job = self.pool.issue_job(
            worker_id="worker-a",
            height=1,
            epoch=1,
            lifetime_seconds=120,
            parent_hash="00" * 32,
            payload_hash=self.payload_hash,
            primary_stride=3037,
            compact_stride=5,
            nonce_start=0,
            max_attempts=8,
        )
        self.submission = execute_pool_job(
            self.job,
            trusted_issuer_public_key_hex=issuer_public,
            expected_issuer_id="pool-issuer",
            expected_pool_id="gaia-pool",
            expected_network_id="hccgn-test",
            worker_id="worker-a",
            now=self.now,
        )
        self.accepted = self.pool.submit_share(
            self.submission, authenticated_worker_id="worker-a",
        )
        proof = base64.b64decode(self.submission["proof_b64"], validate=True)
        proof_hash = self.submission["proof_hash"]
        provider = HCCGNWorkProofProvider(
            resolve_proof=lambda digest: proof if digest == proof_hash else None,
            resolve_target=lambda _proposal: self.target,
        )
        self.hccgn_gate = HCCGNVerifierAdapter(
            provider, profile_id=PROFILE_ID,
        )

        self.validator_keys = {f"v{i}": keypair() for i in range(4)}
        self.validator_set = ValidatorSet("hccgn-test", 1, {
            name: {"public_key_hex": pair[1], "weight": 1}
            for name, pair in self.validator_keys.items()
        })
        self.allow_test_gate = lambda *_args: GateResult(True, "test-only external gate")
        self.engine = GCFEngine(
            self.root / "gcf.sqlite3",
            self.validator_set,
            hccgn_verifier=self.hccgn_gate,
            god_authorizer=self.allow_test_gate,
            justice_verifier=self.allow_test_gate,
            clock=lambda: self.now,
        )
        self.adam_store = AdamCommitStore(self.root / "adam.sqlite3")
        self.apex = APEXValidator(
            self.adam_store, hccgn_verifier=self.hccgn_gate,
            god_authorizer=self.allow_test_gate,
            justice_verifier=self.allow_test_gate,
        )
        self.proposal = make_proposal(
            network_id="hccgn-test",
            epoch=1,
            height=1,
            round=0,
            parent_hash="00" * 32,
            payload_hash=self.payload_hash,
            proof_hash=proof_hash,
            justice_commitment={
                "justice_profile": "GAIA-JUSTICE/1",
                "policy_hash": "1" * 64,
                "policy_audit_hash": "2" * 64,
                "evidence_root": "3" * 64,
                "transition_hash": "4" * 64,
                "value_accounting_hash": "5" * 64,
                "challenge_state_hash": "6" * 64,
            },
            proposer_id="v0",
            proposer_private_key_hex=self.validator_keys["v0"][0],
            nonce="0123456789abcdef0123456789abcdef",
            issued_at=self.now,
            expires_at=self.now + 300,
        )

    def tearDown(self):
        self.temp.cleanup()

    def build_finality(self):
        digest = self.engine.submit_proposal(self.proposal)["candidate_digest"]
        prevotes = []
        for name in ("v0", "v1", "v2"):
            vote = make_vote(
                validator_id=name,
                validator_private_key_hex=self.validator_keys[name][0],
                proposal=self.proposal,
                vote_type="PREVOTE",
                issued_at=self.now,
            )
            self.engine.submit_vote(vote)
            prevotes.append(vote)
        polc_digest = sha256_hex(CERT_DOMAIN + canonical_bytes({
            "schema": "GCF/1",
            "candidate_digest": digest,
            "validator_set_hash": self.validator_set.digest,
            "prevotes": sorted(prevotes, key=lambda item: item["validator_id"]),
        }))
        for name in ("v0", "v1", "v2"):
            self.engine.submit_vote(make_vote(
                validator_id=name,
                validator_private_key_hex=self.validator_keys[name][0],
                proposal=self.proposal,
                vote_type="PRECOMMIT",
                polc_digest=polc_digest,
                issued_at=self.now,
            ))
        return self.engine.finalize(digest)

    def reward_policy(self):
        body = {
            "schema": POLICY_SCHEMA,
            "policy_id": "internal-reward-v1",
            "network_id": "hccgn-test",
            "pool_id": "gaia-pool",
            "epoch": 1,
            "effective_height_start": 1,
            "effective_height_end": 10,
            "reward_units": 25,
            "max_total_credits": 100,
            "asset": INTERNAL_ASSET,
            "issuer_id": "governance-reward-root",
            "issued_at": self.now - 100,
            "expires_at": self.now + 1000,
        }
        signature = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(self.reward_private)
        ).sign(POLICY_DOMAIN + _canonical(body))
        return {**body, "signature": base64.b64encode(signature).decode("ascii")}

    def test_real_hccgn_pool_share_is_finalized_by_gcf_and_settled(self):
        finality = self.build_finality()
        self.apex.validate_and_commit(finality["certificate"], self.state_bytes)
        verifier = build_gcf1_pool_finality_verifier(
            hccgn_verifier=self.hccgn_gate,
            god_authorizer=self.allow_test_gate,
            justice_verifier=self.allow_test_gate,
            clock=lambda: self.now,
            finalized_state_verifier=build_adam_finalized_state_verifier(self.adam_store),
        )
        self.pool.configure_settlement_ledger(
            database=self.root / "settlements.sqlite3",
            trusted_reward_policy_public_key_hex=self.reward_public,
            verify_finality_certificate=verifier,
        )
        settled = self.pool.settle_finalized_block(
            finality=finality,
            reward_policy=self.reward_policy(),
        )
        self.assertTrue(settled["settled"])
        self.assertEqual(settled["worker_id"], "worker-a")
        self.assertEqual(settled["credit_units"], 25)
        status = self.pool.status()
        self.assertEqual(status["shares_accepted"], 1)
        self.assertEqual(status["settlements_recorded"], 1)
        self.assertTrue(status["share_ledger_chain_valid"])
        self.assertTrue(status["settlement_ledger_chain_valid"])

    def test_tampered_finality_certificate_is_not_settled(self):
        finality = self.build_finality()
        verifier = build_gcf1_pool_finality_verifier(
            hccgn_verifier=self.hccgn_gate,
            god_authorizer=self.allow_test_gate,
            justice_verifier=self.allow_test_gate,
            clock=lambda: self.now,
            finalized_state_verifier=build_adam_finalized_state_verifier(self.adam_store),
        )
        self.pool.configure_settlement_ledger(
            database=self.root / "settlements.sqlite3",
            trusted_reward_policy_public_key_hex=self.reward_public,
            verify_finality_certificate=verifier,
        )
        altered = dict(finality)
        certificate = dict(finality["certificate"])
        certificate["precommit_weight"] = 4
        altered["certificate"] = certificate
        altered["certificate_digest"] = hashlib.sha256(
            b"GCF/1|FINALITY-CERTIFICATE\x00" + _canonical(certificate)
        ).hexdigest()
        with self.assertRaises(Exception):
            self.pool.settle_finalized_block(
                finality=altered,
                reward_policy=self.reward_policy(),
            )
        self.assertEqual(self.pool.status()["settlements_recorded"], 0)


if __name__ == "__main__":
    unittest.main()
