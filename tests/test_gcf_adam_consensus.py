import hashlib
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.consensus.gcf import (
    CERT_DOMAIN, GCFEngine, GCFError, GateResult, ValidatorSet,
    canonical_bytes, make_proposal, make_vote, sha256_hex,
    verify_finality_certificate,
)
from src.adam.commit_store import AdamCommitStore, APEXValidator, APEXValidationError


def keypair():
    private = Ed25519PrivateKey.generate()
    private_hex = private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()
    public_hex = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    ).hex()
    return private_hex, public_hex


class GCFAdamConsensusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.now = 1_800_000_000
        self.proposer_private, self.proposer_public = keypair()
        self.keys = {f"v{i}": keypair() for i in range(4)}
        self.vset = ValidatorSet("gaia-testnet", 1, {
            name: {"public_key_hex": pair[1], "weight": 1}
            for name, pair in self.keys.items()
        })
        self.allow = lambda *_args: GateResult(True, "verified")
        self.engine = GCFEngine(
            Path(self.temp.name) / "gcf.sqlite3", self.vset,
            hccgn_verifier=self.allow, god_authorizer=self.allow,
            justice_verifier=self.allow, clock=lambda: self.now,
        )
        self.state = b'{"account":"alpha","balance_units":1250}'
        self.proposal = make_proposal(
            network_id="gaia-testnet", epoch=1, height=1, round=0,
            parent_hash="0" * 64, payload_hash=sha256_hex(self.state),
            proof_hash=hashlib.sha256(b"proof-commitment").hexdigest(),
            justice_commitment={
                "justice_profile": "GAIA-JUSTICE/1",
                "policy_hash": "1" * 64,
                "policy_audit_hash": "2" * 64,
                "evidence_root": "3" * 64,
                "transition_hash": "4" * 64,
                "value_accounting_hash": "5" * 64,
                "challenge_state_hash": "6" * 64,
            },
            proposer_id="proposer-1", proposer_private_key_hex=self.proposer_private,
            nonce="0123456789abcdef0123456789abcdef",
            issued_at=self.now, expires_at=self.now + 300,
        )

    def tearDown(self):
        self.temp.cleanup()

    def _build_certificate(self):
        accepted = self.engine.submit_proposal(self.proposal)
        digest = accepted["candidate_digest"]
        prevotes = []
        for name in ("v0", "v1", "v2"):
            vote = make_vote(
                validator_id=name, validator_private_key_hex=self.keys[name][0],
                proposal=self.proposal, vote_type="PREVOTE", issued_at=self.now,
            )
            self.engine.submit_vote(vote)
            prevotes.append(vote)
        polc_body = {
            "schema": "GCF/1", "candidate_digest": digest,
            "validator_set_hash": self.vset.digest,
            "prevotes": sorted(prevotes, key=lambda v: v["validator_id"]),
        }
        polc_digest = sha256_hex(CERT_DOMAIN + canonical_bytes(polc_body))
        for name in ("v0", "v1", "v2"):
            vote = make_vote(
                validator_id=name, validator_private_key_hex=self.keys[name][0],
                proposal=self.proposal, vote_type="PRECOMMIT",
                polc_digest=polc_digest, issued_at=self.now,
            )
            self.engine.submit_vote(vote)
        finalized = self.engine.finalize(digest)
        return digest, finalized["certificate"]

    def test_weighted_quorum_is_strictly_greater_than_two_thirds(self):
        self.assertEqual(self.vset.quorum_weight(), 3)
        self.assertEqual(self.vset.total_weight, 4)

    def test_proposal_replay_is_rejected(self):
        self.engine.submit_proposal(self.proposal)
        with self.assertRaisesRegex(GCFError, "PROPOSAL_REPLAY_OR_DUPLICATE"):
            self.engine.submit_proposal(self.proposal)

    def test_bad_proposer_signature_is_rejected(self):
        altered = dict(self.proposal)
        altered["height"] = 2
        with self.assertRaisesRegex(GCFError, "PROPOSER_SIGNATURE_INVALID"):
            self.engine.submit_proposal(altered)

    def test_hccgn_gate_fails_closed_when_unconfigured(self):
        engine = GCFEngine(
            Path(self.temp.name) / "closed.sqlite3", self.vset, clock=lambda: self.now
        )
        with self.assertRaisesRegex(GCFError, "MINER_PROOF_INVALID"):
            engine.submit_proposal(self.proposal)

    def test_finality_requires_prevote_and_precommit_quorum(self):
        digest = self.engine.submit_proposal(self.proposal)["candidate_digest"]
        for name in ("v0", "v1"):
            self.engine.submit_vote(make_vote(
                validator_id=name, validator_private_key_hex=self.keys[name][0],
                proposal=self.proposal, vote_type="PREVOTE", issued_at=self.now,
            ))
        with self.assertRaisesRegex(GCFError, "PREVOTE_QUORUM_NOT_REACHED"):
            self.engine.finalize(digest)

    def test_full_finality_certificate_and_adam_commit(self):
        digest, cert = self._build_certificate()
        checked = verify_finality_certificate(
            cert, hccgn_verifier=self.allow, god_authorizer=self.allow,
            justice_verifier=self.allow, clock=lambda: self.now,
        )
        self.assertTrue(checked["valid"], checked)
        store = AdamCommitStore(Path(self.temp.name) / "adam.sqlite3")
        apex = APEXValidator(
            store, hccgn_verifier=self.allow,
            god_authorizer=self.allow, justice_verifier=self.allow,
        )
        committed = apex.validate_and_commit(cert, self.state)
        self.assertTrue(committed["committed"])
        self.assertEqual(committed["candidate_digest"], digest)
        recovered = store.get_commit(1)
        self.assertEqual(recovered["state_bytes"], self.state)
        self.assertEqual(store.head()["height"], 1)

    def test_adam_rejects_wrong_state_payload(self):
        _, cert = self._build_certificate()
        store = AdamCommitStore(Path(self.temp.name) / "adam-wrong.sqlite3")
        apex = APEXValidator(
            store, hccgn_verifier=self.allow,
            god_authorizer=self.allow, justice_verifier=self.allow,
        )
        with self.assertRaisesRegex(APEXValidationError, "PAYLOAD_STATE_HASH_MISMATCH"):
            apex.validate_and_commit(cert, b"not-the-proposed-state")

    def test_certificate_tampering_is_rejected(self):
        _, cert = self._build_certificate()
        altered = dict(cert)
        altered["precommit_weight"] = 999
        result = verify_finality_certificate(
            altered, hccgn_verifier=self.allow, god_authorizer=self.allow,
            justice_verifier=self.allow, clock=lambda: self.now,
        )
        self.assertFalse(result["valid"])

    def test_adam_parent_continuity_is_enforced(self):
        store = AdamCommitStore(Path(self.temp.name) / "adam-parent.sqlite3")
        with self.assertRaisesRegex(APEXValidationError, "PARENT_HASH_MISMATCH"):
            store.commit(
                height=1, candidate_digest="a" * 64, parent_hash="f" * 64,
                state_bytes=b"x", certificate_digest="b" * 64, receipt={},
            )

    def test_consensus_canonical_json_rejects_float(self):
        with self.assertRaises(GCFError):
            canonical_bytes({"unsafe": 0.1})


if __name__ == "__main__":
    unittest.main()
