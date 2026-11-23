import hashlib
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.consensus.gcf import GCFError, ValidatorSet, make_proposal
from src.consensus.gcf2 import (
    SCHEMA, VOTE_DOMAIN, make_vote, tally_votes, verify_vote,
)


def keypair():
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    ).hex()
    return private, public


class GCF2NilVoteTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_800_000_000
        self.keys = {f"v{i}": keypair() for i in range(4)}
        self.vset = ValidatorSet("gaia-testnet", 1, {
            name: {"public_key_hex": pair[1], "weight": 1}
            for name, pair in self.keys.items()
        })
        self.proposal = make_proposal(
            network_id="gaia-testnet", epoch=1, height=9, round=2,
            parent_hash="ab" * 32, payload_hash="cd" * 32,
            proof_hash="ef" * 32,
            justice_commitment={"justice_profile": "GAIA-JUSTICE/1"},
            proposer_id="v0", proposer_private_key_hex=self.keys["v0"][0],
            nonce="0123456789abcdef0123456789abcdef",
            issued_at=self.now, expires_at=self.now + 240,
        )
        from src.consensus.gcf import canonical_bytes, sha256_hex
        self.digest = sha256_hex(canonical_bytes(self.proposal))
        self.clock = lambda: self.now

    def nil_vote(self, validator_id, phase="PREVOTE"):
        return make_vote(
            validator_id=validator_id,
            validator_private_key_hex=self.keys[validator_id][0],
            network_id="gaia-testnet", epoch=1, height=9, round=2,
            parent_hash="ab" * 32, vote_type=phase, vote_kind="NIL",
            issued_at=self.now, expires_at=self.now + 60,
        )

    def candidate_vote(self, validator_id, phase="PREVOTE", approve=True):
        return make_vote(
            validator_id=validator_id,
            validator_private_key_hex=self.keys[validator_id][0],
            network_id="gaia-testnet", epoch=1, height=9, round=2,
            parent_hash="ab" * 32, vote_type=phase, vote_kind="CANDIDATE",
            candidate_digest=self.digest, approve=approve,
            polc_digest=("12" * 32 if phase == "PRECOMMIT" and approve else None),
            issued_at=self.now, expires_at=self.now + 60,
        )

    def test_gcf2_has_distinct_signature_domain_and_schema(self):
        self.assertEqual(SCHEMA, "GCF/2")
        self.assertEqual(VOTE_DOMAIN, b"GCF/2|VOTE|ED25519\x00")
        self.assertNotEqual(VOTE_DOMAIN, b"GCF/1|VOTE|ED25519\x00")

    def test_nil_vote_has_no_candidate_or_approval_or_polc(self):
        vote = self.nil_vote("v0")
        self.assertIsNone(vote["candidate_digest"])
        self.assertIsNone(vote["approve"])
        self.assertIsNone(vote["polc_digest"])
        checked = verify_vote(vote, validator_set=self.vset, clock=self.clock)
        self.assertEqual(checked["vote_kind"], "NIL")

    def test_nil_vote_cannot_be_bound_to_candidate_fields(self):
        with self.assertRaisesRegex(GCFError, "GCF2_NIL_VOTE_MUST_NOT_BIND_CANDIDATE"):
            make_vote(
                validator_id="v0", validator_private_key_hex=self.keys["v0"][0],
                network_id="gaia-testnet", epoch=1, height=9, round=2,
                parent_hash="ab" * 32, vote_type="PREVOTE", vote_kind="NIL",
                candidate_digest=self.digest, approve=True,
                issued_at=self.now, expires_at=self.now + 60,
            )

    def test_candidate_vote_must_bind_exact_proposal_and_parent(self):
        vote = self.candidate_vote("v0")
        self.assertEqual(
            verify_vote(vote, validator_set=self.vset, clock=self.clock,
                        proposal=self.proposal)["candidate_digest"],
            self.digest,
        )
        altered = dict(vote)
        altered["parent_hash"] = "ff" * 32
        with self.assertRaisesRegex(GCFError, "GCF2_CANDIDATE_CONTEXT_MISMATCH"):
            verify_vote(altered, validator_set=self.vset, clock=self.clock,
                        proposal=self.proposal)

    def test_nil_votes_do_not_contribute_to_candidate_quorum(self):
        votes = [self.nil_vote(f"v{i}") for i in range(3)]
        tally = tally_votes(votes, validator_set=self.vset, clock=self.clock,
                            vote_type="PREVOTE", candidate_digest=self.digest,
                            proposal=self.proposal)
        self.assertEqual(tally["nil_weight"], 3)
        self.assertTrue(tally["nil_quorum"])
        self.assertEqual(tally["candidate_weight"], 0)
        self.assertFalse(tally["candidate_quorum"])

    def test_candidate_quorum_excludes_nil_weight(self):
        votes = [self.candidate_vote("v0"), self.candidate_vote("v1"),
                 self.nil_vote("v2"), self.nil_vote("v3")]
        tally = tally_votes(votes, validator_set=self.vset, clock=self.clock,
                            vote_type="PREVOTE", candidate_digest=self.digest,
                            proposal=self.proposal)
        self.assertEqual(tally["candidate_weight"], 2)
        self.assertEqual(tally["nil_weight"], 2)
        self.assertFalse(tally["candidate_quorum"])

    def test_duplicate_validator_slot_rejected(self):
        votes = [self.nil_vote("v0"), self.candidate_vote("v0")]
        with self.assertRaisesRegex(GCFError, "GCF2_DUPLICATE_VALIDATOR_VOTE_SLOT"):
            tally_votes(votes, validator_set=self.vset, clock=self.clock,
                        vote_type="PREVOTE", candidate_digest=self.digest,
                        proposal=self.proposal)

    def test_tampered_nil_vote_signature_rejected(self):
        vote = self.nil_vote("v0")
        vote["round"] = 3
        with self.assertRaisesRegex(GCFError, "GCF2_VALIDATOR_SIGNATURE_INVALID"):
            verify_vote(vote, validator_set=self.vset, clock=self.clock)

    def test_nil_vote_expiry_is_enforced(self):
        vote = self.nil_vote("v0")
        self.now += 61
        with self.assertRaisesRegex(GCFError, "GCF2_VOTE_EXPIRED_OR_FUTURE"):
            verify_vote(vote, validator_set=self.vset, clock=self.clock)

    def test_precommit_nil_does_not_require_polc(self):
        vote = self.nil_vote("v0", phase="PRECOMMIT")
        checked = verify_vote(vote, validator_set=self.vset, clock=self.clock)
        self.assertEqual(checked["vote_type"], "PRECOMMIT")
        self.assertIsNone(checked["polc_digest"])


if __name__ == "__main__":
    unittest.main()
