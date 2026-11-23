import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.consensus.gcf import GCFEngine, GCFError, ValidatorSet, make_proposal, make_vote as make_gcf1_vote, sha256_hex, canonical_bytes
from src.consensus.gcf2 import make_vote
from src.consensus.gcf2_engine import GCF2VoteStore
from src.consensus.gcf2_independent_verifier import (\n    GCF2IndependentVerificationError, verify_finality_certificate,\n)\n

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


class GCF2PersistentVoteStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "gcf.sqlite3"
        self.now = 1_800_000_000
        self.keys = {f"v{i}": keypair() for i in range(4)}
        self.vset = ValidatorSet("gaia-testnet", 1, {
            name: {"public_key_hex": pair[1], "weight": 1}
            for name, pair in self.keys.items()
        })
        self.gcf1 = GCFEngine(
            self.db, self.vset,
            hccgn_verifier=lambda _proposal: True,
            god_authorizer=lambda *_args: True,
            justice_verifier=lambda _proposal: True,
            clock=lambda: self.now,
        )
        self.proposal = make_proposal(
            network_id="gaia-testnet", epoch=1, height=9, round=0,
            parent_hash="ab" * 32, payload_hash="cd" * 32,
            proof_hash="ef" * 32,
            justice_commitment={"justice_profile": "GAIA-JUSTICE/1"},
            proposer_id="v0", proposer_private_key_hex=self.keys["v0"][0],
            nonce="0123456789abcdef0123456789abcdef",
            issued_at=self.now, expires_at=self.now + 240,
        )
        self.digest = sha256_hex(canonical_bytes(self.proposal))
        self.gcf1.submit_proposal(self.proposal)
        self.store = GCF2VoteStore(
            database=self.db, validator_set=self.vset, gcf1_engine=self.gcf1,
            resolve_active_parent=lambda _height: "ab" * 32,
            clock=lambda: self.now,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def vote(self, validator_id, phase="PREVOTE", kind="CANDIDATE",
             approve=True, polc_digest=None):
        return make_vote(
            validator_id=validator_id,
            validator_private_key_hex=self.keys[validator_id][0],
            network_id="gaia-testnet", epoch=1, height=9, round=0,
            parent_hash="ab" * 32, vote_type=phase, vote_kind=kind,
            candidate_digest=self.digest if kind == "CANDIDATE" else None,
            approve=approve if kind == "CANDIDATE" else None,
            polc_digest=polc_digest,
            issued_at=self.now, expires_at=self.now + 60,
        )

    def test_nil_vote_consumes_persistent_slot_but_creates_no_candidate_lock(self):
        nil = self.vote("v1", kind="NIL")
        self.assertTrue(self.store.submit_vote(nil)["accepted"])
        with self.assertRaisesRegex(GCFError, "GCF2_DUPLICATE_VOTE_SLOT|GCF2_EQUIVOCATION_SLOT_CONFLICT"):
            self.store.submit_vote(self.vote("v1"))
        with self.store._connect() as db:
            locks = db.execute("SELECT COUNT(*) FROM gcf2_candidate_locks").fetchone()[0]
            slots = db.execute("SELECT COUNT(*) FROM gcf2_vote_slots").fetchone()[0]
        self.assertEqual(locks, 0)
        self.assertEqual(slots, 1)

    def test_candidate_prevote_quorum_builds_deterministic_persistent_polc(self):
        for validator in ("v0", "v1", "v2"):
            self.store.submit_vote(self.vote(validator))
        polc = self.store.get_polc(self.digest)
        self.assertIsNotNone(polc)
        self.assertEqual(polc["schema"], "GCF/2")
        self.assertEqual(len(polc["prevotes"]), 3)
        self.assertEqual(
            [v["validator_id"] for v in polc["prevotes"]],
            ["v0", "v1", "v2"],
        )
        self.assertEqual(polc["polc_digest"], self.store.get_polc(self.digest)["polc_digest"])

    def test_affirmative_precommit_requires_exact_persisted_polc(self):
        for validator in ("v0", "v1", "v2"):
            self.store.submit_vote(self.vote(validator))
        polc = self.store.get_polc(self.digest)
        self.assertIsNotNone(polc)
        bad = self.vote("v0", phase="PRECOMMIT", polc_digest="00" * 32)
        with self.assertRaisesRegex(GCFError, "GCF2_PRECOMMIT_POLC_NOT_VERIFIED"):
            self.store.submit_vote(bad)
        good = self.vote("v0", phase="PRECOMMIT", polc_digest=polc["polc_digest"])
        self.assertTrue(self.store.submit_vote(good)["accepted"])

    def test_trusted_parent_resolver_rejects_nil_vote_with_untrusted_parent(self):
        self.store.resolve_active_parent = lambda _height: "ff" * 32
        with self.assertRaisesRegex(GCFError, "GCF2_ACTIVE_PARENT_MISMATCH"):
            self.store.submit_vote(self.vote("v3", kind="NIL"))

    def test_finality_certificate_is_persisted_and_independently_verified(self):
        for validator in ("v0", "v1", "v2"):
            self.store.submit_vote(self.vote(validator))
        polc = self.store.get_polc(self.digest)
        self.assertIsNotNone(polc)
        result = None
        for validator in ("v0", "v1", "v2"):
            result = self.store.submit_vote(
                self.vote(validator, phase="PRECOMMIT",
                          polc_digest=polc["polc_digest"])
            )
        self.assertIsNotNone(result["finality"])
        certificate = self.store.get_finality_certificate(height=9)
        self.assertIsNotNone(certificate)
        validators = {
            name: {"public_key_hex": pair[1], "weight": 1}
            for name, pair in self.keys.items()
        }
        checked = verify_finality_certificate(
            certificate, network_id="gaia-testnet", epoch=1,
            validators=validators, proposal=self.proposal,
        )
        self.assertTrue(checked["valid"])
        self.assertEqual(checked["precommit_weight"], 3)

    def test_independent_finality_verifier_rejects_certificate_tampering(self):
        for validator in ("v0", "v1", "v2"):
            self.store.submit_vote(self.vote(validator))
        polc = self.store.get_polc(self.digest)
        for validator in ("v0", "v1", "v2"):
            self.store.submit_vote(
                self.vote(validator, phase="PRECOMMIT",
                          polc_digest=polc["polc_digest"])
            )
        certificate = self.store.get_finality_certificate(height=9)
        certificate["certificate_digest"] = "00" * 32
        validators = {
            name: {"public_key_hex": pair[1], "weight": 1}
            for name, pair in self.keys.items()
        }
        with self.assertRaisesRegex(
            GCF2IndependentVerificationError, "FINALITY_CERTIFICATE_DIGEST_INVALID"
        ):
            verify_finality_certificate(
                certificate, network_id="gaia-testnet", epoch=1,
                validators=validators, proposal=self.proposal,
            )

    def test_validator_round_state_rejects_round_regression_across_phases(self):
        with self.store._db() as db:
            db.execute(
                "INSERT INTO gcf2_validator_rounds VALUES(?,?,?,?,?)",
                ("gaia-testnet", 1, 9, "v3", 2),
            )
        with self.assertRaisesRegex(GCFError, "GCF2_VOTE_ROUND_REGRESSION"):
            self.store.submit_vote(self.vote("v3", kind="NIL"))

    def test_gcf1_existing_lock_blocks_gcf2_vote_for_same_height_phase(self):
        with self.gcf1._db() as db:
            db.execute(
                "INSERT INTO vote_locks VALUES(?,?,?,?,?,?,?)",
                ("gaia-testnet", 1, 9, 0, "PREVOTE", "v3", self.digest),
            )
        with self.assertRaisesRegex(GCFError, "GCF2_CROSS_VERSION_VOTE_SLOT_ALREADY_USED"):
            self.store.submit_vote(self.vote("v3", kind="NIL"))


    def test_gcf2_existing_slot_blocks_gcf1_vote_for_same_height_phase(self):
        with self.store._db() as db:
            db.execute(
                "INSERT INTO gcf2_vote_slots VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                ("gaia-testnet", 1, 9, 0, "PREVOTE", "v3", "NIL", None,
                 "ab" * 32, "{}", "11" * 32),
            )
        legacy_vote = make_gcf1_vote(
            validator_id="v3", validator_private_key_hex=self.keys["v3"][0],
            proposal=self.proposal, vote_type="PREVOTE", approve=True,
            issued_at=self.now,
        )
        with self.assertRaisesRegex(GCFError, "GCF1_CROSS_VERSION_VOTE_SLOT_ALREADY_USED"):
            self.gcf1.submit_vote(legacy_vote)

    def test_gcf2_database_must_be_shared_with_gcf1_engine(self):
        with self.assertRaisesRegex(GCFError, "GCF2_AND_GCF1_MUST_SHARE_DURABLE_VOTE_DATABASE"):
            GCF2VoteStore(
                database=Path(self.tmp.name) / "other.sqlite3",
                validator_set=self.vset, gcf1_engine=self.gcf1,
                resolve_active_parent=lambda _height: "ab" * 32,
                clock=lambda: self.now,
            )


if __name__ == "__main__":
    unittest.main()
