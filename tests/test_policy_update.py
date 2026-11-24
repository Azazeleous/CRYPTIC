import base64
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.consensus.gcf import GCFEngine, ValidatorSet, make_vote, verify_finality_certificate
from src.consensus.hccgn_registry import (
    HCCGNActiveTargetPolicy, POLICY_DOMAIN, POLICY_SCHEMA, _canonical,
)
from src.consensus.policy_update import GCFPolicyUpdateCoordinator, PolicyUpdateError


class LocalSigner:
    def __init__(self, private_key):
        self.private_key = private_key
        self.public_key_hex = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()

    def sign(self, message):
        return self.private_key.sign(message)


class VerifiedMemoryAnchor:
    """Deterministic test anchor that independently verifies every certificate."""
    def __init__(self, network_id, epoch, validators):
        self.network_id = network_id
        self.epoch = epoch
        self.validators = validators
        self.values = {}

    def read_sequence(self, network_id):
        return self.values.get(network_id)

    def advance_sequence(self, network_id, sequence, policy_hash, *, certificate=None):
        if network_id != self.network_id or not isinstance(certificate, dict):
            return False
        result = verify_finality_certificate(
            certificate,
            hccgn_verifier=lambda _p: True,
            god_authorizer=lambda *_a: True,
            justice_verifier=lambda _p: True,
        )
        proposal = certificate.get("proposal", {})
        previous = self.values.get(network_id)
        previous_hash = "0" * 64 if previous is None else previous[1]
        if (not result["valid"] or proposal.get("network_id") != network_id
                or proposal.get("epoch") != self.epoch
                or proposal.get("anchor_sequence") != sequence
                or proposal.get("parent_hash") != previous_hash
                or proposal.get("payload_hash") != policy_hash):
            return False
        current = self.values.get(network_id)
        if current is not None and sequence <= current[0]:
            return False
        self.values[network_id] = (sequence, policy_hash)
        return True


class GCFPolicyUpdateCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.now = 1_800_000_000
        self.network = "gaia-testnet"
        self.epoch = 4
        self.keys = {f"v{i}": Ed25519PrivateKey.generate() for i in range(4)}
        self.signers = {name: LocalSigner(key) for name, key in self.keys.items()}
        validators = {
            name: {"public_key_hex": self.signers[name].public_key_hex, "weight": 1}
            for name in self.keys
        }
        self.validator_set = ValidatorSet(self.network, self.epoch, validators)
        self.anchor = VerifiedMemoryAnchor(self.network, self.epoch, validators)
        self.policy_key = Ed25519PrivateKey.generate()
        policy_public = self.policy_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.policy = HCCGNActiveTargetPolicy(
            Path(self.temp.name) / "policy.sqlite3",
            trusted_public_key=policy_public,
            trusted_signer_id="HCCGN-ROOT",
            clock=lambda: self.now,
            sequence_anchor=self.anchor,
            require_external_anchor=True,
        )
        self.engine = GCFEngine(
            Path(self.temp.name) / "gcf.sqlite3",
            self.validator_set,
            hccgn_verifier=lambda _proposal: True,
            god_authorizer=lambda *_args: True,
            justice_verifier=lambda _proposal: True,
            clock=lambda: self.now,
        )
        self.coordinator = GCFPolicyUpdateCoordinator(
            engine=self.engine,
            target_policy=self.policy,
            sequence_anchor=self.anchor,
            proposer_id="v0",
            proposer_signer=self.signers["v0"],
            clock=lambda: self.now,
        )

    def tearDown(self):
        self.temp.cleanup()

    def snapshot(self, sequence=1):
        body = {
            "schema": POLICY_SCHEMA,
            "profile_id": "HCCGN-WORK/1",
            "network_id": self.network,
            "sequence": sequence,
            "activation_height": 1,
            "activation_epoch": self.epoch,
            "target": "ff" * 32,
            "issued_at": self.now - 10,
            "expires_at": self.now + 600,
            "signer_id": "HCCGN-ROOT",
        }
        signature = self.policy_key.sign(POLICY_DOMAIN + _canonical(body))
        return {**body, "signature": base64.b64encode(signature).decode("ascii")}

    def reach_quorum(self, proposal, candidate_digest):
        for validator_id in ("v0", "v1", "v2"):
            vote = make_vote(
                validator_id=validator_id,
                validator_private_key_hex=self.keys[validator_id].private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                ).hex(),
                proposal=proposal,
                vote_type="PREVOTE",
                issued_at=self.now,
            )
            self.engine.submit_vote(vote)
        with self.engine._db() as db:
            _prevotes, polc_digest = self.engine._polc(db, candidate_digest)
        for validator_id in ("v0", "v1", "v2"):
            vote = make_vote(
                validator_id=validator_id,
                validator_private_key_hex=self.keys[validator_id].private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                ).hex(),
                proposal=proposal,
                vote_type="PRECOMMIT",
                polc_digest=polc_digest,
                issued_at=self.now,
            )
            self.engine.submit_vote(vote)

    def test_complete_policy_update_requires_real_weighted_finality(self):
        snapshot = self.snapshot()
        prepared = self.coordinator.prepare(
            snapshot,
            proof_hash="a" * 64,
            justice_commitment={"decision_digest": "b" * 64},
            height=19,
            expires_at=self.now + 120,
            nonce="policy-update-nonce-00000001",
        )
        self.assertTrue(prepared["accepted"])
        self.assertEqual(prepared["proposal"]["height"], 19)
        self.assertEqual(prepared["proposal"]["anchor_sequence"], 1)
        self.assertEqual(prepared["proposal"]["payload_hash"], prepared["policy_hash"])
        self.reach_quorum(prepared["proposal"], prepared["candidate_digest"])
        result = self.coordinator.finalize_and_install(
            snapshot, candidate_digest=prepared["candidate_digest"]
        )
        self.assertTrue(result["installed"])
        self.assertEqual(result["sequence"], 1)
        self.assertEqual(self.anchor.read_sequence(self.network),
                         (1, prepared["policy_hash"]))
        self.assertEqual(self.policy.digest_snapshot(snapshot), result["policy_hash"])

    def test_no_quorum_does_not_advance_policy_or_anchor(self):
        snapshot = self.snapshot()
        prepared = self.coordinator.prepare(
            snapshot,
            proof_hash="a" * 64,
            justice_commitment={"decision_digest": "b" * 64},
            height=20,
            expires_at=self.now + 120,
        )
        with self.assertRaises(PolicyUpdateError):
            self.coordinator.finalize_and_install(
                snapshot, candidate_digest=prepared["candidate_digest"]
            )
        self.assertIsNone(self.anchor.read_sequence(self.network))
        self.assertIsNone(self.policy.resolve({
            "network_id": self.network, "height": 20,
            "epoch": self.epoch, "issued_at": self.now,
        }))


if __name__ == "__main__":
    unittest.main()
