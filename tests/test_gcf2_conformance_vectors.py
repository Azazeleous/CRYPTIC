import hashlib
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.consensus.gcf import ValidatorSet, canonical_bytes, make_proposal
from src.consensus.gcf2 import make_vote
from src.consensus.gcf2_independent_verifier import verify_finality_certificate


VECTOR = json.loads(
    (Path(__file__).parent / "vectors" / "gcf2_known_answers.json").read_text()
)


class GCF2KnownAnswerTests(unittest.TestCase):
    def build_vector(self):
        keys = {
            f"v{index}": Ed25519PrivateKey.from_private_bytes(bytes([int(seed, 16)]) * 32)
            for index, seed in enumerate(VECTOR["validator_seed_bytes"])
        }
        private_hex = {
            name: key.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            ).hex()
            for name, key in keys.items()
        }
        validators = {
            name: {
                "public_key_hex": key.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw,
                ).hex(),
                "weight": 1,
            }
            for name, key in keys.items()
        }
        validator_set = ValidatorSet(
            VECTOR["network_id"], VECTOR["epoch"], validators,
        )
        v = VECTOR
        proposal = make_proposal(
            network_id=v["network_id"], epoch=v["epoch"], height=v["height"],
            round=v["round"], parent_hash=v["parent_hash"],
            payload_hash=v["payload_hash"], proof_hash=v["proof_hash"],
            justice_commitment={
                "justice_profile": "GAIA-JUSTICE/1",
                "policy_hash": v["justice_policy_hash"],
            },
            proposer_id="v0", proposer_private_key_hex=private_hex["v0"],
            nonce=v["nonce"], issued_at=v["issued_at"],
            expires_at=v["expires_at"], anchor_sequence=v["anchor_sequence"],
        )
        candidate_digest = hashlib.sha256(canonical_bytes(proposal)).hexdigest()
        prevotes = [
            make_vote(
                validator_id=name, validator_private_key_hex=private_hex[name],
                network_id=v["network_id"], epoch=v["epoch"], height=v["height"],
                round=v["round"], parent_hash=v["parent_hash"],
                vote_type="PREVOTE", vote_kind="CANDIDATE",
                candidate_digest=candidate_digest, approve=True, polc_digest=None,
                issued_at=v["vote_issued_at"], expires_at=v["vote_expires_at"],
            )
            for name in ("v0", "v1", "v2")
        ]
        polc_body = {
            "schema": "GCF/2", "network_id": v["network_id"],
            "epoch": v["epoch"], "height": v["height"], "round": v["round"],
            "parent_hash": v["parent_hash"], "candidate_digest": candidate_digest,
            "validator_set_hash": validator_set.digest, "prevotes": prevotes,
        }
        polc_digest = hashlib.sha256(
            b"GCF/2|POLC\x00" + canonical_bytes(polc_body)
        ).hexdigest()
        polc = {**polc_body, "polc_digest": polc_digest}
        precommits = [
            make_vote(
                validator_id=name, validator_private_key_hex=private_hex[name],
                network_id=v["network_id"], epoch=v["epoch"], height=v["height"],
                round=v["round"], parent_hash=v["parent_hash"],
                vote_type="PRECOMMIT", vote_kind="CANDIDATE",
                candidate_digest=candidate_digest, approve=True,
                polc_digest=polc_digest, issued_at=v["vote_issued_at"],
                expires_at=v["vote_expires_at"],
            )
            for name in ("v0", "v1", "v2")
        ]
        certificate_body = {
            "schema": "GCF/2", "network_id": v["network_id"],
            "epoch": v["epoch"], "height": v["height"], "round": v["round"],
            "parent_hash": v["parent_hash"], "candidate_digest": candidate_digest,
            "validator_set_hash": validator_set.digest, "proposal": proposal,
            "finalized_at": v["finalized_at"], "polc": polc,
            "precommits": precommits,
        }
        certificate_digest = hashlib.sha256(
            b"GCF/2|FINALITY-CERTIFICATE\x00" + canonical_bytes(certificate_body)
        ).hexdigest()
        certificate = {**certificate_body, "certificate_digest": certificate_digest}
        return validator_set, validators, proposal, certificate, {
            "validator_set_hash": validator_set.digest,
            "candidate_digest": candidate_digest,
            "polc_digest": polc_digest,
            "certificate_digest": certificate_digest,
        }

    def test_python_known_answer_vector_and_independent_finality_verifier(self):
        validator_set, validators, proposal, certificate, actual = self.build_vector()
        self.assertEqual(actual, VECTOR["expected"])
        checked = verify_finality_certificate(
            certificate, network_id=VECTOR["network_id"],
            epoch=VECTOR["epoch"], validators=validators,
        )
        self.assertTrue(checked["valid"])
        self.assertEqual(checked["certificate_digest"], VECTOR["expected"]["certificate_digest"])


if __name__ == "__main__":
    unittest.main()
