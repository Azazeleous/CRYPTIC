import unittest

from src.consensus.gcf import (
    ValidatorSet, make_proposal, make_vote, public_key_hex, sha256_hex,
)
from src.consensus.round_change import (
    POLC_SCHEMA, make_round_change_certificate, make_round_change_message,
    polc_digest, verify_polc, verify_round_change_certificate,
    verify_round_change_message,
)


class RoundChangeProofTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_800_000_000
        self.private = {f"v{i}": (bytes([i]) * 32).hex() for i in range(1, 5)}
        self.vset = ValidatorSet("test-net", 7, {
            name: {"public_key_hex": public_key_hex(key), "weight": 1}
            for name, key in self.private.items()
        })

    def message(self, validator_id, *, source=0, target=1, polc=None, nonce=None):
        return make_round_change_message(
            validator_id=validator_id, private_key_hex=self.private[validator_id],
            network_id="test-net", epoch=7, height=12,
            source_round=source, target_round=target,
            issued_at=self.now, expires_at=self.now + 60,
            nonce=nonce or (str(list(self.private).index(validator_id) + 1) * 32),
            highest_polc=polc,
        )

    def certificate(self, messages, target=1):
        return make_round_change_certificate(
            messages, network_id="test-net", epoch=7, height=12,
            target_round=target,
        )

    def proposal(self, payload, *, issued_at=None, expires_at=None):
        issued_at = self.now if issued_at is None else issued_at
        expires_at = self.now + 600 if expires_at is None else expires_at
        return make_proposal(
            network_id="test-net", epoch=7, height=12, round=0,
            parent_hash="0" * 64, payload_hash=payload * 64,
            proof_hash="2" * 64, justice_commitment={"justice_profile": "GAIA-JUSTICE/1"},
            proposer_id="v1", proposer_private_key_hex=self.private["v1"],
            nonce=payload * 16, issued_at=issued_at, expires_at=expires_at,
        )

    def polc(self, proposal, signers=("v1", "v2", "v3"), *, vote_issued_at=None):
        votes = [
            make_vote(
                validator_id=validator, validator_private_key_hex=self.private[validator],
                proposal=proposal, vote_type="PREVOTE", approve=True,
                issued_at=(proposal["issued_at"] + 1 if vote_issued_at is None else vote_issued_at),
            )
            for validator in signers
        ]
        item = {
            "schema": POLC_SCHEMA,
            "proposal": proposal,
            "candidate_digest": sha256_hex(__import__(
                "src.consensus.gcf", fromlist=["canonical_bytes"]
            ).canonical_bytes(proposal)),
            "validator_set_hash": self.vset.digest,
            "prevotes": votes,
        }
        item["digest"] = polc_digest(item)
        return item

    def test_strict_weighted_quorum_rejects_two_of_four(self):
        cert = self.certificate([self.message("v1"), self.message("v2")])
        result = verify_round_change_certificate(
            cert, validator_set=self.vset, height=12, clock=lambda: self.now,
        )
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "round_change_quorum_missing")

    def test_three_of_four_round_change_certificate_is_verified(self):
        cert = self.certificate([
            self.message("v1"), self.message("v2"), self.message("v3"),
        ])
        result = verify_round_change_certificate(
            cert, validator_set=self.vset, height=12, clock=lambda: self.now,
        )
        self.assertTrue(result["valid"], result)
        self.assertEqual(result["weight"], 3)
        self.assertEqual(result["quorum_weight"], 3)

    def test_signed_message_rejects_target_not_above_source(self):
        message = self.message("v1", source=1, target=1)
        result = verify_round_change_message(
            message, validator_set=self.vset, height=12, target_round=1,
            clock=lambda: self.now,
        )
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "round_change_target_invalid")

    def test_certificate_rejects_duplicate_validator(self):
        first = self.message("v1", nonce="a" * 32)
        second = self.message("v1", nonce="b" * 32)
        cert = self.certificate([first, second, self.message("v2")])
        result = verify_round_change_certificate(
            cert, validator_set=self.vset, height=12, clock=lambda: self.now,
        )
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "round_change_duplicate_validator")

    def test_highest_polc_is_independently_verified_and_selected(self):
        proposal = self.proposal("a")
        polc = self.polc(proposal)
        self.assertTrue(verify_polc(
            polc, validator_set=self.vset, clock=lambda: self.now,
        )["valid"])
        cert = self.certificate([
            self.message("v1", polc=polc),
            self.message("v2", polc=polc),
            self.message("v3", polc=polc),
        ])
        result = verify_round_change_certificate(
            cert, validator_set=self.vset, height=12, clock=lambda: self.now,
        )
        self.assertTrue(result["valid"], result)
        self.assertEqual(result["highest_polc"]["digest"], polc["digest"])
        self.assertEqual(result["highest_polc_round"], 0)

    def test_expired_proposal_cannot_be_reused_as_live_polc(self):
        proposal = self.proposal("f")
        polc = self.polc(proposal)
        result = verify_polc(
            polc, validator_set=self.vset, clock=lambda: self.now + 601,
        )
        self.assertFalse(result["valid"])
        self.assertIn("CANDIDATE_EXPIRED", result["reason"])

    def test_stale_prevote_cannot_be_reused_as_live_polc(self):
        proposal = self.proposal(
            "g", issued_at=self.now - 600, expires_at=self.now + 600,
        )
        polc = self.polc(proposal, vote_issued_at=self.now - 400)
        result = verify_polc(
            polc, validator_set=self.vset, clock=lambda: self.now,
        )
        self.assertFalse(result["valid"])
        self.assertIn("VOTE_TIME_INVALID", result["reason"])

    def test_polc_vote_list_is_bounded_by_validator_set(self):
        polc = self.polc(self.proposal("8"))
        polc["prevotes"] = polc["prevotes"] + [dict(polc["prevotes"][0])]
        polc["digest"] = polc_digest(polc)
        result = verify_polc(polc, validator_set=self.vset, clock=lambda: self.now)
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "polc_votes_invalid")

    def test_round_change_certificate_message_list_is_bounded(self):
        message = self.message("v1")
        cert = self.certificate([message] * 5)
        result = verify_round_change_certificate(
            cert, validator_set=self.vset, height=12, clock=lambda: self.now,
        )
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "round_change_certificate_messages_invalid")

    def test_round_change_verifier_rejects_unbounded_age_configuration(self):
        message = self.message("v1")
        result = verify_round_change_message(
            message, validator_set=self.vset, height=12, target_round=1,
            clock=lambda: self.now, max_age_seconds=3601,
        )
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "round_change_verifier_limits_invalid")

    def test_invalid_polc_signature_fails_closed(self):
        polc = self.polc(self.proposal("b"))
        polc["prevotes"][0]["signature"] = "AA=="
        polc["digest"] = polc_digest(polc)
        result = verify_polc(polc, validator_set=self.vset, clock=lambda: self.now)
        self.assertFalse(result["valid"])

    def test_same_round_conflicting_polcs_fail_closed(self):
        polc_a = self.polc(self.proposal("c"))
        polc_b = self.polc(self.proposal("d"))
        cert = self.certificate([
            self.message("v1", polc=polc_a),
            self.message("v2", polc=polc_b),
            self.message("v3"),
        ])
        result = verify_round_change_certificate(
            cert, validator_set=self.vset, height=12, clock=lambda: self.now,
        )
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "round_change_conflicting_same_round_polcs")



    def test_exact_two_thirds_round_change_weight_is_rejected(self):
        three = ValidatorSet("test-net", 7, {
            name: {"public_key_hex": public_key_hex(self.private[name]), "weight": 1}
            for name in ("v1", "v2", "v3")
        })
        cert = make_round_change_certificate(
            [self.message("v1"), self.message("v2")],
            network_id="test-net", epoch=7, height=12, target_round=1,
        )
        result = verify_round_change_certificate(
            cert, validator_set=three, height=12, clock=lambda: self.now,
        )
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "round_change_quorum_missing")
        self.assertEqual(three.quorum_weight(), 3)

    def test_same_candidate_same_round_polc_selection_is_order_independent(self):
        proposal = self.proposal("e")
        polc_a = self.polc(proposal, signers=("v1", "v2", "v3"))
        polc_b = self.polc(proposal, signers=("v1", "v2", "v4"))
        self.assertNotEqual(polc_a["digest"], polc_b["digest"])
        cert = self.certificate([
            self.message("v1", polc=polc_a),
            self.message("v2", polc=polc_b),
            self.message("v3"),
        ])
        forward = verify_round_change_certificate(
            cert, validator_set=self.vset, height=12, clock=lambda: self.now,
        )
        reordered = dict(cert)
        reordered["messages"] = list(reversed(cert["messages"]))
        reverse = verify_round_change_certificate(
            reordered, validator_set=self.vset, height=12, clock=lambda: self.now,
        )
        self.assertTrue(forward["valid"], forward)
        self.assertTrue(reverse["valid"], reverse)
        expected = min(polc_a["digest"], polc_b["digest"])
        self.assertEqual(forward["highest_polc"]["digest"], expected)
        self.assertEqual(reverse["highest_polc"]["digest"], expected)

if __name__ == "__main__":
    unittest.main()
