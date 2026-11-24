"""Independent GCF/2 vote verifier.

This module intentionally does not import the GCF/2 producer implementation.
It verifies the wire shape, canonical bytes, validity window, and Ed25519
signature independently. It does not authorize finality.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.consensus.gcf import ValidatorSet
from src.consensus.round_change import value_digest, verify_round_change_certificate

SCHEMA = "GCF/2"
VOTE_DOMAIN = b"GCF/2|VOTE|ED25519\x00"
PROPOSAL_DOMAIN = b"GCF/1|PROPOSAL|ED25519\x00"
VOTE_FIELDS = {
    "schema", "network_id", "epoch", "height", "round", "parent_hash",
    "vote_type", "vote_kind", "candidate_digest", "validator_id",
    "approve", "polc_digest", "issued_at", "expires_at", "signature",
}


class GCF2IndependentVerificationError(ValueError):
    pass


def _canonical_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        raise GCF2IndependentVerificationError("FLOAT_FORBIDDEN")
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    if isinstance(value, Mapping):
        result = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise GCF2IndependentVerificationError("OBJECT_KEY_INVALID")
            if key in result:
                raise GCF2IndependentVerificationError("DUPLICATE_OBJECT_KEY")
            result[key] = _canonical_value(item)
        return result
    raise GCF2IndependentVerificationError("CANONICAL_VALUE_UNSUPPORTED")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        _canonical_value(value), sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def _valid_hash(value: Any, *, nullable: bool = False) -> bool:
    if value is None:
        return nullable
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        return len(bytes.fromhex(value)) == 32
    except ValueError:
        return False


def verify_vote(vote: Any, *, network_id: str, epoch: int,
                validators: Mapping[str, Mapping[str, Any]], now: int,
                proposal: Mapping[str, Any] | None = None) -> dict:
    if not isinstance(vote, Mapping) or set(vote) != VOTE_FIELDS:
        raise GCF2IndependentVerificationError("VOTE_FIELDS_INVALID")
    if vote["schema"] != SCHEMA or vote["network_id"] != network_id:
        raise GCF2IndependentVerificationError("VOTE_NETWORK_OR_SCHEMA_INVALID")
    if vote["epoch"] != epoch:
        raise GCF2IndependentVerificationError("VOTE_EPOCH_INVALID")
    for field, minimum in (("epoch", 1), ("height", 1), ("round", 0),
                           ("issued_at", 0), ("expires_at", 1)):
        value = vote[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > (1 << 63) - 1:
            raise GCF2IndependentVerificationError(f"{field.upper()}_INVALID")
    if not isinstance(vote["validator_id"], str) or not vote["validator_id"]:
        raise GCF2IndependentVerificationError("VALIDATOR_ID_INVALID")
    if not _valid_hash(vote["parent_hash"]):
        raise GCF2IndependentVerificationError("PARENT_HASH_INVALID")
    if vote["vote_type"] not in ("PREVOTE", "PRECOMMIT"):
        raise GCF2IndependentVerificationError("VOTE_TYPE_INVALID")
    if vote["expires_at"] <= vote["issued_at"] or vote["expires_at"] - vote["issued_at"] > 300:
        raise GCF2IndependentVerificationError("VOTE_WINDOW_INVALID")
    if vote["issued_at"] > now + 30 or vote["expires_at"] < now - 30 or abs(now - vote["issued_at"]) > 300:
        raise GCF2IndependentVerificationError("VOTE_EXPIRED_OR_FUTURE")
    if vote["vote_kind"] == "NIL":
        if (vote["candidate_digest"] is not None or vote["approve"] is not None
                or vote["polc_digest"] is not None):
            raise GCF2IndependentVerificationError("NIL_VOTE_FIELDS_INVALID")
    elif vote["vote_kind"] == "CANDIDATE":
        if not _valid_hash(vote["candidate_digest"]) or type(vote["approve"]) is not bool:
            raise GCF2IndependentVerificationError("CANDIDATE_VOTE_FIELDS_INVALID")
        if not _valid_hash(vote["polc_digest"], nullable=True):
            raise GCF2IndependentVerificationError("POLC_DIGEST_INVALID")
        if vote["vote_type"] == "PREVOTE" and vote["polc_digest"] is not None:
            raise GCF2IndependentVerificationError("PREVOTE_HAS_POLC")
        if vote["vote_type"] == "PRECOMMIT" and vote["approve"] and vote["polc_digest"] is None:
            raise GCF2IndependentVerificationError("AFFIRMATIVE_PRECOMMIT_REQUIRES_POLC")
        if vote["vote_type"] == "PRECOMMIT" and not vote["approve"] and vote["polc_digest"] is not None:
            raise GCF2IndependentVerificationError("NEGATIVE_PRECOMMIT_HAS_POLC")
        if not isinstance(proposal, Mapping):
            raise GCF2IndependentVerificationError("CANDIDATE_PROPOSAL_REQUIRED")
        proposal_digest = __import__("hashlib").sha256(canonical_bytes(dict(proposal))).hexdigest()
        if (proposal_digest != vote["candidate_digest"]
                or proposal.get("network_id") != network_id
                or proposal.get("epoch") != epoch
                or proposal.get("height") != vote["height"]
                or proposal.get("round") != vote["round"]
                or proposal.get("parent_hash") != vote["parent_hash"]
                or vote["issued_at"] < proposal.get("issued_at", 0)
                or vote["expires_at"] > proposal.get("expires_at", 0)):
            raise GCF2IndependentVerificationError("CANDIDATE_CONTEXT_MISMATCH")
    else:
        raise GCF2IndependentVerificationError("VOTE_KIND_INVALID")
    validator = validators.get(vote["validator_id"])
    if not isinstance(validator, Mapping):
        raise GCF2IndependentVerificationError("UNKNOWN_VALIDATOR")
    try:
        public = bytes.fromhex(validator["public_key_hex"])
        signature = base64.b64decode(vote["signature"], validate=True)
        if len(public) != 32 or len(signature) != 64:
            raise ValueError("key_or_signature_length_invalid")
        body = {key: value for key, value in vote.items() if key != "signature"}
        Ed25519PublicKey.from_public_bytes(public).verify(
            signature, VOTE_DOMAIN + canonical_bytes(body),
        )
    except (ValueError, TypeError, KeyError, InvalidSignature) as exc:
        raise GCF2IndependentVerificationError("SIGNATURE_INVALID") from exc
    return dict(vote)


POLC_DOMAIN = b"GCF/2|POLC\x00"
CERT_DOMAIN = b"GCF/2|FINALITY-CERTIFICATE\x00"


def _validator_set_digest(network_id: str, epoch: int,
                          validators: Mapping[str, Mapping[str, Any]]) -> str:
    entries = []
    for validator_id, item in sorted(validators.items()):
        weight = item.get("weight")
        public_key = item.get("public_key_hex")
        if (not isinstance(validator_id, str) or not validator_id
                or isinstance(weight, bool) or not isinstance(weight, int) or weight < 1
                or not isinstance(public_key, str) or not _valid_hash(public_key)):
            raise GCF2IndependentVerificationError("VALIDATOR_SET_INVALID")
        entries.append({
            "validator_id": validator_id,
            "public_key_hex": public_key.lower(),
            "weight": weight,
        })
    if not entries:
        raise GCF2IndependentVerificationError("VALIDATOR_SET_EMPTY")
    return hashlib.sha256(canonical_bytes({
        "network_id": network_id, "epoch": epoch, "validators": entries,
    })).hexdigest()


def verify_finality_certificate(
    certificate: Any, *, network_id: str, epoch: int,
    validators: Mapping[str, Mapping[str, Any]], proposal: Mapping[str, Any] | None = None,
) -> dict:
    """Independently verify a GCF/2 POLC and affirmative PRECOMMIT certificate."""
    certificate_fields = {
        "schema", "network_id", "epoch", "height", "round", "parent_hash",
        "candidate_digest", "validator_set_hash", "proposal", "finalized_at", "polc",
        "precommits", "certificate_digest",
    }
    polc_fields = {
        "schema", "network_id", "epoch", "height", "round", "parent_hash",
        "candidate_digest", "validator_set_hash", "prevotes", "polc_digest",
    }

    def fail(reason: str):
        raise GCF2IndependentVerificationError(reason)

    if not isinstance(certificate, Mapping) or set(certificate) != certificate_fields:
        fail("FINALITY_CERTIFICATE_FIELDS_INVALID")
    if certificate["schema"] != SCHEMA or certificate["network_id"] != network_id:
        fail("FINALITY_CERTIFICATE_NETWORK_OR_SCHEMA_INVALID")
    if certificate["epoch"] != epoch:
        fail("FINALITY_CERTIFICATE_EPOCH_INVALID")
    for field, minimum in (("height", 1), ("round", 0), ("finalized_at", 0)):
        value = certificate[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            fail("FINALITY_CERTIFICATE_" + field.upper() + "_INVALID")
    embedded_proposal = certificate["proposal"]
    if not isinstance(embedded_proposal, Mapping):
        fail("FINALITY_CERTIFICATE_PROPOSAL_INVALID")
    if proposal is not None and dict(proposal) != dict(embedded_proposal):
        fail("FINALITY_CERTIFICATE_PROPOSAL_MISMATCH")
    proposal = embedded_proposal
    _verify_gcf1_proposal_signature(
        proposal, network_id=network_id, epoch=epoch,
        validators=validators, verified_at=certificate["finalized_at"],
    )
    if proposal["round"] == 0:
        if "round_change_certificate" in proposal:
            fail("FINALITY_ROUND_ZERO_HAS_ROUND_CHANGE_CERTIFICATE")
    else:
        round_change = proposal.get("round_change_certificate")
        if not isinstance(round_change, Mapping):
            fail("FINALITY_ROUND_CHANGE_CERTIFICATE_REQUIRED")
        validator_set = ValidatorSet(network_id, epoch, validators)
        checked_round_change = verify_round_change_certificate(
            round_change, validator_set=validator_set,
            height=proposal["height"], clock=lambda: certificate["finalized_at"],
        )
        if (not checked_round_change.get("valid")
                or checked_round_change.get("target_round") != proposal["round"]):
            fail("FINALITY_ROUND_CHANGE_CERTIFICATE_INVALID")
        highest_polc = checked_round_change.get("highest_polc")
        if (highest_polc is not None
                and value_digest(highest_polc["proposal"]) != value_digest(proposal)):
            fail("FINALITY_PROPOSAL_CONFLICTS_WITH_HIGHEST_POLC")

    candidate_digest = hashlib.sha256(canonical_bytes(dict(proposal))).hexdigest()
    if (
        proposal.get("network_id") != network_id
        or proposal.get("epoch") != epoch
        or proposal.get("height") != certificate["height"]
        or proposal.get("round") != certificate["round"]
        or proposal.get("parent_hash") != certificate["parent_hash"]
        or candidate_digest != certificate["candidate_digest"]
        or not _valid_hash(certificate["parent_hash"])
    ):
        fail("FINALITY_CERTIFICATE_CANDIDATE_CONTEXT_MISMATCH")

    set_digest = _validator_set_digest(network_id, epoch, validators)
    if certificate["validator_set_hash"] != set_digest:
        fail("FINALITY_CERTIFICATE_VALIDATOR_SET_MISMATCH")

    polc = certificate["polc"]
    if not isinstance(polc, Mapping) or set(polc) != polc_fields:
        fail("POLC_FIELDS_INVALID")
    for field in ("schema", "network_id", "epoch", "height", "round",
                  "parent_hash", "candidate_digest", "validator_set_hash"):
        if polc[field] != certificate[field if field != "validator_set_hash" else field]:
            fail("POLC_CONTEXT_MISMATCH")
    polc_body = {key: value for key, value in polc.items() if key != "polc_digest"}
    expected_polc_digest = hashlib.sha256(
        POLC_DOMAIN + canonical_bytes(polc_body)
    ).hexdigest()
    if polc["polc_digest"] != expected_polc_digest:
        fail("POLC_DIGEST_INVALID")
    prevotes = polc["prevotes"]
    if not isinstance(prevotes, list) or not prevotes:
        fail("POLC_PREVOTES_INVALID")
    prevote_ids = []
    prevote_weight = 0
    for vote in prevotes:
        checked = verify_vote(
            vote, network_id=network_id, epoch=epoch,
            validators=validators, now=certificate["finalized_at"],
            proposal=proposal,
        )
        if (checked["vote_type"] != "PREVOTE"
                or checked["vote_kind"] != "CANDIDATE"
                or checked["approve"] is not True
                or checked["candidate_digest"] != candidate_digest
                or checked["polc_digest"] is not None):
            fail("POLC_CONTAINS_NON_AFFIRMATIVE_OR_MISMATCHED_PREVOTE")
        prevote_ids.append(checked["validator_id"])
        prevote_weight += validators[checked["validator_id"]]["weight"]
    if prevote_ids != sorted(set(prevote_ids)):
        fail("POLC_PREVOTE_ORDER_OR_DUPLICATE_INVALID")

    precommits = certificate["precommits"]
    if not isinstance(precommits, list) or not precommits:
        fail("FINALITY_PRECOMMITS_INVALID")
    precommit_ids = []
    precommit_weight = 0
    for vote in precommits:
        checked = verify_vote(
            vote, network_id=network_id, epoch=epoch,
            validators=validators, now=certificate["finalized_at"],
            proposal=proposal,
        )
        if (checked["vote_type"] != "PRECOMMIT"
                or checked["vote_kind"] != "CANDIDATE"
                or checked["approve"] is not True
                or checked["candidate_digest"] != candidate_digest
                or checked["polc_digest"] != polc["polc_digest"]):
            fail("FINALITY_CONTAINS_NON_AFFIRMATIVE_OR_MISMATCHED_PRECOMMIT")
        precommit_ids.append(checked["validator_id"])
        precommit_weight += validators[checked["validator_id"]]["weight"]
    if precommit_ids != sorted(set(precommit_ids)):
        fail("FINALITY_PRECOMMIT_ORDER_OR_DUPLICATE_INVALID")

    total_weight = sum(item["weight"] for item in validators.values())
    quorum_weight = (2 * total_weight) // 3 + 1
    if prevote_weight < quorum_weight:
        fail("POLC_QUORUM_NOT_REACHED")
    if precommit_weight < quorum_weight:
        fail("FINALITY_PRECOMMIT_QUORUM_NOT_REACHED")

    body = {key: value for key, value in certificate.items()
            if key != "certificate_digest"}
    expected_certificate_digest = hashlib.sha256(
        CERT_DOMAIN + canonical_bytes(body)
    ).hexdigest()
    if certificate["certificate_digest"] != expected_certificate_digest:
        fail("FINALITY_CERTIFICATE_DIGEST_INVALID")
    return {
        "valid": True,
        "reason": "gcf2_finality_certificate_valid",
        "candidate_digest": candidate_digest,
        "height": certificate["height"],
        "prevote_weight": prevote_weight,
        "precommit_weight": precommit_weight,
        "quorum_weight": quorum_weight,
        "validator_set_hash": set_digest,
        "certificate_digest": expected_certificate_digest,
    }


def _verify_gcf1_proposal_signature(
    proposal: Mapping[str, Any], *, network_id: str, epoch: int,
    validators: Mapping[str, Mapping[str, Any]], verified_at: int,
) -> None:
    required = {
        "schema", "network_id", "epoch", "height", "round", "parent_hash",
        "payload_hash", "proof_hash", "justice_commitment", "issued_at",
        "expires_at", "proposer_id", "proposer_public_key", "nonce", "signature",
    }
    allowed = required | {"anchor_sequence", "round_change_certificate"}
    if (not isinstance(proposal, Mapping) or not required.issubset(proposal)
            or not set(proposal).issubset(allowed)):
        raise GCF2IndependentVerificationError("PROPOSAL_FIELDS_INVALID")
    if proposal["schema"] != "GCF/1" or proposal["network_id"] != network_id:
        raise GCF2IndependentVerificationError("PROPOSAL_NETWORK_OR_SCHEMA_INVALID")
    if proposal["epoch"] != epoch:
        raise GCF2IndependentVerificationError("PROPOSAL_EPOCH_INVALID")
    for field, minimum in (("height", 1), ("round", 0),
                           ("issued_at", 0), ("expires_at", 1)):
        value = proposal[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            raise GCF2IndependentVerificationError("PROPOSAL_" + field.upper() + "_INVALID")
    if (proposal["expires_at"] <= proposal["issued_at"]
            or proposal["expires_at"] - proposal["issued_at"] > 3600
            or proposal["issued_at"] > verified_at + 30
            or proposal["expires_at"] < verified_at - 30):
        raise GCF2IndependentVerificationError("PROPOSAL_TIME_WINDOW_INVALID")
    for field in ("parent_hash", "payload_hash", "proof_hash"):
        if not _valid_hash(proposal[field]):
            raise GCF2IndependentVerificationError("PROPOSAL_" + field.upper() + "_INVALID")
    proposer_id = proposal["proposer_id"]
    validator = validators.get(proposer_id)
    if not isinstance(validator, Mapping):
        raise GCF2IndependentVerificationError("PROPOSER_NOT_IN_VALIDATOR_SET")
    public_key_hex = validator.get("public_key_hex")
    if proposal["proposer_public_key"] != public_key_hex:
        raise GCF2IndependentVerificationError("PROPOSER_KEY_MISMATCH")
    try:
        public = bytes.fromhex(public_key_hex)
        signature = base64.b64decode(proposal["signature"], validate=True)
        body = {key: value for key, value in proposal.items() if key != "signature"}
        if len(public) != 32 or len(signature) != 64:
            raise ValueError("key_or_signature_length_invalid")
        Ed25519PublicKey.from_public_bytes(public).verify(
            signature, PROPOSAL_DOMAIN + canonical_bytes(body),
        )
    except (ValueError, TypeError, KeyError, InvalidSignature) as exc:
        raise GCF2IndependentVerificationError("PROPOSAL_SIGNATURE_INVALID") from exc
