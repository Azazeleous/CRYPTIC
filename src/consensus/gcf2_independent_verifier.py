"""Independent GCF/2 vote verifier.

This module intentionally does not import the GCF/2 producer implementation.
It verifies the wire shape, canonical bytes, validity window, and Ed25519
signature independently. It does not authorize finality.
"""
from __future__ import annotations

import base64
import json
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA = "GCF/2"
VOTE_DOMAIN = b"GCF/2|VOTE|ED25519\\x00"
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
