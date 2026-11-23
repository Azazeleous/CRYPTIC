"""GCF/2 explicit nil-vote primitives.

GCF/1 remains unchanged. GCF/2 votes use a distinct signature domain and
explicit vote_kind values. This module is a protocol primitive layer; it does
not by itself authorize finality or replace the GCF/1 engine.
"""
from __future__ import annotations

from typing import Any, Mapping

from src.consensus.gcf import (
    GCFError, ValidatorSet, canonical_bytes, sign_object, verify_object,
)

SCHEMA = "GCF/2"
VOTE_DOMAIN = b"GCF/2|VOTE|ED25519\x00"
MAX_VOTE_LIFETIME_SECONDS = 300
VOTE_FIELDS = {
    "schema", "network_id", "epoch", "height", "round", "parent_hash",
    "vote_type", "vote_kind", "candidate_digest", "validator_id",
    "approve", "polc_digest", "issued_at", "expires_at", "signature",
}


def _integer(value: Any, field: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise GCFError(f"GCF2_{field}_INVALID")
    return value


def _hash(value: Any, field: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or len(value) != 64:
        raise GCFError(f"GCF2_{field}_INVALID")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise GCFError(f"GCF2_{field}_INVALID") from exc
    return value.lower()


def make_vote(
    *, validator_id: str, validator_private_key_hex: str,
    network_id: str, epoch: int, height: int, round: int,
    parent_hash: str, vote_type: str, vote_kind: str,
    candidate_digest: str | None = None, approve: bool | None = None,
    polc_digest: str | None = None, issued_at: int, expires_at: int,
) -> dict:
    """Create a signed GCF/2 candidate or nil vote."""
    body = {
        "schema": SCHEMA,
        "network_id": network_id,
        "epoch": _integer(epoch, "EPOCH", 1),
        "height": _integer(height, "HEIGHT", 1),
        "round": _integer(round, "ROUND"),
        "parent_hash": _hash(parent_hash, "PARENT_HASH"),
        "vote_type": vote_type,
        "vote_kind": vote_kind,
        "candidate_digest": _hash(candidate_digest, "CANDIDATE_DIGEST", nullable=True),
        "validator_id": validator_id,
        "approve": approve,
        "polc_digest": _hash(polc_digest, "POLC_DIGEST", nullable=True),
        "issued_at": _integer(issued_at, "ISSUED_AT"),
        "expires_at": _integer(expires_at, "EXPIRES_AT"),
    }
    _validate_semantics(body)
    return {**body, "signature": sign_object(validator_private_key_hex, VOTE_DOMAIN, body)}


def _validate_semantics(vote: Mapping[str, Any]) -> None:
    for field, minimum in (("epoch", 1), ("height", 1), ("round", 0),
                           ("issued_at", 0), ("expires_at", 1)):
        value = vote.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > (1 << 63) - 1:
            raise GCFError(f"GCF2_{field.upper()}_INVALID")
    if not isinstance(vote.get("network_id"), str) or not vote["network_id"]:
        raise GCFError("GCF2_NETWORK_ID_INVALID")
    if not isinstance(vote.get("validator_id"), str) or not vote["validator_id"]:
        raise GCFError("GCF2_VALIDATOR_ID_INVALID")
    _hash(vote.get("parent_hash"), "PARENT_HASH")
    if vote["vote_type"] not in ("PREVOTE", "PRECOMMIT"):
        raise GCFError("GCF2_VOTE_TYPE_INVALID")
    if vote["vote_kind"] == "NIL":
        if (vote["candidate_digest"] is not None or vote["approve"] is not None
                or vote["polc_digest"] is not None):
            raise GCFError("GCF2_NIL_VOTE_MUST_NOT_BIND_CANDIDATE")
    elif vote["vote_kind"] == "CANDIDATE":
        if vote["candidate_digest"] is None or not isinstance(vote["approve"], bool):
            raise GCFError("GCF2_CANDIDATE_VOTE_FIELDS_INVALID")
        _hash(vote["candidate_digest"], "CANDIDATE_DIGEST")
        if vote["polc_digest"] is not None:
            _hash(vote["polc_digest"], "POLC_DIGEST")
        if vote["vote_type"] == "PREVOTE" and vote["polc_digest"] is not None:
            raise GCFError("GCF2_PREVOTE_MUST_NOT_CARRY_POLC")
        if vote["vote_type"] == "PRECOMMIT" and vote["approve"] and vote["polc_digest"] is None:
            raise GCFError("GCF2_AFFIRMATIVE_PRECOMMIT_REQUIRES_POLC")
        if vote["vote_type"] == "PRECOMMIT" and not vote["approve"] and vote["polc_digest"] is not None:
            raise GCFError("GCF2_NEGATIVE_PRECOMMIT_MUST_NOT_CARRY_POLC")
    else:
        raise GCFError("GCF2_VOTE_KIND_INVALID")
    if vote["expires_at"] <= vote["issued_at"]:
        raise GCFError("GCF2_VOTE_WINDOW_INVALID")
    if vote["expires_at"] - vote["issued_at"] > MAX_VOTE_LIFETIME_SECONDS:
        raise GCFError("GCF2_VOTE_WINDOW_TOO_LONG")


def verify_vote(
    vote: Mapping[str, Any], *, validator_set: ValidatorSet,
    clock, proposal: Mapping[str, Any] | None = None,
) -> dict:
    """Verify a GCF/2 vote; NIL votes are valid without a candidate proposal."""
    if not isinstance(vote, Mapping) or set(vote) != VOTE_FIELDS:
        raise GCFError("GCF2_VOTE_FIELDS_INVALID")
    if vote["schema"] != SCHEMA or vote["network_id"] != validator_set.network_id:
        raise GCFError("GCF2_VOTE_NETWORK_OR_SCHEMA_INVALID")
    if vote["epoch"] != validator_set.epoch:
        raise GCFError("GCF2_VOTE_EPOCH_INVALID")
    _validate_semantics(vote)
    now = int(clock())
    if vote["issued_at"] > now + 30 or vote["expires_at"] < now - 30:
        raise GCFError("GCF2_VOTE_EXPIRED_OR_FUTURE")
    if abs(now - vote["issued_at"]) > 300:
        raise GCFError("GCF2_VOTE_TIME_INVALID")
    validator = validator_set.validators.get(vote["validator_id"])
    if validator is None:
        raise GCFError("UNKNOWN_VALIDATOR")
    if vote["vote_kind"] == "CANDIDATE":
        if not isinstance(proposal, Mapping):
            raise GCFError("GCF2_CANDIDATE_PROPOSAL_REQUIRED")
        from src.consensus.gcf import sha256_hex
        if (proposal.get("network_id") != vote["network_id"]
                or proposal.get("epoch") != vote["epoch"]
                or proposal.get("height") != vote["height"]
                or proposal.get("round") != vote["round"]
                or proposal.get("parent_hash") != vote["parent_hash"]
                or sha256_hex(canonical_bytes(proposal)) != vote["candidate_digest"]):
            raise GCFError("GCF2_CANDIDATE_CONTEXT_MISMATCH")
        if vote["issued_at"] < proposal["issued_at"] or vote["expires_at"] > proposal["expires_at"]:
            raise GCFError("GCF2_CANDIDATE_WINDOW_MISMATCH")
    if not verify_object(
        validator.public_key_hex, vote["signature"], VOTE_DOMAIN,
        {key: value for key, value in vote.items() if key != "signature"},
    ):
        raise GCFError("GCF2_VALIDATOR_SIGNATURE_INVALID")
    return dict(vote)


def tally_votes(votes: list[Mapping[str, Any]], *, validator_set: ValidatorSet,
                clock, vote_type: str, candidate_digest: str | None = None,
                proposal: Mapping[str, Any] | None = None) -> dict:
    """Verify and tally one round/phase slot set; nil never contributes to candidate quorum."""
    if vote_type not in ("PREVOTE", "PRECOMMIT") or not isinstance(votes, list) or not votes:
        raise GCFError("GCF2_TALLY_INPUT_INVALID")
    seen: set[str] = set()
    candidate_ids: set[str] = set()
    nil_ids: set[str] = set()
    negative_ids: set[str] = set()
    context = None
    for vote in votes:
        checked = verify_vote(vote, validator_set=validator_set, clock=clock,
                              proposal=proposal if vote.get("vote_kind") == "CANDIDATE" else None)
        current = tuple(checked[key] for key in
                        ("network_id", "epoch", "height", "round", "parent_hash", "vote_type"))
        if context is None:
            context = current
        elif context != current:
            raise GCFError("GCF2_TALLY_CONTEXT_MISMATCH")
        if checked["vote_type"] != vote_type:
            raise GCFError("GCF2_TALLY_PHASE_MISMATCH")
        validator_id = checked["validator_id"]
        if validator_id in seen:
            raise GCFError("GCF2_DUPLICATE_VALIDATOR_VOTE_SLOT")
        seen.add(validator_id)
        if checked["vote_kind"] == "NIL":
            nil_ids.add(validator_id)
        elif checked["vote_kind"] == "CANDIDATE":
            if checked["candidate_digest"] != candidate_digest:
                raise GCFError("GCF2_CANDIDATE_TALLY_MISMATCH")
            if checked["approve"] is True:
                candidate_ids.add(validator_id)
            else:
                negative_ids.add(validator_id)
        else:
            raise GCFError("GCF2_VOTE_KIND_INVALID")
    candidate_weight = validator_set.weight_of(candidate_ids)
    nil_weight = validator_set.weight_of(nil_ids)
    negative_weight = validator_set.weight_of(negative_ids)
    quorum = validator_set.quorum_weight()
    return {
        "candidate_weight": candidate_weight,
        "nil_weight": nil_weight,
        "negative_weight": negative_weight,
        "quorum_weight": quorum,
        "candidate_quorum": candidate_weight >= quorum,
        "nil_quorum": nil_weight >= quorum,
    }
