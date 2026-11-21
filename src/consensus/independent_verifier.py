"""Standalone GCF/1 finality verifier.

This module intentionally does not import or instantiate GCFEngine and does not
call its proposal/vote validation methods. It independently reconstructs the
canonical profile, validator-set digest, signatures, quorum, and POLC.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Callable, Mapping

SCHEMA = "GCF/1"
PROPOSAL_DOMAIN = b"GCF/1|PROPOSAL|ED25519\x00"
VOTE_DOMAIN = b"GCF/1|VOTE|ED25519\x00"
CERT_DOMAIN = b"GCF/1|FINALITY-CERTIFICATE\x00"

PROPOSAL_FIELDS = {
    "schema", "network_id", "epoch", "height", "round", "parent_hash",
    "payload_hash", "proof_hash", "justice_commitment", "issued_at",
    "expires_at", "proposer_id", "proposer_public_key", "nonce", "signature",
}
VOTE_FIELDS = {
    "schema", "network_id", "epoch", "height", "round", "candidate_digest",
    "validator_id", "vote_type", "approve", "polc_digest", "issued_at", "signature",
}
CERTIFICATE_FIELDS = {
    "schema", "network_id", "epoch", "height", "round", "candidate_digest",
    "proposal", "validator_set", "polc", "precommits",
    "total_voting_weight", "precommit_weight",
}


class IndependentVerificationError(ValueError):
    pass


def _canonical_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        raise IndependentVerificationError("FLOAT_FORBIDDEN")
    if isinstance(value, list):
        return [_canonical_value(x) for x in value]
    if isinstance(value, Mapping):
        result = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise IndependentVerificationError("NON_ASCII_OBJECT_KEY")
            if key in result:
                raise IndependentVerificationError("DUPLICATE_OBJECT_KEY")
            result[key] = _canonical_value(item)
        return result
    raise IndependentVerificationError("UNSUPPORTED_CANONICAL_VALUE")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        _canonical_value(value), sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash32(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise IndependentVerificationError(f"{field}_NOT_TEXT")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise IndependentVerificationError(f"{field}_NOT_HEX") from exc
    if len(raw) != 32:
        raise IndependentVerificationError(f"{field}_WRONG_LENGTH")
    return raw.hex()


def _integer(value: Any, field: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise IndependentVerificationError(f"{field}_INVALID_INTEGER")
    return value


def _ed25519_verify(public_hex: str, signature_b64: str, message: bytes) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        public = bytes.fromhex(_hash32(public_hex, "PUBLIC_KEY"))
        signature = base64.b64decode(signature_b64, validate=True)
        if len(signature) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
        return True
    except Exception:
        return False


def _gate(gate: Callable | None, *args: Any) -> bool:
    if gate is None:
        return False
    try:
        result = gate(*args)
    except Exception:
        return False
    return result.allowed is True if hasattr(result, "allowed") else result is True


def _proposal_digest(proposal: Mapping[str, Any]) -> str:
    return _digest(canonical_bytes(dict(proposal)))


def _verify_proposal(proposal: Any, network_id: str, epoch: int) -> str:
    if not isinstance(proposal, Mapping) or set(proposal) != PROPOSAL_FIELDS:
        raise IndependentVerificationError("PROPOSAL_FIELDS_INVALID")
    if proposal["schema"] != SCHEMA or proposal["network_id"] != network_id:
        raise IndependentVerificationError("PROPOSAL_NETWORK_OR_SCHEMA_INVALID")
    if _integer(proposal["epoch"], "EPOCH", 1) != epoch:
        raise IndependentVerificationError("PROPOSAL_EPOCH_INVALID")
    _integer(proposal["height"], "HEIGHT", 1)
    _integer(proposal["round"], "ROUND")
    _hash32(proposal["parent_hash"], "PARENT_HASH")
    _hash32(proposal["payload_hash"], "PAYLOAD_HASH")
    _hash32(proposal["proof_hash"], "PROOF_HASH")
    issued = _integer(proposal["issued_at"], "PROPOSAL_ISSUED_AT")
    expires = _integer(proposal["expires_at"], "PROPOSAL_EXPIRES_AT")
    if expires <= issued or expires - issued > 3600:
        raise IndependentVerificationError("PROPOSAL_TIME_WINDOW_INVALID")
    if not isinstance(proposal["proposer_id"], str) or not proposal["proposer_id"]:
        raise IndependentVerificationError("PROPOSER_ID_INVALID")
    nonce = proposal["nonce"]
    if not isinstance(nonce, str) or not 16 <= len(nonce) <= 128:
        raise IndependentVerificationError("PROPOSAL_NONCE_INVALID")
    if not isinstance(proposal["justice_commitment"], Mapping):
        raise IndependentVerificationError("JUSTICE_COMMITMENT_INVALID")
    public = _hash32(proposal["proposer_public_key"], "PROPOSER_PUBLIC_KEY")
    body = {k: v for k, v in proposal.items() if k != "signature"}
    if not _ed25519_verify(
        public, proposal["signature"],
        PROPOSAL_DOMAIN + canonical_bytes(body),
    ):
        raise IndependentVerificationError("PROPOSER_SIGNATURE_INVALID")
    return _proposal_digest(proposal)


def _validator_set(raw: Any, network_id: str, epoch: int) -> tuple[dict, int, str]:
    if not isinstance(raw, Mapping) or set(raw) != {
        "network_id", "epoch", "validators", "validator_set_hash"
    }:
        raise IndependentVerificationError("VALIDATOR_SET_FIELDS_INVALID")
    if raw["network_id"] != network_id or raw["epoch"] != epoch:
        raise IndependentVerificationError("VALIDATOR_SET_NETWORK_OR_EPOCH_INVALID")
    members = raw["validators"]
    if not isinstance(members, list) or not members:
        raise IndependentVerificationError("VALIDATOR_SET_EMPTY")
    parsed = {}
    for member in members:
        if not isinstance(member, Mapping) or set(member) != {
            "validator_id", "public_key_hex", "weight"
        }:
            raise IndependentVerificationError("VALIDATOR_ENTRY_INVALID")
        name = member["validator_id"]
        if not isinstance(name, str) or not name or name in parsed:
            raise IndependentVerificationError("VALIDATOR_ID_DUPLICATE_OR_INVALID")
        parsed[name] = {
            "public_key_hex": _hash32(member["public_key_hex"], "VALIDATOR_PUBLIC_KEY"),
            "weight": _integer(member["weight"], "VALIDATOR_WEIGHT", 1),
        }
    normalized = {
        "network_id": network_id,
        "epoch": epoch,
        "validators": [
            {"validator_id": name, "public_key_hex": item["public_key_hex"],
             "weight": item["weight"]}
            for name, item in sorted(parsed.items())
        ],
    }
    set_hash = _digest(canonical_bytes(normalized))
    if set_hash != _hash32(raw["validator_set_hash"], "VALIDATOR_SET_HASH"):
        raise IndependentVerificationError("VALIDATOR_SET_HASH_MISMATCH")
    total = sum(x["weight"] for x in parsed.values())
    return parsed, total, set_hash


def _verify_vote(vote: Any, proposal: Mapping[str, Any], validators: Mapping[str, Any],
                 candidate_digest: str, vote_type: str,
                 polc_digest: str | None = None) -> str:
    if not isinstance(vote, Mapping) or set(vote) != VOTE_FIELDS:
        raise IndependentVerificationError("VOTE_FIELDS_INVALID")
    if vote["schema"] != SCHEMA:
        raise IndependentVerificationError("VOTE_SCHEMA_INVALID")
    for field in ("network_id", "epoch", "height", "round"):
        if vote[field] != proposal[field]:
            raise IndependentVerificationError(f"VOTE_{field.upper()}_MISMATCH")
    if vote["candidate_digest"] != candidate_digest:
        raise IndependentVerificationError("VOTE_CANDIDATE_MISMATCH")
    if vote["vote_type"] != vote_type or vote["approve"] is not True:
        raise IndependentVerificationError("VOTE_TYPE_OR_APPROVAL_INVALID")
    validator_id = vote["validator_id"]
    if validator_id not in validators:
        raise IndependentVerificationError("UNKNOWN_VALIDATOR")
    issued = _integer(vote["issued_at"], "VOTE_ISSUED_AT")
    if not proposal["issued_at"] <= issued <= proposal["expires_at"]:
        raise IndependentVerificationError("VOTE_OUTSIDE_PROPOSAL_WINDOW")
    if vote_type == "PREVOTE" and vote["polc_digest"] is not None:
        raise IndependentVerificationError("PREVOTE_HAS_POLC")
    if vote_type == "PRECOMMIT" and vote["polc_digest"] != polc_digest:
        raise IndependentVerificationError("PRECOMMIT_POLC_MISMATCH")
    body = {k: v for k, v in vote.items() if k != "signature"}
    if not _ed25519_verify(
        validators[validator_id]["public_key_hex"], vote["signature"],
        VOTE_DOMAIN + canonical_bytes(body),
    ):
        raise IndependentVerificationError("VOTE_SIGNATURE_INVALID")
    return validator_id


def verify_certificate(certificate: Any, *,
                       hccgn_verifier: Callable | None = None,
                       god_authorizer: Callable | None = None,
                       justice_verifier: Callable | None = None) -> dict:
    """Verify a GCF/1 finality certificate without invoking GCFEngine."""
    try:
        if not isinstance(certificate, Mapping) or set(certificate) != CERTIFICATE_FIELDS:
            raise IndependentVerificationError("CERTIFICATE_FIELDS_INVALID")
        if certificate["schema"] != SCHEMA:
            raise IndependentVerificationError("CERTIFICATE_SCHEMA_INVALID")
        network_id = certificate["network_id"]
        epoch = _integer(certificate["epoch"], "CERTIFICATE_EPOCH", 1)
        if not isinstance(network_id, str) or not network_id:
            raise IndependentVerificationError("NETWORK_ID_INVALID")
        proposal = certificate["proposal"]
        digest = _verify_proposal(proposal, network_id, epoch)
        if certificate["candidate_digest"] != digest:
            raise IndependentVerificationError("CANDIDATE_DIGEST_MISMATCH")
        cert_height = _integer(certificate["height"], "CERTIFICATE_HEIGHT", 1)
        cert_round = _integer(certificate["round"], "CERTIFICATE_ROUND")
        if cert_height != proposal["height"] or cert_round != proposal["round"]:
            raise IndependentVerificationError("CERTIFICATE_POSITION_MISMATCH")

        validators, total_weight, set_hash = _validator_set(
            certificate["validator_set"], network_id, epoch
        )
        if not _gate(hccgn_verifier, proposal):
            raise IndependentVerificationError("HCCGN_PROOF_NOT_INDEPENDENTLY_VERIFIED")
        if not _gate(god_authorizer, "gcf.propose", proposal):
            raise IndependentVerificationError("GOD_POLICY_NOT_AUTHORIZED")
        if not _gate(justice_verifier, proposal):
            raise IndependentVerificationError("JUSTICE_EVIDENCE_NOT_VERIFIED")

        polc = certificate["polc"]
        if not isinstance(polc, Mapping) or set(polc) != {"digest", "prevotes"}:
            raise IndependentVerificationError("POLC_FIELDS_INVALID")
        prevotes = polc["prevotes"]
        if not isinstance(prevotes, list):
            raise IndependentVerificationError("PREVOTE_LIST_INVALID")
        seen_prevotes = set()
        prevote_weight = 0
        for vote in prevotes:
            validator_id = _verify_vote(
                vote, proposal, validators, digest, "PREVOTE"
            )
            if validator_id in seen_prevotes:
                raise IndependentVerificationError("DUPLICATE_PREVOTE")
            seen_prevotes.add(validator_id)
            prevote_weight += validators[validator_id]["weight"]
        quorum = (2 * total_weight) // 3 + 1
        if prevote_weight < quorum:
            raise IndependentVerificationError("PREVOTE_QUORUM_NOT_REACHED")
        polc_body = {
            "schema": SCHEMA, "candidate_digest": digest,
            "validator_set_hash": set_hash, "prevotes": prevotes,
        }
        expected_polc = _digest(CERT_DOMAIN + canonical_bytes(polc_body))
        if _hash32(polc["digest"], "POLC_DIGEST") != expected_polc:
            raise IndependentVerificationError("POLC_DIGEST_MISMATCH")

        precommits = certificate["precommits"]
        if not isinstance(precommits, list):
            raise IndependentVerificationError("PRECOMMIT_LIST_INVALID")
        seen_precommits = set()
        precommit_weight = 0
        for vote in precommits:
            validator_id = _verify_vote(
                vote, proposal, validators, digest, "PRECOMMIT", expected_polc
            )
            if validator_id in seen_precommits:
                raise IndependentVerificationError("DUPLICATE_PRECOMMIT")
            seen_precommits.add(validator_id)
            precommit_weight += validators[validator_id]["weight"]
        if precommit_weight < quorum:
            raise IndependentVerificationError("PRECOMMIT_QUORUM_NOT_REACHED")
        declared_total = _integer(certificate["total_voting_weight"], "TOTAL_VOTING_WEIGHT", 1)
        declared_precommit = _integer(certificate["precommit_weight"], "PRECOMMIT_WEIGHT", 0)
        if declared_total != total_weight:
            raise IndependentVerificationError("TOTAL_WEIGHT_MISMATCH")
        if declared_precommit != precommit_weight:
            raise IndependentVerificationError("PRECOMMIT_WEIGHT_MISMATCH")
        return {
            "valid": True, "reason": "independent_finality_verified",
            "candidate_digest": digest, "height": proposal["height"],
            "validator_set_hash": set_hash, "total_weight": total_weight,
            "quorum_weight": quorum, "prevote_weight": prevote_weight,
            "precommit_weight": precommit_weight,
        }
    except (IndependentVerificationError, TypeError, ValueError, KeyError) as exc:
        return {"valid": False, "reason": str(exc)}
