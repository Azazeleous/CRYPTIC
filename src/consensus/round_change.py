"""Pure, fail-closed GCF round-change proof verification.

This module intentionally does not mutate consensus locks, advance engine rounds,
or authorize signatures. It supplies independently verifiable proof primitives
for the later integrated state-machine change.
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Callable, Mapping

from src.consensus.gcf import (
    CERT_DOMAIN, PROPOSAL_DOMAIN, SCHEMA, VOTE_DOMAIN, GCFEngine, GCFError,
    ValidatorSet, canonical_bytes, sha256_hex, verify_object, _unsigned,
)

ROUND_CHANGE_SCHEMA = "GCF-ROUND-CHANGE/1"
POLC_SCHEMA = "GCF-POLC/1"
ROUND_CHANGE_DOMAIN = b"GCF/1|ROUND-CHANGE|ED25519\x00"
ROUND_CHANGE_CERT_DOMAIN = b"GCF/1|ROUND-CHANGE-CERTIFICATE\x00"
_NONCE = re.compile(r"^[0-9a-f]{32}$")


def _fail(reason: str) -> dict:
    return {"valid": False, "reason": reason}


def _engine_for(vset: ValidatorSet, clock: Callable[[], float]) -> GCFEngine:
    engine = object.__new__(GCFEngine)
    engine.validator_set = vset
    engine.clock = clock
    engine.max_clock_skew = 30
    return engine


def polc_digest(polc: Mapping[str, Any]) -> str:
    body = {
        "schema": SCHEMA,
        "candidate_digest": polc["candidate_digest"],
        "validator_set_hash": polc["validator_set_hash"],
        "prevotes": polc["prevotes"],
    }
    return sha256_hex(CERT_DOMAIN + canonical_bytes(body))


def verify_polc(polc: Mapping[str, Any], *, validator_set: ValidatorSet,
                clock: Callable[[], float] = time.time) -> dict:
    """Verify a complete affirmative PREVOTE certificate; never trust claimed weight."""
    try:
        if not isinstance(polc, Mapping) or set(polc) != {
            "schema", "proposal", "candidate_digest", "validator_set_hash",
            "prevotes", "digest",
        }:
            return _fail("polc_fields_invalid")
        if polc["schema"] != POLC_SCHEMA:
            return _fail("polc_schema_invalid")
        if polc["validator_set_hash"] != validator_set.digest:
            return _fail("polc_validator_set_mismatch")
        proposal = polc["proposal"]
        if not isinstance(proposal, Mapping):
            return _fail("polc_proposal_invalid")
        engine = _engine_for(validator_set, lambda: proposal["issued_at"])
        digest, normalized = engine._validate_proposal(proposal)
        if digest != polc["candidate_digest"]:
            return _fail("polc_candidate_mismatch")
        votes = polc["prevotes"]
        if not isinstance(votes, list) or not votes:
            return _fail("polc_votes_invalid")
        seen: set[str] = set()
        for vote in votes:
            issued = vote.get("issued_at") if isinstance(vote, Mapping) else None
            engine.clock = lambda issued=issued: issued
            parsed = engine._verify_vote(vote, normalized)
            validator_id = parsed["validator_id"]
            if validator_id in seen:
                return _fail("polc_duplicate_validator")
            if parsed["vote_type"] != "PREVOTE" or parsed["approve"] is not True:
                return _fail("polc_requires_affirmative_prevote")
            seen.add(validator_id)
        weight = validator_set.weight_of(seen)
        required = validator_set.quorum_weight()
        if weight < required:
            return _fail("polc_quorum_missing")
        expected = polc_digest(polc)
        if polc["digest"] != expected:
            return _fail("polc_digest_mismatch")
        return {
            "valid": True, "reason": "polc_valid", "digest": expected,
            "candidate_digest": digest, "round": normalized["round"],
            "height": normalized["height"], "network_id": normalized["network_id"],
            "epoch": normalized["epoch"], "weight": weight,
            "quorum_weight": required, "proposal": dict(normalized),
        }
    except (KeyError, TypeError, ValueError, GCFError) as exc:
        return _fail(f"polc_invalid:{exc}")


def verify_round_change_message(message: Mapping[str, Any], *,
                                validator_set: ValidatorSet,
                                height: int,
                                target_round: int,
                                clock: Callable[[], float] = time.time,
                                max_age_seconds: int = 300) -> dict:
    try:
        required = {
            "schema", "network_id", "epoch", "height", "source_round",
            "target_round", "validator_id", "issued_at", "expires_at",
            "nonce", "highest_polc", "signature",
        }
        if not isinstance(message, Mapping) or set(message) != required:
            return _fail("round_change_fields_invalid")
        if message["schema"] != ROUND_CHANGE_SCHEMA:
            return _fail("round_change_schema_invalid")
        if (message["network_id"] != validator_set.network_id
                or message["epoch"] != validator_set.epoch
                or message["height"] != height):
            return _fail("round_change_context_mismatch")
        source = message["source_round"]
        target = message["target_round"]
        for value in (source, target, message["height"], message["epoch"],
                      message["issued_at"], message["expires_at"]):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                return _fail("round_change_integer_invalid")
        if target != target_round or target <= source:
            return _fail("round_change_target_invalid")
        validator_id = message["validator_id"]
        validator = validator_set.validators.get(validator_id)
        if validator is None:
            return _fail("round_change_unknown_validator")
        if not isinstance(message["nonce"], str) or not _NONCE.fullmatch(message["nonce"]):
            return _fail("round_change_nonce_invalid")
        now = int(clock())
        issued, expires = message["issued_at"], message["expires_at"]
        if expires <= issued or expires - issued > max_age_seconds:
            return _fail("round_change_time_window_invalid")
        if issued > now + 30 or now > expires or now - issued > max_age_seconds:
            return _fail("round_change_expired_or_future")
        if not verify_object(validator.public_key_hex, message["signature"],
                             ROUND_CHANGE_DOMAIN, _unsigned(message)):
            return _fail("round_change_signature_invalid")
        polc = message["highest_polc"]
        if polc is not None:
            checked = verify_polc(polc, validator_set=validator_set, clock=clock)
            if not checked["valid"]:
                return _fail("round_change_polc_invalid:" + checked["reason"])
            if (checked["height"] != height
                    or checked["network_id"] != validator_set.network_id
                    or checked["epoch"] != validator_set.epoch
                    or checked["round"] > source):
                return _fail("round_change_polc_context_invalid")
        return {
            "valid": True, "reason": "round_change_message_valid",
            "validator_id": validator_id, "weight": validator.weight,
            "source_round": source, "target_round": target,
            "highest_polc": dict(polc) if polc is not None else None,
        }
    except (KeyError, TypeError, ValueError, GCFError) as exc:
        return _fail(f"round_change_message_invalid:{exc}")


def verify_round_change_certificate(certificate: Mapping[str, Any], *,
                                    validator_set: ValidatorSet,
                                    height: int,
                                    clock: Callable[[], float] = time.time,
                                    max_age_seconds: int = 300) -> dict:
    """Verify unique signed messages and strict weighted quorum, then select highest POLC."""
    try:
        if not isinstance(certificate, Mapping) or set(certificate) != {
            "schema", "network_id", "epoch", "height", "target_round",
            "messages", "digest",
        }:
            return _fail("round_change_certificate_fields_invalid")
        if certificate["schema"] != ROUND_CHANGE_SCHEMA + "-CERT":
            return _fail("round_change_certificate_schema_invalid")
        if (certificate["network_id"] != validator_set.network_id
                or certificate["epoch"] != validator_set.epoch
                or certificate["height"] != height):
            return _fail("round_change_certificate_context_mismatch")
        target = certificate["target_round"]
        if isinstance(target, bool) or not isinstance(target, int) or target < 1:
            return _fail("round_change_certificate_target_invalid")
        messages = certificate["messages"]
        if not isinstance(messages, list) or not messages:
            return _fail("round_change_certificate_messages_invalid")
        ids: set[str] = set()
        nonce_ids: set[tuple[str, str]] = set()
        weight = 0
        polcs: dict[int, tuple[str, dict]] = {}
        normalized_messages = []
        for message in messages:
            checked = verify_round_change_message(
                message, validator_set=validator_set, height=height,
                target_round=target, clock=clock, max_age_seconds=max_age_seconds,
            )
            if not checked["valid"]:
                return _fail("round_change_message_rejected:" + checked["reason"])
            validator_id = checked["validator_id"]
            if validator_id in ids:
                return _fail("round_change_duplicate_validator")
            ids.add(validator_id)
            nonce_key = (validator_id, message["nonce"])
            if nonce_key in nonce_ids:
                return _fail("round_change_replayed_nonce")
            nonce_ids.add(nonce_key)
            weight += checked["weight"]
            polc = checked["highest_polc"]
            if polc is not None:
                result = verify_polc(polc, validator_set=validator_set, clock=clock)
                round_number = result["round"]
                candidate = result["candidate_digest"]
                prior = polcs.get(round_number)
                if prior is not None and prior[0] != candidate:
                    return _fail("round_change_conflicting_same_round_polcs")
                polcs[round_number] = (candidate, dict(polc))
            normalized_messages.append(dict(message))
        required = validator_set.quorum_weight()
        if weight < required:
            return _fail("round_change_quorum_missing")
        normalized_messages.sort(key=lambda item: item["validator_id"])
        highest = None
        if polcs:
            highest_round = max(polcs)
            highest = polcs[highest_round][1]
        body = {
            "schema": certificate["schema"],
            "network_id": certificate["network_id"],
            "epoch": certificate["epoch"],
            "height": height,
            "target_round": target,
            "messages": normalized_messages,
        }
        expected_digest = sha256_hex(
            ROUND_CHANGE_CERT_DOMAIN + canonical_bytes(body)
        )
        if certificate["digest"] != expected_digest:
            return _fail("round_change_certificate_digest_mismatch")
        return {
            "valid": True, "reason": "round_change_certificate_valid",
            "digest": expected_digest, "network_id": validator_set.network_id,
            "epoch": validator_set.epoch, "height": height,
            "target_round": target, "weight": weight,
            "quorum_weight": required, "highest_polc": highest,
            "highest_polc_round": max(polcs) if polcs else None,
        }
    except (KeyError, TypeError, ValueError, GCFError) as exc:
        return _fail(f"round_change_certificate_invalid:{exc}")


def make_round_change_message(*, validator_id: str, private_key_hex: str,
                              network_id: str, epoch: int, height: int,
                              source_round: int, target_round: int,
                              issued_at: int, expires_at: int, nonce: str,
                              highest_polc: Mapping[str, Any] | None = None) -> dict:
    """Create a signed message; callers must still verify local lock policy."""
    from src.consensus.gcf import sign_object
    body = {
        "schema": ROUND_CHANGE_SCHEMA, "network_id": network_id,
        "epoch": epoch, "height": height, "source_round": source_round,
        "target_round": target_round, "validator_id": validator_id,
        "issued_at": issued_at, "expires_at": expires_at, "nonce": nonce,
        "highest_polc": dict(highest_polc) if highest_polc is not None else None,
    }
    return {**body, "signature": sign_object(
        private_key_hex, ROUND_CHANGE_DOMAIN, body
    )}


def make_round_change_certificate(messages: list[Mapping[str, Any]], *,
                                  network_id: str, epoch: int, height: int,
                                  target_round: int) -> dict:
    """Canonicalize message ordering and compute a digest; does not imply validity."""
    ordered = sorted((dict(item) for item in messages),
                     key=lambda item: item.get("validator_id", ""))
    body = {
        "schema": ROUND_CHANGE_SCHEMA + "-CERT",
        "network_id": network_id, "epoch": epoch, "height": height,
        "target_round": target_round, "messages": ordered,
    }
    return {**body, "digest": sha256_hex(
        ROUND_CHANGE_CERT_DOMAIN + canonical_bytes(body)
    )}
