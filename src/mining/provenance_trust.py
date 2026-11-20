"""Versioned trust snapshots, key rotation/revocation, and attestation quorum.

Snapshots are content-addressed and hash-chained. A hash chain detects
inconsistency but does not authenticate its publisher; operators must anchor
snapshot digests through an independent trusted channel.
"""
from __future__ import annotations

import hashlib
from typing import Any, Iterable, Mapping

from .provenance_attestation import (
    TRUST_SCHEMA,
    canonical_bytes,
    trust_store_entry,
    verify_attestation,
)

SNAPSHOT_SCHEMA = "cryptic.provenance-trust-snapshot.v1"


class TrustLifecycleError(ValueError):
    """Raised for invalid trust lifecycle operations."""


def _digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _timestamp(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TrustLifecycleError(f"{field} must be a non-negative Unix timestamp")
    return value


def _normalise_entries(entries: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if isinstance(entries, (str, bytes, Mapping)):
        raise TypeError("issuers must be an iterable of issuer key entries")
    result = []
    seen_fingerprints = set()
    seen_pairs = set()
    for item in entries:
        if not isinstance(item, Mapping):
            raise TypeError("each issuer key entry must be an object")
        base = trust_store_entry(item.get("issuer_id"), item.get("public_key_hex"))
        supplied_fingerprint = item.get("key_fingerprint", base["key_fingerprint"])
        if supplied_fingerprint != base["key_fingerprint"]:
            raise TrustLifecycleError("public key fingerprint mismatch")
        fingerprint = base["key_fingerprint"]
        pair = (base["issuer_id"], fingerprint)
        if pair in seen_pairs or fingerprint in seen_fingerprints:
            raise TrustLifecycleError("duplicate issuer key or public-key fingerprint")
        seen_pairs.add(pair)
        seen_fingerprints.add(fingerprint)
        valid_from = _timestamp(item.get("valid_from", 0), "valid_from")
        revoked_at = item.get("revoked_at")
        if revoked_at is not None:
            revoked_at = _timestamp(revoked_at, "revoked_at")
            if revoked_at <= valid_from:
                raise TrustLifecycleError("revoked_at must be later than valid_from")
        result.append({
            "issuer_id": base["issuer_id"],
            "key_fingerprint": fingerprint,
            "public_key_hex": base["public_key_hex"],
            "valid_from": valid_from,
            "revoked_at": revoked_at,
        })
    if not result:
        raise TrustLifecycleError("at least one issuer key is required")
    return sorted(result, key=lambda row: (row["issuer_id"], row["key_fingerprint"]))


def _snapshot_body(
    *,
    version: int,
    created_at: int,
    previous_snapshot_digest: str | None,
    issuers: list[dict[str, Any]],
) -> dict[str, Any]:
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise TrustLifecycleError("version must be a positive integer")
    _timestamp(created_at, "created_at")
    if previous_snapshot_digest is not None and not _digest(previous_snapshot_digest):
        raise TrustLifecycleError("previous_snapshot_digest must be lowercase SHA-256")
    if version == 1 and previous_snapshot_digest is not None:
        raise TrustLifecycleError("version 1 cannot reference a previous snapshot")
    if version > 1 and previous_snapshot_digest is None:
        raise TrustLifecycleError("versions after 1 require previous_snapshot_digest")
    return {
        "schema": SNAPSHOT_SCHEMA,
        "version": version,
        "created_at": created_at,
        "previous_snapshot_digest": previous_snapshot_digest,
        "issuers": issuers,
    }


def create_trust_snapshot(
    issuers: Iterable[Mapping[str, Any]],
    *,
    version: int = 1,
    created_at: int,
    previous_snapshot_digest: str | None = None,
) -> dict[str, Any]:
    """Create a deterministic, content-addressed trust-policy snapshot."""
    rows = _normalise_entries(issuers)
    body = _snapshot_body(
        version=version,
        created_at=created_at,
        previous_snapshot_digest=previous_snapshot_digest,
        issuers=rows,
    )
    return {**body, "snapshot_digest": hashlib.sha256(canonical_bytes(body)).hexdigest()}


def _verify_snapshot_contents(snapshot: Mapping[str, Any]) -> tuple[bool, str, str | None]:
    if not isinstance(snapshot, Mapping):
        return False, "invalid_snapshot", None
    expected_fields = {
        "schema", "version", "created_at", "previous_snapshot_digest",
        "issuers", "snapshot_digest",
    }
    if set(snapshot.keys()) != expected_fields or snapshot.get("schema") != SNAPSHOT_SCHEMA:
        return False, "unsupported_or_malformed_snapshot", None
    try:
        rows = _normalise_entries(snapshot.get("issuers"))
        body = _snapshot_body(
            version=snapshot.get("version"),
            created_at=snapshot.get("created_at"),
            previous_snapshot_digest=snapshot.get("previous_snapshot_digest"),
            issuers=rows,
        )
    except (TypeError, ValueError):
        return False, "invalid_snapshot_contents", None
    if rows != snapshot.get("issuers"):
        return False, "issuer_entries_not_canonical", None
    expected = hashlib.sha256(canonical_bytes(body)).hexdigest()
    if snapshot.get("snapshot_digest") != expected:
        return False, "snapshot_digest_mismatch", None
    return True, "snapshot_integrity_valid", expected


def verify_trust_snapshot(
    snapshot: Mapping[str, Any],
    previous_snapshot: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify snapshot integrity and, when supplied, its direct chain link.

    A standalone version greater than one can be integrity-checked, but its
    chain is explicitly reported as unchecked until predecessor history is
    supplied. Use verify_trust_snapshot_chain for complete chain validation.
    """
    failure = lambda reason: {"valid": False, "reason": reason}
    valid, reason, expected = _verify_snapshot_contents(snapshot)
    if not valid:
        return failure(reason)
    previous_digest = snapshot["previous_snapshot_digest"]
    if previous_digest is None:
        if snapshot["version"] != 1 or previous_snapshot is not None:
            return failure("snapshot_chain_mismatch")
        chain_link_verified = True
    elif previous_snapshot is None:
        chain_link_verified = False
    else:
        previous_valid, _, previous_expected = _verify_snapshot_contents(previous_snapshot)
        if not previous_valid:
            return failure("previous_snapshot_invalid")
        if (previous_expected != previous_digest
                or snapshot["version"] != previous_snapshot["version"] + 1
                or snapshot["created_at"] < previous_snapshot["created_at"]):
            return failure("snapshot_chain_mismatch")
        chain_link_verified = True
    return {
        "valid": True,
        "reason": "snapshot_integrity_valid" if chain_link_verified
        else "snapshot_integrity_valid_chain_unchecked",
        "version": snapshot["version"],
        "snapshot_digest": expected,
        "issuer_key_count": len(snapshot["issuers"]),
        "chain_link_verified": chain_link_verified,
    }


def verify_trust_snapshot_chain(
    snapshots: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Verify a complete ordered chain beginning at trust snapshot version 1."""
    if isinstance(snapshots, (str, bytes, Mapping)):
        raise TypeError("snapshots must be an ordered iterable of snapshot objects")
    history = list(snapshots)
    if not history:
        return {"valid": False, "reason": "empty_snapshot_chain"}
    previous = None
    for index, current in enumerate(history):
        result = verify_trust_snapshot(current, previous)
        if not result["valid"] or (index == 0 and not result["chain_link_verified"]):
            return {
                "valid": False,
                "reason": "snapshot_chain_invalid",
                "index": index,
                "detail": result["reason"],
            }
        previous = current
    return {
        "valid": True,
        "reason": "snapshot_chain_valid",
        "version": previous["version"],
        "snapshot_digest": previous["snapshot_digest"],
        "snapshot_count": len(history),
    }

def revoke_trust_key(
    snapshot: Mapping[str, Any],
    *,
    issuer_id: str,
    key_fingerprint: str,
    effective_at: int,
    created_at: int,
    snapshot_history: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return a new snapshot revoking exactly one currently active issuer key."""
    verified = verify_trust_snapshot(snapshot)
    if not verified["valid"]:
        raise TrustLifecycleError("cannot modify an invalid trust snapshot")
    if snapshot.get("version", 0) > 1:
        if snapshot_history is None or not verify_trust_snapshot_chain(
            [*snapshot_history, snapshot]
        )["valid"]:
            raise TrustLifecycleError("cannot modify a snapshot with an unverified history")
    effective_at = _timestamp(effective_at, "effective_at")
    created_at = _timestamp(created_at, "created_at")
    rows = [dict(row) for row in snapshot["issuers"]]
    matches = [
        row for row in rows
        if row["issuer_id"] == issuer_id
        and row["key_fingerprint"] == key_fingerprint
        and row["revoked_at"] is None
    ]
    if len(matches) != 1:
        raise TrustLifecycleError("active issuer key not found uniquely")
    if effective_at <= matches[0]["valid_from"]:
        raise TrustLifecycleError("revocation must follow key activation")
    matches[0]["revoked_at"] = effective_at
    return create_trust_snapshot(
        rows,
        version=snapshot["version"] + 1,
        created_at=created_at,
        previous_snapshot_digest=snapshot["snapshot_digest"],
    )


def rotate_trust_key(
    snapshot: Mapping[str, Any],
    *,
    issuer_id: str,
    old_key_fingerprint: str,
    new_public_key_hex: str,
    effective_at: int,
    created_at: int,
    snapshot_history: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Atomically revoke one active key and activate its replacement."""
    verified = verify_trust_snapshot(snapshot)
    if not verified["valid"]:
        raise TrustLifecycleError("cannot rotate keys from an invalid snapshot")
    if snapshot.get("version", 0) > 1:
        if snapshot_history is None or not verify_trust_snapshot_chain(
            [*snapshot_history, snapshot]
        )["valid"]:
            raise TrustLifecycleError("cannot rotate a snapshot with an unverified history")
    effective_at = _timestamp(effective_at, "effective_at")
    created_at = _timestamp(created_at, "created_at")
    rows = [dict(row) for row in snapshot["issuers"]]
    matches = [
        row for row in rows
        if row["issuer_id"] == issuer_id
        and row["key_fingerprint"] == old_key_fingerprint
        and row["revoked_at"] is None
    ]
    if len(matches) != 1:
        raise TrustLifecycleError("active old issuer key not found uniquely")
    if effective_at <= matches[0]["valid_from"]:
        raise TrustLifecycleError("rotation must follow old key activation")
    new_entry = trust_store_entry(issuer_id, new_public_key_hex)
    if any(row["key_fingerprint"] == new_entry["key_fingerprint"] for row in rows):
        raise TrustLifecycleError("new key already exists in trust history")
    matches[0]["revoked_at"] = effective_at
    rows.append({
        **new_entry,
        "valid_from": effective_at,
        "revoked_at": None,
    })
    return create_trust_snapshot(
        rows,
        version=snapshot["version"] + 1,
        created_at=created_at,
        previous_snapshot_digest=snapshot["snapshot_digest"],
    )


def _verify_with_snapshot(
    attestation: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    *,
    historical: bool,
    snapshot_history: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    snapshot_result = verify_trust_snapshot(snapshot)
    if not snapshot_result["valid"]:
        return {"valid": False, "reason": "trust_snapshot_invalid",
                "detail": snapshot_result["reason"]}
    if snapshot.get("version", 0) > 1:
        if snapshot_history is None:
            return {"valid": False, "reason": "trust_snapshot_chain_unverified"}
        chain_result = verify_trust_snapshot_chain([*snapshot_history, snapshot])
        if not chain_result["valid"]:
            return {"valid": False, "reason": "trust_snapshot_chain_invalid",
                    "detail": chain_result["reason"]}

    payload = attestation.get("payload") if isinstance(attestation, Mapping) else None
    if not isinstance(payload, Mapping):
        return {"valid": False, "reason": "malformed_attestation"}
    issuer_id = payload.get("issuer_id")
    fingerprint = payload.get("key_fingerprint")
    issued_at = payload.get("issued_at")
    if (not isinstance(issuer_id, str) or not _digest(fingerprint)
            or isinstance(issued_at, bool) or not isinstance(issued_at, int)):
        return {"valid": False, "reason": "malformed_issuer_identity"}
    matches = [
        row for row in snapshot["issuers"]
        if row["issuer_id"] == issuer_id and row["key_fingerprint"] == fingerprint
    ]
    if len(matches) != 1:
        return {"valid": False, "reason": "issuer_key_not_in_snapshot"}
    row = matches[0]
    if issued_at < row["valid_from"] or (
        row["revoked_at"] is not None and issued_at >= row["revoked_at"]
    ):
        return {"valid": False, "reason": "attestation_outside_key_validity"}
    if not historical and row["valid_from"] > snapshot["created_at"]:
        return {"valid": False, "reason": "issuer_key_not_yet_active"}
    if (not historical and row["revoked_at"] is not None
            and row["revoked_at"] <= snapshot["created_at"]):
        return {"valid": False, "reason": "issuer_key_revoked"}
    active_entry = {
        "issuer_id": row["issuer_id"],
        "key_fingerprint": row["key_fingerprint"],
        "public_key_hex": row["public_key_hex"],
        "status": "active",
    }
    result = verify_attestation(
        attestation,
        {"schema": TRUST_SCHEMA, "issuers": [active_entry]},
    )
    if not result["valid"]:
        return result
    return {
        **result,
        "trust_snapshot_version": snapshot["version"],
        "trust_snapshot_digest": snapshot["snapshot_digest"],
        "historical_policy": historical,
    }


def verify_attestation_historical(
    attestation: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    *,
    snapshot_history: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Verify at issue time; v2+ snapshots require their ordered predecessor history."""
    return _verify_with_snapshot(
        attestation, snapshot, historical=True, snapshot_history=snapshot_history
    )


def verify_attestation_current(
    attestation: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    *,
    snapshot_history: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Verify current snapshot policy; v2+ snapshots require predecessor history."""
    return _verify_with_snapshot(
        attestation, snapshot, historical=False, snapshot_history=snapshot_history
    )


def verify_attestation_quorum(
    attestations: Iterable[Mapping[str, Any]],
    snapshot: Mapping[str, Any],
    *,
    threshold: int,
    historical: bool = True,
    snapshot_history: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Require threshold valid attestations from distinct trusted issuers.

    Every accepted attestation must bind the exact same subject schema, ID,
    digest algorithm, and digest. This is a collection-level quorum, not an
    aggregate or threshold cryptographic signature.
    """
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
        raise TrustLifecycleError("threshold must be a positive integer")
    if isinstance(attestations, (str, bytes, Mapping)):
        raise TypeError("attestations must be an iterable of attestation objects")
    verify_one = verify_attestation_historical if historical else verify_attestation_current
    history = None if snapshot_history is None else list(snapshot_history)
    accepted = []
    rejected = []
    seen_issuers = set()
    seen_fingerprints = set()
    common_subject = None
    common_purpose = None
    for index, item in enumerate(attestations):
        result = verify_one(item, snapshot, snapshot_history=history)
        if not result.get("valid"):
            rejected.append({"index": index, "reason": result.get("reason")})
            continue
        subject = result["subject"]
        subject_key = (
            subject.get("schema"), subject.get("id"),
            subject.get("digest_algorithm"), subject.get("digest"),
        )
        if common_subject is None:
            common_subject = subject_key
        elif subject_key != common_subject:
            rejected.append({"index": index, "reason": "subject_mismatch"})
            continue
        purpose = result["purpose"]
        if common_purpose is None:
            common_purpose = purpose
        elif purpose != common_purpose:
            rejected.append({"index": index, "reason": "purpose_mismatch"})
            continue
        issuer = result["issuer_id"]
        fingerprint = result["key_fingerprint"]
        if issuer in seen_issuers or fingerprint in seen_fingerprints:
            rejected.append({"index": index, "reason": "duplicate_quorum_issuer"})
            continue
        seen_issuers.add(issuer)
        seen_fingerprints.add(fingerprint)
        accepted.append({
            "issuer_id": issuer,
            "key_fingerprint": fingerprint,
            "attestation_id": item.get("attestation_id"),
        })
    valid = len(accepted) >= threshold
    return {
        "valid": valid,
        "reason": "quorum_met" if valid else "quorum_not_met",
        "threshold": threshold,
        "valid_signer_count": len(accepted),
        "accepted": accepted,
        "rejected": rejected,
        "subject": ({
            "schema": common_subject[0],
            "id": common_subject[1],
            "digest_algorithm": common_subject[2],
            "digest": common_subject[3],
        } if common_subject is not None else None),
        "purpose": common_purpose,
        "historical_policy": historical,
        "trust_snapshot_digest": snapshot.get("snapshot_digest")
        if isinstance(snapshot, Mapping) else None,
    }
