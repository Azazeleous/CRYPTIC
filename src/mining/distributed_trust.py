"""Portable, independently verifiable governance bundles for CRYPTIC.

The verifier is pure: callers must persist the returned next_state separately.
A valid local bundle is not network consensus or external acceptance.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any, Iterable

from .provenance_attestation import canonical_bytes
from .provenance_trust import verify_trust_snapshot_chain
from .root_of_trust import (
    verify_root_manifest,
    verify_root_rotation,
    verify_signed_policy_snapshot,
)

BUNDLE_SCHEMA = "cryptic.distributed-trust-bundle.v1"
STATE_SCHEMA = "cryptic.distributed-trust-state.v1"


class DistributedTrustError(ValueError):
    """Invalid distributed trust bundle or verifier state."""


def _sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _positive(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise DistributedTrustError(f"{field} must be a positive integer")
    return value


def _sequence(value: Any, field: str) -> list:
    if isinstance(value, (str, bytes, Mapping)):
        raise DistributedTrustError(f"{field} must be an array")
    try:
        result = list(value)
    except TypeError as exc:
        raise DistributedTrustError(f"{field} must be an array") from exc
    return result


def _bundle_body(
    initial_root_manifest: Mapping[str, Any],
    root_rotations: Iterable[Mapping[str, Any]],
    trust_snapshot_history: Iterable[Mapping[str, Any]],
    trust_snapshot: Mapping[str, Any],
    signed_policy: Mapping[str, Any],
) -> dict[str, Any]:
    if not all(isinstance(x, Mapping) for x in (
        initial_root_manifest, trust_snapshot, signed_policy
    )):
        raise DistributedTrustError("root, snapshot, and policy values must be objects")
    return {
        "schema": BUNDLE_SCHEMA,
        "initial_root_manifest": dict(initial_root_manifest),
        "root_rotations": [dict(x) if isinstance(x, Mapping) else x
                           for x in _sequence(root_rotations, "root_rotations")],
        "trust_snapshot_history": [
            dict(x) if isinstance(x, Mapping) else x
            for x in _sequence(trust_snapshot_history, "trust_snapshot_history")
        ],
        "trust_snapshot": dict(trust_snapshot),
        "signed_policy": dict(signed_policy),
    }


def create_distributed_trust_bundle(
    initial_root_manifest: Mapping[str, Any],
    *,
    root_rotations: Iterable[Mapping[str, Any]] = (),
    trust_snapshot_history: Iterable[Mapping[str, Any]] = (),
    trust_snapshot: Mapping[str, Any],
    signed_policy: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a deterministic portable bundle; verification remains a separate step."""
    body = _bundle_body(
        initial_root_manifest, root_rotations, trust_snapshot_history,
        trust_snapshot, signed_policy,
    )
    return {**body, "bundle_digest": _sha256(body)}


def _validate_state(state: Any) -> dict[str, Any] | None:
    if state is None:
        return None
    fields = {
        "schema", "root_epoch", "root_fingerprint", "policy_sequence",
        "policy_digest", "snapshot_digest",
    }
    if not isinstance(state, Mapping) or set(state) != fields:
        raise DistributedTrustError("previous_state is malformed")
    if state.get("schema") != STATE_SCHEMA:
        raise DistributedTrustError("previous_state schema is unsupported")
    _positive(state.get("root_epoch"), "previous_state.root_epoch")
    _positive(state.get("policy_sequence"), "previous_state.policy_sequence")
    for name in ("root_fingerprint", "policy_digest", "snapshot_digest"):
        value = state.get(name)
        if (not isinstance(value, str) or len(value) != 64
                or any(c not in "0123456789abcdef" for c in value)):
            raise DistributedTrustError(f"previous_state.{name} must be lowercase SHA-256")
    return dict(state)


def verify_distributed_trust_bundle(
    bundle: Mapping[str, Any],
    *,
    pinned_root_fingerprint: str,
    previous_state: Mapping[str, Any] | None = None,
    minimum_root_epoch: int = 1,
    minimum_policy_sequence: int = 1,
) -> dict[str, Any]:
    """Verify a bundle against an independently pinned root and external state.

    With no previous_state, authenticity and internal ordering can be checked,
    but replay of an older otherwise-valid bundle cannot be detected.
    Persist next_state outside the bundle before accepting a later update.
    """
    fail = lambda reason: {"valid": False, "reason": reason}
    try:
        minimum_root_epoch = _positive(minimum_root_epoch, "minimum_root_epoch")
        minimum_policy_sequence = _positive(minimum_policy_sequence, "minimum_policy_sequence")
        prior = _validate_state(previous_state)
    except (TypeError, ValueError) as exc:
        return fail("invalid_verifier_state:" + str(exc))

    fields = {
        "schema", "initial_root_manifest", "root_rotations",
        "trust_snapshot_history", "trust_snapshot", "signed_policy",
        "bundle_digest",
    }
    if not isinstance(bundle, Mapping) or set(bundle) != fields:
        return fail("malformed_bundle")
    if bundle.get("schema") != BUNDLE_SCHEMA:
        return fail("unsupported_bundle_schema")
    try:
        body = {key: bundle[key] for key in fields if key != "bundle_digest"}
        if _sha256(body) != bundle.get("bundle_digest"):
            return fail("bundle_digest_mismatch")
        rotations = _sequence(bundle["root_rotations"], "root_rotations")
        history = _sequence(bundle["trust_snapshot_history"], "trust_snapshot_history")
    except (TypeError, ValueError, KeyError):
        return fail("malformed_bundle_contents")

    root = bundle.get("initial_root_manifest")
    root_result = verify_root_manifest(root)
    if not root_result.get("valid"):
        return fail("initial_root_invalid")
    if not isinstance(pinned_root_fingerprint, str) or root_result.get(
        "root_fingerprint"
    ) != pinned_root_fingerprint:
        return fail("pinned_root_mismatch")

    current_root = dict(root)
    root_chain = [dict(root)]
    for index, transition in enumerate(rotations):
        result = verify_root_rotation(
            transition, current_root,
            pinned_old_root_fingerprint=current_root["root_fingerprint"],
        )
        if not result.get("valid"):
            return {"valid": False, "reason": "root_rotation_invalid",
                    "rotation_index": index, "detail": result.get("reason")}
        current_root = dict(transition["new_root_manifest"])
        root_chain.append(current_root)

    root_epoch = current_root["epoch"]
    root_fingerprint = current_root["root_fingerprint"]
    effective_min_root = max(
        minimum_root_epoch, prior["root_epoch"] if prior else 1
    )
    if root_epoch < effective_min_root:
        return fail("root_epoch_rollback")
    if prior:
        prior_roots = [
            item for item in root_chain
            if item.get("epoch") == prior["root_epoch"]
        ]
        if not prior_roots or prior_roots[-1].get("root_fingerprint") != prior["root_fingerprint"]:
            return fail("root_history_does_not_match_previous_state")

    snapshot = bundle.get("trust_snapshot")
    if not isinstance(snapshot, Mapping):
        return fail("trust_snapshot_invalid")
    try:
        chain = verify_trust_snapshot_chain([*history, snapshot])
    except (TypeError, ValueError):
        return fail("trust_snapshot_chain_invalid")
    if not chain.get("valid"):
        return fail("trust_snapshot_chain_invalid")
    if prior and prior["snapshot_digest"] not in {
        item.get("snapshot_digest") for item in [*history, snapshot]
        if isinstance(item, Mapping)
    }:
        return fail("snapshot_history_does_not_match_previous_state")

    policy = bundle.get("signed_policy")
    if not isinstance(policy, Mapping):
        return fail("signed_policy_invalid")
    prior_policy_sequence = prior["policy_sequence"] if prior else 0
    effective_min_policy = max(
        minimum_policy_sequence, prior_policy_sequence + 1
    )
    expected_previous = prior["policy_digest"] if prior else None
    policy_result = verify_signed_policy_snapshot(
        policy, snapshot, current_root,
        pinned_root_fingerprint=root_fingerprint,
        minimum_sequence=effective_min_policy,
        expected_previous_policy_digest=expected_previous,
        snapshot_history=history if snapshot.get("version", 0) > 1 else None,
    )
    if not policy_result.get("valid"):
        return {"valid": False, "reason": "signed_policy_invalid",
                "detail": policy_result.get("reason")}

    policy_digest = _sha256(dict(policy))
    next_state = {
        "schema": STATE_SCHEMA,
        "root_epoch": root_epoch,
        "root_fingerprint": root_fingerprint,
        "policy_sequence": policy_result["sequence"],
        "policy_digest": policy_digest,
        "snapshot_digest": chain["snapshot_digest"],
    }
    evidence = {
        "bundle_digest": bundle["bundle_digest"],
        "root_fingerprint": root_fingerprint,
        "root_epoch": root_epoch,
        "snapshot_digest": chain["snapshot_digest"],
        "policy_digest": policy_digest,
        "policy_sequence": policy_result["sequence"],
    }
    return {
        "valid": True,
        "reason": "distributed_trust_bundle_valid",
        **evidence,
        "evidence_digest": _sha256(evidence),
        "next_state": next_state,
        "state_persisted": False,
    }
