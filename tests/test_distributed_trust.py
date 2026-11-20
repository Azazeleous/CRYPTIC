"""Tests for portable distributed trust bundle verification."""
import copy
import hashlib

from src.mining.provenance_attestation import canonical_bytes, generate_ed25519_keypair
from src.mining.provenance_trust import create_trust_snapshot
from src.mining.root_of_trust import (
    create_root_manifest, create_root_rotation, create_signed_policy_snapshot,
)
from src.mining.distributed_trust import (
    create_distributed_trust_bundle, verify_distributed_trust_bundle,
)


def _digest(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _fixture(sequence=1, previous_policy_digest=None):
    root_key = generate_ed25519_keypair()
    root = create_root_manifest([root_key["public_key_hex"]], threshold=1)
    issuer = generate_ed25519_keypair()
    snapshot = create_trust_snapshot(
        [{"issuer_id": "test-issuer", "public_key_hex": issuer["public_key_hex"]}],
        created_at=100,
    )
    policy = create_signed_policy_snapshot(
        snapshot, root, [root_key["private_key_hex"]],
        sequence=sequence, previous_policy_digest=previous_policy_digest,
    )
    bundle = create_distributed_trust_bundle(
        root, trust_snapshot=snapshot, signed_policy=policy,
    )
    return root, root_key, snapshot, policy, bundle


def test_bundle_verifies_deterministically():
    root, _, _, _, bundle = _fixture()
    first = verify_distributed_trust_bundle(
        bundle, pinned_root_fingerprint=root["root_fingerprint"],
    )
    second = verify_distributed_trust_bundle(
        copy.deepcopy(bundle), pinned_root_fingerprint=root["root_fingerprint"],
    )
    assert first["valid"] is True
    assert first["evidence_digest"] == second["evidence_digest"]
    assert first["next_state"] == second["next_state"]
    assert first["state_persisted"] is False


def test_pinned_root_mismatch_fails_closed():
    _, _, _, _, bundle = _fixture()
    result = verify_distributed_trust_bundle(
        bundle, pinned_root_fingerprint="0" * 64,
    )
    assert result == {"valid": False, "reason": "pinned_root_mismatch"}


def test_bundle_tampering_is_detected():
    root, _, _, _, bundle = _fixture()
    altered = copy.deepcopy(bundle)
    altered["signed_policy"]["sequence"] = 9
    result = verify_distributed_trust_bundle(
        altered, pinned_root_fingerprint=root["root_fingerprint"],
    )
    assert result == {"valid": False, "reason": "bundle_digest_mismatch"}


def test_external_state_rejects_replay_and_accepts_successor():
    root, root_key, snapshot, first_policy, first_bundle = _fixture()
    first = verify_distributed_trust_bundle(
        first_bundle, pinned_root_fingerprint=root["root_fingerprint"],
    )
    assert first["valid"] is True

    replay = verify_distributed_trust_bundle(
        first_bundle, pinned_root_fingerprint=root["root_fingerprint"],
        previous_state=first["next_state"],
    )
    assert replay["valid"] is False
    assert replay["detail"] == "policy_rollback"

    second_policy = create_signed_policy_snapshot(
        snapshot, root, [root_key["private_key_hex"]],
        sequence=2, previous_policy_digest=_digest(first_policy),
    )
    second_bundle = create_distributed_trust_bundle(
        root, trust_snapshot=snapshot, signed_policy=second_policy,
    )
    second = verify_distributed_trust_bundle(
        second_bundle, pinned_root_fingerprint=root["root_fingerprint"],
        previous_state=first["next_state"],
    )
    assert second["valid"] is True
    assert second["next_state"]["policy_sequence"] == 2


def test_policy_sequence_floor_is_enforced():
    root, _, _, _, bundle = _fixture()
    result = verify_distributed_trust_bundle(
        bundle, pinned_root_fingerprint=root["root_fingerprint"],
        minimum_policy_sequence=2,
    )
    assert result["valid"] is False
    assert result["detail"] == "policy_rollback"


def test_malformed_external_state_is_rejected():
    root, _, _, _, bundle = _fixture()
    result = verify_distributed_trust_bundle(
        bundle, pinned_root_fingerprint=root["root_fingerprint"],
        previous_state={"schema": "wrong"},
    )
    assert result["valid"] is False
    assert result["reason"].startswith("invalid_verifier_state:")


def test_rotation_chain_verifies_against_original_pin():
    old_key = generate_ed25519_keypair()
    new_key = generate_ed25519_keypair()
    old_root = create_root_manifest([old_key["public_key_hex"]], threshold=1)
    new_root = create_root_manifest(
        [new_key["public_key_hex"]], threshold=1, epoch=2,
        previous_root_fingerprint=old_root["root_fingerprint"],
    )
    rotation = create_root_rotation(
        old_root, new_root, [old_key["private_key_hex"]],
        [new_key["private_key_hex"]],
    )
    issuer = generate_ed25519_keypair()
    snapshot = create_trust_snapshot(
        [{"issuer_id": "issuer", "public_key_hex": issuer["public_key_hex"]}],
        created_at=100,
    )
    policy = create_signed_policy_snapshot(
        snapshot, new_root, [new_key["private_key_hex"]], sequence=1,
    )
    bundle = create_distributed_trust_bundle(
        old_root, root_rotations=[rotation],
        trust_snapshot=snapshot, signed_policy=policy,
    )
    result = verify_distributed_trust_bundle(
        bundle, pinned_root_fingerprint=old_root["root_fingerprint"],
    )
    assert result["valid"] is True
    assert result["root_epoch"] == 2
    assert result["root_fingerprint"] == new_root["root_fingerprint"]
