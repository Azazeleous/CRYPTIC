"""Offline pinned-root governance signatures for CRYPTIC provenance policy."""
from __future__ import annotations
import base64
import hashlib
from typing import Any, Iterable, Mapping
from .provenance_attestation import canonical_bytes
from .provenance_trust import verify_trust_snapshot, verify_trust_snapshot_chain

ROOT_SCHEMA = "cryptic.governance-root.v1"
POLICY_SCHEMA = "cryptic.signed-policy-snapshot.v1"
ROTATION_SCHEMA = "cryptic.root-rotation.v1"
_FP = b"CRYPTIC|GOVERNANCE-ROOT|FINGERPRINT|V1\x00"
_POLICY = b"CRYPTIC|SIGNED-POLICY|ED25519|V1\x00"
_ROTATE = b"CRYPTIC|ROOT-ROTATION|ED25519|V1\x00"

class RootOfTrustError(ValueError):
    """Invalid governance root, policy, or rotation."""

def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    except ImportError as exc:
        raise RuntimeError("Root-of-trust support requires cryptography") from exc
    return InvalidSignature, serialization, Ed25519PrivateKey, Ed25519PublicKey

def _raw(value, size, field):
    if not isinstance(value, str):
        raise RootOfTrustError(f"{field} must be hexadecimal text")
    try: raw = bytes.fromhex(value)
    except ValueError as exc: raise RootOfTrustError(f"{field} is malformed") from exc
    if len(raw) != size: raise RootOfTrustError(f"{field} must be exactly {size} bytes")
    return raw

def _pos(value, field):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise RootOfTrustError(f"{field} must be a positive integer")
    return value

def _keys(values, field):
    if isinstance(values, (str, bytes, Mapping)):
        raise TypeError(f"{field} must be an iterable of public-key hex strings")
    rows, seen = [], set()
    for value in values:
        raw = _raw(value, 32, field); fp = hashlib.sha256(raw).hexdigest()
        if fp in seen: raise RootOfTrustError(f"duplicate key in {field}")
        seen.add(fp); rows.append({"key_fingerprint": fp, "public_key_hex": raw.hex()})
    return sorted(rows, key=lambda x: x["key_fingerprint"])

def _root_body(epoch, keys, threshold, recovery, recovery_threshold, previous):
    _pos(epoch, "epoch")
    if isinstance(threshold, bool) or not isinstance(threshold, int) or not keys or not 1 <= threshold <= len(keys):
        raise RootOfTrustError("root threshold must be within the root-key count")
    if isinstance(recovery_threshold, bool) or not isinstance(recovery_threshold, int):
        raise RootOfTrustError("recovery threshold must be an integer")
    if recovery and not 1 <= recovery_threshold <= len(recovery):
        raise RootOfTrustError("recovery threshold must be within recovery-key count")
    if not recovery and recovery_threshold != 0:
        raise RootOfTrustError("recovery threshold must be zero without recovery keys")
    if previous is None:
        if epoch != 1: raise RootOfTrustError("root epochs after 1 require a predecessor")
    else:
        _raw(previous, 32, "previous_root_fingerprint")
        if epoch == 1: raise RootOfTrustError("epoch 1 cannot have a predecessor")
    return {"schema": ROOT_SCHEMA, "epoch": epoch, "previous_root_fingerprint": previous,
            "keys": keys, "threshold": threshold, "recovery_keys": recovery,
            "recovery_threshold": recovery_threshold}

def create_root_manifest(root_public_keys, *, threshold, recovery_public_keys=(),
                         recovery_threshold=0, epoch=1, previous_root_fingerprint=None):
    body = _root_body(epoch, _keys(root_public_keys, "root_public_keys"), threshold,
                      _keys(recovery_public_keys, "recovery_public_keys"),
                      recovery_threshold, previous_root_fingerprint)
    fp = hashlib.sha256(_FP + canonical_bytes(body)).hexdigest()
    return {**body, "root_fingerprint": fp}

def verify_root_manifest(manifest):
    fail = lambda why: {"valid": False, "reason": why}
    fields = {"schema","epoch","previous_root_fingerprint","keys","threshold",
              "recovery_keys","recovery_threshold","root_fingerprint"}
    if not isinstance(manifest, Mapping): return fail("invalid_root_manifest")
    if set(manifest) != fields or manifest.get("schema") != ROOT_SCHEMA:
        return fail("malformed_root_manifest")
    try:
        keys = _keys([x["public_key_hex"] for x in manifest["keys"]], "keys")
        recovery = _keys([x["public_key_hex"] for x in manifest["recovery_keys"]], "recovery_keys")
        if keys != manifest["keys"] or recovery != manifest["recovery_keys"]:
            return fail("noncanonical_root_keys")
        body = _root_body(manifest["epoch"], keys, manifest["threshold"], recovery,
                          manifest["recovery_threshold"], manifest["previous_root_fingerprint"])
    except (TypeError, KeyError, ValueError): return fail("invalid_root_manifest_contents")
    expected = hashlib.sha256(_FP + canonical_bytes(body)).hexdigest()
    if manifest.get("root_fingerprint") != expected: return fail("root_fingerprint_mismatch")
    return {"valid": True, "reason": "root_manifest_valid", "root_fingerprint": expected,
            "epoch": body["epoch"], "root_key_count": len(keys),
            "root_threshold": body["threshold"], "recovery_key_count": len(recovery),
            "recovery_threshold": body["recovery_threshold"]}

def _sign(private_hex, domain, payload):
    _, ser, private_type, _ = _crypto()
    private = private_type.from_private_bytes(_raw(private_hex, 32, "private_key_hex"))
    public = private.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    return {"key_fingerprint": hashlib.sha256(public).hexdigest(),
            "signature": base64.b64encode(private.sign(domain + canonical_bytes(dict(payload)))).decode("ascii")}

def _quorum(payload, signatures, keys, threshold, domain):
    InvalidSignature, _, _, public_type = _crypto()
    if not isinstance(signatures, list): return False, 0, ["malformed_signatures"]
    trusted = {x["key_fingerprint"]: x["public_key_hex"] for x in keys}
    accepted, rejected = set(), []
    for item in signatures:
        if not isinstance(item, Mapping) or set(item) != {"key_fingerprint","signature"}:
            rejected.append("malformed_signature_entry"); continue
        fp = item.get("key_fingerprint")
        if not isinstance(fp, str) or fp not in trusted:
            rejected.append("untrusted_signer"); continue
        if fp in accepted: rejected.append("duplicate_signer"); continue
        if not isinstance(item.get("signature"), str):
            rejected.append("malformed_signature"); continue
        try:
            sig = base64.b64decode(item["signature"], validate=True)
            pub = _raw(trusted[fp], 32, "trusted_public_key")
            if len(sig) != 64 or hashlib.sha256(pub).hexdigest() != fp: raise ValueError("invalid key/signature")
            public_type.from_public_bytes(pub).verify(sig, domain + canonical_bytes(dict(payload)))
        except (ValueError, InvalidSignature): rejected.append("signature_invalid"); continue
        accepted.add(fp)
    return len(accepted) >= threshold, len(accepted), rejected

def create_signed_policy_snapshot(snapshot, root_manifest, private_key_hexes, *,
                                  sequence, previous_policy_digest=None, snapshot_history=None):
    if not verify_root_manifest(root_manifest)["valid"]:
        raise RootOfTrustError("cannot sign policy under an invalid root")
    if not isinstance(snapshot, Mapping): raise TypeError("snapshot must be an object")
    if not verify_trust_snapshot(snapshot)["valid"]: raise RootOfTrustError("cannot sign an invalid trust snapshot")
    if snapshot.get("version", 0) > 1:
        if snapshot_history is None or not verify_trust_snapshot_chain([*snapshot_history, snapshot])["valid"]:
            raise RootOfTrustError("cannot sign a snapshot with unverified history")
    _pos(sequence, "sequence")
    if sequence == 1 and previous_policy_digest is not None:
        raise RootOfTrustError("policy sequence 1 cannot have a predecessor")
    if sequence > 1: _raw(previous_policy_digest, 32, "previous_policy_digest")
    body = {"schema": POLICY_SCHEMA, "root_fingerprint": root_manifest["root_fingerprint"],
            "root_epoch": root_manifest["epoch"], "sequence": sequence,
            "previous_policy_digest": previous_policy_digest,
            "snapshot_digest": hashlib.sha256(canonical_bytes(dict(snapshot))).hexdigest()}
    return {**body, "signatures": [_sign(k, _POLICY, body) for k in private_key_hexes]}

def verify_signed_policy_snapshot(envelope, snapshot, root_manifest, *,
                                  pinned_root_fingerprint, minimum_sequence=1,
                                  expected_previous_policy_digest=None, snapshot_history=None):
    fail = lambda why: {"valid": False, "reason": why}
    root = verify_root_manifest(root_manifest)
    if not root["valid"]: return fail("root_manifest_invalid")
    if pinned_root_fingerprint != root_manifest.get("root_fingerprint"): return fail("root_pin_mismatch")
    if not isinstance(envelope, Mapping) or not isinstance(snapshot, Mapping): return fail("invalid_policy_input")
    if not verify_trust_snapshot(snapshot)["valid"]: return fail("trust_snapshot_invalid")
    if snapshot.get("version", 0) > 1:
        if snapshot_history is None or not verify_trust_snapshot_chain([*snapshot_history, snapshot])["valid"]:
            return fail("trust_snapshot_chain_unverified")
    fields = {"schema","root_fingerprint","root_epoch","sequence","previous_policy_digest","snapshot_digest","signatures"}
    if set(envelope) != fields or envelope.get("schema") != POLICY_SCHEMA: return fail("malformed_policy_envelope")
    try:
        seq = _pos(envelope.get("sequence"), "sequence"); _pos(minimum_sequence, "minimum_sequence")
    except ValueError: return fail("invalid_policy_sequence")
    if seq < minimum_sequence: return fail("policy_rollback")
    if envelope.get("root_fingerprint") != pinned_root_fingerprint: return fail("policy_root_mismatch")
    if envelope.get("root_epoch") != root_manifest.get("epoch"): return fail("policy_root_epoch_mismatch")
    digest = hashlib.sha256(canonical_bytes(dict(snapshot))).hexdigest()
    if envelope.get("snapshot_digest") != digest: return fail("policy_snapshot_digest_mismatch")
    previous = envelope.get("previous_policy_digest")
    if seq == 1:
        if previous is not None: return fail("policy_chain_mismatch")
    else:
        try: _raw(previous, 32, "previous_policy_digest")
        except ValueError: return fail("policy_chain_mismatch")
        if expected_previous_policy_digest is not None and previous != expected_previous_policy_digest:
            return fail("policy_chain_mismatch")
    body = {k: envelope[k] for k in ("schema","root_fingerprint","root_epoch","sequence","previous_policy_digest","snapshot_digest")}
    ok, count, rejected = _quorum(body, envelope.get("signatures"), root_manifest["keys"], root_manifest["threshold"], _POLICY)
    if not ok: return {"valid": False, "reason": "policy_quorum_not_met", "valid_signer_count": count,
                       "threshold": root_manifest["threshold"], "rejected": rejected}
    return {"valid": True, "reason": "signed_policy_valid", "sequence": seq,
            "root_epoch": root_manifest["epoch"], "root_fingerprint": pinned_root_fingerprint,
            "snapshot_digest": digest, "valid_signer_count": count}

def create_root_rotation(old_root_manifest, new_root_manifest, old_authorizer_private_keys,
                         new_root_private_keys, *, authorization="root"):
    if not verify_root_manifest(old_root_manifest)["valid"] or not verify_root_manifest(new_root_manifest)["valid"]:
        raise RootOfTrustError("both root manifests must be valid")
    if new_root_manifest["epoch"] != old_root_manifest["epoch"] + 1:
        raise RootOfTrustError("new root epoch must increment exactly once")
    if new_root_manifest["previous_root_fingerprint"] != old_root_manifest["root_fingerprint"]:
        raise RootOfTrustError("new root must reference the old root fingerprint")
    if authorization not in {"root","recovery"}: raise RootOfTrustError("authorization must be root or recovery")
    body = {"schema": ROTATION_SCHEMA, "authorization": authorization,
            "old_root_fingerprint": old_root_manifest["root_fingerprint"],
            "new_root_manifest": dict(new_root_manifest)}
    return {**body, "old_signatures": [_sign(k, _ROTATE, body) for k in old_authorizer_private_keys],
            "new_key_proofs": [_sign(k, _ROTATE, body) for k in new_root_private_keys]}

def verify_root_rotation(transition, old_root_manifest, *, pinned_old_root_fingerprint):
    fail = lambda why: {"valid": False, "reason": why}
    if not verify_root_manifest(old_root_manifest)["valid"]: return fail("old_root_invalid")
    if pinned_old_root_fingerprint != old_root_manifest.get("root_fingerprint"): return fail("old_root_pin_mismatch")
    fields = {"schema","authorization","old_root_fingerprint","new_root_manifest","old_signatures","new_key_proofs"}
    if not isinstance(transition, Mapping): return fail("invalid_transition")
    if set(transition) != fields or transition.get("schema") != ROTATION_SCHEMA: return fail("malformed_transition")
    new = transition.get("new_root_manifest")
    if not verify_root_manifest(new)["valid"]: return fail("new_root_invalid")
    if transition.get("old_root_fingerprint") != pinned_old_root_fingerprint: return fail("transition_old_root_mismatch")
    if new["epoch"] != old_root_manifest["epoch"] + 1 or new["previous_root_fingerprint"] != pinned_old_root_fingerprint:
        return fail("root_transition_chain_mismatch")
    body = {k: transition[k] for k in ("schema","authorization","old_root_fingerprint","new_root_manifest")}
    auth = transition.get("authorization")
    if auth == "root": keys, threshold = old_root_manifest["keys"], old_root_manifest["threshold"]
    elif auth == "recovery":
        keys, threshold = old_root_manifest["recovery_keys"], old_root_manifest["recovery_threshold"]
        if not keys or not threshold: return fail("recovery_not_configured")
    else: return fail("invalid_rotation_authorization")
    old_ok, old_count, old_rejected = _quorum(body, transition.get("old_signatures"), keys, threshold, _ROTATE)
    if not old_ok: return {"valid": False, "reason": "old_root_authorization_not_met",
                           "valid_signer_count": old_count, "threshold": threshold, "rejected": old_rejected}
    new_ok, new_count, new_rejected = _quorum(body, transition.get("new_key_proofs"), new["keys"], new["threshold"], _ROTATE)
    if not new_ok: return {"valid": False, "reason": "new_root_possession_not_met",
                           "valid_signer_count": new_count, "threshold": new["threshold"], "rejected": new_rejected}
    return {"valid": True, "reason": "root_rotation_valid", "old_root_fingerprint": pinned_old_root_fingerprint,
            "new_root_fingerprint": new["root_fingerprint"], "new_epoch": new["epoch"],
            "authorization": auth, "old_authorizer_count": old_count, "new_key_proof_count": new_count}
