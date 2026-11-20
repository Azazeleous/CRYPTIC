"""Ed25519 attestations for local CRYPTIC provenance checkpoints.

Attestations are a separate trust layer. They do not alter receipts,
manifests, federation indexes, or claims about external network acceptance.
Requires the optional 'cryptography' package.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "cryptic.provenance-attestation.v1"
TRUST_SCHEMA = "cryptic.provenance-trust-store.v1"
_DOMAIN = b"CRYPTIC|PROVENANCE-ATTESTATION|ED25519|V1\x00"


class AttestationError(ValueError):
    """Raised when an attestation cannot be constructed safely."""


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:
        raise RuntimeError(
            "Ed25519 support requires the optional 'cryptography' package"
        ) from exc
    return InvalidSignature, serialization, Ed25519PrivateKey, Ed25519PublicKey


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _issuer(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AttestationError("issuer_id must be a non-empty string")
    value = value.strip()
    if len(value) > 256:
        raise AttestationError("issuer_id exceeds 256 characters")
    return value


def generate_ed25519_keypair() -> dict[str, str]:
    """Generate raw Ed25519 key material; caller must protect the private key."""
    _, serialization, private_type, _ = _crypto()
    private_key = private_type.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fingerprint = hashlib.sha256(public_bytes).hexdigest()
    return {
        "private_key_hex": private_bytes.hex(),
        "public_key_hex": public_bytes.hex(),
        "key_fingerprint": fingerprint,
    }


def create_attestation(
    *,
    issuer_id: str,
    private_key_hex: str,
    subject_schema: str,
    subject_id: str,
    subject_digest: str,
    issued_at: int,
    purpose: str = "provenance-audit",
) -> dict[str, Any]:
    """Sign a digest reference; this does not validate the subject itself."""
    _, serialization, private_type, _ = _crypto()
    issuer_id = _issuer(issuer_id)
    if not isinstance(private_key_hex, str):
        raise AttestationError("private_key_hex must be a hexadecimal string")
    try:
        private_bytes = bytes.fromhex(private_key_hex)
    except ValueError as exc:
        raise AttestationError("private_key_hex is malformed") from exc
    if len(private_bytes) != 32:
        raise AttestationError("Ed25519 private keys must be exactly 32 bytes")
    if not isinstance(subject_schema, str) or not subject_schema.strip():
        raise AttestationError("subject_schema is required")
    if not isinstance(subject_id, str) or not subject_id.strip():
        raise AttestationError("subject_id is required")
    if not _is_digest(subject_digest):
        raise AttestationError("subject_digest must be lowercase SHA-256")
    if isinstance(issued_at, bool) or not isinstance(issued_at, int) or issued_at < 0:
        raise AttestationError("issued_at must be a non-negative Unix timestamp")
    if not isinstance(purpose, str) or not purpose.strip() or len(purpose) > 128:
        raise AttestationError("purpose must be a non-empty string of at most 128 characters")

    private_key = private_type.from_private_bytes(private_bytes)
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    payload = {
        "schema": SCHEMA,
        "issuer_id": issuer_id,
        "key_fingerprint": hashlib.sha256(public_bytes).hexdigest(),
        "subject": {
            "schema": subject_schema.strip(),
            "id": subject_id.strip(),
            "digest_algorithm": "SHA-256",
            "digest": subject_digest,
        },
        "issued_at": issued_at,
        "purpose": purpose.strip(),
    }
    signature = private_key.sign(_DOMAIN + canonical_bytes(payload))
    signed = {
        "schema": SCHEMA,
        "payload": payload,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    return {
        **signed,
        "attestation_id": hashlib.sha256(canonical_bytes(signed)).hexdigest(),
    }


def verify_attestation(
    attestation: Mapping[str, Any],
    trust_store: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify structure, key trust/revocation, fingerprint, ID, and signature."""
    InvalidSignature, serialization, _, public_type = _crypto()
    failure = lambda reason: {"valid": False, "reason": reason}
    if not isinstance(attestation, Mapping) or not isinstance(trust_store, Mapping):
        return failure("invalid_input")
    if attestation.get("schema") != SCHEMA or trust_store.get("schema") != TRUST_SCHEMA:
        return failure("unsupported_schema")
    payload = attestation.get("payload")
    signature_text = attestation.get("signature")
    attestation_id = attestation.get("attestation_id")
    if not isinstance(payload, Mapping) or not isinstance(signature_text, str):
        return failure("malformed_attestation")
    required_payload = {
        "schema", "issuer_id", "key_fingerprint", "subject",
        "issued_at", "purpose",
    }
    if set(payload.keys()) != required_payload or payload.get("schema") != SCHEMA:
        return failure("malformed_payload")
    issuer_id = payload.get("issuer_id")
    fingerprint = payload.get("key_fingerprint")
    if not isinstance(issuer_id, str) or not _is_digest(fingerprint):
        return failure("malformed_issuer_identity")
    subject = payload.get("subject")
    if (not isinstance(subject, Mapping)
            or set(subject.keys()) != {"schema", "id", "digest_algorithm", "digest"}
            or subject.get("digest_algorithm") != "SHA-256"
            or not _is_digest(subject.get("digest"))
            or not isinstance(subject.get("schema"), str)
            or not isinstance(subject.get("id"), str)):
        return failure("malformed_subject")
    issued_at = payload.get("issued_at")
    if isinstance(issued_at, bool) or not isinstance(issued_at, int) or issued_at < 0:
        return failure("malformed_timestamp")
    purpose = payload.get("purpose")
    if not isinstance(purpose, str) or not purpose:
        return failure("malformed_purpose")

    signed = {"schema": SCHEMA, "payload": dict(payload), "signature": signature_text}
    expected_id = hashlib.sha256(canonical_bytes(signed)).hexdigest()
    if not isinstance(attestation_id, str) or attestation_id != expected_id:
        return failure("attestation_id_mismatch")

    issuers = trust_store.get("issuers")
    if not isinstance(issuers, list):
        return failure("malformed_trust_store")
    matches = [
        entry for entry in issuers
        if isinstance(entry, Mapping) and entry.get("issuer_id") == issuer_id
        and entry.get("key_fingerprint") == fingerprint
    ]
    if len(matches) != 1:
        return failure("issuer_key_not_trusted")
    entry = matches[0]
    if entry.get("status") != "active":
        return failure("issuer_key_revoked_or_inactive")
    public_hex = entry.get("public_key_hex")
    try:
        public_bytes = bytes.fromhex(public_hex)
    except (TypeError, ValueError):
        return failure("malformed_trusted_public_key")
    if len(public_bytes) != 32 or hashlib.sha256(public_bytes).hexdigest() != fingerprint:
        return failure("trusted_key_fingerprint_mismatch")
    try:
        signature = base64.b64decode(signature_text, validate=True)
        if len(signature) != 64:
            return failure("malformed_signature")
        public_key = public_type.from_public_bytes(public_bytes)
        public_key.verify(signature, _DOMAIN + canonical_bytes(dict(payload)))
    except (ValueError, InvalidSignature):
        return failure("signature_invalid")
    return {
        "valid": True,
        "reason": "signature_valid_and_issuer_key_trusted",
        "issuer_id": issuer_id,
        "key_fingerprint": fingerprint,
        "subject": dict(subject),
        "issued_at": issued_at,
        "purpose": purpose,
    }


def trust_store_entry(issuer_id: str, public_key_hex: str) -> dict[str, str]:
    """Create an active trust entry; trust-store publication is a governance act."""
    issuer_id = _issuer(issuer_id)
    try:
        public_bytes = bytes.fromhex(public_key_hex)
    except (TypeError, ValueError) as exc:
        raise AttestationError("public_key_hex is malformed") from exc
    if len(public_bytes) != 32:
        raise AttestationError("Ed25519 public keys must be exactly 32 bytes")
    return {
        "issuer_id": issuer_id,
        "key_fingerprint": hashlib.sha256(public_bytes).hexdigest(),
        "public_key_hex": public_bytes.hex(),
        "status": "active",
    }
