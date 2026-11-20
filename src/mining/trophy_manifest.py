"""Portable provenance manifests for locally verified CRYPTIC receipts.

A manifest is a deterministic, portable representation of an authoritative
receipt. It does not mine, submit work, issue or transfer tokens, establish
network acceptance, authenticate an issuer, or assign monetary value.
"""
from __future__ import annotations

import hashlib
import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any

from .receipt_wallet import verify_receipt

SCHEMA = "cryptic.portable-trophy.v1"
HASH_ALGORITHM = "SHA-256"
VERIFICATION_VERSION = "1.0"


def _canonical_json(value: dict[str, Any]) -> bytes:
    """Return stable UTF-8 JSON bytes for JSON-compatible objects."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonicalize_manifest(manifest: dict[str, Any]) -> bytes:
    """Serialize the complete manifest deterministically, including its hash."""
    if not isinstance(manifest, dict):
        raise TypeError("manifest must be a dictionary")
    return _canonical_json(manifest)


def _manifest_hash_payload(manifest: dict[str, Any]) -> dict[str, Any]:
    payload = deepcopy(manifest)
    integrity = payload.get("integrity")
    if not isinstance(integrity, dict):
        raise ValueError("manifest integrity section is missing")
    integrity.pop("manifest_hash", None)
    return payload


def compute_manifest_hash(manifest: dict[str, Any]) -> str:
    """Hash the canonical manifest body, excluding integrity.manifest_hash."""
    return hashlib.sha256(_canonical_json(_manifest_hash_payload(manifest))).hexdigest()


def _derived_id(domain: bytes, receipt_id: str) -> str:
    return hashlib.sha256(domain + receipt_id.encode("ascii")).hexdigest()


def create_manifest(receipt: dict[str, Any]) -> dict[str, Any]:
    """Create a portable manifest only from a valid authoritative receipt."""
    if not verify_receipt(receipt):
        raise ValueError("cannot create a manifest from an invalid receipt")

    receipt_id = receipt["receipt_id"]
    work = receipt["work"]
    body: dict[str, Any] = {
        "format": SCHEMA,
        "identity": {
            "work_id": _derived_id(b"CRYPTIC-WORK-ID-v1\0", receipt_id),
            "trophy_id": _derived_id(b"CRYPTIC-TROPHY-ID-v1\0", receipt_id),
            "issuer": "CRYPTIC",
        },
        "provenance": {
            "receipt_hash": receipt_id,
            "wallet_id": receipt["wallet_id"],
            "ruleset_id": receipt["ruleset_id"],
            "accepted_at": receipt["accepted_at"],
            "algorithm": work["algorithm"],
            "proof_digest": work["digest_hex"],
        },
        "verification": {
            "receipt_integrity": "verified",
            "proof_verification": "verified",
            "network_acceptance": "not_claimed",
            "verification_version": VERIFICATION_VERSION,
        },
        "representation": {
            "asset_type": "proof_trophy",
            "transferability": "not_defined",
            "valuation": None,
        },
        "integrity": {
            "algorithm": HASH_ALGORITHM,
        },
    }
    body["integrity"]["manifest_hash"] = compute_manifest_hash(body)
    return body


def verify_manifest(manifest: dict[str, Any], receipt: dict[str, Any]) -> bool:
    """Verify manifest integrity and its exact binding to an authoritative receipt."""
    if not isinstance(manifest, dict) or not isinstance(receipt, dict):
        return False
    if not verify_receipt(receipt):
        return False
    try:
        if manifest.get("format") != SCHEMA:
            return False
        integrity = manifest["integrity"]
        if integrity.get("algorithm") != HASH_ALGORITHM:
            return False
        if integrity.get("manifest_hash") != compute_manifest_hash(manifest):
            return False
        expected = create_manifest(receipt)
        return manifest == expected
    except (KeyError, TypeError, ValueError, UnicodeError):
        return False


def export_manifest(manifest: dict[str, Any], destination: str | os.PathLike[str]) -> Path:
    """Write canonical JSON without overwriting an existing destination."""
    if not isinstance(manifest, dict):
        raise TypeError("manifest must be a dictionary")
    expected_hash = compute_manifest_hash(manifest)
    integrity = manifest.get("integrity", {})
    if integrity.get("manifest_hash") != expected_hash:
        raise ValueError("refusing to export a manifest with an invalid integrity hash")

    path = Path(destination).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonicalize_manifest(manifest) + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb", closefd=True) as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    return path


def audit_manifest_file(
    path: str | os.PathLike[str], receipt: dict[str, Any]
) -> dict[str, Any]:
    """Load and fully verify a manifest against its authoritative receipt."""
    source = Path(path).expanduser()
    try:
        with source.open("r", encoding="utf-8") as stream:
            manifest = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {
            "path": str(source),
            "valid": False,
            "error": f"{type(exc).__name__}: {exc}",
        }

    valid = verify_manifest(manifest, receipt)
    return {
        "path": str(source),
        "valid": valid,
        "manifest_hash": manifest.get("integrity", {}).get("manifest_hash")
        if isinstance(manifest, dict) else None,
        "receipt_hash": manifest.get("provenance", {}).get("receipt_hash")
        if isinstance(manifest, dict) else None,
        "network_acceptance": "not_claimed",
    }
