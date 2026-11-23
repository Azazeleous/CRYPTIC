"""Signed, declarative extension manifests; artifacts are never executed here."""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MANIFEST_SCHEMA = "CRYPTIC-EXTENSION/1"
MANIFEST_DOMAIN = b"CRYPTIC-EXTENSION-MANIFEST/1\x00"
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_TTL_SECONDS = 365 * 24 * 60 * 60
EXTENSION_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
CAPABILITY = re.compile(r"^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*){1,3}$")
SUPPORTED_CAPABILITIES = frozenset({
    "filesystem.read", "filesystem.write", "filesystem.list",
    "filesystem.delete", "process.invoke",
})


class ExtensionManifestError(ValueError):
    """A manifest, publisher signature, or artifact failed validation."""


@dataclass(frozen=True)
class VerifiedManifest:
    extension_id: str
    version: str
    publisher_id: str
    description: str
    artifact_sha256: str
    requested_capabilities: tuple[str, ...]
    issued_at: int
    expires_at: int
    manifest: dict[str, Any]


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ExtensionManifestError("manifest_canonicalization_failed") from exc


def verify_extension_manifest(
    manifest: Mapping[str, Any],
    artifact: bytes | bytearray,
    publisher_trust: Mapping[str, bytes | Ed25519PublicKey],
    *,
    now: int | None = None,
) -> VerifiedManifest:
    if not isinstance(manifest, Mapping) or not isinstance(manifest, dict):
        raise ExtensionManifestError("manifest_object_required")
    required = {
        "schema", "extension_id", "version", "publisher_id", "description",
        "artifact_sha256", "requested_capabilities", "issued_at", "expires_at",
        "signature",
    }
    if set(manifest) != required:
        raise ExtensionManifestError("manifest_fields_invalid")
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise ExtensionManifestError("manifest_schema_unsupported")
    extension_id = manifest["extension_id"]
    version = manifest["version"]
    publisher_id = manifest["publisher_id"]
    description = manifest["description"]
    digest = manifest["artifact_sha256"]
    capabilities = manifest["requested_capabilities"]
    issued_at, expires_at = manifest["issued_at"], manifest["expires_at"]
    if not isinstance(extension_id, str) or not EXTENSION_ID.fullmatch(extension_id):
        raise ExtensionManifestError("extension_id_invalid")
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        raise ExtensionManifestError("extension_version_invalid")
    if not isinstance(publisher_id, str) or not publisher_id or len(publisher_id) > 128:
        raise ExtensionManifestError("publisher_id_invalid")
    if not isinstance(description, str) or len(description) > 1024:
        raise ExtensionManifestError("extension_description_invalid")
    if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
        raise ExtensionManifestError("artifact_digest_invalid")
    if not isinstance(artifact, (bytes, bytearray)) or len(artifact) > MAX_ARTIFACT_BYTES:
        raise ExtensionManifestError("artifact_size_invalid")
    if hashlib.sha256(bytes(artifact)).hexdigest() != digest:
        raise ExtensionManifestError("artifact_digest_mismatch")
    if (not isinstance(capabilities, list) or len(capabilities) > len(SUPPORTED_CAPABILITIES)
            or any(not isinstance(value, str) or not CAPABILITY.fullmatch(value)
                   for value in capabilities)
            or capabilities != sorted(set(capabilities))
            or any(value not in SUPPORTED_CAPABILITIES for value in capabilities)):
        raise ExtensionManifestError("requested_capabilities_invalid")
    if (isinstance(issued_at, bool) or not isinstance(issued_at, int)
            or isinstance(expires_at, bool) or not isinstance(expires_at, int)
            or expires_at <= issued_at
            or expires_at - issued_at > MAX_MANIFEST_TTL_SECONDS):
        raise ExtensionManifestError("manifest_validity_invalid")
    current = int(time.time()) if now is None else now
    if (isinstance(current, bool) or not isinstance(current, int)
            or issued_at > current + 30 or expires_at < current - 30):
        raise ExtensionManifestError("manifest_expired_or_not_yet_valid")
    try:
        key_value = publisher_trust[publisher_id]
    except (KeyError, TypeError) as exc:
        raise ExtensionManifestError("publisher_not_trusted") from exc
    try:
        key = key_value if isinstance(key_value, Ed25519PublicKey) else Ed25519PublicKey.from_public_bytes(key_value)
    except (TypeError, ValueError) as exc:
        raise ExtensionManifestError("publisher_key_invalid") from exc
    signature_text = manifest["signature"]
    if not isinstance(signature_text, str):
        raise ExtensionManifestError("manifest_signature_invalid")
    try:
        signature = base64.b64decode(signature_text, validate=True)
        if len(signature) != 64:
            raise ValueError("signature_length")
        unsigned = {key: value for key, value in manifest.items() if key != "signature"}
        key.verify(signature, MANIFEST_DOMAIN + canonical_json(unsigned))
    except (ValueError, InvalidSignature, TypeError) as exc:
        raise ExtensionManifestError("manifest_signature_invalid") from exc
    return VerifiedManifest(
        extension_id=extension_id,
        version=version,
        publisher_id=publisher_id,
        description=description,
        artifact_sha256=digest,
        requested_capabilities=tuple(capabilities),
        issued_at=issued_at,
        expires_at=expires_at,
        manifest=dict(manifest),
    )
