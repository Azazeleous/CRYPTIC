"""Signed declarative extension admission."""
from .manifest import (
    MANIFEST_DOMAIN, MANIFEST_SCHEMA, ExtensionManifestError,
    VerifiedManifest, verify_extension_manifest,
)

__all__ = [
    "MANIFEST_DOMAIN", "MANIFEST_SCHEMA", "ExtensionManifestError",
    "VerifiedManifest", "verify_extension_manifest",
]
