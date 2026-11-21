"""ML-DSA-65 signed adapter manifests and explicit trust anchors."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import threading
from typing import Any

from src.ingestion.pq_security import MLDSA65, RECEIPT_CONTEXT

MANIFEST_SCHEMA = "cryptic.adapter-manifest.v1"
MANIFEST_CONTEXT = b"CRYPTIC-ADAPTER-MANIFEST-v1"
MANIFEST_DOMAIN = b"CRYPTIC-ADAPTER-MANIFEST-CANONICAL-v1\x00"


@dataclass(frozen=True, slots=True)
class SignedAdapterManifest:
    manifest: dict[str, Any]
    signer_key_id: str
    signature: bytes


class AdapterTrustStore:
    """Explicit pinset for ML-DSA-65 public keys; no self-trust on import."""

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}
        self._lock = threading.RLock()

    @staticmethod
    def key_id(public_key: bytes) -> str:
        if not isinstance(public_key, bytes) or len(public_key) != 1952:
            raise ValueError("ml_dsa_65_public_key_length_invalid")
        return hashlib.sha256(b"CRYPTIC-ML-DSA-65-TRUST-ANCHOR-v1\x00" + public_key).hexdigest()

    def add(self, public_key: bytes) -> str:
        key_id = self.key_id(public_key)
        with self._lock:
            self._keys[key_id] = bytes(public_key)
        return key_id

    def revoke(self, key_id: str) -> bool:
        with self._lock:
            return self._keys.pop(key_id, None) is not None

    def resolve(self, key_id: str) -> bytes | None:
        with self._lock:
            key = self._keys.get(key_id)
            return bytes(key) if key is not None else None


def adapter_manifest_document(adapter: Any) -> dict[str, Any]:
    """Build a public, secret-free manifest from an adapter's declared capabilities."""
    adapter_id = getattr(adapter, "adapter_id", None)
    caps = getattr(adapter, "capabilities", None)
    if not isinstance(adapter_id, str) or not adapter_id.strip():
        raise ValueError("adapter_id_required")
    if caps is None:
        raise ValueError("adapter_capabilities_required")
    return {
        "schema": MANIFEST_SCHEMA,
        "adapter_id": adapter_id,
        "protocols": sorted(caps.protocols),
        "kem_algorithms": sorted(caps.kem_algorithms),
        "signature_algorithms": sorted(caps.signature_algorithms),
        "max_request_bytes": caps.max_request_bytes,
        "max_response_bytes": caps.max_response_bytes,
        "authenticated": caps.authenticated,
        "deadline_enforced": caps.deadline_enforced,
    }


def _manifest_payload(document: dict[str, Any]) -> bytes:
    from src.ingestion.research_commitment import canonical_experiment_bytes

    if not isinstance(document, dict) or document.get("schema") != MANIFEST_SCHEMA:
        raise ValueError("adapter_manifest_schema_invalid")
    return MANIFEST_DOMAIN + canonical_experiment_bytes(document)


def sign_adapter_manifest(adapter: Any, *, signing_secret_key: bytes,
                          signer_public_key: bytes) -> SignedAdapterManifest:
    document = adapter_manifest_document(adapter)
    payload = _manifest_payload(document)
    key_id = AdapterTrustStore.key_id(signer_public_key)
    signature = MLDSA65.sign(
        signing_secret_key, payload, context=MANIFEST_CONTEXT
    )
    if not MLDSA65.verify(
        signer_public_key, payload, signature, context=MANIFEST_CONTEXT
    ):
        raise ValueError("adapter_manifest_signature_self_verification_failed")
    return SignedAdapterManifest(document, key_id, signature)


def verify_signed_adapter_manifest(
    signed: SignedAdapterManifest, trust_store: AdapterTrustStore
) -> bool:
    if not isinstance(signed, SignedAdapterManifest) or not isinstance(trust_store, AdapterTrustStore):
        return False
    public_key = trust_store.resolve(signed.signer_key_id)
    if public_key is None:
        return False
    try:
        if AdapterTrustStore.key_id(public_key) != signed.signer_key_id:
            return False
        payload = _manifest_payload(signed.manifest)
        return MLDSA65.verify(
            public_key, payload, signed.signature, context=MANIFEST_CONTEXT
        )
    except (TypeError, ValueError):
        return False


def manifest_matches_adapter(signed: SignedAdapterManifest, adapter: Any) -> bool:
    try:
        return signed.manifest == adapter_manifest_document(adapter)
    except (AttributeError, TypeError, ValueError):
        return False
