"""FIPS 203/204 algorithm-provider integration and authenticated envelopes.

The implementation delegates the standardized primitives to the pinned
pqcrypto provider. This wrapper is an application integration layer; it is
not a CMVP/FIPS 140 validated cryptographic module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto import InvalidSignatureError
from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65

ML_KEM_ALGORITHM = "ML-KEM-768"
ML_DSA_ALGORITHM = "ML-DSA-65"
AEAD_ALGORITHM = "AES-256-GCM"
ENVELOPE_DOMAIN = b"CRYPTIC-PQ-ENVELOPE-v1\x00"
RECEIPT_CONTEXT = b"CRYPTIC-RESEARCH-RECEIPT-v1"

ML_KEM_768_SIZES = {
    "public_key": 1184,
    "secret_key": 2400,
    "ciphertext": 1088,
    "shared_secret": 32,
}
ML_DSA_65_SIZES = {
    "public_key": 1952,
    "secret_key": 4032,
    "signature": 3309,
}


class PQProviderError(RuntimeError):
    """Invalid provider output or application-level PQ envelope."""


@dataclass(frozen=True, slots=True)
class KEMKeyPair:
    public_key: bytes
    secret_key: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class SignatureKeyPair:
    public_key: bytes
    secret_key: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class PQEnvelope:
    version: int
    kem: str
    aead: str
    encapsulated_key: bytes
    salt: bytes
    nonce: bytes
    ciphertext: bytes


def _require_bytes(value: bytes, name: str, *, allow_empty: bool = True) -> bytes:
    if not isinstance(value, bytes) or (not allow_empty and not value):
        raise TypeError(f"{name}_must_be_bytes")
    return value


def _validate_context(context: bytes) -> bytes:
    _require_bytes(context, "context")
    if len(context) > 255:
        raise ValueError("mldsa_context_exceeds_255_bytes")
    return context


class MLKEM768:
    """FIPS 203 ML-KEM-768 key generation, encapsulation, and decapsulation."""

    @staticmethod
    def keygen() -> KEMKeyPair:
        public_key, secret_key = ml_kem_768.keygen()
        if len(public_key) != ML_KEM_768_SIZES["public_key"]:
            raise PQProviderError("ml_kem_768_public_key_size_mismatch")
        if len(secret_key) != ML_KEM_768_SIZES["secret_key"]:
            raise PQProviderError("ml_kem_768_secret_key_size_mismatch")
        return KEMKeyPair(public_key, secret_key)

    @staticmethod
    def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
        _require_bytes(public_key, "public_key", allow_empty=False)
        if len(public_key) != ML_KEM_768_SIZES["public_key"]:
            raise ValueError("ml_kem_768_public_key_length_invalid")
        ciphertext, shared_secret = ml_kem_768.encaps(public_key)
        if len(ciphertext) != ML_KEM_768_SIZES["ciphertext"]:
            raise PQProviderError("ml_kem_768_ciphertext_size_mismatch")
        if len(shared_secret) != ML_KEM_768_SIZES["shared_secret"]:
            raise PQProviderError("ml_kem_768_shared_secret_size_mismatch")
        return ciphertext, shared_secret

    @staticmethod
    def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
        _require_bytes(secret_key, "secret_key", allow_empty=False)
        _require_bytes(ciphertext, "ciphertext", allow_empty=False)
        if len(secret_key) != ML_KEM_768_SIZES["secret_key"]:
            raise ValueError("ml_kem_768_secret_key_length_invalid")
        if len(ciphertext) != ML_KEM_768_SIZES["ciphertext"]:
            raise ValueError("ml_kem_768_ciphertext_length_invalid")
        shared_secret = ml_kem_768.decaps(secret_key, ciphertext)
        if len(shared_secret) != ML_KEM_768_SIZES["shared_secret"]:
            raise PQProviderError("ml_kem_768_decapsulated_secret_size_mismatch")
        return shared_secret


class MLDSA65:
    """FIPS 204 ML-DSA-65 key generation, context-bound signing and verification."""

    @staticmethod
    def keygen() -> SignatureKeyPair:
        public_key, secret_key = ml_dsa_65.keygen()
        if len(public_key) != ML_DSA_65_SIZES["public_key"]:
            raise PQProviderError("ml_dsa_65_public_key_size_mismatch")
        if len(secret_key) != ML_DSA_65_SIZES["secret_key"]:
            raise PQProviderError("ml_dsa_65_secret_key_size_mismatch")
        return SignatureKeyPair(public_key, secret_key)

    @staticmethod
    def sign(secret_key: bytes, message: bytes, *, context: bytes = b"") -> bytes:
        _require_bytes(secret_key, "secret_key", allow_empty=False)
        _require_bytes(message, "message")
        _validate_context(context)
        if len(secret_key) != ML_DSA_65_SIZES["secret_key"]:
            raise ValueError("ml_dsa_65_secret_key_length_invalid")
        signature = ml_dsa_65.sign(secret_key, message, context)
        if len(signature) != ML_DSA_65_SIZES["signature"]:
            raise PQProviderError("ml_dsa_65_signature_size_mismatch")
        return signature

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes, *,
               context: bytes = b"") -> bool:
        _require_bytes(public_key, "public_key", allow_empty=False)
        _require_bytes(message, "message")
        _require_bytes(signature, "signature", allow_empty=False)
        _validate_context(context)
        if len(public_key) != ML_DSA_65_SIZES["public_key"]:
            return False
        if len(signature) != ML_DSA_65_SIZES["signature"]:
            return False
        try:
            result = ml_dsa_65.verify(public_key, message, signature, context)
        except InvalidSignatureError:
            return False
        except ValueError:
            return False
        if result is not None:
            raise PQProviderError("ml_dsa_provider_return_contract_changed")
        return True


def _derive_aead_key(shared_secret: bytes, salt: bytes, context: bytes) -> bytes:
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        info=ENVELOPE_DOMAIN + context,
    ).derive(shared_secret)


def seal_for_recipient(public_key: bytes, plaintext: bytes, *,
                       associated_data: bytes = b"", context: bytes = b"") -> PQEnvelope:
    """Encapsulate to a recipient and encrypt with HKDF-SHA256 + AES-256-GCM."""
    _require_bytes(plaintext, "plaintext")
    _require_bytes(associated_data, "associated_data")
    _require_bytes(context, "context")
    ciphertext_key, shared_secret = MLKEM768.encapsulate(public_key)
    salt = os.urandom(32)
    nonce = os.urandom(12)
    key = _derive_aead_key(shared_secret, salt, context)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return PQEnvelope(
        version=1,
        kem=ML_KEM_ALGORITHM,
        aead=AEAD_ALGORITHM,
        encapsulated_key=ciphertext_key,
        salt=salt,
        nonce=nonce,
        ciphertext=ciphertext,
    )


def open_envelope(secret_key: bytes, envelope: PQEnvelope, *,
                  associated_data: bytes = b"", context: bytes = b"") -> bytes:
    """Decapsulate and authenticate/decrypt a CRYPTIC PQ envelope."""
    _require_bytes(associated_data, "associated_data")
    _require_bytes(context, "context")
    if not isinstance(envelope, PQEnvelope):
        raise TypeError("envelope_must_be_PQEnvelope")
    if envelope.version != 1 or envelope.kem != ML_KEM_ALGORITHM or envelope.aead != AEAD_ALGORITHM:
        raise PQProviderError("unsupported_pq_envelope_profile")
    if len(envelope.salt) != 32 or len(envelope.nonce) != 12:
        raise PQProviderError("pq_envelope_salt_or_nonce_length_invalid")
    shared_secret = MLKEM768.decapsulate(secret_key, envelope.encapsulated_key)
    key = _derive_aead_key(shared_secret, envelope.salt, context)
    try:
        return AESGCM(key).decrypt(envelope.nonce, envelope.ciphertext, associated_data)
    except InvalidTag as exc:
        raise PQProviderError("pq_envelope_authentication_failed") from exc


def sign_research_receipt(secret_key: bytes, receipt: bytes, *,
                          context: bytes = RECEIPT_CONTEXT) -> bytes:
    """Sign exact receipt bytes with ML-DSA-65 and a domain-specific context."""
    return MLDSA65.sign(secret_key, receipt, context=context)


def verify_research_receipt(public_key: bytes, receipt: bytes, signature: bytes, *,
                             context: bytes = RECEIPT_CONTEXT) -> bool:
    """Verify a context-bound ML-DSA-65 receipt signature."""
    return MLDSA65.verify(public_key, receipt, signature, context=context)
