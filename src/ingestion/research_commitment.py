"""Domain-separated experiment commitments for reproducible regtest headers."""
from __future__ import annotations

import hashlib
import json
from typing import Any

MAX_SAFE_INTEGER = (1 << 53) - 1

DOMAIN = b"CRYPTIC-RESEARCH-EXPERIMENT-V1\x00"
HEADER_PREFIX_BYTES = 76
MERKLE_ROOT_START = 36
MERKLE_ROOT_END = 68


def _validate_canonical_value(value: Any, path: str = "$") -> None:
    """Restrict metadata to an interoperable JSON subset with safe integers."""
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ValueError(f"unsafe_integer_at_{path}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_canonical_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise ValueError(f"object_keys_must_be_ascii_strings_at_{path}")
            _validate_canonical_value(item, f"{path}.{key}")
        return
    raise ValueError(f"unsupported_canonical_value_at_{path}")


def canonical_experiment_bytes(document: Any) -> bytes:
    """Serialize restricted JSON metadata deterministically across runtimes."""
    _validate_canonical_value(document)
    try:
        encoded = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("experiment_metadata_must_be_finite_json") from exc
    return encoded


def compute_experiment_commitment(document: Any) -> str:
    """Return a lowercase SHA-256 commitment with an explicit domain separator."""
    return hashlib.sha256(DOMAIN + canonical_experiment_bytes(document)).hexdigest()


def bind_commitment_to_header_prefix(header_prefix: bytes, commitment_hex: str) -> bytes:
    """Bind the 32-byte experiment commitment into the 80-byte header's root slot.

    The result is a research/regtest header prefix, not a Bitcoin transaction
    merkle root unless the experiment commitment is also the actual tx-tree root.
    """
    if not isinstance(header_prefix, bytes) or len(header_prefix) != HEADER_PREFIX_BYTES:
        raise ValueError("header_prefix_must_be_76_bytes")
    if not isinstance(commitment_hex, str) or len(commitment_hex) != 64:
        raise ValueError("commitment_must_be_64_hex_characters")
    try:
        commitment = bytes.fromhex(commitment_hex)
    except ValueError as exc:
        raise ValueError("commitment_must_be_64_hex_characters") from exc
    if len(commitment) != 32:
        raise ValueError("commitment_must_be_32_bytes")
    return (
        header_prefix[:MERKLE_ROOT_START]
        + commitment
        + header_prefix[MERKLE_ROOT_END:]
    )


def verify_header_commitment(header_prefix: bytes, commitment_hex: str) -> bool:
    """Check that the header-prefix root slot equals the declared commitment."""
    try:
        expected = bytes.fromhex(commitment_hex)
    except (TypeError, ValueError):
        return False
    return (
        isinstance(header_prefix, bytes)
        and len(header_prefix) == HEADER_PREFIX_BYTES
        and len(expected) == 32
        and header_prefix[MERKLE_ROOT_START:MERKLE_ROOT_END] == expected
    )
