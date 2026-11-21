"""Canonical, bounded JSON transport encoding and strict decoding."""
from __future__ import annotations

import json
import math
from typing import Any


class TransportCodecError(ValueError):
    """Input cannot be represented by the canonical transport profile."""


def _validate_json_value(value: Any, seen: set[int]) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TransportCodecError("non_finite_number")
        return
    if isinstance(value, list):
        identity = id(value)
        if identity in seen:
            raise TransportCodecError("cyclic_value")
        seen.add(identity)
        try:
            for item in value:
                _validate_json_value(item, seen)
        finally:
            seen.remove(identity)
        return
    if isinstance(value, dict):
        identity = id(value)
        if identity in seen:
            raise TransportCodecError("cyclic_value")
        seen.add(identity)
        try:
            for key, item in value.items():
                if not isinstance(key, str):
                    raise TransportCodecError("object_key_must_be_string")
                _validate_json_value(item, seen)
        finally:
            seen.remove(identity)
        return
    raise TransportCodecError("unsupported_json_value")


def canonical_json_bytes(value: Any, *, max_bytes: int | None = None) -> bytes:
    """Encode JSON-compatible values deterministically as UTF-8 bytes."""
    _validate_json_value(value, set())
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise TransportCodecError("canonical_encoding_failed") from None
    if max_bytes is not None:
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
            raise TransportCodecError("max_bytes_invalid")
        if len(payload) > max_bytes:
            raise TransportCodecError("encoded_payload_too_large")
    return payload


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TransportCodecError("duplicate_object_key")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise TransportCodecError("non_finite_number")


def decode_json_document(payload: bytes, *, max_bytes: int) -> dict[str, Any]:
    """Decode one bounded UTF-8 JSON object, rejecting duplicate keys."""
    if not isinstance(payload, bytes):
        raise TransportCodecError("payload_must_be_bytes")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
        raise TransportCodecError("max_bytes_invalid")
    if len(payload) > max_bytes:
        raise TransportCodecError("payload_too_large")
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except TransportCodecError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise TransportCodecError("json_decode_failed") from None
    if not isinstance(document, dict):
        raise TransportCodecError("json_root_must_be_object")
    return document
