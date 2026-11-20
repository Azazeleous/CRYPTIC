"""Append-only raw observation journal with a verifiable SHA-256 chain.

The journal preserves provider page payloads as observed. It is tamper-evident,
not privileged-proof storage: an administrator able to rewrite the file can
also rewrite its hash chain. Export/pin the final root independently when
stronger audit anchoring is required.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
from typing import Any, Iterator, Mapping

from .source_registry import SourceDescriptor, SourcePage, SourceRegistryError


SCHEMA = "cryptic.raw-observation.v1"
AUDIT_SCHEMA = "cryptic.raw-observation-audit.v1"
_GENESIS = "0" * 64
_DEFAULT_MAX_RECORD_BYTES = 8_388_608
_RECORD_KEYS = {
    "schema", "sequence", "source_id", "source_kind", "source_schema",
    "observed_at", "item_count", "items", "next_cursor_sha256",
    "observation_id", "previous_digest", "record_digest",
}


class ObservationJournalError(ValueError):
    """Invalid journal path, page, or journal record."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str) and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _validate_json(value: Any, *, depth: int = 0) -> None:
    if depth > 64:
        raise ObservationJournalError("observation payload exceeds maximum nesting")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ObservationJournalError("observation payload contains a non-finite number")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json(item, depth=depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ObservationJournalError("observation object keys must be strings")
            _validate_json(item, depth=depth + 1)
        return
    raise ObservationJournalError("observation payload contains a non-JSON value")


@contextmanager
def _exclusive_lock(lock_path: Path) -> Iterator[None]:
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        if os.name == "nt":
            import msvcrt
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _audit_unlocked(path: Path, max_record_bytes: int) -> dict[str, Any]:
    if not path.exists():
        return {
            "schema": AUDIT_SCHEMA, "valid": True, "record_count": 0,
            "journal_root": _GENESIS, "last_sequence": 0, "error": None,
        }
    if not path.is_file():
        return {
            "schema": AUDIT_SCHEMA, "valid": False, "record_count": 0,
            "journal_root": _GENESIS, "last_sequence": 0,
            "error": "journal_path_not_regular_file",
        }

    previous = _GENESIS
    count = 0
    try:
        with path.open("rb") as stream:
            for line_number, raw in enumerate(stream, 1):
                if len(raw) > max_record_bytes + 1:
                    raise ObservationJournalError(f"line_{line_number}:record_too_large")
                if not raw.endswith(b"\n"):
                    raise ObservationJournalError(f"line_{line_number}:missing_newline")
                try:
                    record = json.loads(raw[:-1].decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise ObservationJournalError(f"line_{line_number}:invalid_json") from None
                if not isinstance(record, dict) or set(record) != _RECORD_KEYS:
                    raise ObservationJournalError(f"line_{line_number}:invalid_record_shape")
                if raw[:-1] != canonical_bytes(record):
                    raise ObservationJournalError(f"line_{line_number}:noncanonical_record")
                if record.get("schema") != SCHEMA:
                    raise ObservationJournalError(f"line_{line_number}:unsupported_schema")
                sequence = record.get("sequence")
                if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence != count + 1:
                    raise ObservationJournalError(f"line_{line_number}:sequence_mismatch")
                if record.get("previous_digest") != previous:
                    raise ObservationJournalError(f"line_{line_number}:previous_digest_mismatch")
                source_id = record.get("source_id")
                source_kind = record.get("source_kind")
                source_schema = record.get("source_schema")
                observed_at = record.get("observed_at")
                items = record.get("items")
                item_count = record.get("item_count")
                if not all(isinstance(value, str) and value for value in (source_id, source_kind, source_schema)):
                    raise ObservationJournalError(f"line_{line_number}:source_identity_invalid")
                if isinstance(observed_at, bool) or not isinstance(observed_at, int) or observed_at < 0:
                    raise ObservationJournalError(f"line_{line_number}:observed_at_invalid")
                if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                    raise ObservationJournalError(f"line_{line_number}:items_invalid")
                if isinstance(item_count, bool) or item_count != len(items):
                    raise ObservationJournalError(f"line_{line_number}:item_count_mismatch")
                _validate_json(items)
                cursor_digest = record.get("next_cursor_sha256")
                if cursor_digest is not None and not _is_digest(cursor_digest):
                    raise ObservationJournalError(f"line_{line_number}:cursor_digest_invalid")
                observation_body = {
                    "source_id": source_id,
                    "source_schema": source_schema,
                    "observed_at": observed_at,
                    "items": items,
                }
                expected_observation_id = _sha256(b"CRYPTIC|OBSERVATION|V1\0" + canonical_bytes(observation_body))
                if record.get("observation_id") != expected_observation_id:
                    raise ObservationJournalError(f"line_{line_number}:observation_id_mismatch")
                record_body = {key: value for key, value in record.items() if key != "record_digest"}
                expected_digest = _sha256(b"CRYPTIC|RAW-OBSERVATION|V1\0" + canonical_bytes(record_body))
                if record.get("record_digest") != expected_digest:
                    raise ObservationJournalError(f"line_{line_number}:record_digest_mismatch")
                previous = expected_digest
                count += 1
    except (OSError, ObservationJournalError, TypeError, ValueError) as exc:
        return {
            "schema": AUDIT_SCHEMA, "valid": False, "record_count": count,
            "journal_root": previous, "last_sequence": count,
            "error": str(exc)[:240],
        }
    return {
        "schema": AUDIT_SCHEMA, "valid": True, "record_count": count,
        "journal_root": previous, "last_sequence": count, "error": None,
    }


def audit_journal(
    journal_path: str | os.PathLike[str],
    *,
    max_record_bytes: int = _DEFAULT_MAX_RECORD_BYTES,
) -> dict[str, Any]:
    """Verify every line, sequence, canonical form, and hash-chain link."""
    if isinstance(max_record_bytes, bool) or not isinstance(max_record_bytes, int) or not 1024 <= max_record_bytes <= 67_108_864:
        raise ObservationJournalError("max_record_bytes must be between 1024 and 67108864")
    path = Path(journal_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    with _exclusive_lock(path.with_name(path.name + ".lock")):
        return _audit_unlocked(path, max_record_bytes)


def append_page(
    journal_path: str | os.PathLike[str],
    descriptor: SourceDescriptor,
    page: SourcePage,
    *,
    max_record_bytes: int = _DEFAULT_MAX_RECORD_BYTES,
) -> dict[str, Any]:
    """Append one validated source page, fsync it, and return its chain position."""
    if isinstance(max_record_bytes, bool) or not isinstance(max_record_bytes, int) or not 1024 <= max_record_bytes <= 67_108_864:
        raise ObservationJournalError("max_record_bytes must be between 1024 and 67108864")
    if not isinstance(descriptor, SourceDescriptor) or not isinstance(page, SourcePage):
        raise ObservationJournalError("descriptor and page must use registered source contracts")
    descriptor.validate()
    if descriptor.read_only is not True:
        raise ObservationJournalError("only read-only source observations may be journaled")
    page.validate(descriptor, descriptor.max_page_size)
    items = [dict(item) for item in page.items]
    _validate_json(items)
    cursor_digest = (
        _sha256(page.next_cursor.encode("utf-8"))
        if page.next_cursor is not None else None
    )
    observation_body = {
        "source_id": descriptor.source_id,
        "source_schema": page.schema_id,
        "observed_at": page.observed_at,
        "items": items,
    }
    observation_id = _sha256(
        b"CRYPTIC|OBSERVATION|V1\0" + canonical_bytes(observation_body)
    )
    path = Path(journal_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    with _exclusive_lock(lock_path):
        audit = _audit_unlocked(path, max_record_bytes)
        if not audit["valid"]:
            raise ObservationJournalError(f"refusing append to invalid journal: {audit['error']}")
        body = {
            "schema": SCHEMA,
            "sequence": audit["last_sequence"] + 1,
            "source_id": descriptor.source_id,
            "source_kind": descriptor.source_kind,
            "source_schema": page.schema_id,
            "observed_at": page.observed_at,
            "item_count": len(items),
            "items": items,
            "next_cursor_sha256": cursor_digest,
            "observation_id": observation_id,
            "previous_digest": audit["journal_root"],
        }
        record_digest = _sha256(
            b"CRYPTIC|RAW-OBSERVATION|V1\0" + canonical_bytes(body)
        )
        record = {**body, "record_digest": record_digest}
        line = canonical_bytes(record) + b"\n"
        if len(line) > max_record_bytes:
            raise ObservationJournalError("observation record exceeds configured byte limit")
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        existed = path.exists()
        file_descriptor = os.open(path, flags, 0o600)
        try:
            if os.name != "nt":
                os.fchmod(file_descriptor, 0o600)
            offset = 0
            while offset < len(line):
                written = os.write(file_descriptor, line[offset:])
                if written <= 0:
                    raise OSError("journal append made no progress")
                offset += written
            os.fsync(file_descriptor)
        finally:
            os.close(file_descriptor)
        if not existed and os.name != "nt":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        return {
            "appended": True,
            "sequence": body["sequence"],
            "observation_id": observation_id,
            "record_digest": record_digest,
            "journal_root": record_digest,
        }


def read_records(
    journal_path: str | os.PathLike[str],
    *,
    max_record_bytes: int = _DEFAULT_MAX_RECORD_BYTES,
) -> tuple[dict[str, Any], ...]:
    """Return verified records; never return partial data from an invalid journal."""
    report = audit_journal(journal_path, max_record_bytes=max_record_bytes)
    if not report["valid"]:
        raise ObservationJournalError(f"journal verification failed: {report['error']}")
    path = Path(journal_path).expanduser()
    if not path.exists():
        return ()
    records: list[dict[str, Any]] = []
    with path.open("rb") as stream:
        for raw in stream:
            records.append(json.loads(raw[:-1].decode("utf-8")))
    return tuple(records)
