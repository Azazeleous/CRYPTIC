"""Immutable content-addressed chunk storage with canonical manifests."""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MANIFEST_SCHEMA = "CRYPTIC-CHUNK-MANIFEST/1"
HEX_256 = re.compile(r"^[0-9a-f]{64}$")
MAX_CHUNK_SIZE = 4 * 1024 * 1024
MAX_TOTAL_SIZE = 1024 * 1024 * 1024
MAX_CHUNKS = 4096


class ChunkStoreError(ValueError):
    """A chunk or manifest failed validation, integrity, or storage checks."""


@dataclass(frozen=True)
class StoredManifest:
    manifest_id: str
    total_size: int
    content_sha256: str
    chunk_count: int


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ChunkStoreError("manifest_canonicalization_failed") from exc


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        # Some platforms do not expose directory fsync. File data is still
        # flushed; physical power-loss guarantees require platform testing.
        return


def _atomic_immutable_write(path: Path, payload: bytes) -> None:
    if path.is_symlink():
        raise ChunkStoreError("symlink_target_forbidden")
    if path.exists():
        if path.read_bytes() != payload:
            raise ChunkStoreError("content_address_collision_or_tampering")
        return
    descriptor, temporary_name = tempfile.mkstemp(prefix=".cryptic-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if path.is_symlink() or path.read_bytes() != payload:
            raise ChunkStoreError("atomic_write_verification_failed")
        _fsync_directory(path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


class ChunkStore:
    """Content-addressed chunks with immutable, hash-addressed manifests."""

    def __init__(self, root: str | os.PathLike[str]):
        self.root = Path(root).expanduser()
        if self.root.exists() and self.root.is_symlink():
            raise ChunkStoreError("store_root_symlink_forbidden")
        self.root.mkdir(parents=True, exist_ok=True)
        if self.root.is_symlink() or not self.root.is_dir():
            raise ChunkStoreError("store_root_invalid")
        self.objects = self.root / "objects"
        self.manifests = self.root / "manifests"
        for directory in (self.objects, self.manifests):
            if directory.exists() and directory.is_symlink():
                raise ChunkStoreError("store_directory_symlink_forbidden")
            directory.mkdir(exist_ok=True)
            if directory.is_symlink() or not directory.is_dir():
                raise ChunkStoreError("store_directory_invalid")

    def _object_path(self, digest: str) -> Path:
        if not isinstance(digest, str) or not HEX_256.fullmatch(digest):
            raise ChunkStoreError("chunk_digest_invalid")
        directory = self.objects / digest[:2]
        if directory.exists() and directory.is_symlink():
            raise ChunkStoreError("object_directory_symlink_forbidden")
        directory.mkdir(exist_ok=True)
        if directory.is_symlink() or not directory.is_dir():
            raise ChunkStoreError("object_directory_invalid")
        return directory / digest[2:]

    def put(self, data: bytes | bytearray, *, chunk_size: int = 1024 * 1024) -> StoredManifest:
        payload = bytes(data)
        if len(payload) > MAX_TOTAL_SIZE:
            raise ChunkStoreError("payload_too_large")
        if (isinstance(chunk_size, bool) or not isinstance(chunk_size, int)
                or not 1 <= chunk_size <= MAX_CHUNK_SIZE):
            raise ChunkStoreError("chunk_size_invalid")
        chunks = [
            payload[offset:offset + chunk_size]
            for offset in range(0, len(payload), chunk_size)
        ]
        if len(chunks) > MAX_CHUNKS:
            raise ChunkStoreError("chunk_count_limit_exceeded")
        entries = []
        for chunk in chunks:
            digest = hashlib.sha256(chunk).hexdigest()
            _atomic_immutable_write(self._object_path(digest), chunk)
            entries.append({"sha256": digest, "size": len(chunk)})
        manifest = {
            "schema": MANIFEST_SCHEMA,
            "chunk_size": chunk_size,
            "total_size": len(payload),
            "content_sha256": hashlib.sha256(payload).hexdigest(),
            "chunks": entries,
        }
        encoded = _canonical(manifest)
        manifest_id = hashlib.sha256(encoded).hexdigest()
        manifest_path = self.manifests / (manifest_id + ".json")
        _atomic_immutable_write(manifest_path, encoded)
        return StoredManifest(
            manifest_id=manifest_id,
            total_size=len(payload),
            content_sha256=manifest["content_sha256"],
            chunk_count=len(chunks),
        )

    def get(self, manifest_id: str) -> bytes:
        if not isinstance(manifest_id, str) or not HEX_256.fullmatch(manifest_id):
            raise ChunkStoreError("manifest_id_invalid")
        path = self.manifests / (manifest_id + ".json")
        if path.is_symlink() or not path.is_file():
            raise ChunkStoreError("manifest_not_found_or_symlinked")
        encoded = path.read_bytes()
        if hashlib.sha256(encoded).hexdigest() != manifest_id:
            raise ChunkStoreError("manifest_digest_mismatch")
        try:
            manifest = json.loads(encoded.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ChunkStoreError("manifest_encoding_invalid") from exc
        if _canonical(manifest) != encoded:
            raise ChunkStoreError("manifest_not_canonical")
        required = {"schema", "chunk_size", "total_size", "content_sha256", "chunks"}
        if not isinstance(manifest, dict) or set(manifest) != required:
            raise ChunkStoreError("manifest_fields_invalid")
        chunk_size, total_size = manifest["chunk_size"], manifest["total_size"]
        if (manifest["schema"] != MANIFEST_SCHEMA
                or isinstance(chunk_size, bool) or not isinstance(chunk_size, int)
                or not 1 <= chunk_size <= MAX_CHUNK_SIZE
                or isinstance(total_size, bool) or not isinstance(total_size, int)
                or not 0 <= total_size <= MAX_TOTAL_SIZE
                or not isinstance(manifest["content_sha256"], str)
                or not HEX_256.fullmatch(manifest["content_sha256"])
                or not isinstance(manifest["chunks"], list)
                or len(manifest["chunks"]) > MAX_CHUNKS):
            raise ChunkStoreError("manifest_values_invalid")
        entries = manifest["chunks"]
        if (total_size == 0 and entries) or (total_size > 0 and not entries):
            raise ChunkStoreError("manifest_chunk_count_invalid")
        output = bytearray()
        for index, entry in enumerate(entries):
            if (not isinstance(entry, dict) or set(entry) != {"sha256", "size"}
                    or not isinstance(entry["sha256"], str)
                    or not HEX_256.fullmatch(entry["sha256"])
                    or isinstance(entry["size"], bool) or not isinstance(entry["size"], int)
                    or not 1 <= entry["size"] <= chunk_size
                    or (index < len(entries) - 1 and entry["size"] != chunk_size)):
                raise ChunkStoreError("manifest_chunk_entry_invalid")
            object_path = self._object_path(entry["sha256"])
            if object_path.is_symlink() or not object_path.is_file():
                raise ChunkStoreError("chunk_missing_or_symlinked")
            chunk = object_path.read_bytes()
            if len(chunk) != entry["size"] or hashlib.sha256(chunk).hexdigest() != entry["sha256"]:
                raise ChunkStoreError("chunk_integrity_failure")
            output.extend(chunk)
        if len(output) != total_size:
            raise ChunkStoreError("manifest_total_size_mismatch")
        if hashlib.sha256(output).hexdigest() != manifest["content_sha256"]:
            raise ChunkStoreError("content_digest_mismatch")
        return bytes(output)

    def verify(self, manifest_id: str) -> bool:
        try:
            self.get(manifest_id)
            return True
        except (ChunkStoreError, OSError):
            return False
