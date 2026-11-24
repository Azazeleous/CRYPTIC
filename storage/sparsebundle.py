"""Portable content-addressed sparse bundle with a declared partition set.

This is CRYPTIC-SPARSEBUNDLE/1, a repository-defined virtual block container.
It is not an Apple .sparsebundle image and does not perform host OS mounts.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import tempfile
import threading
from pathlib import Path
from typing import Mapping

SCHEMA = "CRYPTIC-SPARSEBUNDLE/1"
PARTITION_ROLES = {"boot", "system", "data", "ledger", "recovery", "scratch"}
PARTITION_ID = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_CHUNK_SIZE = 65_536
MAX_CHUNK_SIZE = 4 * 1024 * 1024
MAX_PARTITIONS = 32
MAX_PARTITION_SIZE = 1 << 40


class SparseBundleError(ValueError):
    """A sparse bundle or partition operation failed closed."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise SparseBundleError("manifest_encoding_invalid") from exc


def _uint(value: object, field: str, minimum: int = 0,
          maximum: int = (1 << 63) - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SparseBundleError(field + "_invalid")
    if not minimum <= value <= maximum:
        raise SparseBundleError(field + "_out_of_range")
    return value


class SparseBundle:
    """Immutable-chunk sparse storage with atomic manifest replacement.

    Chunks are content addressed by SHA-256. All-zero chunks are omitted.
    A manifest checksum detects torn or modified metadata; it is not a
    signature and does not establish publisher authenticity.
    """

    def __init__(self, root: str | os.PathLike[str]):
        self.root = Path(root).expanduser()
        if self.root.is_symlink() or not self.root.is_dir():
            raise SparseBundleError("bundle_root_must_be_real_directory")
        self.objects = self.root / "objects"
        if self.objects.is_symlink() or not self.objects.is_dir():
            raise SparseBundleError("bundle_objects_directory_invalid")
        self._lock = threading.RLock()
        self._manifest = self._load_manifest()

    @classmethod
    def create(
        cls,
        root: str | os.PathLike[str],
        partitions: Mapping[str, Mapping[str, object]],
        *,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> "SparseBundle":
        path = Path(root).expanduser()
        if path.exists() or path.is_symlink():
            raise SparseBundleError("bundle_path_already_exists")
        if not isinstance(partitions, Mapping) or not 1 <= len(partitions) <= MAX_PARTITIONS:
            raise SparseBundleError("partition_set_invalid")
        chunk_size = _uint(chunk_size, "chunk_size", 4096, MAX_CHUNK_SIZE)
        if chunk_size & (chunk_size - 1):
            raise SparseBundleError("chunk_size_must_be_power_of_two")

        rows = []
        seen_names = set()
        for partition_id, spec in sorted(partitions.items()):
            if not isinstance(partition_id, str) or not PARTITION_ID.fullmatch(partition_id):
                raise SparseBundleError("partition_id_invalid")
            if not isinstance(spec, Mapping) or set(spec) != {"name", "role", "size"}:
                raise SparseBundleError("partition_spec_invalid")
            name, role = spec["name"], spec["role"]
            if (not isinstance(name, str) or not name.strip() or len(name) > 80
                    or name in seen_names):
                raise SparseBundleError("partition_name_invalid_or_duplicate")
            if role not in PARTITION_ROLES:
                raise SparseBundleError("partition_role_invalid")
            size = _uint(spec["size"], "partition_size", 1, MAX_PARTITION_SIZE)
            seen_names.add(name)
            rows.append({
                "id": partition_id, "name": name, "role": role,
                "size": size, "extents": {},
            })

        path.mkdir(mode=0o700, parents=True, exist_ok=False)
        os.chmod(path, 0o700)
        objects = path / "objects"
        objects.mkdir(mode=0o700)
        manifest = {
            "schema": SCHEMA,
            "bundle_id": secrets.token_hex(16),
            "chunk_size": chunk_size,
            "generation": 0,
            "partitions": rows,
        }
        cls._write_manifest_files(path, manifest)
        return cls(path)

    @staticmethod
    def _write_atomic(path: Path, data: bytes) -> None:
        fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=str(path.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except Exception:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise

    @classmethod
    def _write_manifest_files(cls, root: Path, manifest: dict) -> None:
        encoded = _canonical(manifest)
        digest = hashlib.sha256(encoded).hexdigest().encode("ascii") + b"\n"
        cls._write_atomic(root / "manifest.json", encoded)
        cls._write_atomic(root / "manifest.sha256", digest)

    def _load_manifest(self) -> dict:
        try:
            raw = (self.root / "manifest.json").read_bytes()
            supplied = (self.root / "manifest.sha256").read_text("ascii").strip()
            if not HEX64.fullmatch(supplied):
                raise SparseBundleError("manifest_digest_invalid")
            if hashlib.sha256(raw).hexdigest() != supplied:
                raise SparseBundleError("manifest_integrity_failure")
            value = json.loads(raw.decode("ascii"))
        except SparseBundleError:
            raise
        except Exception as exc:
            raise SparseBundleError("manifest_unavailable_or_invalid") from exc
        if _canonical(value) != raw:
            raise SparseBundleError("manifest_not_canonical")
        self._validate_manifest(value)
        return value

    @staticmethod
    def _validate_manifest(value: object) -> None:
        if not isinstance(value, dict) or set(value) != {
            "schema", "bundle_id", "chunk_size", "generation", "partitions"
        }:
            raise SparseBundleError("manifest_fields_invalid")
        if value["schema"] != SCHEMA:
            raise SparseBundleError("manifest_schema_unsupported")
        if not isinstance(value["bundle_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", value["bundle_id"]):
            raise SparseBundleError("bundle_id_invalid")
        chunk_size = _uint(value["chunk_size"], "chunk_size", 4096, MAX_CHUNK_SIZE)
        if chunk_size & (chunk_size - 1):
            raise SparseBundleError("chunk_size_must_be_power_of_two")
        _uint(value["generation"], "generation")
        rows = value["partitions"]
        if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_PARTITIONS:
            raise SparseBundleError("partition_set_invalid")
        ids, names = set(), set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"id", "name", "role", "size", "extents"}:
                raise SparseBundleError("partition_manifest_invalid")
            pid, name, role = row["id"], row["name"], row["role"]
            if not isinstance(pid, str) or not PARTITION_ID.fullmatch(pid) or pid in ids:
                raise SparseBundleError("partition_id_invalid_or_duplicate")
            if not isinstance(name, str) or not name or name in names:
                raise SparseBundleError("partition_name_invalid_or_duplicate")
            if role not in PARTITION_ROLES:
                raise SparseBundleError("partition_role_invalid")
            size = _uint(row["size"], "partition_size", 1, MAX_PARTITION_SIZE)
            extents = row["extents"]
            if not isinstance(extents, dict):
                raise SparseBundleError("partition_extents_invalid")
            chunk_count = (size + chunk_size - 1) // chunk_size
            for index, digest in extents.items():
                if not isinstance(index, str) or not index.isdigit():
                    raise SparseBundleError("extent_index_invalid")
                if int(index) >= chunk_count or not isinstance(digest, str) or not HEX64.fullmatch(digest):
                    raise SparseBundleError("extent_reference_invalid")
            ids.add(pid)
            names.add(name)

    def _partition(self, partition_id: str) -> dict:
        for row in self._manifest["partitions"]:
            if row["id"] == partition_id:
                return row
        raise SparseBundleError("partition_not_found")

    def partitions(self) -> tuple[dict, ...]:
        with self._lock:
            return tuple({
                "id": row["id"], "name": row["name"], "role": row["role"],
                "size": row["size"], "allocated_chunks": len(row["extents"]),
            } for row in self._manifest["partitions"])

    def _read_chunk(self, digest: str | None) -> bytes:
        size = self._manifest["chunk_size"]
        if digest is None:
            return bytes(size)
        path = self.objects / digest
        if path.is_symlink() or not path.is_file():
            raise SparseBundleError("chunk_missing_or_not_regular")
        data = path.read_bytes()
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise SparseBundleError("chunk_integrity_failure")
        return data

    def _store_chunk(self, data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()
        target = self.objects / digest
        if target.exists():
            if target.is_symlink() or target.read_bytes() != data:
                raise SparseBundleError("content_address_collision_or_corruption")
        else:
            self._write_atomic(target, data)
        return digest

    def read(self, partition_id: str, offset: int, length: int) -> bytes:
        with self._lock:
            row = self._partition(partition_id)
            offset = _uint(offset, "offset")
            length = _uint(length, "length")
            if offset + length > row["size"]:
                raise SparseBundleError("read_out_of_bounds")
            chunk_size = self._manifest["chunk_size"]
            result = bytearray()
            while length:
                index, within = divmod(offset, chunk_size)
                take = min(length, chunk_size - within)
                block = self._read_chunk(row["extents"].get(str(index)))
                result.extend(block[within:within + take])
                offset += take
                length -= take
            return bytes(result)

    def write(self, partition_id: str, offset: int, data: bytes) -> int:
        if not isinstance(data, bytes):
            raise SparseBundleError("write_data_must_be_bytes")
        with self._lock:
            row = self._partition(partition_id)
            offset = _uint(offset, "offset")
            if offset + len(data) > row["size"]:
                raise SparseBundleError("write_out_of_bounds")
            if not data:
                return self._manifest["generation"]
            chunk_size = self._manifest["chunk_size"]
            cursor = 0
            while cursor < len(data):
                index, within = divmod(offset, chunk_size)
                take = min(len(data) - cursor, chunk_size - within)
                block = bytearray(self._read_chunk(row["extents"].get(str(index))))
                block[within:within + take] = data[cursor:cursor + take]
                if any(block):
                    row["extents"][str(index)] = self._store_chunk(bytes(block))
                else:
                    row["extents"].pop(str(index), None)
                offset += take
                cursor += take
            self._manifest["generation"] += 1
            self._write_manifest_files(self.root, self._manifest)
            return self._manifest["generation"]

    def verify(self) -> dict:
        with self._lock:
            checked = 0
            for row in self._manifest["partitions"]:
                for digest in row["extents"].values():
                    self._read_chunk(digest)
                    checked += 1
            encoded = _canonical(self._manifest)
            return {
                "valid": True,
                "bundle_id": self._manifest["bundle_id"],
                "generation": self._manifest["generation"],
                "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
                "chunks_verified": checked,
                "allocated_bytes": checked * self._manifest["chunk_size"],
            }
