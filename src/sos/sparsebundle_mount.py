"""Capability-gated S.O.S. mount adapter for CRYPTIC sparse bundles.

The adapter exposes bounded partition reads/writes to a virtual filesystem.
It does not mount host block devices or grant host filesystem access.
"""
from __future__ import annotations

import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable

from storage.sparsebundle import SparseBundle, SparseBundleError

MOUNT_ID = re.compile(r"^[0-9a-f]{32}$")
MAX_LEASE_SECONDS = 3600
MAX_IO_BYTES = 1024 * 1024


class SparseBundleMountError(ValueError):
    """A virtual mount operation failed authorization or integrity checks."""


@dataclass(frozen=True)
class MountRecord:
    mount_id: str
    principal: str
    partition_id: str
    mountpoint: str
    mode: str
    created_at: int
    expires_at: int


class SparseBundleMountManager:
    """Lease-bound virtual partition mounts with per-operation authorization."""

    def __init__(
        self,
        *,
        bundle: SparseBundle,
        authorize: Callable[[str, str, str], bool],
        audit: Callable[[dict], object],
        clock: Callable[[], float] = time.time,
    ):
        if not isinstance(bundle, SparseBundle):
            raise SparseBundleMountError("sparsebundle_required")
        if not callable(authorize) or not callable(audit) or not callable(clock):
            raise SparseBundleMountError("authorization_audit_and_clock_required")
        self.bundle = bundle
        self.authorize = authorize
        self.audit = audit
        self.clock = clock
        self._lock = threading.RLock()
        self._mounts: dict[str, MountRecord] = {}

    @staticmethod
    def _mountpoint(value: str) -> str:
        if (not isinstance(value, str) or not value.startswith("/")
                or value == "/" or "\x00" in value or "\\" in value):
            raise SparseBundleMountError("mountpoint_invalid")
        parts = value.split("/")[1:]
        if any(part in ("", ".", "..") for part in parts):
            raise SparseBundleMountError("mountpoint_invalid")
        return "/" + "/".join(parts)

    def _record(self, mount_id: str) -> MountRecord:
        if not isinstance(mount_id, str) or not MOUNT_ID.fullmatch(mount_id):
            raise SparseBundleMountError("mount_id_invalid")
        record = self._mounts.get(mount_id)
        if record is None:
            raise SparseBundleMountError("mount_not_found")
        now = self.clock()
        if isinstance(now, bool) or not isinstance(now, (int, float)):
            raise SparseBundleMountError("clock_invalid")
        if now >= record.expires_at:
            self._mounts.pop(mount_id, None)
            self._emit("sos.mount.expired", record)
            raise SparseBundleMountError("mount_lease_expired")
        return record

    def _emit(self, event_type: str, record: MountRecord, **extra) -> None:
        event = {
            "event_type": event_type,
            "mount_id": record.mount_id,
            "principal": record.principal,
            "partition_id": record.partition_id,
            "mountpoint": record.mountpoint,
            "mode": record.mode,
            "expires_at": record.expires_at,
            **extra,
        }
        try:
            accepted = self.audit(event)
        except Exception as exc:
            raise SparseBundleMountError("mount_audit_unavailable") from exc
        if accepted is not True:
            raise SparseBundleMountError("mount_audit_not_committed")

    def mount(
        self,
        *,
        principal: str,
        partition_id: str,
        mountpoint: str,
        mode: str = "ro",
        lease_seconds: int = 300,
    ) -> MountRecord:
        if not isinstance(principal, str) or not principal or len(principal) > 256:
            raise SparseBundleMountError("principal_invalid")
        if mode not in ("ro", "rw"):
            raise SparseBundleMountError("mount_mode_invalid")
        if (isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int)
                or not 1 <= lease_seconds <= MAX_LEASE_SECONDS):
            raise SparseBundleMountError("mount_lease_invalid")
        self.bundle.partitions()
        if not any(row["id"] == partition_id for row in self.bundle.partitions()):
            raise SparseBundleMountError("partition_not_found")
        path = self._mountpoint(mountpoint)
        required = "sos.mount.read" if mode == "ro" else "sos.mount.write"
        try:
            permitted = self.authorize(principal, required, path)
        except Exception as exc:
            raise SparseBundleMountError("mount_authorization_unavailable") from exc
        if permitted is not True:
            raise SparseBundleMountError("mount_authorization_denied")
        now = self.clock()
        if isinstance(now, bool) or not isinstance(now, (int, float)) or now < 0:
            raise SparseBundleMountError("clock_invalid")
        record = MountRecord(
            secrets.token_hex(16), principal, partition_id, path, mode,
            int(now), int(now) + lease_seconds,
        )
        with self._lock:
            if any(item.mountpoint == path for item in self._mounts.values()):
                raise SparseBundleMountError("mountpoint_already_in_use")
            self._emit("sos.mount.created", record)
            self._mounts[record.mount_id] = record
        return record

    def read(self, mount_id: str, *, principal: str, offset: int, length: int) -> bytes:
        with self._lock:
            record = self._record(mount_id)
            if principal != record.principal:
                raise SparseBundleMountError("mount_principal_mismatch")
            if (isinstance(length, bool) or not isinstance(length, int)
                    or not 0 <= length <= MAX_IO_BYTES):
                raise SparseBundleMountError("mount_read_size_invalid")
            try:
                permitted = self.authorize(principal, "sos.mount.read", record.mountpoint)
            except Exception as exc:
                raise SparseBundleMountError("mount_authorization_unavailable") from exc
            if permitted is not True:
                raise SparseBundleMountError("mount_authorization_denied")
            try:
                data = self.bundle.read(record.partition_id, offset, length)
            except SparseBundleError as exc:
                raise SparseBundleMountError("mount_read_failed:" + str(exc)) from exc
            self._emit("sos.mount.read", record, offset=offset, bytes=len(data))
            return data

    def write(self, mount_id: str, *, principal: str, offset: int, data: bytes) -> int:
        with self._lock:
            record = self._record(mount_id)
            if principal != record.principal:
                raise SparseBundleMountError("mount_principal_mismatch")
            if record.mode != "rw":
                raise SparseBundleMountError("mount_read_only")
            if not isinstance(data, bytes) or len(data) > MAX_IO_BYTES:
                raise SparseBundleMountError("mount_write_size_invalid")
            try:
                permitted = self.authorize(principal, "sos.mount.write", record.mountpoint)
            except Exception as exc:
                raise SparseBundleMountError("mount_authorization_unavailable") from exc
            if permitted is not True:
                raise SparseBundleMountError("mount_authorization_denied")
            try:
                generation = self.bundle.write(record.partition_id, offset, data)
            except SparseBundleError as exc:
                raise SparseBundleMountError("mount_write_failed:" + str(exc)) from exc
            self._emit("sos.mount.write", record, offset=offset, bytes=len(data),
                       generation=generation)
            return generation

    def unmount(self, mount_id: str, *, principal: str) -> bool:
        with self._lock:
            record = self._record(mount_id)
            if principal != record.principal:
                raise SparseBundleMountError("mount_principal_mismatch")
            self._emit("sos.mount.removed", record)
            self._mounts.pop(mount_id, None)
            return True

    def status(self) -> dict:
        with self._lock:
            now = self.clock()
            expired = [key for key, value in self._mounts.items()
                       if now >= value.expires_at]
            for key in expired:
                record = self._mounts.pop(key)
                self._emit("sos.mount.expired", record)
            return {
                "active_mounts": len(self._mounts),
                "mounts": [
                    {
                        "mount_id": row.mount_id,
                        "principal": row.principal,
                        "partition_id": row.partition_id,
                        "mountpoint": row.mountpoint,
                        "mode": row.mode,
                        "expires_at": row.expires_at,
                    }
                    for row in sorted(self._mounts.values(), key=lambda item: item.mountpoint)
                ],
            }
