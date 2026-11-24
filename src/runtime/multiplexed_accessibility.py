"""Capability-checked command router for the Multiplexed Accessibility Terminal.

This module exposes only typed pool and S.O.S. operations. It does not provide
shell execution, arbitrary Python evaluation, or unrestricted filesystem access.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from src.mining.pool_service import PoolCoordinator
from src.sos.sparsebundle_mount import SparseBundleMountManager

SCHEMA = "GAIA-MULTIPLEXED-COMMAND/1"
COMMAND_ID = re.compile(r"^[0-9a-f]{32}$")
MAX_ENVELOPE_BYTES = 65_536
MAX_READ_BYTES = 32 * 1024
MAX_WRITE_BYTES = 32 * 1024

CAPABILITIES = {
    "pool.issue_job": "pool.job.issue",
    "pool.submit_share": "pool.share.submit",
    "pool.status": "pool.status.read",
    "sos.mount": "sos.mount.read",
    "sos.read": "sos.mount.read",
    "sos.write": "sos.mount.write",
    "sos.unmount": "sos.mount.unmount",
}


class MultiplexedCommandError(ValueError):
    """A multiplexed command failed schema, policy, replay, or execution checks."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise MultiplexedCommandError("command_json_invalid") from exc


def _connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10.0, isolation_level=None)
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    return conn


class MultiplexedAccessibilityRuntime:
    """Durable idempotent command boundary for browser and native clients.

    Authentication identity is supplied by the transport adapter, never by
    the command payload. A reserved command ID that is interrupted by process
    failure is not automatically retried: the caller must inspect service
    state and issue a new command ID after resolving the outcome.
    """

    def __init__(
        self,
        *,
        database: str | os.PathLike[str],
        pool: PoolCoordinator,
        mounts: SparseBundleMountManager,
        authorize: Callable[[str, str, str], bool],
        audit: Callable[[dict], object],
        clock: Callable[[], int] = lambda: int(time.time()),
    ):
        path = Path(database).expanduser()
        if str(database) == ":memory:" or (path.exists() and path.is_symlink()):
            raise MultiplexedCommandError("persistent_non_symlink_command_ledger_required")
        if not isinstance(pool, PoolCoordinator) or not isinstance(mounts, SparseBundleMountManager):
            raise MultiplexedCommandError("pool_and_sos_mount_adapters_required")
        if not callable(authorize) or not callable(audit) or not callable(clock):
            raise MultiplexedCommandError("authorization_audit_and_clock_required")
        path.parent.mkdir(parents=True, exist_ok=True)
        self.database = str(path)
        self.pool = pool
        self.mounts = mounts
        self.authorize = authorize
        self.audit = audit
        self.clock = clock
        with _connect(self.database) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS multiplexed_commands (
                    command_id TEXT PRIMARY KEY,
                    request_hash TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('started','completed','failed')),
                    response_json BLOB,
                    created_at INTEGER NOT NULL,
                    completed_at INTEGER
                )
            """)
        try:
            os.chmod(self.database, 0o600)
        except OSError as exc:
            raise MultiplexedCommandError("command_ledger_permissions_failed") from exc

    def _authorize(self, principal: str, capability: str, resource: str) -> None:
        try:
            permitted = self.authorize(principal, capability, resource)
        except Exception as exc:
            raise MultiplexedCommandError("command_authorization_unavailable") from exc
        if permitted is not True:
            raise MultiplexedCommandError("command_authorization_denied")

    def _emit(self, event: dict) -> None:
        try:
            accepted = self.audit(event)
        except Exception as exc:
            raise MultiplexedCommandError("command_audit_unavailable") from exc
        if accepted is not True:
            raise MultiplexedCommandError("command_audit_not_committed")

    def _reserve(self, command_id: str, request_hash: str, now: int) -> dict | None:
        with _connect(self.database) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT request_hash,state,response_json FROM multiplexed_commands WHERE command_id=?",
                    (command_id,),
                ).fetchone()
                if row is not None:
                    if row[0] != request_hash:
                        raise MultiplexedCommandError("command_id_reused_with_different_request")
                    if row[1] == "completed" and row[2] is not None:
                        conn.execute("COMMIT")
                        return json.loads(bytes(row[2]).decode("ascii"))
                    raise MultiplexedCommandError("command_outcome_requires_reconciliation")
                conn.execute(
                    "INSERT INTO multiplexed_commands(command_id,request_hash,state,created_at) VALUES(?,?,?,?)",
                    (command_id, request_hash, "started", now),
                )
                conn.execute("COMMIT")
                return None
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def _finish(self, command_id: str, state: str, response: dict, now: int) -> None:
        encoded = _canonical(response)
        with _connect(self.database) as conn:
            conn.execute(
                "UPDATE multiplexed_commands SET state=?,response_json=?,completed_at=? WHERE command_id=? AND state='started'",
                (state, encoded, now, command_id),
            )

    @staticmethod
    def _mount_dict(record) -> dict:
        return {
            "mount_id": record.mount_id,
            "principal": record.principal,
            "partition_id": record.partition_id,
            "mountpoint": record.mountpoint,
            "mode": record.mode,
            "created_at": record.created_at,
            "expires_at": record.expires_at,
        }

    def _execute(
        self,
        operation: str,
        payload: Mapping[str, Any],
        *,
        principal: str,
        worker_id: str | None,
    ) -> dict:
        if operation == "pool.issue_job":
            required = {
                "worker_id", "height", "epoch", "lifetime_seconds",
                "parent_hash", "payload_hash", "primary_stride",
                "compact_stride", "nonce_start", "max_attempts",
            }
            if set(payload) != required or payload.get("worker_id") != worker_id or not worker_id:
                raise MultiplexedCommandError("pool_job_payload_or_worker_invalid")
            job = self.pool.issue_job(**dict(payload))
            return {"job": job}

        if operation == "pool.submit_share":
            if set(payload) != {"submission"} or not isinstance(payload["submission"], Mapping):
                raise MultiplexedCommandError("pool_submission_payload_invalid")
            if not worker_id:
                raise MultiplexedCommandError("authenticated_worker_required")
            return self.pool.submit_share(
                payload["submission"], authenticated_worker_id=worker_id,
            )

        if operation == "pool.status":
            if payload:
                raise MultiplexedCommandError("pool_status_payload_invalid")
            return self.pool.status()

        if operation == "sos.mount":
            if set(payload) != {"partition_id", "mountpoint", "mode", "lease_seconds"}:
                raise MultiplexedCommandError("sos_mount_payload_invalid")
            record = self.mounts.mount(
                principal=principal,
                partition_id=payload["partition_id"],
                mountpoint=payload["mountpoint"],
                mode=payload["mode"],
                lease_seconds=payload["lease_seconds"],
            )
            return {"mount": self._mount_dict(record)}

        if operation == "sos.read":
            if set(payload) != {"mount_id", "offset", "length"}:
                raise MultiplexedCommandError("sos_read_payload_invalid")
            length = payload["length"]
            if isinstance(length, bool) or not isinstance(length, int) or not 0 <= length <= MAX_READ_BYTES:
                raise MultiplexedCommandError("sos_read_size_invalid")
            data = self.mounts.read(
                payload["mount_id"], principal=principal,
                offset=payload["offset"], length=length,
            )
            return {"data_b64": base64.b64encode(data).decode("ascii"), "bytes": len(data)}

        if operation == "sos.write":
            if set(payload) != {"mount_id", "offset", "data_b64"}:
                raise MultiplexedCommandError("sos_write_payload_invalid")
            encoded = payload["data_b64"]
            if not isinstance(encoded, str):
                raise MultiplexedCommandError("sos_write_encoding_invalid")
            try:
                data = base64.b64decode(encoded, validate=True)
            except Exception as exc:
                raise MultiplexedCommandError("sos_write_encoding_invalid") from exc
            if len(data) > MAX_WRITE_BYTES:
                raise MultiplexedCommandError("sos_write_size_invalid")
            generation = self.mounts.write(
                payload["mount_id"], principal=principal,
                offset=payload["offset"], data=data,
            )
            return {"generation": generation, "bytes": len(data)}

        if operation == "sos.unmount":
            if set(payload) != {"mount_id"}:
                raise MultiplexedCommandError("sos_unmount_payload_invalid")
            return {
                "unmounted": self.mounts.unmount(
                    payload["mount_id"], principal=principal,
                )
            }

        raise MultiplexedCommandError("command_operation_not_allowed")

    def dispatch(
        self,
        envelope: Mapping[str, Any],
        *,
        authenticated_principal: str,
        authenticated_worker_id: str | None = None,
    ) -> dict:
        """Validate, authorize, reserve, execute, audit, and persist one command."""
        fields = {
            "schema", "command_id", "correlation_id", "principal",
            "capability", "operation", "payload",
        }
        if not isinstance(envelope, Mapping) or set(envelope) != fields:
            raise MultiplexedCommandError("command_envelope_fields_invalid")
        if envelope["schema"] != SCHEMA:
            raise MultiplexedCommandError("command_schema_unsupported")
        command_id = envelope["command_id"]
        correlation_id = envelope["correlation_id"]
        if not isinstance(command_id, str) or not COMMAND_ID.fullmatch(command_id):
            raise MultiplexedCommandError("command_id_invalid")
        if not isinstance(correlation_id, str) or not COMMAND_ID.fullmatch(correlation_id):
            raise MultiplexedCommandError("correlation_id_invalid")
        principal = envelope["principal"]
        if (not isinstance(authenticated_principal, str) or not authenticated_principal
                or principal != authenticated_principal):
            raise MultiplexedCommandError("authenticated_principal_mismatch")
        operation = envelope["operation"]
        capability = envelope["capability"]
        if operation not in CAPABILITIES:
            raise MultiplexedCommandError("command_operation_not_allowed")
        payload = envelope["payload"]
        if not isinstance(payload, Mapping):
            raise MultiplexedCommandError("command_payload_invalid")
        expected_capability = CAPABILITIES[operation]
        if operation == "sos.mount":
            expected_capability = (
                "sos.mount.write" if payload.get("mode") == "rw"
                else "sos.mount.read"
            )
        if capability != expected_capability:
            raise MultiplexedCommandError("command_capability_mismatch")
        raw = _canonical(dict(envelope))
        if len(raw) > MAX_ENVELOPE_BYTES:
            raise MultiplexedCommandError("command_envelope_too_large")
        if operation == "sos.mount":
            resource = str(payload.get("mountpoint", ""))
        elif operation.startswith("sos."):
            mount_id = payload.get("mount_id")
            active = self.mounts.status()["mounts"]
            mounted = next((row for row in active if row["mount_id"] == mount_id), None)
            if mounted is None:
                raise MultiplexedCommandError("mount_not_found")
            resource = mounted["mountpoint"]
        else:
            resource = self.pool.pool_id
        self._authorize(principal, capability, resource)
        now = self.clock()
        if isinstance(now, bool) or not isinstance(now, int) or now < 0:
            raise MultiplexedCommandError("command_clock_invalid")
        request_hash = hashlib.sha256(raw).hexdigest()
        cached = self._reserve(command_id, request_hash, now)
        if cached is not None:
            return cached

        try:
            result = self._execute(
                operation, payload, principal=principal,
                worker_id=authenticated_worker_id,
            )
            response = {
                "schema": "GAIA-MULTIPLEXED-RESPONSE/1",
                "command_id": command_id,
                "correlation_id": correlation_id,
                "status": "completed",
                "result": result,
            }
            self._emit({
                "event_type": "multiplexed.command.completed",
                "command_id": command_id,
                "correlation_id": correlation_id,
                "principal": principal,
                "operation": operation,
                "request_hash": request_hash,
            })
            self._finish(command_id, "completed", response, self.clock())
            return response
        except Exception as exc:
            response = {
                "schema": "GAIA-MULTIPLEXED-RESPONSE/1",
                "command_id": command_id,
                "correlation_id": correlation_id,
                "status": "failed",
                "error": str(exc) if isinstance(exc, MultiplexedCommandError) else "command_execution_failed",
            }
            try:
                self._emit({
                    "event_type": "multiplexed.command.failed",
                    "command_id": command_id,
                    "correlation_id": correlation_id,
                    "principal": principal,
                    "operation": operation,
                    "request_hash": request_hash,
                    "error": response["error"],
                })
            except Exception:
                response["error"] = "command_outcome_requires_reconciliation"
            self._finish(command_id, "failed", response, self.clock())
            return response
