"""Capability-scoped, SQLite-backed virtual computer.

Only built-in declarative commands execute. Extension artifacts are verified
and stored as data; this module never imports, evals, execs, or launches them.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.extensions.manifest import (
    ExtensionManifestError,
    VerifiedManifest,
    canonical_json,
    verify_extension_manifest,
)
from src.sos.sparsebundle_mount import SparseBundleMountManager

GRANT_SCHEMA = "CRYPTIC-SOS-CAPABILITY-GRANT/1"
GRANT_DOMAIN = b"CRYPTIC-SOS-CAPABILITY-GRANT/1\x00"
AUDIT_DOMAIN = b"CRYPTIC-SOS-AUDIT/1\x00"
ZERO_HASH = "0" * 64
GRANT_ID = re.compile(r"^[0-9a-f]{32}$")
MAX_GRANT_TTL_SECONDS = 3600
MAX_COMMAND_ARGS = 16
MAX_COMMAND_BYTES = 16 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_EXTENSION_BYTES = 10 * 1024 * 1024
MAX_EXTENSION_FILES = 1024


class VirtualComputerError(ValueError):
    """A virtual-computer operation failed a policy, scope, or integrity check."""


@dataclass(frozen=True)
class VerifiedGrant:
    grant_id: str
    extension_id: str
    signer_id: str
    capabilities: tuple[str, ...]
    resources: tuple[str, ...]
    issued_at: int
    expires_at: int
    grant: dict[str, Any]


@dataclass(frozen=True)
class VirtualProcess:
    process_id: str
    extension_id: str
    argv: tuple[str, ...]
    status: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int


def _path(value: str, *, scope: bool = False) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 512:
        raise VirtualComputerError("virtual_path_invalid")
    if value.startswith("/") or "\\" in value or "\x00" in value:
        raise VirtualComputerError("virtual_path_absolute_or_malformed")
    trailing = scope and value.endswith("/")
    parts = value[:-1].split("/") if trailing else value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise VirtualComputerError("virtual_path_traversal_rejected")
    normalized = "/".join(parts)
    return normalized + ("/" if trailing else "")


def _scope_allows(path: str, scopes: Sequence[str]) -> bool:
    for scope in scopes:
        if scope.endswith("/"):
            if path == scope[:-1] or path.startswith(scope):
                return True
        elif path == scope:
            return True
    return False


def verify_capability_grant(
    grant: Mapping[str, Any],
    authority_trust: Mapping[str, bytes | Ed25519PublicKey],
    manifest: VerifiedManifest,
    *,
    now: int | None = None,
) -> VerifiedGrant:
    if not isinstance(grant, dict):
        raise VirtualComputerError("capability_grant_object_required")
    required = {
        "schema", "grant_id", "extension_id", "signer_id", "capabilities",
        "resources", "issued_at", "expires_at", "nonce", "signature",
    }
    if set(grant) != required or grant["schema"] != GRANT_SCHEMA:
        raise VirtualComputerError("capability_grant_schema_invalid")
    grant_id, extension_id, signer_id = (
        grant["grant_id"], grant["extension_id"], grant["signer_id"]
    )
    if not isinstance(grant_id, str) or not GRANT_ID.fullmatch(grant_id):
        raise VirtualComputerError("capability_grant_id_invalid")
    if extension_id != manifest.extension_id:
        raise VirtualComputerError("capability_grant_extension_mismatch")
    if not isinstance(signer_id, str) or not signer_id or len(signer_id) > 128:
        raise VirtualComputerError("capability_grant_signer_invalid")
    capabilities = grant["capabilities"]
    if (not isinstance(capabilities, list)
            or any(not isinstance(value, str) for value in capabilities)
            or capabilities != sorted(set(capabilities))
            or any(value not in manifest.requested_capabilities for value in capabilities)):
        raise VirtualComputerError("capability_grant_exceeds_manifest")
    resources = grant["resources"]
    if not isinstance(resources, list) or len(resources) > 128:
        raise VirtualComputerError("capability_grant_resources_invalid")
    try:
        normalized_scopes = [_path(value, scope=True) for value in resources]
    except VirtualComputerError as exc:
        raise VirtualComputerError("capability_grant_resources_invalid") from exc
    if normalized_scopes != sorted(set(normalized_scopes)):
        raise VirtualComputerError("capability_grant_resources_not_canonical")
    issued_at, expires_at = grant["issued_at"], grant["expires_at"]
    if (isinstance(issued_at, bool) or not isinstance(issued_at, int)
            or isinstance(expires_at, bool) or not isinstance(expires_at, int)
            or expires_at <= issued_at
            or expires_at - issued_at > MAX_GRANT_TTL_SECONDS):
        raise VirtualComputerError("capability_grant_validity_invalid")
    current = int(time.time()) if now is None else now
    if (isinstance(current, bool) or not isinstance(current, int)
            or issued_at > current + 30 or expires_at < current - 30):
        raise VirtualComputerError("capability_grant_expired_or_not_yet_valid")
    nonce = grant["nonce"]
    if not isinstance(nonce, str) or not GRANT_ID.fullmatch(nonce):
        raise VirtualComputerError("capability_grant_nonce_invalid")
    try:
        key_value = authority_trust[signer_id]
    except (KeyError, TypeError) as exc:
        raise VirtualComputerError("capability_grant_signer_untrusted") from exc
    try:
        key = key_value if isinstance(key_value, Ed25519PublicKey) else Ed25519PublicKey.from_public_bytes(key_value)
        signature = base64.b64decode(grant["signature"], validate=True)
        if len(signature) != 64:
            raise ValueError("signature_length")
        unsigned = {key: value for key, value in grant.items() if key != "signature"}
        key.verify(signature, GRANT_DOMAIN + canonical_json(unsigned))
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise VirtualComputerError("capability_grant_signature_invalid") from exc
    return VerifiedGrant(
        grant_id=grant_id,
        extension_id=extension_id,
        signer_id=signer_id,
        capabilities=tuple(capabilities),
        resources=tuple(normalized_scopes),
        issued_at=issued_at,
        expires_at=expires_at,
        grant=dict(grant),
    )


class VirtualComputer:
    """An auditable virtual filesystem and allowlisted command interpreter."""

    def __init__(
        self,
        database: str | Path,
        *,
        publisher_trust: Mapping[str, bytes | Ed25519PublicKey],
        authority_trust: Mapping[str, bytes | Ed25519PublicKey],
        clock=time.time,
        command_budget_seconds: float = 0.25,
        mount_provider: SparseBundleMountManager | None = None,
    ):
        self.database = Path(database).expanduser()
        if self.database.exists() and self.database.is_symlink():
            raise VirtualComputerError("virtual_database_symlink_forbidden")
        self.database.parent.mkdir(parents=True, exist_ok=True)
        if self.database.parent.is_symlink():
            raise VirtualComputerError("virtual_database_parent_symlink_forbidden")
        if (isinstance(command_budget_seconds, bool)
                or not isinstance(command_budget_seconds, (int, float))
                or not 0 < command_budget_seconds <= 1.0):
            raise VirtualComputerError("command_budget_invalid")
        self.publisher_trust = dict(publisher_trust)
        self.authority_trust = dict(authority_trust)
        if mount_provider is not None and not isinstance(mount_provider, SparseBundleMountManager):
            raise VirtualComputerError("sparsebundle_mount_provider_invalid")
        self.mount_provider = mount_provider
        self.clock = clock
        self.command_budget_seconds = float(command_budget_seconds)
        with closing(self._connect()) as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS extensions (
                    extension_id TEXT PRIMARY KEY,
                    version TEXT NOT NULL,
                    publisher_id TEXT NOT NULL,
                    manifest_json TEXT NOT NULL,
                    artifact BLOB NOT NULL,
                    installed_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS capability_grants (
                    grant_id TEXT PRIMARY KEY,
                    extension_id TEXT NOT NULL REFERENCES extensions(extension_id),
                    grant_json TEXT NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    revoked_at INTEGER
                );
                CREATE TABLE IF NOT EXISTS virtual_files (
                    extension_id TEXT NOT NULL REFERENCES extensions(extension_id),
                    path TEXT NOT NULL,
                    content BLOB NOT NULL,
                    sha256 TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY(extension_id, path)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY,
                    event_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                );
            """)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @staticmethod
    def _verify_audit_connection(connection: sqlite3.Connection) -> bool:
        previous_hash = ZERO_HASH
        expected_sequence = 1
        rows = connection.execute(
            "SELECT sequence,event_json,previous_hash,event_hash FROM audit_events ORDER BY sequence"
        ).fetchall()
        for sequence, event_json, recorded_previous, recorded_hash in rows:
            try:
                event = json.loads(event_json)
                if not isinstance(event, dict):
                    return False
                encoded = canonical_json(event)
                digest = hashlib.sha256(
                    AUDIT_DOMAIN + bytes.fromhex(previous_hash) + encoded
                ).hexdigest()
            except (ValueError, TypeError, json.JSONDecodeError):
                return False
            if (sequence != expected_sequence or event.get("sequence") != sequence
                    or encoded.decode("utf-8") != event_json
                    or recorded_previous != previous_hash or recorded_hash != digest):
                return False
            previous_hash = digest
            expected_sequence += 1
        return True

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        *,
        actor: str,
        action: str,
        resource: str,
        outcome: str,
        details: Mapping[str, Any] | None = None,
        timestamp: int,
    ) -> None:
        if not VirtualComputer._verify_audit_connection(connection):
            raise VirtualComputerError("audit_chain_integrity_failure")
        previous = connection.execute(
            "SELECT sequence,event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if previous is None else previous[0] + 1
        previous_hash = ZERO_HASH if previous is None else previous[1]
        event = {
            "sequence": sequence,
            "timestamp": timestamp,
            "actor": actor,
            "action": action,
            "resource": resource,
            "outcome": outcome,
            "details": dict(details or {}),
        }
        encoded = canonical_json(event)
        digest = hashlib.sha256(AUDIT_DOMAIN + bytes.fromhex(previous_hash) + encoded).hexdigest()
        connection.execute(
            "INSERT INTO audit_events(sequence,event_json,previous_hash,event_hash) VALUES(?,?,?,?)",
            (sequence, encoded.decode("utf-8"), previous_hash, digest),
        )

    def install_extension(self, manifest: Mapping[str, Any], artifact: bytes | bytearray) -> VerifiedManifest:
        try:
            verified = verify_extension_manifest(
                manifest, artifact, self.publisher_trust, now=int(self.clock())
            )
        except ExtensionManifestError as exc:
            raise VirtualComputerError(str(exc)) from exc
        timestamp = int(self.clock())
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT version,manifest_json,artifact FROM extensions WHERE extension_id=?",
                (verified.extension_id,),
            ).fetchone()
            encoded_manifest = canonical_json(dict(manifest)).decode("utf-8")
            if existing is not None:
                if existing[0] == verified.version and existing[1] == encoded_manifest and bytes(existing[2]) == bytes(artifact):
                    self._audit(
                        connection, actor="operator", action="extension.install",
                        resource=verified.extension_id, outcome="idempotent",
                        details={"version": verified.version}, timestamp=timestamp,
                    )
                    connection.execute("COMMIT")
                    return verified
                connection.execute("ROLLBACK")
                raise VirtualComputerError("extension_replacement_requires_separate_review")
            connection.execute(
                "INSERT INTO extensions(extension_id,version,publisher_id,manifest_json,artifact,installed_at) VALUES(?,?,?,?,?,?)",
                (verified.extension_id, verified.version, verified.publisher_id,
                 encoded_manifest, bytes(artifact), timestamp),
            )
            self._audit(
                connection, actor="operator", action="extension.install",
                resource=verified.extension_id, outcome="accepted",
                details={"version": verified.version, "artifact_sha256": verified.artifact_sha256},
                timestamp=timestamp,
            )
            connection.execute("COMMIT")
        return verified

    def activate_grant(self, grant: Mapping[str, Any]) -> VerifiedGrant:
        extension_id = grant.get("extension_id") if isinstance(grant, Mapping) else None
        if not isinstance(extension_id, str):
            raise VirtualComputerError("capability_grant_extension_invalid")
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT manifest_json,artifact FROM extensions WHERE extension_id=?",
                (extension_id,),
            ).fetchone()
            if row is None:
                raise VirtualComputerError("extension_not_installed")
            manifest_data = json.loads(row[0])
            try:
                manifest = verify_extension_manifest(
                    manifest_data, bytes(row[1]), self.publisher_trust, now=int(self.clock())
                )
            except ExtensionManifestError as exc:
                raise VirtualComputerError(str(exc)) from exc
            verified = verify_capability_grant(
                grant, self.authority_trust, manifest, now=int(self.clock())
            )
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT extension_id,grant_json FROM capability_grants WHERE grant_id=?",
                (verified.grant_id,),
            ).fetchone()
            encoded = canonical_json(dict(grant)).decode("utf-8")
            if existing is not None:
                if existing == (extension_id, encoded):
                    connection.execute("COMMIT")
                    return verified
                connection.execute("ROLLBACK")
                raise VirtualComputerError("capability_grant_id_collision")
            connection.execute(
                "INSERT INTO capability_grants(grant_id,extension_id,grant_json) VALUES(?,?,?)",
                (verified.grant_id, extension_id, encoded),
            )
            self._audit(
                connection, actor=verified.signer_id, action="capability.grant",
                resource=extension_id, outcome="accepted",
                details={"grant_id": verified.grant_id, "capabilities": list(verified.capabilities)},
                timestamp=int(self.clock()),
            )
            connection.execute("COMMIT")
        return verified

    def revoke_grant(self, grant_id: str, *, actor: str) -> bool:
        if not isinstance(grant_id, str) or not GRANT_ID.fullmatch(grant_id):
            raise VirtualComputerError("capability_grant_id_invalid")
        if not isinstance(actor, str) or not actor or len(actor) > 128:
            raise VirtualComputerError("revocation_actor_invalid")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT extension_id,revoked FROM capability_grants WHERE grant_id=?",
                (grant_id,),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                return False
            if row[1]:
                connection.execute("COMMIT")
                return True
            connection.execute(
                "UPDATE capability_grants SET revoked=1,revoked_at=? WHERE grant_id=?",
                (int(self.clock()), grant_id),
            )
            self._audit(
                connection, actor=actor, action="capability.revoke",
                resource=row[0], outcome="accepted",
                details={"grant_id": grant_id}, timestamp=int(self.clock()),
            )
            connection.execute("COMMIT")
        return True

    def run(self, extension_id: str, grant_id: str, argv: Sequence[str]) -> VirtualProcess:
        started = time.monotonic()
        process_id = secrets.token_hex(16)
        if (not isinstance(extension_id, str) or not extension_id
                or not isinstance(argv, Sequence) or isinstance(argv, (str, bytes))
                or not 1 <= len(argv) <= MAX_COMMAND_ARGS
                or any(not isinstance(value, str) or "\x00" in value for value in argv)
                or sum(len(value.encode("utf-8")) for value in argv) > MAX_COMMAND_BYTES):
            raise VirtualComputerError("virtual_process_arguments_invalid")
        args = tuple(argv)
        command = args[0]
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT e.manifest_json,e.artifact,g.grant_json,g.revoked "
                    "FROM extensions e JOIN capability_grants g ON g.extension_id=e.extension_id "
                    "WHERE e.extension_id=? AND g.grant_id=?",
                    (extension_id, grant_id),
                ).fetchone()
                if row is None:
                    raise VirtualComputerError("extension_or_grant_not_found")
                if row[3]:
                    raise VirtualComputerError("capability_grant_revoked")
                manifest = verify_extension_manifest(
                    json.loads(row[0]), bytes(row[1]), self.publisher_trust,
                    now=int(self.clock()),
                )
                verified = verify_capability_grant(
                    json.loads(row[2]), self.authority_trust, manifest,
                    now=int(self.clock()),
                )
                if "process.invoke" not in verified.capabilities:
                    raise VirtualComputerError("capability_denied:process.invoke")
                output = self._dispatch(connection, manifest.extension_id, verified, args)
                if time.monotonic() - started > self.command_budget_seconds:
                    raise VirtualComputerError("command_budget_exceeded")
                if len(output.encode("utf-8")) > MAX_OUTPUT_BYTES:
                    raise VirtualComputerError("virtual_process_output_too_large")
                self._audit(
                    connection, actor=extension_id, action="sos.command",
                    resource=command, outcome="accepted",
                    details={"process_id": process_id, "argv": list(args)},
                    timestamp=int(self.clock()),
                )
                connection.execute("COMMIT")
            return VirtualProcess(
                process_id, extension_id, args, "completed", 0, output, "",
                int((time.monotonic() - started) * 1000),
            )
        except (VirtualComputerError, ExtensionManifestError) as exc:
            with closing(self._connect()) as connection:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                connection.execute("BEGIN IMMEDIATE")
                self._audit(
                    connection, actor=extension_id, action="sos.command",
                    resource=command, outcome="denied",
                    details={"process_id": process_id, "argv": list(args), "reason": str(exc)},
                    timestamp=int(self.clock()),
                )
                connection.execute("COMMIT")
            return VirtualProcess(
                process_id, extension_id, args, "denied", 126, "",
                str(exc), int((time.monotonic() - started) * 1000),
            )

    def _require(self, grant: VerifiedGrant, capability: str, resource: str | None = None) -> None:
        if capability not in grant.capabilities:
            raise VirtualComputerError("capability_denied:" + capability)
        if resource is not None:
            normalized = _path(resource)
            if not _scope_allows(normalized, grant.resources):
                raise VirtualComputerError("resource_scope_denied")

    def _mounted_record(self, extension_id: str, path: str) -> dict:
        if self.mount_provider is None:
            raise VirtualComputerError("sparsebundle_mount_provider_unavailable")
        target = "/" + path
        rows = self.mount_provider.status()["mounts"]
        record = next((
            row for row in rows
            if row["principal"] == extension_id and row["mountpoint"] == target
        ), None)
        if record is None:
            raise VirtualComputerError("sparsebundle_mount_not_found")
        return record

    def _dispatch(
        self, connection: sqlite3.Connection, extension_id: str,
        grant: VerifiedGrant, args: tuple[str, ...],
    ) -> str:
        command = args[0]
        if command == "help":
            if len(args) != 1:
                raise VirtualComputerError("help_arguments_invalid")
            return "help pwd ls cat write sha256 rm mounts mount mread mwrite umount"
        if command == "pwd":
            if len(args) != 1:
                raise VirtualComputerError("pwd_arguments_invalid")
            return "/extensions/" + extension_id
        if command == "mounts":
            if len(args) != 1:
                raise VirtualComputerError("mounts_arguments_invalid")
            self._require(grant, "filesystem.mount.list")
            if self.mount_provider is None:
                raise VirtualComputerError("sparsebundle_mount_provider_unavailable")
            rows = [
                row for row in self.mount_provider.status()["mounts"]
                if row["principal"] == extension_id
            ]
            return "\n".join(
                f'{row["mount_id"]} {row["mountpoint"]} {row["mode"]} {row["expires_at"]}'
                for row in rows
            )
        if command == "mount":
            if len(args) != 5:
                raise VirtualComputerError("mount_arguments_invalid")
            if self.mount_provider is None:
                raise VirtualComputerError("sparsebundle_mount_provider_unavailable")
            path = _path(args[2])
            mode = args[3]
            capability = "filesystem.mount.write" if mode == "rw" else "filesystem.mount.read"
            self._require(grant, capability, path)
            try:
                lease_seconds = int(args[4], 10)
            except ValueError as exc:
                raise VirtualComputerError("mount_lease_invalid") from exc
            record = self.mount_provider.mount(
                principal=extension_id,
                partition_id=args[1],
                mountpoint="/" + path,
                mode=mode,
                lease_seconds=lease_seconds,
            )
            return f"mounted {record.mount_id} {record.mountpoint} {record.mode}"
        if command == "umount":
            if len(args) != 2:
                raise VirtualComputerError("umount_arguments_invalid")
            if self.mount_provider is None:
                raise VirtualComputerError("sparsebundle_mount_provider_unavailable")
            rows = self.mount_provider.status()["mounts"]
            record = next((
                row for row in rows
                if row["mount_id"] == args[1] and row["principal"] == extension_id
            ), None)
            if record is None:
                raise VirtualComputerError("sparsebundle_mount_not_found")
            path = record["mountpoint"].lstrip("/")
            self._require(grant, "filesystem.mount.unmount", path)
            self.mount_provider.unmount(args[1], principal=extension_id)
            return "unmounted " + args[1]
        if command == "mread":
            if len(args) != 4:
                raise VirtualComputerError("mread_arguments_invalid")
            path = _path(args[1])
            self._require(grant, "filesystem.mount.read", path)
            record = self._mounted_record(extension_id, path)
            try:
                offset, length = int(args[2], 10), int(args[3], 10)
            except ValueError as exc:
                raise VirtualComputerError("mread_range_invalid") from exc
            if not 0 <= length <= (MAX_OUTPUT_BYTES * 3 // 4):
                raise VirtualComputerError("mread_size_invalid")
            data = self.mount_provider.read(
                record["mount_id"], principal=extension_id,
                offset=offset, length=length,
            )
            return base64.b64encode(data).decode("ascii")
        if command == "mwrite":
            if len(args) != 4:
                raise VirtualComputerError("mwrite_arguments_invalid")
            path = _path(args[1])
            self._require(grant, "filesystem.mount.write", path)
            record = self._mounted_record(extension_id, path)
            try:
                offset = int(args[2], 10)
                data = base64.b64decode(args[3], validate=True)
            except (ValueError, TypeError) as exc:
                raise VirtualComputerError("mwrite_payload_invalid") from exc
            if len(data) > MAX_COMMAND_BYTES:
                raise VirtualComputerError("mwrite_size_invalid")
            generation = self.mount_provider.write(
                record["mount_id"], principal=extension_id,
                offset=offset, data=data,
            )
            return f"written {len(data)} bytes generation {generation}"
        if command == "ls":
            if len(args) != 2:
                raise VirtualComputerError("ls_arguments_invalid")
            directory = _path(args[1])
            self._require(grant, "filesystem.list", directory)
            prefix = directory + "/"
            rows = connection.execute(
                "SELECT path FROM virtual_files WHERE extension_id=? AND path LIKE ? ORDER BY path",
                (extension_id, prefix.replace("%", "\\%").replace("_", "\\_") + "%"),
            ).fetchall()
            visible = [
                row[0] for row in rows
                if row[0].startswith(prefix) and _scope_allows(row[0], grant.resources)
            ]
            return "\n".join(visible)
        if command == "cat" or command == "sha256":
            if len(args) != 2:
                raise VirtualComputerError(command + "_arguments_invalid")
            path = _path(args[1])
            self._require(grant, "filesystem.read", path)
            row = connection.execute(
                "SELECT content,sha256 FROM virtual_files WHERE extension_id=? AND path=?",
                (extension_id, path),
            ).fetchone()
            if row is None:
                raise VirtualComputerError("virtual_file_not_found")
            if hashlib.sha256(bytes(row[0])).hexdigest() != row[1]:
                raise VirtualComputerError("virtual_file_integrity_failure")
            return bytes(row[0]).decode("utf-8") if command == "cat" else row[1]
        if command == "write":
            if len(args) != 3:
                raise VirtualComputerError("write_arguments_invalid")
            path = _path(args[1])
            self._require(grant, "filesystem.write", path)
            content = args[2].encode("utf-8")
            if len(content) > MAX_FILE_BYTES:
                raise VirtualComputerError("virtual_file_too_large")
            existing = connection.execute(
                "SELECT length(content) FROM virtual_files WHERE extension_id=? AND path=?",
                (extension_id, path),
            ).fetchone()
            total = connection.execute(
                "SELECT COALESCE(SUM(length(content)),0),COUNT(*) FROM virtual_files WHERE extension_id=?",
                (extension_id,),
            ).fetchone()
            if existing is None and total[1] >= MAX_EXTENSION_FILES:
                raise VirtualComputerError("virtual_file_count_quota_exceeded")
            next_total = total[0] - (0 if existing is None else existing[0]) + len(content)
            if next_total > MAX_EXTENSION_BYTES:
                raise VirtualComputerError("virtual_storage_quota_exceeded")
            digest = hashlib.sha256(content).hexdigest()
            connection.execute(
                "INSERT INTO virtual_files(extension_id,path,content,sha256,updated_at) "
                "VALUES(?,?,?,?,?) ON CONFLICT(extension_id,path) DO UPDATE SET "
                "content=excluded.content,sha256=excluded.sha256,updated_at=excluded.updated_at",
                (extension_id, path, content, digest, int(self.clock())),
            )
            return digest
        if command == "rm":
            if len(args) != 2:
                raise VirtualComputerError("rm_arguments_invalid")
            path = _path(args[1])
            self._require(grant, "filesystem.delete", path)
            result = connection.execute(
                "DELETE FROM virtual_files WHERE extension_id=? AND path=?",
                (extension_id, path),
            )
            if result.rowcount != 1:
                raise VirtualComputerError("virtual_file_not_found")
            return "deleted " + path
        raise VirtualComputerError("virtual_command_not_allowed")

    def verify_audit_chain(self) -> bool:
        with closing(self._connect()) as connection:
            return self._verify_audit_connection(connection)

    def audit_events(self) -> tuple[dict[str, Any], ...]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT event_json FROM audit_events ORDER BY sequence"
            ).fetchall()
        return tuple(json.loads(row[0]) for row in rows)
