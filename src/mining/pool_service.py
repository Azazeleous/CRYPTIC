"""Durable pool coordinator joining policy-bound jobs, proof admission, and share ledger.

Worker identity must come from an authenticated transport/middleware adapter.
This module never trusts worker identity from an HTTP header or submission alone.
"""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
from pathlib import Path
from typing import Any, Callable, Mapping

from src.consensus.pool_admission import PoolAdmissionError, admit_pool_submission
from src.consensus.pool_ledger import PoolShareLedger, PoolLedgerError
from src.mining.pool_protocol import PoolJobError, issue_pool_job


class PoolServiceError(ValueError):
    """A pool coordinator operation failed closed."""


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10.0, isolation_level=None)
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    return conn


class PoolCoordinator:
    """Single-coordinator durable job lifecycle and independently verified shares.

    The injected target resolver must return the currently authorized target
    for the complete job boundary. The authenticated worker ID must be supplied
    by trusted transport middleware (for example, verified mTLS identity).
    Run one coordinator writer per database unless deployment supplies an
    external serialization/transaction boundary across coordinator instances.
    """

    def __init__(
        self,
        *,
        database: str | os.PathLike[str],
        share_ledger: PoolShareLedger,
        issuer_private_key_hex: str,
        issuer_id: str,
        pool_id: str,
        network_id: str,
        trusted_issuer_public_key_hex: str,
        resolve_active_target: Callable[[Mapping[str, Any]], bytes | None],
        clock: Callable[[], int],
    ):
        path = Path(database).expanduser()
        if str(path) == ":memory:":
            raise PoolServiceError("persistent_database_required")
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.is_symlink():
            raise PoolServiceError("database_symlink_forbidden")
        if not callable(resolve_active_target) or not callable(clock):
            raise PoolServiceError("policy_resolver_and_clock_required")
        for name, value in (("issuer_id", issuer_id), ("pool_id", pool_id),
                            ("network_id", network_id)):
            if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 256:
                raise PoolServiceError(name + "_invalid")
        self.database = str(path)
        self.share_ledger = share_ledger
        self.issuer_private_key_hex = issuer_private_key_hex
        self.issuer_id = issuer_id
        self.pool_id = pool_id
        self.network_id = network_id
        self.trusted_issuer_public_key_hex = trusted_issuer_public_key_hex
        self.resolve_active_target = resolve_active_target
        self.clock = clock
        self._lock = threading.RLock()
        with _connect(self.database) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS pool_jobs (
                    job_id TEXT PRIMARY KEY,
                    job_json BLOB NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active','revoked')),
                    created_at INTEGER NOT NULL,
                    revoked_at INTEGER,
                    assigned_worker_id TEXT NOT NULL
                )
            """)
        with _connect(self.database) as conn:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(pool_jobs)")}
            if "assigned_worker_id" not in columns:
                # Legacy jobs have no worker assignment and are intentionally
                # inaccessible until reissued with an authenticated worker binding.
                conn.execute("ALTER TABLE pool_jobs ADD COLUMN assigned_worker_id TEXT NOT NULL DEFAULT ''")
        try:
            os.chmod(self.database, 0o600)
        except OSError as exc:
            raise PoolServiceError("database_permissions_failed") from exc

    def issue_job(
        self, *, worker_id: str, height: int, epoch: int, lifetime_seconds: int,
        parent_hash: str, payload_hash: str, primary_stride: int,
        compact_stride: int, nonce_start: int, max_attempts: int,
    ) -> dict:
        """Issue a short-lived job using only the target active at its boundary."""
        with self._lock:
            if (not isinstance(worker_id, str) or not worker_id
                    or len(worker_id.encode("utf-8")) > 256):
                raise PoolServiceError("worker_id_invalid")
            now = self.clock()
            if isinstance(now, bool) or not isinstance(now, int) or now < 1:
                raise PoolServiceError("clock_invalid")
            if (isinstance(lifetime_seconds, bool) or not isinstance(lifetime_seconds, int)
                    or not 1 <= lifetime_seconds <= 300):
                raise PoolServiceError("job_lifetime_invalid")
            boundary = {
                "network_id": self.network_id, "height": height, "epoch": epoch,
                "issued_at": now, "parent_hash": parent_hash, "payload_hash": payload_hash,
            }
            try:
                target = self.resolve_active_target(boundary)
            except Exception as exc:
                raise PoolServiceError("active_target_unavailable") from exc
            if not isinstance(target, bytes) or len(target) != 32:
                raise PoolServiceError("active_target_unavailable")
            job_id = secrets.token_hex(16)
            try:
                job = issue_pool_job(
                    private_key_hex=self.issuer_private_key_hex,
                    issuer_id=self.issuer_id, pool_id=self.pool_id,
                    network_id=self.network_id, epoch=epoch, height=height,
                    issued_at=now, expires_at=now + lifetime_seconds,
                    parent_hash=parent_hash, payload_hash=payload_hash,
                    target=target.hex(), primary_stride=primary_stride,
                    compact_stride=compact_stride, nonce_start=nonce_start,
                    max_attempts=max_attempts, job_id=job_id,
                )
            except PoolJobError as exc:
                raise PoolServiceError("job_issue_rejected:" + str(exc)) from exc
            encoded = _canonical(job)
            with _connect(self.database) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    conn.execute(
                        "INSERT INTO pool_jobs(job_id,job_json,status,created_at,assigned_worker_id) VALUES(?,?,'active',?,?)",
                        (job_id, encoded, now, worker_id),
                    )
                    conn.execute("COMMIT")
                except Exception:
                    if conn.in_transaction:
                        conn.execute("ROLLBACK")
                    raise
            return job

    def get_job(self, job_id: str, *, authenticated_worker_id: str) -> dict:
        """Return an active job only to the worker to which it was assigned."""
        if not isinstance(job_id, str) or len(job_id) != 32:
            raise PoolServiceError("job_id_invalid")
        now = self.clock()
        if isinstance(now, bool) or not isinstance(now, int) or now < 0:
            raise PoolServiceError("clock_invalid")
        if not isinstance(authenticated_worker_id, str) or not authenticated_worker_id:
            raise PoolServiceError("worker_identity_invalid")
        with self._lock, _connect(self.database) as conn:
            row = conn.execute(
                "SELECT job_json,status,assigned_worker_id FROM pool_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
        if row is None:
            raise PoolServiceError("job_not_found")
        if row[1] != "active":
            raise PoolServiceError("job_revoked")
        if row[2] != authenticated_worker_id:
            raise PoolServiceError("job_not_assigned_to_worker")
        job = json.loads(bytes(row[0]).decode("ascii"))
        if now < job["issued_at"] or now > job["expires_at"]:
            raise PoolServiceError("job_expired_or_not_yet_valid")
        return job

    def revoke_job(self, job_id: str) -> bool:
        """Revoke an issued job; repeated revocation is an idempotent false result."""
        if not isinstance(job_id, str) or len(job_id) != 32:
            raise PoolServiceError("job_id_invalid")
        with self._lock, _connect(self.database) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT status FROM pool_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                raise PoolServiceError("job_not_found")
            if row[0] == "revoked":
                conn.execute("COMMIT")
                return False
            now = self.clock()
            conn.execute(
                "UPDATE pool_jobs SET status='revoked',revoked_at=? WHERE job_id=?",
                (now, job_id),
            )
            conn.execute("COMMIT")
            return True

    def submit_share(self, submission: Mapping[str, Any], *,
                     authenticated_worker_id: str) -> dict:
        """Authenticate-by-injection, verify proof/policy, then durably record share."""
        with self._lock:
            if not isinstance(submission, Mapping):
                raise PoolServiceError("submission_invalid")
            job = submission.get("job")
            if not isinstance(job, Mapping) or not isinstance(job.get("job_id"), str):
                raise PoolServiceError("submission_job_invalid")
            with _connect(self.database) as conn:
                row = conn.execute(
                    "SELECT job_json,status,assigned_worker_id FROM pool_jobs WHERE job_id=?",
                    (job["job_id"],),
                ).fetchone()
            if row is None:
                raise PoolServiceError("job_unknown")
            if row[1] != "active":
                raise PoolServiceError("job_revoked")
            if row[2] != authenticated_worker_id:
                raise PoolServiceError("job_not_assigned_to_worker")
            if bytes(row[0]) != _canonical(job):
                raise PoolServiceError("job_not_issued_by_this_pool")
            now = self.clock()
            if isinstance(now, bool) or not isinstance(now, int) or now < 0:
                raise PoolServiceError("clock_invalid")
            try:
                accepted = admit_pool_submission(
                    submission,
                    trusted_issuer_public_key_hex=self.trusted_issuer_public_key_hex,
                    expected_issuer_id=self.issuer_id,
                    expected_pool_id=self.pool_id,
                    expected_network_id=self.network_id,
                    authenticated_worker_id=authenticated_worker_id,
                    active_target_resolver=self.resolve_active_target,
                    now=now,
                )
                persisted = self.share_ledger.record_accepted_share(accepted)
            except (PoolAdmissionError, PoolLedgerError) as exc:
                raise PoolServiceError("share_rejected:" + str(exc)) from exc
            return {"accepted": True, "share_id": accepted["share_id"],
                    "worker_id": accepted["worker_id"], **persisted}

    def status(self) -> dict:
        """Return measured durable state; chain integrity failure is explicit."""
        with self._lock, _connect(self.database) as conn:
            active, revoked = conn.execute(
                "SELECT SUM(status='active'),SUM(status='revoked') FROM pool_jobs"
            ).fetchone()
            total = conn.execute("SELECT COUNT(*) FROM pool_jobs").fetchone()[0]
        shares = self.share_ledger.list_shares()
        chain_ok = self.share_ledger.verify_chain()
        return {
            "pool_id": self.pool_id, "network_id": self.network_id,
            "jobs_total": total, "jobs_active": active or 0,
            "jobs_revoked": revoked or 0, "shares_accepted": len(shares),
            "share_ledger_chain_valid": chain_ok,
            "healthy": bool(chain_ok),
        }
