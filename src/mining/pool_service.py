"""Durable pool coordinator joining policy-bound jobs, proof admission, and share ledger.

Worker identity must come from an authenticated transport/middleware adapter.
This module never trusts worker identity from an HTTP header or submission alone.
"""
from __future__ import annotations

import json
import hashlib
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
        max_submissions_per_minute: int = 120,
        settlement_ledger: Any | None = None,
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
        self.settlement_ledger = settlement_ledger
        self.issuer_private_key_hex = issuer_private_key_hex
        self.issuer_id = issuer_id
        self.pool_id = pool_id
        self.network_id = network_id
        self.trusted_issuer_public_key_hex = trusted_issuer_public_key_hex
        self.resolve_active_target = resolve_active_target
        self.clock = clock
        if (isinstance(max_submissions_per_minute, bool)
                or not isinstance(max_submissions_per_minute, int)
                or not 1 <= max_submissions_per_minute <= 100_000):
            raise PoolServiceError("worker_rate_limit_invalid")
        self.max_submissions_per_minute = max_submissions_per_minute
        self._lock = threading.RLock()
        with _connect(self.database) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS pool_jobs (
                    job_id TEXT PRIMARY KEY,
                    job_json BLOB NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active','revoked','expired')),
                    created_at INTEGER NOT NULL,
                    revoked_at INTEGER,
                    assigned_worker_id TEXT NOT NULL
                );
            CREATE TABLE IF NOT EXISTS pool_worker_rate_windows (
                    worker_id TEXT NOT NULL,
                    window_start INTEGER NOT NULL,
                    request_count INTEGER NOT NULL CHECK(request_count>=0),
                    PRIMARY KEY(worker_id,window_start)
                );
            CREATE TABLE IF NOT EXISTS pool_nonce_ranges (
                    job_id TEXT PRIMARY KEY,
                    network_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    height INTEGER NOT NULL,
                    parent_hash TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    nonce_start TEXT NOT NULL CHECK(length(nonce_start)=20),
                    nonce_end TEXT NOT NULL CHECK(length(nonce_end)=20),
                    CHECK(nonce_end > nonce_start)
                );
            CREATE INDEX IF NOT EXISTS pool_nonce_ranges_context
              ON pool_nonce_ranges(network_id,epoch,height,parent_hash,payload_hash,nonce_start,nonce_end)
            """)
        with _connect(self.database) as conn:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(pool_jobs)")}
            if "assigned_worker_id" not in columns:
                # Legacy jobs have no worker assignment and are intentionally
                # inaccessible until reissued with an authenticated worker binding.
                conn.execute("ALTER TABLE pool_jobs ADD COLUMN assigned_worker_id TEXT NOT NULL DEFAULT ''")
            schema_row = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='pool_jobs'"
            ).fetchone()
            if schema_row is not None and "'expired'" not in schema_row[0]:
                # Upgrade the original two-state lifecycle without discarding jobs.
                conn.execute("BEGIN IMMEDIATE")
                try:
                    conn.execute("""
                        CREATE TABLE pool_jobs_v2 (
                            job_id TEXT PRIMARY KEY,
                            job_json BLOB NOT NULL,
                            status TEXT NOT NULL CHECK(status IN ('active','revoked','expired')),
                            created_at INTEGER NOT NULL,
                            revoked_at INTEGER,
                            assigned_worker_id TEXT NOT NULL
                        )
                    """)
                    conn.execute("""
                        INSERT INTO pool_jobs_v2
                        SELECT job_id,job_json,status,created_at,revoked_at,assigned_worker_id
                        FROM pool_jobs
                    """)
                    conn.execute("DROP TABLE pool_jobs")
                    conn.execute("ALTER TABLE pool_jobs_v2 RENAME TO pool_jobs")
                    conn.execute("COMMIT")
                except Exception:
                    if conn.in_transaction:
                        conn.execute("ROLLBACK")
                    raise
            range_columns = {
                row[1]: row[2].upper()
                for row in conn.execute("PRAGMA table_info(pool_nonce_ranges)")
            }
            if (range_columns.get("nonce_start") != "TEXT"
                    or range_columns.get("nonce_end") != "TEXT"):
                legacy_ranges = conn.execute(
                    "SELECT job_id,network_id,epoch,height,parent_hash,payload_hash,nonce_start,nonce_end FROM pool_nonce_ranges"
                ).fetchall()
                conn.execute("DROP INDEX IF EXISTS pool_nonce_ranges_context")
                conn.execute("DROP TABLE pool_nonce_ranges")
                conn.execute("""
                    CREATE TABLE pool_nonce_ranges (
                        job_id TEXT PRIMARY KEY,
                        network_id TEXT NOT NULL,
                        epoch INTEGER NOT NULL,
                        height INTEGER NOT NULL,
                        parent_hash TEXT NOT NULL,
                        payload_hash TEXT NOT NULL,
                        nonce_start TEXT NOT NULL CHECK(length(nonce_start)=20),
                        nonce_end TEXT NOT NULL CHECK(length(nonce_end)=20),
                        CHECK(nonce_end > nonce_start)
                    )
                """)
                conn.execute("""
                    CREATE INDEX pool_nonce_ranges_context
                    ON pool_nonce_ranges(network_id,epoch,height,parent_hash,payload_hash,nonce_start,nonce_end)
                """)
                for item in legacy_ranges:
                    conn.execute(
                        "INSERT INTO pool_nonce_ranges VALUES(?,?,?,?,?,?,?,?)",
                        (*item[:6], f"{int(item[6]):020d}", f"{int(item[7]):020d}"),
                    )
            # Reconstruct nonce ownership for jobs created before range tracking.
            for job_id, raw_job in conn.execute(
                "SELECT job_id,job_json FROM pool_jobs ORDER BY created_at,job_id"
            ).fetchall():
                job = json.loads(bytes(raw_job).decode("ascii"))
                start = job["nonce_start"]
                end = start + job["max_attempts"]
                overlap = conn.execute("""
                    SELECT job_id FROM pool_nonce_ranges
                    WHERE network_id=? AND epoch=? AND height=?
                      AND parent_hash=? AND payload_hash=?
                      AND nonce_start < ? AND nonce_end > ?
                    LIMIT 1
                """, (job["network_id"], job["epoch"], job["height"],
                      job["parent_hash"], job["payload_hash"], f"{end:020d}", f"{start:020d}")).fetchone()
                if overlap is not None and overlap[0] != job_id:
                    raise PoolServiceError("persisted_nonce_range_overlap")
                conn.execute("""
                    INSERT OR IGNORE INTO pool_nonce_ranges
                    VALUES(?,?,?,?,?,?,?,?)
                """, (job_id, job["network_id"], job["epoch"], job["height"],
                      job["parent_hash"], job["payload_hash"], f"{start:020d}", f"{end:020d}"))
        try:
            os.chmod(self.database, 0o600)
        except OSError as exc:
            raise PoolServiceError("database_permissions_failed") from exc
        self.expire_jobs()

    def _consume_worker_rate_limit(self, worker_id: str, *, now: int) -> None:
        """Atomically enforce a durable fixed-window worker submission limit."""
        window_start = (now // 60) * 60
        with _connect(self.database) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    """SELECT request_count FROM pool_worker_rate_windows
                       WHERE worker_id=? AND window_start=?""",
                    (worker_id, window_start),
                ).fetchone()
                count = row[0] if row else 0
                if count >= self.max_submissions_per_minute:
                    raise PoolServiceError("worker_rate_limit_exceeded")
                if row is None:
                    conn.execute(
                        "INSERT INTO pool_worker_rate_windows VALUES(?,?,1)",
                        (worker_id, window_start),
                    )
                else:
                    conn.execute(
                        """UPDATE pool_worker_rate_windows SET request_count=request_count+1
                           WHERE worker_id=? AND window_start=?""",
                        (worker_id, window_start),
                    )
                conn.execute(
                    "DELETE FROM pool_worker_rate_windows WHERE window_start < ?",
                    (window_start - 7 * 24 * 60 * 60,),
                )
                conn.execute("COMMIT")
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def expire_jobs(self, *, now: int | None = None) -> int:
        """Durably transition every elapsed active job to the expired state."""
        if now is None:
            now = self.clock()
        if isinstance(now, bool) or not isinstance(now, int) or now < 0:
            raise PoolServiceError("clock_invalid")
        expired = 0
        with self._lock, _connect(self.database) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                rows = conn.execute(
                    "SELECT job_id,job_json FROM pool_jobs WHERE status='active'"
                ).fetchall()
                for job_id, raw_job in rows:
                    try:
                        job = json.loads(bytes(raw_job).decode("ascii"))
                    except (ValueError, TypeError, UnicodeDecodeError) as exc:
                        raise PoolServiceError("persisted_job_corrupt") from exc
                    if now > job.get("expires_at", -1):
                        conn.execute(
                            "UPDATE pool_jobs SET status='expired' WHERE job_id=? AND status='active'",
                            (job_id,),
                        )
                        expired += conn.execute("SELECT changes()").fetchone()[0]
                conn.execute("COMMIT")
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
        return expired

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
            nonce_start = job["nonce_start"]
            nonce_end = nonce_start + job["max_attempts"]
            with _connect(self.database) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    overlap = conn.execute("""
                        SELECT job_id FROM pool_nonce_ranges
                        WHERE network_id=? AND epoch=? AND height=?
                          AND parent_hash=? AND payload_hash=?
                          AND nonce_start < ? AND nonce_end > ?
                        LIMIT 1
                    """, (job["network_id"], job["epoch"], job["height"],
                          job["parent_hash"], job["payload_hash"],
                          f"{nonce_end:020d}", f"{nonce_start:020d}")).fetchone()
                    if overlap is not None:
                        raise PoolServiceError("nonce_range_overlap:" + overlap[0])
                    conn.execute(
                        "INSERT INTO pool_jobs(job_id,job_json,status,created_at,assigned_worker_id) VALUES(?,?,'active',?,?)",
                        (job_id, encoded, now, worker_id),
                    )
                    conn.execute("""
                        INSERT INTO pool_nonce_ranges
                        VALUES(?,?,?,?,?,?,?,?)
                    """, (job_id, job["network_id"], job["epoch"], job["height"],
                          job["parent_hash"], job["payload_hash"],
                          f"{nonce_start:020d}", f"{nonce_end:020d}"))
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
        self.expire_jobs(now=now)
        if not isinstance(authenticated_worker_id, str) or not authenticated_worker_id:
            raise PoolServiceError("worker_identity_invalid")
        with self._lock, _connect(self.database) as conn:
            row = conn.execute(
                "SELECT job_json,status,assigned_worker_id FROM pool_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
        if row is None:
            raise PoolServiceError("job_not_found")
        if row[1] == "expired":
            raise PoolServiceError("job_expired")
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
            if row[0] in ("revoked", "expired"):
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
        now = self.clock()
        if isinstance(now, bool) or not isinstance(now, int) or now < 0:
            raise PoolServiceError("clock_invalid")
        self.expire_jobs(now=now)
        with self._lock:
            if not isinstance(authenticated_worker_id, str) or not authenticated_worker_id:
                raise PoolServiceError("worker_identity_invalid")
            if not isinstance(submission, Mapping):
                raise PoolServiceError("submission_invalid")
            job = submission.get("job")
            if not isinstance(job, Mapping) or not isinstance(job.get("job_id"), str):
                raise PoolServiceError("submission_job_invalid")
            # Recover an already committed share before checking job expiry or
            # revocation. This is acknowledgement of prior verified work, not
            # a new admission; the append-only journal must still verify.
            submitted_worker = submission.get("worker_id")
            proof_hash = submission.get("proof_hash")
            if (submitted_worker == authenticated_worker_id
                    and isinstance(proof_hash, str)):
                identity = {
                    "network_id": self.network_id, "pool_id": self.pool_id,
                    "job_id": job["job_id"], "worker_id": authenticated_worker_id,
                    "proof_hash": proof_hash,
                }
                recovered_id = hashlib.sha256(
                    repr(sorted(identity.items())).encode("utf-8")
                ).hexdigest()
                recovered = self.share_ledger.get_share(
                    share_id=recovered_id, proof_hash=proof_hash,
                )
                if recovered is not None:
                    if not self.share_ledger.verify_chain():
                        raise PoolServiceError("share_ledger_integrity_failure")
                    return {
                        "accepted": True, "share_id": recovered["share_id"],
                        "worker_id": recovered["worker_id"], "recorded": True,
                        "replayed": True, "event_hash": recovered["event_hash"],
                    }
            with _connect(self.database) as conn:
                row = conn.execute(
                    "SELECT job_json,status,assigned_worker_id FROM pool_jobs WHERE job_id=?",
                    (job["job_id"],),
                ).fetchone()
            if row is None:
                raise PoolServiceError("job_unknown")
            if row[1] == "expired":
                raise PoolServiceError("job_expired")
            if row[1] != "active":
                raise PoolServiceError("job_revoked")
            if row[2] != authenticated_worker_id:
                raise PoolServiceError("job_not_assigned_to_worker")
            if bytes(row[0]) != _canonical(job):
                raise PoolServiceError("job_not_issued_by_this_pool")
            self._consume_worker_rate_limit(authenticated_worker_id, now=now)
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

    def configure_settlement_ledger(
        self, *, database: str | os.PathLike[str],
        trusted_reward_policy_public_key_hex: str,
        verify_finality_certificate: Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]],
    ):
        """Bind the pool's historical job resolver to its settlement ledger."""
        if self.settlement_ledger is not None:
            raise PoolServiceError("pool_settlement_ledger_already_configured")
        try:
            from src.consensus.pool_settlement import PoolSettlementLedger
            ledger = PoolSettlementLedger(
                database=database, share_ledger=self.share_ledger,
                trusted_reward_policy_public_key_hex=trusted_reward_policy_public_key_hex,
                resolve_issued_job=self.resolve_issued_job,
                verify_finality_certificate=verify_finality_certificate,
                clock=self.clock,
            )
        except Exception as exc:
            raise PoolServiceError("pool_settlement_configuration_failed:" + str(exc)) from exc
        self.settlement_ledger = ledger
        return ledger

    def settle_finalized_block(
        self, *, finality: Mapping[str, Any],
        reward_policy: Mapping[str, Any],
        proposal: Mapping[str, Any] | None = None,
    ) -> dict:
        """Settle only a verified finalized block matching one accepted pool proof."""
        if self.settlement_ledger is None:
            raise PoolServiceError("pool_settlement_ledger_not_configured")
        try:
            return self.settlement_ledger.settle_finalized_block(
                finality=finality, reward_policy=reward_policy,
                pool_id=self.pool_id, proposal=proposal,
            )
        except Exception as exc:
            raise PoolServiceError("pool_settlement_rejected:" + str(exc)) from exc

    def resolve_issued_job(self, job_id: str) -> dict:
        """Resolve an issuer-authenticated historical job for finality settlement.

        Expired or revoked jobs remain non-submittable. This read-only method
        verifies their original signature at issuance time for audit purposes.
        """
        if not isinstance(job_id, str) or len(job_id) != 32:
            raise PoolServiceError("job_id_invalid")
        with _connect(self.database) as conn:
            row = conn.execute(
                "SELECT job_json FROM pool_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
        if row is None:
            raise PoolServiceError("job_unknown")
        try:
            job = json.loads(bytes(row[0]).decode("ascii"))
            verify_pool_job(
                job,
                trusted_issuer_public_key_hex=self.trusted_issuer_public_key_hex,
                expected_issuer_id=self.issuer_id,
                expected_pool_id=self.pool_id,
                expected_network_id=self.network_id,
                now=job["issued_at"],
            )
        except Exception as exc:
            raise PoolServiceError("persisted_job_signature_invalid") from exc
        return job

    def status(self) -> dict:
        """Return measured durable state; chain integrity failure is explicit."""
        self.expire_jobs()
        with self._lock, _connect(self.database) as conn:
            active, revoked, expired = conn.execute(
                "SELECT SUM(status='active'),SUM(status='revoked'),SUM(status='expired') FROM pool_jobs"
            ).fetchone()
            total = conn.execute("SELECT COUNT(*) FROM pool_jobs").fetchone()[0]
        shares = self.share_ledger.list_shares()
        worker_stats = self.share_ledger.worker_stats()
        chain_ok = self.share_ledger.verify_chain()
        settlement_chain_ok = (
            self.settlement_ledger.verify_chain()
            if self.settlement_ledger is not None else None
        )
        settlement_count = (
            len(self.settlement_ledger.list_settlements(network_id=self.network_id))
            if self.settlement_ledger is not None else 0
        )
        return {
            "pool_id": self.pool_id, "network_id": self.network_id,
            "jobs_total": total, "jobs_active": active or 0,
            "jobs_revoked": revoked or 0, "jobs_expired": expired or 0,
            "shares_accepted": len(shares),
            "workers_seen": len(worker_stats),
            "worker_share_totals": worker_stats,
            "share_ledger_chain_valid": chain_ok,
            "settlements_recorded": settlement_count,
            "settlement_ledger_chain_valid": settlement_chain_ok,
            "healthy": bool(chain_ok and settlement_chain_ok is not False),
        }
