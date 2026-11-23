"""Finalized-block settlement ledger for internal, nonredeemable pool credits.

Accepted shares are work evidence only. A credit is recorded only when an
injected independent GCF finality verifier accepts the certificate and the
certificate's proposal proof_hash exactly identifies one accepted pool share.
No transfer, withdrawal, or external asset operation exists in this module.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

POLICY_SCHEMA = "CRYPTIC-POOL-REWARD-POLICY/1"
POLICY_DOMAIN = b"CRYPTIC-POOL-REWARD-POLICY/1\x00"
GCF1_CERT_DOMAIN = b"GCF/1|FINALITY-CERTIFICATE\x00"
HEX32 = re.compile(r"^[0-9a-f]{64}$")
MAX_SQLITE_INT = (1 << 63) - 1
ZERO_HASH = "0" * 64
INTERNAL_ASSET = "INTERNAL_NONREDEEMABLE_CREDIT"


class PoolSettlementError(ValueError):
    """A finalized block cannot be safely credited to the pool ledger."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise PoolSettlementError("canonical_encoding_invalid") from exc


def _uint(value: Any, field: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= MAX_SQLITE_INT:
        raise PoolSettlementError(field + "_invalid")
    return value


def _policy_body(policy: Mapping[str, Any]) -> dict:
    fields = {
        "schema", "policy_id", "network_id", "pool_id", "epoch",
        "effective_height_start", "effective_height_end",
        "reward_units", "max_total_credits", "asset",
        "issuer_id", "issued_at", "expires_at",
    }
    if not isinstance(policy, Mapping) or set(policy) != fields | {"signature"}:
        raise PoolSettlementError("reward_policy_fields_invalid")
    body = {key: policy[key] for key in fields}
    if body["schema"] != POLICY_SCHEMA or body["asset"] != INTERNAL_ASSET:
        raise PoolSettlementError("reward_policy_schema_or_asset_invalid")
    for field in ("policy_id", "network_id", "pool_id", "issuer_id"):
        value = body[field]
        if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 256:
            raise PoolSettlementError("reward_policy_" + field + "_invalid")
    _uint(body["epoch"], "reward_policy_epoch", 1)
    start = _uint(body["effective_height_start"], "reward_policy_height_start", 1)
    end = _uint(body["effective_height_end"], "reward_policy_height_end", start)
    _uint(body["reward_units"], "reward_policy_reward_units", 1)
    _uint(body["max_total_credits"], "reward_policy_max_total_credits", 1)
    issued = _uint(body["issued_at"], "reward_policy_issued_at", 1)
    expires = _uint(body["expires_at"], "reward_policy_expires_at", 1)
    if expires <= issued or body["reward_units"] > body["max_total_credits"]:
        raise PoolSettlementError("reward_policy_bounds_invalid")
    signature = policy["signature"]
    if not isinstance(signature, str):
        raise PoolSettlementError("reward_policy_signature_invalid")
    return body


def verify_reward_policy(
    policy: Mapping[str, Any], *, trusted_public_key_hex: str,
    network_id: str, pool_id: str, epoch: int, height: int, now: int,
) -> dict:
    """Verify a reward schedule signed by the independently pinned policy key."""
    body = _policy_body(policy)
    if (body["network_id"] != network_id or body["pool_id"] != pool_id or body["epoch"] != epoch):
        raise PoolSettlementError("reward_policy_scope_mismatch")
    if not body["effective_height_start"] <= height <= body["effective_height_end"]:
        raise PoolSettlementError("reward_policy_not_effective_at_height")
    if now < body["issued_at"] or now > body["expires_at"]:
        raise PoolSettlementError("reward_policy_expired_or_not_yet_valid")
    if not isinstance(trusted_public_key_hex, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", trusted_public_key_hex):
        raise PoolSettlementError("reward_policy_trust_key_invalid")
    try:
        signature = base64.b64decode(policy["signature"], validate=True)
        if len(signature) != 64:
            raise ValueError("signature_length")
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_public_key_hex)).verify(
            signature, POLICY_DOMAIN + _canonical(body),
        )
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise PoolSettlementError("reward_policy_signature_invalid") from exc
    digest = hashlib.sha256(POLICY_DOMAIN + _canonical(body)).hexdigest()
    return {**body, "policy_digest": digest}


def normalize_finality(
    finality: Mapping[str, Any], proposal: Mapping[str, Any] | None = None,
) -> tuple[dict, dict, str]:
    """Accept a GCF/1 finalize result or a GCF/2 certificate without guessing."""
    if not isinstance(finality, Mapping):
        raise PoolSettlementError("finality_certificate_required")
    if finality.get("schema") == "GCF/2-ANCHOR-ENVELOPE/1":
        certificate = finality.get("certificate")
        supplied_proposal = finality.get("proposal")
        if proposal is not None and dict(proposal) != dict(supplied_proposal or {}):
            raise PoolSettlementError("finality_proposal_mismatch")
        proposal = supplied_proposal
        if not isinstance(certificate, Mapping):
            raise PoolSettlementError("gcf2_finality_envelope_invalid")
        digest = certificate.get("certificate_digest")
        if not isinstance(digest, str) or not HEX32.fullmatch(digest):
            raise PoolSettlementError("gcf2_finality_digest_missing")
    elif "certificate" in finality:
        certificate = finality.get("certificate")
        supplied_digest = finality.get("certificate_digest")
        if not isinstance(certificate, Mapping) or not isinstance(supplied_digest, str):
            raise PoolSettlementError("gcf1_finality_envelope_invalid")
        expected = hashlib.sha256(
            GCF1_CERT_DOMAIN + _canonical(certificate)
        ).hexdigest()
        if supplied_digest != expected:
            raise PoolSettlementError("gcf1_finality_digest_invalid")
        resolved_proposal = certificate.get("proposal")
        if proposal is not None and dict(proposal) != dict(resolved_proposal or {}):
            raise PoolSettlementError("finality_proposal_mismatch")
        proposal = resolved_proposal
        digest = supplied_digest
    else:
        certificate = dict(finality)
        digest = certificate.get("certificate_digest")
        if not isinstance(digest, str) or not HEX32.fullmatch(digest):
            raise PoolSettlementError("gcf2_finality_digest_missing")
    if proposal is None:
        proposal = certificate.get("proposal")
    elif certificate.get("proposal") is not None and dict(proposal) != dict(certificate["proposal"]):
        raise PoolSettlementError("finality_proposal_mismatch")
    if not isinstance(proposal, Mapping):
        raise PoolSettlementError("finality_proposal_missing")
    if certificate.get("network_id") != proposal.get("network_id") or \
       certificate.get("epoch") != proposal.get("epoch") or \
       certificate.get("height") != proposal.get("height") or \
       certificate.get("candidate_digest") != hashlib.sha256(_canonical(dict(proposal))).hexdigest():
        raise PoolSettlementError("finality_proposal_binding_invalid")
    if not isinstance(proposal.get("proof_hash"), str) or not HEX32.fullmatch(proposal["proof_hash"]):
        raise PoolSettlementError("finality_proof_hash_invalid")
    return dict(certificate), dict(proposal), digest


class PoolSettlementLedger:
    """Append-only, replay-resistant ledger for finalized-block pool credits.

    The caller must inject an independent finality verifier configured with
    active validator and external evidence gates. The ledger verifies that
    the callback explicitly returns valid=True; missing verifiers fail closed.
    """

    def __init__(
        self, *, database: str | os.PathLike[str], share_ledger: Any,
        trusted_reward_policy_public_key_hex: str,
        resolve_issued_job: Callable[[str], Mapping[str, Any]],
        verify_finality_certificate: Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]],
        clock: Callable[[], int],
    ):
        if not callable(verify_finality_certificate) or not callable(clock) or not callable(resolve_issued_job):
            raise PoolSettlementError("independent_finality_verifier_and_clock_required")
        if not callable(getattr(share_ledger, "verify_chain", None)) or \
           not callable(getattr(share_ledger, "list_shares", None)):
            raise PoolSettlementError("verified_share_ledger_required")
        if not isinstance(trusted_reward_policy_public_key_hex, str) or \
           not re.fullmatch(r"[0-9a-fA-F]{64}", trusted_reward_policy_public_key_hex):
            raise PoolSettlementError("reward_policy_trust_key_invalid")
        path = Path(database).expanduser()
        if str(database) == ":memory:" or (path.exists() and path.is_symlink()):
            raise PoolSettlementError("persistent_non_symlink_database_required")
        path.parent.mkdir(parents=True, exist_ok=True)
        self.database = str(path)
        self.share_ledger = share_ledger
        self.resolve_issued_job = resolve_issued_job
        self.trusted_reward_policy_public_key_hex = trusted_reward_policy_public_key_hex.lower()
        self.verify_finality_certificate = verify_finality_certificate
        self.clock = clock
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS pool_settlement_events (
                  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                  event_type TEXT NOT NULL,
                  event_json BLOB NOT NULL,
                  previous_hash TEXT NOT NULL CHECK(length(previous_hash)=64),
                  event_hash TEXT NOT NULL UNIQUE CHECK(length(event_hash)=64)
                );
                CREATE TABLE IF NOT EXISTS pool_settlements (
                  network_id TEXT NOT NULL, epoch INTEGER NOT NULL,
                  height INTEGER NOT NULL, certificate_digest TEXT NOT NULL UNIQUE,
                  policy_id TEXT NOT NULL, policy_digest TEXT NOT NULL,
                  pool_id TEXT NOT NULL, worker_id TEXT NOT NULL,
                  share_id TEXT NOT NULL UNIQUE, proof_hash TEXT NOT NULL UNIQUE,
                  asset TEXT NOT NULL CHECK(asset='INTERNAL_NONREDEEMABLE_CREDIT'),
                  credit_units INTEGER NOT NULL CHECK(credit_units>0),
                  settled_at INTEGER NOT NULL, event_hash TEXT NOT NULL UNIQUE
                    REFERENCES pool_settlement_events(event_hash),
                  PRIMARY KEY(network_id,epoch,height)
                );
                CREATE TRIGGER IF NOT EXISTS pool_settlement_events_no_update
                  BEFORE UPDATE ON pool_settlement_events
                  BEGIN SELECT RAISE(ABORT,'pool_settlement_event_immutable'); END;
                CREATE TRIGGER IF NOT EXISTS pool_settlement_events_no_delete
                  BEFORE DELETE ON pool_settlement_events
                  BEGIN SELECT RAISE(ABORT,'pool_settlement_event_immutable'); END;
                CREATE TRIGGER IF NOT EXISTS pool_settlements_no_update
                  BEFORE UPDATE ON pool_settlements
                  BEGIN SELECT RAISE(ABORT,'pool_settlement_immutable'); END;
                CREATE TRIGGER IF NOT EXISTS pool_settlements_no_delete
                  BEFORE DELETE ON pool_settlements
                  BEGIN SELECT RAISE(ABORT,'pool_settlement_immutable'); END;
            """)
        try:
            os.chmod(self.database, 0o600)
        except OSError as exc:
            raise PoolSettlementError("database_permissions_failed") from exc

    def _connect(self):
        conn = sqlite3.connect(self.database, timeout=15, isolation_level=None)
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def settle_finalized_block(
        self, *, finality: Mapping[str, Any],
        reward_policy: Mapping[str, Any], pool_id: str,
        proposal: Mapping[str, Any] | None = None,
    ) -> dict:
        now = _uint(self.clock(), "clock", 0)
        certificate, normalized_proposal, certificate_digest = normalize_finality(finality, proposal)
        try:
            verification = self.verify_finality_certificate(certificate, normalized_proposal)
        except Exception as exc:
            raise PoolSettlementError("finality_certificate_verification_failed") from exc
        if not isinstance(verification, Mapping) or verification.get("valid") is not True:
            raise PoolSettlementError("finality_certificate_not_verified")
        network_id = normalized_proposal["network_id"]
        epoch = _uint(normalized_proposal["epoch"], "finality_epoch", 1)
        height = _uint(normalized_proposal["height"], "finality_height", 1)
        if not isinstance(pool_id, str) or not pool_id:
            raise PoolSettlementError("pool_id_invalid")
        policy = verify_reward_policy(
            reward_policy,
            trusted_public_key_hex=self.trusted_reward_policy_public_key_hex,
            network_id=network_id, pool_id=pool_id, epoch=epoch, height=height, now=now,
        )
        if not self.share_ledger.verify_chain():
            raise PoolSettlementError("share_ledger_integrity_failure")
        matches = [
            share for share in self.share_ledger.list_shares()
            if share["network_id"] == network_id
            and share["pool_id"] == pool_id
            and share["proof_hash"] == normalized_proposal["proof_hash"]
        ]
        if len(matches) != 1:
            raise PoolSettlementError("finalized_proof_has_no_unique_accepted_pool_share")
        share = matches[0]
        try:
            job = self.resolve_issued_job(share["job_id"])
        except Exception as exc:
            raise PoolSettlementError("issued_job_verification_failed") from exc
        if (not isinstance(job, Mapping)
                or job.get("job_id") != share["job_id"]
                or job.get("network_id") != network_id
                or job.get("pool_id") != pool_id
                or job.get("epoch") != epoch
                or job.get("height") != height
                or job.get("parent_hash") != normalized_proposal.get("parent_hash")
                or job.get("payload_hash") != normalized_proposal.get("payload_hash")):
            raise PoolSettlementError("accepted_share_job_context_mismatch")
        event_body = {
            "event_type": "pool.block.settled",
            "network_id": network_id, "epoch": epoch, "height": height,
            "certificate_digest": certificate_digest,
            "policy_id": policy["policy_id"], "policy_digest": policy["policy_digest"],
            "pool_id": pool_id, "worker_id": share["worker_id"],
            "share_id": share["share_id"], "proof_hash": share["proof_hash"],
            "asset": INTERNAL_ASSET, "credit_units": policy["reward_units"],
            "settled_at": now,
        }
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                existing = conn.execute(
                    """SELECT certificate_digest,policy_digest,event_hash
                       FROM pool_settlements
                       WHERE network_id=? AND epoch=? AND height=?""",
                    (network_id, epoch, height),
                ).fetchone()
                if existing is not None:
                    if existing[0] == certificate_digest and existing[1] == policy["policy_digest"]:
                        conn.execute("COMMIT")
                        return {"settled": True, "replayed": True,
                                "certificate_digest": certificate_digest,
                                "event_hash": existing[2]}
                    raise PoolSettlementError("settlement_height_conflict")
                issued = conn.execute(
                    """SELECT COALESCE(SUM(credit_units),0)
                       FROM pool_settlements WHERE network_id=? AND epoch=? AND policy_digest=?""",
                    (network_id, epoch, policy["policy_digest"]),
                ).fetchone()[0]
                if issued + policy["reward_units"] > policy["max_total_credits"]:
                    raise PoolSettlementError("reward_policy_credit_cap_exceeded")
                previous_row = conn.execute(
                    "SELECT event_hash FROM pool_settlement_events ORDER BY event_id DESC LIMIT 1"
                ).fetchone()
                previous = previous_row[0] if previous_row else ZERO_HASH
                encoded = _canonical(event_body)
                event_hash = hashlib.sha256(bytes.fromhex(previous) + encoded).hexdigest()
                conn.execute(
                    "INSERT INTO pool_settlement_events(event_type,event_json,previous_hash,event_hash) VALUES(?,?,?,?)",
                    ("pool.block.settled", encoded, previous, event_hash),
                )
                conn.execute(
                    """INSERT INTO pool_settlements
                       (network_id,epoch,height,certificate_digest,policy_id,policy_digest,
                        pool_id,worker_id,share_id,proof_hash,asset,credit_units,settled_at,event_hash)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (network_id, epoch, height, certificate_digest, policy["policy_id"],
                     policy["policy_digest"], pool_id, share["worker_id"], share["share_id"],
                     share["proof_hash"], INTERNAL_ASSET, policy["reward_units"], now, event_hash),
                )
                conn.execute("COMMIT")
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
        return {"settled": True, "replayed": False,
                "network_id": network_id, "epoch": epoch, "height": height,
                "worker_id": share["worker_id"], "share_id": share["share_id"],
                "credit_units": policy["reward_units"], "asset": INTERNAL_ASSET,
                "certificate_digest": certificate_digest, "policy_digest": policy["policy_digest"],
                "event_hash": event_hash}

    def verify_chain(self) -> bool:
        with self._connect() as conn:
            events = conn.execute(
                "SELECT event_type,event_json,previous_hash,event_hash FROM pool_settlement_events ORDER BY event_id"
            ).fetchall()
            rows = conn.execute(
                """SELECT network_id,epoch,height,certificate_digest,policy_id,policy_digest,
                          pool_id,worker_id,share_id,proof_hash,asset,credit_units,settled_at,event_hash
                   FROM pool_settlements"""
            ).fetchall()
        if len(events) != len(rows):
            return False
        by_hash = {row[13]: row[:13] for row in rows}
        previous = ZERO_HASH
        for event_type, encoded, stored_previous, stored_hash in events:
            raw = bytes(encoded)
            if stored_previous != previous or hashlib.sha256(bytes.fromhex(previous) + raw).hexdigest() != stored_hash:
                return False
            try:
                event = json.loads(raw.decode("utf-8"))
                if _canonical(event) != raw or set(event) != {
                    "event_type", "network_id", "epoch", "height", "certificate_digest",
                    "policy_id", "policy_digest", "pool_id", "worker_id", "share_id",
                    "proof_hash", "asset", "credit_units", "settled_at",
                }:
                    return False
            except Exception:
                return False
            if event_type != "pool.block.settled" or event.get("event_type") != event_type:
                return False
            row = by_hash.get(stored_hash)
            if row is None:
                return False
            keys = ("network_id", "epoch", "height", "certificate_digest", "policy_id",
                    "policy_digest", "pool_id", "worker_id", "share_id", "proof_hash",
                    "asset", "credit_units", "settled_at")
            if tuple(event[key] for key in keys) != tuple(row):
                return False
            previous = stored_hash
        return True

    def worker_balances(self, *, pool_id: str | None = None) -> list[dict]:
        """Report internal credits; these are not redeemable or transferable."""
        with self._connect() as conn:
            if pool_id is None:
                rows = conn.execute(
                    """SELECT worker_id,SUM(credit_units),COUNT(*)
                       FROM pool_settlements GROUP BY worker_id ORDER BY worker_id"""
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT worker_id,SUM(credit_units),COUNT(*)
                       FROM pool_settlements WHERE pool_id=?
                       GROUP BY worker_id ORDER BY worker_id""",
                    (pool_id,),
                ).fetchall()
        return [
            {"worker_id": row[0], "credit_units": row[1],
             "settled_blocks": row[2], "asset": INTERNAL_ASSET,
             "redeemable": False, "transferable": False}
            for row in rows
        ]

    def list_settlements(self, *, network_id: str | None = None) -> list[dict]:
        with self._connect() as conn:
            if network_id is None:
                rows = conn.execute(
                    """SELECT network_id,epoch,height,certificate_digest,policy_id,policy_digest,
                              pool_id,worker_id,share_id,proof_hash,asset,credit_units,settled_at,event_hash
                       FROM pool_settlements ORDER BY settled_at,network_id,epoch,height"""
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT network_id,epoch,height,certificate_digest,policy_id,policy_digest,
                              pool_id,worker_id,share_id,proof_hash,asset,credit_units,settled_at,event_hash
                       FROM pool_settlements WHERE network_id=? ORDER BY settled_at,epoch,height""",
                    (network_id,),
                ).fetchall()
        keys = ("network_id", "epoch", "height", "certificate_digest", "policy_id",
                "policy_digest", "pool_id", "worker_id", "share_id", "proof_hash",
                "asset", "credit_units", "settled_at", "event_hash")
        return [dict(zip(keys, row)) for row in rows]
