"""Durable HCCGN proof storage and authenticated target-policy resolution.

Policy signatures are verified against an operator-pinned Ed25519 public key.
This module does not invent or embed a GOD key: deployments must provision the
actual GOD-authorized trust root out of band. Missing/expired policy fails closed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path
from contextlib import closing
from typing import Any, Mapping, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.consensus.hccgn_work import PROFILE_ID

POLICY_SCHEMA = "HCCGN-TARGET-POLICY/1"
POLICY_DOMAIN = b"HCCGN-TARGET-POLICY/1\x00"
MAX_PROOF_BYTES = 1_048_576
MAX_SQLITE_INT = (1 << 63) - 1
POLICY_FIELDS = {
    "schema", "profile_id", "network_id", "sequence",
    "activation_height", "activation_epoch", "target",
    "issued_at", "expires_at", "signer_id", "signature",
}


class HCCGNRegistryError(ValueError):
    """A proof-store or authenticated target-policy failure."""


class HCCGNSequenceAnchor(Protocol):
    """Externally protected monotonic checkpoint for policy sequence/hash."""
    def read_sequence(self, network_id: str) -> tuple[int, str] | None: ...
    def advance_sequence(self, network_id: str, sequence: int, policy_hash: str) -> bool: ...


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _uint(value: Any, field: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > MAX_SQLITE_INT:
        raise HCCGNRegistryError(field + "_invalid")
    return value


def _target(value: Any) -> bytes:
    if not isinstance(value, str):
        raise HCCGNRegistryError("target_invalid")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise HCCGNRegistryError("target_invalid") from exc
    if len(raw) != 32 or raw.hex() != value.lower():
        raise HCCGNRegistryError("target_invalid")
    return raw


def _connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10.0, isolation_level=None)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    return conn


class HCCGNProofStore:
    """Content-addressed, immutable SQLite proof-envelope store."""
    def __init__(self, database: str | os.PathLike[str], *,
                 max_proof_bytes: int = MAX_PROOF_BYTES):
        self.database = str(database)
        if self.database == ":memory:":
            raise HCCGNRegistryError("persistent_database_required")
        if self.database != ":memory:":
            Path(self.database).expanduser().resolve().parent.mkdir(
                parents=True, exist_ok=True
            )
        if isinstance(max_proof_bytes, bool) or not isinstance(max_proof_bytes, int) or not 1 <= max_proof_bytes <= MAX_PROOF_BYTES:
            raise HCCGNRegistryError("max_proof_bytes_invalid")
        self.max_proof_bytes = max_proof_bytes
        with closing(_connect(self.database)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS hccgn_proofs (
                    proof_hash TEXT PRIMARY KEY,
                    proof BLOB NOT NULL,
                    byte_length INTEGER NOT NULL,
                    inserted_at INTEGER NOT NULL
                )
            """)

    def put(self, proof: bytes, *, inserted_at: int | None = None) -> str:
        if not isinstance(proof, bytes) or not proof:
            raise HCCGNRegistryError("proof_bytes_invalid")
        if len(proof) > self.max_proof_bytes:
            raise HCCGNRegistryError("proof_too_large")
        digest = hashlib.sha256(proof).hexdigest()
        timestamp = int(time.time()) if inserted_at is None else _uint(inserted_at, "inserted_at")
        conn = _connect(self.database)
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT proof FROM hccgn_proofs WHERE proof_hash=?", (digest,)
            ).fetchone()
            if row is not None and bytes(row[0]) != proof:
                raise HCCGNRegistryError("content_address_collision")
            conn.execute(
                "INSERT OR IGNORE INTO hccgn_proofs(proof_hash,proof,byte_length,inserted_at) VALUES(?,?,?,?)",
                (digest, sqlite3.Binary(proof), len(proof), timestamp),
            )
            conn.execute("COMMIT")
            return digest
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def get(self, proof_hash: str) -> bytes | None:
        if not isinstance(proof_hash, str) or len(proof_hash) != 64:
            return None
        try:
            bytes.fromhex(proof_hash)
        except ValueError:
            return None
        with closing(_connect(self.database)) as conn:
            row = conn.execute(
                "SELECT proof,byte_length FROM hccgn_proofs WHERE proof_hash=?",
                (proof_hash.lower(),),
            ).fetchone()
        if row is None:
            return None
        proof = bytes(row[0])
        if len(proof) != row[1] or hashlib.sha256(proof).hexdigest() != proof_hash.lower():
            raise HCCGNRegistryError("stored_proof_integrity_failure")
        return proof


class HCCGNActiveTargetPolicy:
    """Verify and persist signed target snapshots; resolve by proposal boundary.

    The constructor's public key is the trust anchor. It must be supplied by
    the deployment's authenticated GOD/APEX configuration, never by a proposal.
    """
    def __init__(self, database: str | os.PathLike[str], *,
                 trusted_public_key: bytes, trusted_signer_id: str,
                 clock=time.time, sequence_anchor: HCCGNSequenceAnchor | None = None,
                 require_external_anchor: bool = False):
        if not isinstance(trusted_public_key, bytes) or len(trusted_public_key) != 32:
            raise HCCGNRegistryError("trusted_public_key_invalid")
        if not isinstance(trusted_signer_id, str) or not trusted_signer_id:
            raise HCCGNRegistryError("trusted_signer_id_invalid")
        self.database = str(database)
        if self.database == ":memory:":
            raise HCCGNRegistryError("persistent_database_required")
        if self.database != ":memory:":
            Path(self.database).expanduser().resolve().parent.mkdir(
                parents=True, exist_ok=True
            )
        self.public_key = Ed25519PublicKey.from_public_bytes(trusted_public_key)
        self.signer_id = trusted_signer_id
        if not isinstance(require_external_anchor, bool):
            raise HCCGNRegistryError("require_external_anchor_invalid")
        self.clock = clock
        self.sequence_anchor = sequence_anchor
        self.require_external_anchor = require_external_anchor
        with closing(_connect(self.database)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS hccgn_target_policies (
                    network_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    activation_height INTEGER NOT NULL,
                    activation_epoch INTEGER NOT NULL,
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    target BLOB NOT NULL,
                    policy_hash TEXT NOT NULL,
                    policy_json BLOB NOT NULL,
                    PRIMARY KEY(network_id, sequence)
                )
            """)

    def _verify_snapshot(self, snapshot: Mapping[str, Any]) -> tuple[dict, bytes, str]:
        if not isinstance(snapshot, Mapping) or set(snapshot) != POLICY_FIELDS:
            raise HCCGNRegistryError("policy_fields_invalid")
        policy = dict(snapshot)
        signature_text = policy.pop("signature")
        if policy["schema"] != POLICY_SCHEMA or policy["profile_id"] != PROFILE_ID:
            raise HCCGNRegistryError("policy_schema_or_profile_invalid")
        if policy["signer_id"] != self.signer_id:
            raise HCCGNRegistryError("policy_signer_invalid")
        network_id = policy["network_id"]
        if not isinstance(network_id, str) or not network_id:
            raise HCCGNRegistryError("policy_network_invalid")
        _uint(policy["sequence"], "sequence", 1)
        _uint(policy["activation_height"], "activation_height", 1)
        _uint(policy["activation_epoch"], "activation_epoch", 1)
        issued = _uint(policy["issued_at"], "issued_at", 1)
        expires = _uint(policy["expires_at"], "expires_at", 1)
        if expires <= issued:
            raise HCCGNRegistryError("policy_time_window_invalid")
        target = _target(policy["target"])
        if not isinstance(signature_text, str):
            raise HCCGNRegistryError("policy_signature_invalid")
        try:
            signature = base64.b64decode(signature_text, validate=True)
            self.public_key.verify(signature, POLICY_DOMAIN + _canonical(policy))
        except Exception as exc:
            raise HCCGNRegistryError("policy_signature_invalid") from exc
        digest = hashlib.sha256(POLICY_DOMAIN + _canonical(policy) + signature).hexdigest()
        return policy, target, digest

    def install(self, snapshot: Mapping[str, Any]) -> str:
        policy, target, digest = self._verify_snapshot(snapshot)
        now = _uint(int(self.clock()), "clock")
        if not policy["issued_at"] <= now <= policy["expires_at"]:
            raise HCCGNRegistryError("policy_not_current")
        network = policy["network_id"]
        seq = policy["sequence"]
        encoded = _canonical(dict(snapshot))
        anchor = self.sequence_anchor
        if self.require_external_anchor and anchor is None:
            raise HCCGNRegistryError("external_sequence_anchor_required")
        if anchor is not None:
            try:
                anchored = anchor.read_sequence(network)
                if anchored is None:
                    if anchor.advance_sequence(network, seq, digest) is not True:
                        raise HCCGNRegistryError("external_sequence_anchor_update_failed")
                else:
                    if not isinstance(anchored, tuple) or len(anchored) != 2:
                        raise HCCGNRegistryError("external_sequence_anchor_response_invalid")
                    anchored_sequence = _uint(anchored[0], "anchor_sequence", 1)
                    anchored_hash = anchored[1]
                    if not isinstance(anchored_hash, str) or len(anchored_hash) != 64:
                        raise HCCGNRegistryError("external_sequence_anchor_response_invalid")
                    try:
                        bytes.fromhex(anchored_hash)
                    except ValueError as exc:
                        raise HCCGNRegistryError("external_sequence_anchor_response_invalid") from exc
                    if seq < anchored_sequence or (seq == anchored_sequence and digest != anchored_hash):
                        raise HCCGNRegistryError("external_sequence_anchor_rollback")
                    if seq > anchored_sequence and anchor.advance_sequence(network, seq, digest) is not True:
                        raise HCCGNRegistryError("external_sequence_anchor_update_failed")
            except HCCGNRegistryError:
                raise
            except Exception as exc:
                raise HCCGNRegistryError("external_sequence_anchor_unavailable") from exc
        conn = _connect(self.database)
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT sequence,policy_hash FROM hccgn_target_policies WHERE network_id=? ORDER BY sequence DESC LIMIT 1",
                (network,),
            ).fetchone()
            if row is not None:
                if seq == row[0] and digest == row[1]:
                    conn.execute("COMMIT")
                    return digest
                if seq <= row[0]:
                    raise HCCGNRegistryError("policy_rollback_or_sequence_reuse")
            conn.execute(
                """INSERT INTO hccgn_target_policies
                (network_id,sequence,activation_height,activation_epoch,issued_at,expires_at,target,policy_hash,policy_json)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (network, seq, policy["activation_height"], policy["activation_epoch"],
                 policy["issued_at"], policy["expires_at"], sqlite3.Binary(target),
                 digest, sqlite3.Binary(encoded)),
            )
            conn.execute("COMMIT")
            return digest
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def resolve(self, proposal: Mapping[str, Any]) -> bytes | None:
        if not isinstance(proposal, Mapping):
            return None
        network = proposal.get("network_id")
        try:
            height = _uint(proposal.get("height"), "height", 1)
            epoch = _uint(proposal.get("epoch"), "epoch", 1)
            issued_at = _uint(proposal.get("issued_at"), "issued_at", 1)
            now = _uint(int(self.clock()), "clock")
        except HCCGNRegistryError:
            return None
        if not isinstance(network, str) or not network:
            return None
        anchor = self.sequence_anchor
        if self.require_external_anchor and anchor is None:
            return None
        if anchor is not None:
            try:
                anchored = anchor.read_sequence(network)
                if not isinstance(anchored, tuple) or len(anchored) != 2:
                    return None
                anchored_sequence = _uint(anchored[0], "anchor_sequence", 1)
                anchored_hash = anchored[1]
                if not isinstance(anchored_hash, str) or len(anchored_hash) != 64:
                    return None
                with closing(_connect(self.database)) as check_conn:
                    latest = check_conn.execute(
                        "SELECT sequence,policy_hash FROM hccgn_target_policies WHERE network_id=? ORDER BY sequence DESC LIMIT 1",
                        (network,),
                    ).fetchone()
                if latest is None or latest[0] != anchored_sequence or latest[1] != anchored_hash:
                    return None
            except Exception:
                return None
        with closing(_connect(self.database)) as conn:
            row = conn.execute(
                """SELECT target,issued_at,expires_at FROM hccgn_target_policies
                WHERE network_id=? AND activation_height<=? AND activation_epoch<=?
                AND issued_at<=? AND expires_at>=?
                ORDER BY sequence DESC LIMIT 1""",
                (network, height, epoch, issued_at, now),
            ).fetchone()
        return bytes(row[0]) if row is not None else None
