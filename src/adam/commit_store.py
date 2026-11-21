"""ADAM commitment store and APEX acceptance authority."""
from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
import sqlite3
import threading
from pathlib import Path
from typing import Any, Callable, Mapping

MAX_STATE_BYTES = 1_048_576
MAX_SQLITE_INT = (1 << 63) - 1

from src.consensus.gcf import (
    GCFError, canonical_bytes, sha256_hex, DenyUnconfigured,
)
from src.consensus.independent_verifier import verify_certificate as verify_independent_certificate


class APEXValidationError(ValueError):
    pass


class AdamCommitStore:
    """Append-only state commitment store with parent/height continuity."""
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._db() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS adam_commits(
              height INTEGER PRIMARY KEY,
              candidate_digest TEXT NOT NULL UNIQUE,
              parent_hash TEXT NOT NULL,
              state_hash TEXT NOT NULL,
              certificate_digest TEXT NOT NULL,
              state_bytes BLOB NOT NULL,
              receipt_json TEXT NOT NULL
            );
            """)

    def _connect(self):
        db = sqlite3.connect(self.db_path, timeout=15, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    @contextmanager
    def _db(self):
        db = self._connect()
        try:
            yield db
        finally:
            db.close()

    @staticmethod
    def _valid_digest(value: Any) -> bool:
        if not isinstance(value, str) or len(value) != 64:
            return False
        try:
            return bytes.fromhex(value).hex() == value
        except ValueError:
            return False

    def verify_chain(self) -> dict:
        """Recheck every persisted commitment from genesis before recovery/use."""
        expected_height = 1
        expected_parent = "0" * 64
        with self._db() as db:
            rows = db.execute("SELECT * FROM adam_commits ORDER BY height ASC").fetchall()
        for row in rows:
            state = bytes(row["state_bytes"])
            if row["height"] != expected_height:
                raise APEXValidationError("ADAM_CHAIN_HEIGHT_GAP")
            if row["parent_hash"] != expected_parent:
                raise APEXValidationError("ADAM_CHAIN_PARENT_MISMATCH")
            if not self._valid_digest(row["candidate_digest"]) or not self._valid_digest(row["certificate_digest"]):
                raise APEXValidationError("ADAM_CHAIN_DIGEST_FORMAT_INVALID")
            if hashlib.sha256(state).hexdigest() != row["state_hash"]:
                raise APEXValidationError("ADAM_STORED_STATE_INTEGRITY_FAILURE")
            try:
                receipt = json.loads(row["receipt_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise APEXValidationError("ADAM_RECEIPT_CORRUPT") from exc
            if not isinstance(receipt, dict):
                raise APEXValidationError("ADAM_RECEIPT_CORRUPT")
            expected_parent = row["state_hash"]
            expected_height += 1
        return {"valid": True, "height": expected_height - 1, "state_hash": expected_parent}

    def head(self) -> dict:
        self.verify_chain()
        with self._db() as db:
            row = db.execute("SELECT * FROM adam_commits ORDER BY height DESC LIMIT 1").fetchone()
        if row is None:
            return {"height": 0, "state_hash": "0" * 64}
        return {"height": row["height"], "state_hash": row["state_hash"],
                "candidate_digest": row["candidate_digest"]}

    def commit(self, *, height: int, candidate_digest: str, parent_hash: str,
               state_bytes: bytes, certificate_digest: str, receipt: Mapping[str, Any]) -> dict:
        if isinstance(height, bool) or not isinstance(height, int) or not 1 <= height <= MAX_SQLITE_INT:
            raise APEXValidationError("ADAM_HEIGHT_INVALID")
        if not self._valid_digest(candidate_digest) or not self._valid_digest(parent_hash) or not self._valid_digest(certificate_digest):
            raise APEXValidationError("ADAM_DIGEST_FORMAT_INVALID")
        if not isinstance(state_bytes, (bytes, bytearray, memoryview)):
            raise APEXValidationError("ADAM_STATE_BYTES_INVALID")
        raw = bytes(state_bytes)
        if len(raw) > MAX_STATE_BYTES:
            raise APEXValidationError("ADAM_STATE_TOO_LARGE")
        if not isinstance(receipt, Mapping):
            raise APEXValidationError("ADAM_RECEIPT_INVALID")
        self.verify_chain()
        state_hash = sha256_hex(raw)
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("SELECT height,state_hash FROM adam_commits ORDER BY height DESC LIMIT 1").fetchone()
                current_height = row["height"] if row else 0
                current_hash = row["state_hash"] if row else "0" * 64
                if height != current_height + 1:
                    raise APEXValidationError("ADAM_HEIGHT_NOT_CONTIGUOUS")
                if parent_hash != current_hash:
                    raise APEXValidationError("ADAM_PARENT_HASH_MISMATCH")
                db.execute(
                    "INSERT INTO adam_commits VALUES(?,?,?,?,?,?,?)",
                    (height, candidate_digest, parent_hash, state_hash,
                     certificate_digest, raw, canonical_bytes(dict(receipt)).decode()),
                )
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
        return {"committed": True, "height": height, "state_hash": state_hash,
                "candidate_digest": candidate_digest, "certificate_digest": certificate_digest}

    def get_commit(self, height: int) -> dict | None:
        self.verify_chain()
        with self._db() as db:
            row = db.execute("SELECT * FROM adam_commits WHERE height=?", (height,)).fetchone()
        if row is None:
            return None
        state = bytes(row["state_bytes"])
        if sha256_hex(state) != row["state_hash"]:
            raise APEXValidationError("ADAM_STORED_STATE_INTEGRITY_FAILURE")
        return {"height": row["height"], "candidate_digest": row["candidate_digest"],
                "parent_hash": row["parent_hash"], "state_hash": row["state_hash"],
                "certificate_digest": row["certificate_digest"], "state_bytes": state,
                "receipt": json.loads(row["receipt_json"])}


class APEXValidator:
    """Independent ADAM gate: verifies finality, GOD, HCCGN, justice and state."""
    def __init__(self, store: AdamCommitStore, *,
                 hccgn_verifier: Callable | None = None,
                 god_authorizer: Callable | None = None,
                 justice_verifier: Callable | None = None):
        self.store = store
        self.hccgn_verifier = hccgn_verifier or DenyUnconfigured("HCCGN")
        self.god_authorizer = god_authorizer or DenyUnconfigured("GOD")
        self.justice_verifier = justice_verifier or DenyUnconfigured("JUSTICE")

    def validate_and_commit(self, certificate: Mapping[str, Any],
                            state_bytes: bytes) -> dict:
        verified = verify_independent_certificate(
            certificate, hccgn_verifier=self.hccgn_verifier,
            god_authorizer=self.god_authorizer,
            justice_verifier=self.justice_verifier,
        )
        if not verified["valid"]:
            raise APEXValidationError("APEX_FINALITY_REJECTED:" + verified["reason"])
        proposal = certificate["proposal"]
        if sha256_hex(bytes(state_bytes)) != proposal["payload_hash"]:
            raise APEXValidationError("APEX_PAYLOAD_STATE_HASH_MISMATCH")
        if proposal["height"] != self.store.head()["height"] + 1:
            raise APEXValidationError("APEX_HEIGHT_CONTINUITY_FAILURE")
        if proposal["parent_hash"] != self.store.head()["state_hash"]:
            raise APEXValidationError("APEX_PARENT_STATE_MISMATCH")
        certificate_digest = sha256_hex(
            b"GCF/1|FINALITY-CERTIFICATE\x00" + canonical_bytes(certificate)
        )
        receipt = {
            "schema": "ADAM/APEX-RECEIPT/1",
            "candidate_digest": verified["candidate_digest"],
            "certificate_digest": certificate_digest,
            "validator_set_hash": verified["validator_set_hash"],
            "height": verified["height"],
            "policy_commitment": proposal["justice_commitment"],
            "apex_result": "ACCEPT",
            "state_hash": proposal["payload_hash"],
        }
        return self.store.commit(
            height=proposal["height"],
            candidate_digest=verified["candidate_digest"],
            parent_hash=proposal["parent_hash"],
            state_bytes=bytes(state_bytes),
            certificate_digest=certificate_digest,
            receipt=receipt,
        )
