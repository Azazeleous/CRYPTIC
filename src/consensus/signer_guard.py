"""Persistent cross-version anti-equivocation guard for consensus signing.

A deployment supplies an HSM/KMS-backed Ed25519 signing callback. This module
never creates or stores private key material. It reserves a logical vote slot
before calling the provider and only retries the exact same signed payload.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

GCF1_VOTE_DOMAIN = b"GCF/1|VOTE|ED25519\x00"
GCF2_VOTE_DOMAIN = b"GCF/2|VOTE|ED25519\x00"
GCF1_ROUND_CHANGE_DOMAIN = b"GCF/1|ROUND-CHANGE|ED25519\x00"


class ConsensusSigningError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ConsensusSigningError("signing_payload_not_canonical") from exc


class ConsensusSigningGuard:
    """One logical signature slot across GCF versions, backed by SQLite."""

    def __init__(
        self, *, database: str | Path, network_id: str, epoch: int,
        validator_id: str, public_key_hex: str,
        sign_bytes: Callable[[bytes], bytes],
    ):
        if not callable(sign_bytes):
            raise ConsensusSigningError("hardware_signing_provider_required")
        if not isinstance(network_id, str) or not network_id:
            raise ConsensusSigningError("network_id_invalid")
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
            raise ConsensusSigningError("epoch_invalid")
        if not isinstance(validator_id, str) or not validator_id:
            raise ConsensusSigningError("validator_id_invalid")
        try:
            public = bytes.fromhex(public_key_hex)
            if len(public) != 32:
                raise ValueError("key_length")
        except (TypeError, ValueError) as exc:
            raise ConsensusSigningError("public_key_invalid") from exc
        path = Path(database).expanduser()
        if str(database) == ":memory:" or (path.exists() and path.is_symlink()):
            raise ConsensusSigningError("persistent_non_symlink_database_required")
        path.parent.mkdir(parents=True, exist_ok=True)
        self.database = str(path)
        self.network_id = network_id
        self.epoch = epoch
        self.validator_id = validator_id
        self.public_key_hex = public_key.hex()
        self.sign_bytes = sign_bytes
        with self._db() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS consensus_signing_slots (
                  network_id TEXT NOT NULL, epoch INTEGER NOT NULL,
                  height INTEGER NOT NULL, round INTEGER NOT NULL,
                  slot_type TEXT NOT NULL,
                  validator_id TEXT NOT NULL,
                  protocol_schema TEXT NOT NULL,
                  payload_digest TEXT NOT NULL,
                  payload_json BLOB NOT NULL,
                  signature_b64 TEXT,
                  created_at INTEGER NOT NULL,
                  PRIMARY KEY(network_id,epoch,height,round,slot_type,validator_id)
                )
            """)
            db.execute("""
                CREATE TRIGGER IF NOT EXISTS consensus_signing_slots_no_delete
                BEFORE DELETE ON consensus_signing_slots
                BEGIN SELECT RAISE(ABORT,'consensus_signing_slot_immutable'); END
            """)

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.database, timeout=15, isolation_level=None)
        db.execute("PRAGMA busy_timeout=15000")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        try:
            yield db
        finally:
            db.close()

    def sign_vote(self, unsigned_vote: Mapping[str, Any], *, created_at: int) -> dict:
        if not isinstance(unsigned_vote, Mapping) or "signature" in unsigned_vote:
            raise ConsensusSigningError("unsigned_vote_required")
        body = dict(unsigned_vote)
        schema = body.get("schema")
        if schema == "GCF/1":
            domain = GCF1_VOTE_DOMAIN
            required = {"network_id", "epoch", "height", "round", "vote_type",
                        "validator_id", "candidate_digest", "approve", "polc_digest"}
        elif schema == "GCF/2":
            domain = GCF2_VOTE_DOMAIN
            required = {"network_id", "epoch", "height", "round", "vote_type",
                        "validator_id", "vote_kind", "candidate_digest",
                        "approve", "polc_digest", "parent_hash", "issued_at", "expires_at"}
        else:
            raise ConsensusSigningError("consensus_vote_schema_unsupported")
        if not required.issubset(body):
            raise ConsensusSigningError("consensus_vote_fields_missing")
        if body["network_id"] != self.network_id or body["epoch"] != self.epoch:
            raise ConsensusSigningError("consensus_vote_scope_mismatch")
        if body["validator_id"] != self.validator_id:
            raise ConsensusSigningError("consensus_vote_signer_mismatch")
        height, round_number = body["height"], body["round"]
        if (isinstance(height, bool) or not isinstance(height, int) or height < 1
                or isinstance(round_number, bool) or not isinstance(round_number, int) or round_number < 0):
            raise ConsensusSigningError("consensus_vote_slot_invalid")
        if body["vote_type"] not in ("PREVOTE", "PRECOMMIT"):
            raise ConsensusSigningError("consensus_vote_phase_invalid")
        return self._sign_slot(
            body=body, domain=domain, slot_type=body["vote_type"],
            protocol_schema=schema, height=height, round_number=round_number,
            created_at=created_at,
        )

    def sign_round_change(self, unsigned_message: Mapping[str, Any], *, created_at: int) -> dict:
        if not isinstance(unsigned_message, Mapping) or "signature" in unsigned_message:
            raise ConsensusSigningError("unsigned_round_change_required")
        body = dict(unsigned_message)
        if body.get("schema") != "GCF-ROUND-CHANGE/1":
            raise ConsensusSigningError("round_change_schema_unsupported")
        if body.get("network_id") != self.network_id or body.get("epoch") != self.epoch:
            raise ConsensusSigningError("round_change_scope_mismatch")
        if body.get("validator_id") != self.validator_id:
            raise ConsensusSigningError("round_change_signer_mismatch")
        height, target = body.get("height"), body.get("target_round")
        if (isinstance(height, bool) or not isinstance(height, int) or height < 1
                or isinstance(target, bool) or not isinstance(target, int) or target < 1):
            raise ConsensusSigningError("round_change_slot_invalid")
        return self._sign_slot(
            body=body, domain=GCF1_ROUND_CHANGE_DOMAIN,
            slot_type="ROUND_CHANGE:" + str(target),
            protocol_schema=body["schema"], height=height,
            round_number=target, created_at=created_at,
        )

    def _sign_slot(
        self, *, body: dict, domain: bytes, slot_type: str,
        protocol_schema: str, height: int, round_number: int,
        created_at: int,
    ) -> dict:
        if isinstance(created_at, bool) or not isinstance(created_at, int) or created_at < 0:
            raise ConsensusSigningError("signing_timestamp_invalid")
        payload = domain + _canonical(body)
        digest = hashlib.sha256(payload).hexdigest()
        encoded_body = _canonical(body)
        key = (self.network_id, self.epoch, height, round_number,
               slot_type, self.validator_id)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    """SELECT payload_digest,payload_json,signature_b64
                       FROM consensus_signing_slots
                       WHERE network_id=? AND epoch=? AND height=? AND round=?
                         AND slot_type=? AND validator_id=?""", key,
                ).fetchone()
                if row is None:
                    db.execute(
                        """INSERT INTO consensus_signing_slots
                           (network_id,epoch,height,round,slot_type,validator_id,
                            protocol_schema,payload_digest,payload_json,signature_b64,created_at)
                           VALUES(?,?,?,?,?,?,?,?,?,NULL,?)""",
                        (*key, protocol_schema, digest, encoded_body, created_at),
                    )
                    signature_b64 = None
                else:
                    if row[0] != digest or bytes(row[1]) != encoded_body:
                        raise ConsensusSigningError("consensus_signing_slot_conflict")
                    signature_b64 = row[2]
                db.execute("COMMIT")
            except Exception:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
        if signature_b64 is None:
            try:
                signature = self.sign_bytes(payload)
                if not isinstance(signature, bytes) or len(signature) != 64:
                    raise ValueError("provider_signature_invalid")
                Ed25519PublicKey.from_public_bytes(
                    bytes.fromhex(self.public_key_hex)
                ).verify(signature, payload)
            except (ValueError, TypeError, InvalidSignature, Exception) as exc:
                raise ConsensusSigningError("hardware_signing_provider_failed") from exc
            signature_b64 = base64.b64encode(signature).decode("ascii")
            with self._db() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    row = db.execute(
                        """SELECT payload_digest,signature_b64
                           FROM consensus_signing_slots
                           WHERE network_id=? AND epoch=? AND height=? AND round=?
                             AND slot_type=? AND validator_id=?""", key,
                    ).fetchone()
                    if row is None or row[0] != digest:
                        raise ConsensusSigningError("consensus_signing_reservation_lost")
                    if row[1] is None:
                        db.execute(
                            """UPDATE consensus_signing_slots SET signature_b64=?
                               WHERE network_id=? AND epoch=? AND height=? AND round=?
                                 AND slot_type=? AND validator_id=? AND signature_b64 IS NULL""",
                            (signature_b64, *key),
                        )
                    else:
                        signature_b64 = row[1]
                    db.execute("COMMIT")
                except Exception:
                    if db.in_transaction:
                        db.execute("ROLLBACK")
                    raise
        return {**body, "signature": signature_b64}

    def slot_status(self) -> list[dict]:
        with self._db() as db:
            rows = db.execute(
                """SELECT height,round,slot_type,protocol_schema,payload_digest,
                          signature_b64,created_at
                   FROM consensus_signing_slots
                   WHERE network_id=? AND epoch=? AND validator_id=?
                   ORDER BY height,round,slot_type""",
                (self.network_id, self.epoch, self.validator_id),
            ).fetchall()
        return [
            {"height": row[0], "round": row[1], "slot_type": row[2],
             "protocol_schema": row[3], "payload_digest": row[4],
             "signed": row[5] is not None, "created_at": row[6]}
            for row in rows
        ]
