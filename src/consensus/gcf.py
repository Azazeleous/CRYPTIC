"""GCF/1 consensus core: signed proposals, weighted BFT rounds and finality.

This module is deliberately fail-closed. A deployment must inject independent
HCCGN proof, GOD authorization, and justice-evidence verifiers. No local miner
format is silently accepted as an HCCGN network proof.
"""
from __future__ import annotations

import base64
import hashlib
from contextlib import contextmanager
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

SCHEMA = "GCF/1"
PROPOSAL_DOMAIN = b"GCF/1|PROPOSAL|ED25519\x00"
VOTE_DOMAIN = b"GCF/1|VOTE|ED25519\x00"
CERT_DOMAIN = b"GCF/1|FINALITY-CERTIFICATE\x00"
ZERO_HASH = "0" * 64
MAX_SQLITE_INT = (1 << 63) - 1


class GCFError(ValueError):
    pass


def _canonical_value(value: Any) -> Any:
    """Consensus JSON subset: finite integers only; no floats or non-ASCII keys."""
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        raise GCFError("floating-point values are forbidden in consensus JSON")
    if isinstance(value, list):
        return [_canonical_value(v) for v in value]
    if isinstance(value, tuple):
        return [_canonical_value(v) for v in value]
    if isinstance(value, Mapping):
        out = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise GCFError("consensus object keys must be ASCII strings")
            out[key] = _canonical_value(item)
        return out
    raise GCFError(f"unsupported consensus value: {type(value).__name__}")


def canonical_bytes(value: Mapping[str, Any] | list[Any]) -> bytes:
    normalized = _canonical_value(value)
    return json.dumps(
        normalized, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex(value: Any, field: str, size: int = 32) -> bytes:
    if not isinstance(value, str):
        raise GCFError(f"{field} must be hexadecimal text")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise GCFError(f"{field} is malformed hexadecimal") from exc
    if len(raw) != size:
        raise GCFError(f"{field} must be {size} bytes")
    return raw


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey,
        )
    except ImportError as exc:
        raise RuntimeError("GCF/1 requires the 'cryptography' package") from exc
    return InvalidSignature, serialization, Ed25519PrivateKey, Ed25519PublicKey


def public_key_hex(private_key_hex: str) -> str:
    _, serialization, private_type, _ = _crypto()
    private = private_type.from_private_bytes(_hex(private_key_hex, "private_key", 32))
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def sign_object(private_key_hex: str, domain: bytes, body: Mapping[str, Any]) -> str:
    _, _, private_type, _ = _crypto()
    private = private_type.from_private_bytes(_hex(private_key_hex, "private_key", 32))
    return base64.b64encode(private.sign(domain + canonical_bytes(body))).decode("ascii")


def verify_object(public_hex: str, signature: str, domain: bytes,
                  body: Mapping[str, Any]) -> bool:
    invalid, _, _, public_type = _crypto()
    try:
        public = public_type.from_public_bytes(_hex(public_hex, "public_key", 32))
        sig = base64.b64decode(signature, validate=True)
        if len(sig) != 64:
            return False
        public.verify(sig, domain + canonical_bytes(body))
        return True
    except (ValueError, TypeError, invalid, GCFError):
        return False


def _require_int(value: Any, field: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > MAX_SQLITE_INT:
        raise GCFError(f"{field} must be an integer in [{minimum}, {MAX_SQLITE_INT}]")
    return value


def _require_hash(value: Any, field: str) -> str:
    return _hex(value, field, 32).hex()


def _unsigned(record: Mapping[str, Any], signature_field: str = "signature") -> dict:
    return {k: v for k, v in record.items() if k != signature_field}


@dataclass(frozen=True)
class GateResult:
    allowed: bool
    reason: str


class DenyUnconfigured:
    """Safe default for integrations that have not been connected."""
    def __init__(self, label: str):
        self.label = label

    def __call__(self, *_args, **_kwargs) -> GateResult:
        return GateResult(False, f"{self.label}_VERIFIER_NOT_CONFIGURED")


@dataclass(frozen=True)
class Validator:
    validator_id: str
    public_key_hex: str
    weight: int


class ValidatorSet:
    def __init__(self, network_id: str, epoch: int,
                 validators: Mapping[str, Mapping[str, Any]]):
        if not network_id:
            raise GCFError("network_id is required")
        self.network_id = network_id
        self.epoch = _require_int(epoch, "epoch", 1)
        parsed: dict[str, Validator] = {}
        for validator_id, item in validators.items():
            if not isinstance(validator_id, str) or not validator_id:
                raise GCFError("validator IDs must be non-empty strings")
            key = _hex(item.get("public_key_hex"), "validator public key", 32).hex()
            weight = _require_int(item.get("weight"), "validator weight", 1)
            parsed[validator_id] = Validator(validator_id, key, weight)
        if not parsed:
            raise GCFError("validator set cannot be empty")
        self.validators = parsed
        self.total_weight = sum(v.weight for v in parsed.values())
        if self.total_weight > MAX_SQLITE_INT:
            raise GCFError("validator_total_weight_exceeds_storage_limit")
        self.digest = sha256_hex(canonical_bytes({
            "network_id": network_id,
            "epoch": self.epoch,
            "validators": [
                {"validator_id": v.validator_id, "public_key_hex": v.public_key_hex,
                 "weight": v.weight}
                for v in sorted(parsed.values(), key=lambda x: x.validator_id)
            ],
        }))

    def quorum_weight(self) -> int:
        # Strictly greater than 2/3, expressed with integer arithmetic.
        return (2 * self.total_weight) // 3 + 1

    def weight_of(self, signer_ids: set[str]) -> int:
        return sum(self.validators[x].weight for x in signer_ids if x in self.validators)


class GCFEngine:
    """SQLite-backed GCF/1 proposal/vote/finality engine.

    hccgn_verifier(proposal), god_authorizer("gcf.propose", proposal), and
    justice_verifier(proposal) must independently return GateResult or bool.
    Unconfigured gates deny by default.
    """
    def __init__(self, db_path: str | Path, validator_set: ValidatorSet, *,
                 hccgn_verifier: Callable | None = None,
                 god_authorizer: Callable | None = None,
                 justice_verifier: Callable | None = None,
                 clock: Callable[[], float] = time.time,
                 max_clock_skew: int = 30):
        self.db_path = str(db_path)
        self.validator_set = validator_set
        self.hccgn_verifier = hccgn_verifier or DenyUnconfigured("HCCGN")
        self.god_authorizer = god_authorizer or DenyUnconfigured("GOD")
        self.justice_verifier = justice_verifier or DenyUnconfigured("JUSTICE")
        self.clock = clock
        self.max_clock_skew = _require_int(max_clock_skew, "max_clock_skew")
        self._lock = threading.RLock()
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self):
        db = sqlite3.connect(self.db_path, timeout=15, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
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

    def _init_db(self):
        with self._db() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS proposals(
              candidate_digest TEXT PRIMARY KEY,
              network_id TEXT NOT NULL, epoch INTEGER NOT NULL, height INTEGER NOT NULL,
              round INTEGER NOT NULL, proposer_id TEXT NOT NULL, nonce TEXT NOT NULL,
              issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
              proposal_json TEXT NOT NULL, status TEXT NOT NULL,
              UNIQUE(network_id, proposer_id, nonce)
            );
            CREATE TABLE IF NOT EXISTS votes(
              candidate_digest TEXT NOT NULL REFERENCES proposals(candidate_digest),
              vote_type TEXT NOT NULL CHECK(vote_type IN ('PREVOTE','PRECOMMIT')),
              validator_id TEXT NOT NULL, approve INTEGER NOT NULL,
              polc_digest TEXT, vote_json TEXT NOT NULL,
              PRIMARY KEY(candidate_digest, vote_type, validator_id)
            );
            CREATE TABLE IF NOT EXISTS vote_locks(
              network_id TEXT NOT NULL, epoch INTEGER NOT NULL, height INTEGER NOT NULL,
              round INTEGER NOT NULL, vote_type TEXT NOT NULL,
              validator_id TEXT NOT NULL, candidate_digest TEXT NOT NULL,
              PRIMARY KEY(network_id, epoch, height, vote_type, validator_id)
            );
            CREATE TABLE IF NOT EXISTS certificates(
              candidate_digest TEXT PRIMARY KEY REFERENCES proposals(candidate_digest),
              certificate_json TEXT NOT NULL, certificate_digest TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS round_change_messages(
              network_id TEXT NOT NULL, epoch INTEGER NOT NULL, height INTEGER NOT NULL,
              target_round INTEGER NOT NULL, validator_id TEXT NOT NULL, nonce TEXT NOT NULL,
              message_json TEXT NOT NULL, received_at INTEGER NOT NULL,
              PRIMARY KEY(network_id,epoch,height,target_round,validator_id),
              UNIQUE(network_id,epoch,height,validator_id,nonce)
            );
            CREATE TABLE IF NOT EXISTS round_change_certificates(
              network_id TEXT NOT NULL, epoch INTEGER NOT NULL, height INTEGER NOT NULL,
              target_round INTEGER NOT NULL, certificate_json TEXT NOT NULL,
              certificate_digest TEXT NOT NULL,
              PRIMARY KEY(network_id,epoch,height,target_round)
            );
            INSERT OR IGNORE INTO vote_locks
              SELECT p.network_id,p.epoch,p.height,p.round,v.vote_type,v.validator_id,v.candidate_digest
              FROM votes v JOIN proposals p ON p.candidate_digest=v.candidate_digest;
            """)
            # Upgrade databases created by the earlier round-scoped lock schema.
            # If historical records show cross-round conflicting votes, refuse to
            # start rather than silently choosing one lock and masking equivocation.
            lock_columns = db.execute("PRAGMA table_info(vote_locks)").fetchall()
            round_is_primary = any(row["name"] == "round" and row["pk"] for row in lock_columns)
            if round_is_primary:
                conflict = db.execute("""
                    SELECT network_id,epoch,height,vote_type,validator_id
                    FROM vote_locks
                    GROUP BY network_id,epoch,height,vote_type,validator_id
                    HAVING COUNT(DISTINCT candidate_digest) > 1
                    LIMIT 1
                """).fetchone()
                if conflict is not None:
                    raise GCFError("PERSISTED_CROSS_ROUND_EQUIVOCATION")
                db.execute("BEGIN IMMEDIATE")
                try:
                    db.execute("""
                        CREATE TABLE vote_locks_v2(
                          network_id TEXT NOT NULL, epoch INTEGER NOT NULL,
                          height INTEGER NOT NULL, round INTEGER NOT NULL,
                          vote_type TEXT NOT NULL, validator_id TEXT NOT NULL,
                          candidate_digest TEXT NOT NULL,
                          PRIMARY KEY(network_id,epoch,height,vote_type,validator_id)
                        )
                    """)
                    db.execute("""
                        INSERT INTO vote_locks_v2
                        SELECT network_id,epoch,height,MIN(round),vote_type,
                               validator_id,candidate_digest
                        FROM vote_locks
                        GROUP BY network_id,epoch,height,vote_type,
                                 validator_id,candidate_digest
                    """)
                    db.execute("DROP TABLE vote_locks")
                    db.execute("ALTER TABLE vote_locks_v2 RENAME TO vote_locks")
                    db.execute("COMMIT")
                except Exception:
                    db.execute("ROLLBACK")
                    raise

    def _gate(self, gate: Callable, *args) -> GateResult:
        try:
            result = gate(*args)
        except Exception:
            return GateResult(False, "GATE_EVALUATION_ERROR")
        if isinstance(result, GateResult):
            if type(result.allowed) is not bool or not isinstance(result.reason, str):
                return GateResult(False, "GATE_RESPONSE_INVALID")
            return result
        if result is True:
            return GateResult(True, "ALLOW")
        if result is False:
            return GateResult(False, "DENIED")
        return GateResult(False, "GATE_RESPONSE_INVALID")

    def _validate_proposal(self, proposal: Mapping[str, Any]) -> tuple[str, dict]:
        required = {
            "schema", "network_id", "epoch", "height", "round", "parent_hash",
            "payload_hash", "proof_hash", "justice_commitment", "issued_at",
            "expires_at", "proposer_id", "proposer_public_key", "nonce", "signature",
        }
        allowed = required | {"anchor_sequence"}
        if not isinstance(proposal, Mapping) or set(proposal) not in (required, allowed):
            raise GCFError("proposal_fields_invalid")
        if proposal["schema"] != SCHEMA:
            raise GCFError("schema_unsupported")
        if proposal["network_id"] != self.validator_set.network_id:
            raise GCFError("NETWORK_ID_MISMATCH")
        if _require_int(proposal["epoch"], "epoch", 1) != self.validator_set.epoch:
            raise GCFError("VALIDATOR_EPOCH_MISMATCH")
        _require_int(proposal["height"], "height", 1)
        if "anchor_sequence" in proposal:
            _require_int(proposal["anchor_sequence"], "anchor_sequence", 1)
        _require_int(proposal["round"], "round")
        _require_hash(proposal["parent_hash"], "parent_hash")
        _require_hash(proposal["payload_hash"], "payload_hash")
        _require_hash(proposal["proof_hash"], "proof_hash")
        _require_int(proposal["issued_at"], "issued_at")
        _require_int(proposal["expires_at"], "expires_at")
        if proposal["expires_at"] <= proposal["issued_at"]:
            raise GCFError("invalid_time_window")
        now = int(self.clock())
        if proposal["issued_at"] > now + self.max_clock_skew:
            raise GCFError("PROPOSAL_FROM_FUTURE")
        if now > proposal["expires_at"]:
            raise GCFError("CANDIDATE_EXPIRED")
        if proposal["expires_at"] - proposal["issued_at"] > 3600:
            raise GCFError("proposal_ttl_exceeds_limit")
        if not isinstance(proposal["proposer_id"], str) or not proposal["proposer_id"]:
            raise GCFError("proposer_id_invalid")
        if not isinstance(proposal["nonce"], str) or not 16 <= len(proposal["nonce"]) <= 128:
            raise GCFError("nonce_invalid")
        if not isinstance(proposal["justice_commitment"], Mapping):
            raise GCFError("justice_commitment_invalid")
        public = _hex(proposal["proposer_public_key"], "proposer_public_key", 32).hex()
        body = _unsigned(proposal)
        if not verify_object(public, proposal["signature"], PROPOSAL_DOMAIN, body):
            raise GCFError("PROPOSER_SIGNATURE_INVALID")
        digest = sha256_hex(canonical_bytes(dict(proposal)))
        return digest, dict(proposal)

    def submit_proposal(self, proposal: Mapping[str, Any]) -> dict:
        digest, normalized = self._validate_proposal(proposal)
        for gate, args, code in (
            (self.hccgn_verifier, (normalized,), "MINER_PROOF_INVALID"),
            (self.god_authorizer, ("gcf.propose", normalized), "GOD_POLICY_DENIED"),
            (self.justice_verifier, (normalized,), "JUSTICE_VALIDATION_FAILED"),
        ):
            result = self._gate(gate, *args)
            if not result.allowed:
                raise GCFError(f"{code}:{result.reason}")
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute(
                    """INSERT INTO proposals VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (digest, normalized["network_id"], normalized["epoch"],
                     normalized["height"], normalized["round"], normalized["proposer_id"],
                     normalized["nonce"], normalized["issued_at"], normalized["expires_at"],
                     canonical_bytes(normalized).decode(), "RECEIVED"),
                )
                db.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                db.execute("ROLLBACK")
                raise GCFError("PROPOSAL_REPLAY_OR_DUPLICATE") from exc
            except Exception:
                db.execute("ROLLBACK")
                raise
        return {"accepted": True, "candidate_digest": digest, "status": "RECEIVED"}

    def _proposal(self, db, digest: str) -> dict:
        row = db.execute(
            "SELECT proposal_json FROM proposals WHERE candidate_digest=?", (digest,)
        ).fetchone()
        if row is None:
            raise GCFError("candidate_unknown")
        return json.loads(row["proposal_json"])

    def _verify_vote(self, vote: Mapping[str, Any], proposal: Mapping[str, Any]) -> dict:
        required = {
            "schema", "network_id", "epoch", "height", "round", "candidate_digest",
            "validator_id", "vote_type", "approve", "polc_digest", "issued_at", "signature",
        }
        if not isinstance(vote, Mapping) or set(vote) != required:
            raise GCFError("vote_fields_invalid")
        if vote["schema"] != SCHEMA or vote["network_id"] != self.validator_set.network_id:
            raise GCFError("vote_network_or_schema_invalid")
        for key in ("epoch", "height", "round"):
            if vote[key] != proposal[key]:
                raise GCFError(f"vote_{key}_mismatch")
        digest = sha256_hex(canonical_bytes(proposal))
        if vote["candidate_digest"] != digest:
            raise GCFError("vote_candidate_mismatch")
        validator = self.validator_set.validators.get(vote["validator_id"])
        if validator is None:
            raise GCFError("UNKNOWN_VALIDATOR")
        if vote["vote_type"] not in ("PREVOTE", "PRECOMMIT"):
            raise GCFError("vote_type_invalid")
        if not isinstance(vote["approve"], bool):
            raise GCFError("vote_approve_must_be_boolean")
        _require_int(vote["issued_at"], "issued_at")
        if abs(int(self.clock()) - vote["issued_at"]) > 300:
            raise GCFError("VOTE_TIME_INVALID")
        if vote["issued_at"] < proposal["issued_at"] or vote["issued_at"] > proposal["expires_at"]:
            raise GCFError("VOTE_OUTSIDE_PROPOSAL_WINDOW")
        if int(self.clock()) > proposal["expires_at"]:
            raise GCFError("CANDIDATE_EXPIRED")
        if vote["vote_type"] == "PREVOTE" and vote["polc_digest"] is not None:
            raise GCFError("PREVOTE_MUST_NOT_CARRY_POLC")
        if vote["vote_type"] == "PRECOMMIT" and vote["approve"]:
            if not isinstance(vote["polc_digest"], str):
                raise GCFError("PRECOMMIT_REQUIRES_POLC")
        if not verify_object(validator.public_key_hex, vote["signature"],
                             VOTE_DOMAIN, _unsigned(vote)):
            raise GCFError("VALIDATOR_SIGNATURE_INVALID")
        return dict(vote)

    def _votes(self, db, digest: str, vote_type: str) -> list[dict]:
        rows = db.execute(
            "SELECT vote_json FROM votes WHERE candidate_digest=? AND vote_type=? AND approve=1",
            (digest, vote_type),
        ).fetchall()
        return sorted((json.loads(r["vote_json"]) for r in rows),
                      key=lambda v: v["validator_id"])

    def _quorum(self, votes: list[dict]) -> tuple[bool, int]:
        ids = {v["validator_id"] for v in votes}
        return self.validator_set.weight_of(ids) >= self.validator_set.quorum_weight(), \
            self.validator_set.weight_of(ids)

    def _polc(self, db, digest: str) -> tuple[list[dict], str]:
        votes = self._votes(db, digest, "PREVOTE")
        reached, weight = self._quorum(votes)
        if not reached:
            raise GCFError(f"PREVOTE_QUORUM_NOT_REACHED:{weight}/{self.validator_set.quorum_weight()}")
        body = {
            "schema": SCHEMA, "candidate_digest": digest,
            "validator_set_hash": self.validator_set.digest,
            "prevotes": votes,
        }
        return votes, sha256_hex(CERT_DOMAIN + canonical_bytes(body))

    def submit_vote(self, vote: Mapping[str, Any]) -> dict:
        digest = vote.get("candidate_digest") if isinstance(vote, Mapping) else None
        if not isinstance(digest, str):
            raise GCFError("candidate_digest_required")
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                proposal = self._proposal(db, digest)
                normalized = self._verify_vote(vote, proposal)
                if normalized["vote_type"] == "PRECOMMIT" and normalized["approve"]:
                    _, polc_digest = self._polc(db, digest)
                    if normalized["polc_digest"] != polc_digest:
                        raise GCFError("PRECOMMIT_POLC_MISMATCH")
                lock = db.execute(
                    """SELECT candidate_digest FROM vote_locks
                       WHERE network_id=? AND epoch=? AND height=?
                         AND vote_type=? AND validator_id=?""",
                    (normalized["network_id"], normalized["epoch"], normalized["height"],
                     normalized["vote_type"], normalized["validator_id"]),
                ).fetchone()
                if lock is not None:
                    if lock["candidate_digest"] != digest:
                        raise GCFError("VALIDATOR_EQUIVOCATION_DETECTED")
                    raise GCFError("DUPLICATE_VOTE_OR_EQUIVOCATION")
                db.execute(
                    "INSERT INTO vote_locks VALUES(?,?,?,?,?,?,?)",
                    (normalized["network_id"], normalized["epoch"], normalized["height"],
                     normalized["round"], normalized["vote_type"],
                     normalized["validator_id"], digest),
                )
                try:
                    db.execute(
                        "INSERT INTO votes VALUES(?,?,?,?,?,?)",
                        (digest, normalized["vote_type"], normalized["validator_id"],
                         int(normalized["approve"]), normalized["polc_digest"],
                         canonical_bytes(normalized).decode()),
                    )
                except sqlite3.IntegrityError as exc:
                    raise GCFError("DUPLICATE_VOTE_OR_EQUIVOCATION") from exc
                votes = self._votes(db, digest, normalized["vote_type"])
                reached, weight = self._quorum(votes)
                if normalized["vote_type"] == "PREVOTE" and reached:
                    db.execute("UPDATE proposals SET status='PREVOTE' WHERE candidate_digest=?", (digest,))
                if normalized["vote_type"] == "PRECOMMIT" and reached:
                    db.execute("UPDATE proposals SET status='PRECOMMIT' WHERE candidate_digest=?", (digest,))
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
        return {"accepted": True, "vote_type": normalized["vote_type"],
                "quorum_reached": reached, "voting_weight": weight,
                "quorum_weight": self.validator_set.quorum_weight()}

    def submit_round_change(self, message: Mapping[str, Any]) -> dict:
        """Persist authenticated round-change evidence and cache a verified quorum certificate.

        This records proof evidence only. It deliberately does not mutate vote
        locks, authorize a conflicting signature, or advance proposal admission.
        """
        from src.consensus.round_change import (
            make_round_change_certificate, verify_round_change_message,
            verify_round_change_certificate,
        )
        if not isinstance(message, Mapping):
            raise GCFError("ROUND_CHANGE_MESSAGE_INVALID")
        height, target = message.get("height"), message.get("target_round")
        checked = verify_round_change_message(
            message, validator_set=self.validator_set, height=height,
            target_round=target, clock=self.clock,
        )
        if not checked.get("valid"):
            raise GCFError("ROUND_CHANGE_REJECTED:" + str(checked.get("reason")))
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                existing = db.execute("""
                    SELECT message_json FROM round_change_messages
                    WHERE network_id=? AND epoch=? AND height=?
                      AND target_round=? AND validator_id=?
                """, (self.validator_set.network_id, self.validator_set.epoch,
                      height, target, checked["validator_id"])).fetchone()
                encoded = canonical_bytes(dict(message)).decode()
                if existing is not None:
                    if existing["message_json"] != encoded:
                        raise GCFError("ROUND_CHANGE_EQUIVOCATION")
                    raise GCFError("ROUND_CHANGE_DUPLICATE")
                db.execute("""
                    INSERT INTO round_change_messages VALUES(?,?,?,?,?,?,?,?)
                """, (self.validator_set.network_id, self.validator_set.epoch,
                      height, target, checked["validator_id"], message["nonce"],
                      encoded, int(self.clock())))
                rows = db.execute("""
                    SELECT message_json FROM round_change_messages
                    WHERE network_id=? AND epoch=? AND height=? AND target_round=?
                    ORDER BY validator_id
                """, (self.validator_set.network_id, self.validator_set.epoch,
                      height, target)).fetchall()
                messages = [json.loads(row["message_json"]) for row in rows]
                certificate = make_round_change_certificate(
                    messages, network_id=self.validator_set.network_id,
                    epoch=self.validator_set.epoch, height=height, target_round=target,
                )
                result = verify_round_change_certificate(
                    certificate, validator_set=self.validator_set, height=height,
                    clock=self.clock,
                )
                if result["valid"]:
                    db.execute("""
                        INSERT INTO round_change_certificates
                        VALUES(?,?,?,?,?,?)
                        ON CONFLICT(network_id,epoch,height,target_round)
                        DO UPDATE SET certificate_json=excluded.certificate_json,
                                      certificate_digest=excluded.certificate_digest
                    """, (self.validator_set.network_id, self.validator_set.epoch,
                          height, target, canonical_bytes(certificate).decode(),
                          result["digest"]))
                db.execute("COMMIT")
            except Exception:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
        return {
            "accepted": True, "validator_id": checked["validator_id"],
            "height": height, "target_round": target,
            "quorum_reached": bool(result["valid"]),
            "voting_weight": result.get("weight", 0),
            "quorum_weight": result.get("quorum_weight", self.validator_set.quorum_weight()),
            "certificate": certificate if result["valid"] else None,
        }

    def get_round_change_certificate(self, *, height: int, target_round: int) -> dict | None:
        """Return a cached certificate only after re-verifying it against current trust."""
        from src.consensus.round_change import verify_round_change_certificate
        with self._db() as db:
            row = db.execute("""
                SELECT certificate_json FROM round_change_certificates
                WHERE network_id=? AND epoch=? AND height=? AND target_round=?
            """, (self.validator_set.network_id, self.validator_set.epoch,
                  height, target_round)).fetchone()
        if row is None:
            return None
        certificate = json.loads(row["certificate_json"])
        checked = verify_round_change_certificate(
            certificate, validator_set=self.validator_set, height=height,
            clock=self.clock,
        )
        if not checked["valid"]:
            raise GCFError("PERSISTED_ROUND_CHANGE_CERTIFICATE_INVALID:" + checked["reason"])
        return certificate

    def finalize(self, candidate_digest: str) -> dict:
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                proposal = self._proposal(db, candidate_digest)
                prevotes, polc_digest = self._polc(db, candidate_digest)
                precommits = self._votes(db, candidate_digest, "PRECOMMIT")
                for vote in precommits:
                    if vote["polc_digest"] != polc_digest:
                        raise GCFError("PRECOMMIT_POLC_MISMATCH")
                reached, weight = self._quorum(precommits)
                if not reached:
                    raise GCFError(f"PRECOMMIT_QUORUM_NOT_REACHED:{weight}/{self.validator_set.quorum_weight()}")
                certificate = {
                    "schema": SCHEMA,
                    "network_id": self.validator_set.network_id,
                    "epoch": self.validator_set.epoch,
                    "height": proposal["height"],
                    "round": proposal["round"],
                    "candidate_digest": candidate_digest,
                    "proposal": proposal,
                    "validator_set": {
                        "network_id": self.validator_set.network_id,
                        "epoch": self.validator_set.epoch,
                        "validators": [
                            {"validator_id": v.validator_id,
                             "public_key_hex": v.public_key_hex, "weight": v.weight}
                            for v in sorted(self.validator_set.validators.values(),
                                            key=lambda x: x.validator_id)
                        ],
                        "validator_set_hash": self.validator_set.digest,
                    },
                    "polc": {"digest": polc_digest, "prevotes": prevotes},
                    "precommits": precommits,
                    "total_voting_weight": self.validator_set.total_weight,
                    "precommit_weight": weight,
                }
                cert_digest = sha256_hex(CERT_DOMAIN + canonical_bytes(certificate))
                db.execute(
                    "INSERT OR REPLACE INTO certificates VALUES(?,?,?)",
                    (candidate_digest, canonical_bytes(certificate).decode(), cert_digest),
                )
                db.execute("UPDATE proposals SET status='FINALIZED' WHERE candidate_digest=?",
                           (candidate_digest,))
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
        return {"finalized": True, "certificate": certificate,
                "certificate_digest": cert_digest, "precommit_weight": weight}

    def get_status(self, candidate_digest: str) -> dict:
        with self._db() as db:
            row = db.execute(
                "SELECT status FROM proposals WHERE candidate_digest=?", (candidate_digest,)
            ).fetchone()
            if row is None:
                raise GCFError("candidate_unknown")
            cert = db.execute(
                "SELECT certificate_digest FROM certificates WHERE candidate_digest=?",
                (candidate_digest,),
            ).fetchone()
        return {"status": row["status"],
                "certificate_digest": cert["certificate_digest"] if cert else None}


def verify_finality_certificate(certificate: Mapping[str, Any], *,
                                hccgn_verifier: Callable | None = None,
                                god_authorizer: Callable | None = None,
                                justice_verifier: Callable | None = None,
                                clock: Callable[[], float] = time.time) -> dict:
    """Independent certificate verification; all external gates fail closed."""
    fail = lambda reason: {"valid": False, "reason": reason}
    try:
        if not isinstance(certificate, Mapping) or certificate.get("schema") != SCHEMA:
            return fail("certificate_schema_invalid")
        proposal = certificate["proposal"]
        validators_raw = certificate["validator_set"]["validators"]
        validators = {v["validator_id"]: {"public_key_hex": v["public_key_hex"],
                                          "weight": v["weight"]} for v in validators_raw}
        vset = ValidatorSet(certificate["network_id"], certificate["epoch"], validators)
        if vset.digest != certificate["validator_set"]["validator_set_hash"]:
            return fail("validator_set_hash_mismatch")
        engine = object.__new__(GCFEngine)
        engine.validator_set = vset
        # A finalized certificate must remain independently verifiable after
        # proposal expiry. Verify that it was valid at its signed issue time.
        engine.clock = lambda: proposal["issued_at"]
        engine.max_clock_skew = 30
        digest, normalized = engine._validate_proposal(proposal)
        if certificate["height"] != proposal["height"] or certificate["round"] != proposal["round"]:
            return fail("certificate_round_or_height_mismatch")
        if digest != certificate["candidate_digest"]:
            return fail("candidate_digest_mismatch")
        for gate, args, code in (
            (hccgn_verifier or DenyUnconfigured("HCCGN"), (normalized,), "hccgn_proof_invalid"),
            (god_authorizer or DenyUnconfigured("GOD"), ("gcf.propose", normalized), "god_policy_denied"),
            (justice_verifier or DenyUnconfigured("JUSTICE"), (normalized,), "justice_invalid"),
        ):
            result = gate(*args)
            if not (result.allowed is True if isinstance(result, GateResult) else result is True):
                return fail(code)
        prevotes = certificate["polc"]["prevotes"]
        precommits = certificate["precommits"]
        def check_votes(votes, kind, expected_polc=None):
            seen = set()
            for vote in votes:
                # Historical votes are checked cryptographically, not against
                # the verifier's current wall clock.
                engine.clock = lambda issued=vote.get("issued_at"): issued
                parsed = engine._verify_vote(vote, normalized)
                if (parsed["vote_type"] != kind or not parsed["approve"]
                        or parsed["validator_id"] in seen):
                    return False
                seen.add(parsed["validator_id"])
                if expected_polc is not None and parsed["approve"] and parsed["polc_digest"] != expected_polc:
                    return False
            return True
        if not check_votes(prevotes, "PREVOTE"):
            return fail("prevote_signature_or_shape_invalid")
        prevote_weight = vset.weight_of({v["validator_id"] for v in prevotes if v["approve"]})
        if prevote_weight < vset.quorum_weight():
            return fail("prevote_quorum_missing")
        polc_body = {"schema": SCHEMA, "candidate_digest": digest,
                     "validator_set_hash": vset.digest, "prevotes": prevotes}
        polc_digest = sha256_hex(CERT_DOMAIN + canonical_bytes(polc_body))
        if certificate["polc"]["digest"] != polc_digest:
            return fail("polc_digest_mismatch")
        if not check_votes(precommits, "PRECOMMIT", polc_digest):
            return fail("precommit_signature_or_lock_invalid")
        precommit_weight = vset.weight_of({v["validator_id"] for v in precommits if v["approve"]})
        if precommit_weight < vset.quorum_weight():
            return fail("precommit_quorum_missing")
        if certificate["precommit_weight"] != precommit_weight:
            return fail("precommit_weight_mismatch")
        if certificate["total_voting_weight"] != vset.total_weight:
            return fail("total_weight_mismatch")
        return {"valid": True, "reason": "finality_certificate_valid",
                "candidate_digest": digest, "height": proposal["height"],
                "precommit_weight": precommit_weight,
                "quorum_weight": vset.quorum_weight(),
                "validator_set_hash": vset.digest}
    except (KeyError, TypeError, ValueError, GCFError) as exc:
        return fail(f"certificate_invalid:{exc}")


def make_proposal(*, network_id: str, epoch: int, height: int, round: int,
                  parent_hash: str, payload_hash: str, proof_hash: str,
                  justice_commitment: Mapping[str, Any], proposer_id: str,
                  proposer_private_key_hex: str, nonce: str, issued_at: int,
                  expires_at: int, anchor_sequence: int | None = None) -> dict:
    body = {
        "schema": SCHEMA, "network_id": network_id, "epoch": epoch,
        "height": height, "round": round, "parent_hash": parent_hash,
        "payload_hash": payload_hash, "proof_hash": proof_hash,
        "justice_commitment": dict(justice_commitment),
        "issued_at": issued_at, "expires_at": expires_at,
        "proposer_id": proposer_id,
        "proposer_public_key": public_key_hex(proposer_private_key_hex),
        "nonce": nonce,
    }
    if anchor_sequence is not None:
        body["anchor_sequence"] = _require_int(anchor_sequence, "anchor_sequence", 1)
    return {**body, "signature": sign_object(proposer_private_key_hex, PROPOSAL_DOMAIN, body)}


def make_vote(*, validator_id: str, validator_private_key_hex: str,
              proposal: Mapping[str, Any], vote_type: str, approve: bool = True,
              polc_digest: str | None = None, issued_at: int | None = None) -> dict:
    body = {
        "schema": SCHEMA, "network_id": proposal["network_id"],
        "epoch": proposal["epoch"], "height": proposal["height"],
        "round": proposal["round"],
        "candidate_digest": sha256_hex(canonical_bytes(proposal)),
        "validator_id": validator_id, "vote_type": vote_type,
        "approve": approve, "polc_digest": polc_digest,
        "issued_at": int(time.time()) if issued_at is None else issued_at,
    }
    return {**body, "signature": sign_object(validator_private_key_hex, VOTE_DOMAIN, body)}
