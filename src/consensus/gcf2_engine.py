"""Durable GCF/2 vote-slot admission and POLC construction.

This is an opt-in compatibility engine. GCF/1 remains the active finality
protocol. GCF/2 votes are durably admitted and can form a GCF/2 POLC, but this
module does not authorize block finality or advance chain height.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
import sqlite3
import threading
from pathlib import Path
from typing import Any, Callable, Mapping

from src.consensus.gcf import (
    GCFError, GCFEngine, ValidatorSet, canonical_bytes, sha256_hex,
)
from src.consensus.gcf2 import (
    SCHEMA, VOTE_DOMAIN, verify_vote,
)

POLC_DOMAIN = b"GCF/2|POLC\x00"
CERT_DOMAIN = b"GCF/2|FINALITY-CERTIFICATE\x00"


class GCF2VoteStore:
    """Persistent one-vote-per-slot admission with trusted-parent binding.

    Candidate locks are conservative: a validator cannot change candidate
    digest within a height/phase. NIL votes consume the durable vote slot but
    never create, erase, or override a candidate lock. A later, separately
    specified proof-bound lock-transition implementation may relax this rule.
    """

    def __init__(
        self, *, database: str | Path, validator_set: ValidatorSet,
        gcf1_engine: GCFEngine,
        resolve_active_parent: Callable[[int], str | None],
        clock: Callable[[], float],
    ):
        if not callable(resolve_active_parent) or not callable(clock):
            raise GCFError("GCF2_TRUSTED_PARENT_RESOLVER_AND_CLOCK_REQUIRED")
        self.database = str(Path(database).expanduser().resolve())
        if Path(self.database).resolve() != Path(gcf1_engine.db_path).expanduser().resolve():
            raise GCFError("GCF2_AND_GCF1_MUST_SHARE_DURABLE_VOTE_DATABASE")
        Path(self.database).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self.validator_set = validator_set
        self.gcf1_engine = gcf1_engine
        self.resolve_active_parent = resolve_active_parent
        self.clock = clock
        self._lock = threading.RLock()
        with self._db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS gcf2_vote_slots (
                  network_id TEXT NOT NULL, epoch INTEGER NOT NULL,
                  height INTEGER NOT NULL, round INTEGER NOT NULL,
                  vote_type TEXT NOT NULL CHECK(vote_type IN ('PREVOTE','PRECOMMIT')),
                  validator_id TEXT NOT NULL, vote_kind TEXT NOT NULL
                    CHECK(vote_kind IN ('CANDIDATE','NIL')),
                  candidate_digest TEXT, parent_hash TEXT NOT NULL,
                  vote_json TEXT NOT NULL, vote_digest TEXT NOT NULL,
                  PRIMARY KEY(network_id,epoch,height,round,vote_type,validator_id),
                  UNIQUE(network_id,epoch,height,round,vote_type,vote_digest)
                );
                CREATE TABLE IF NOT EXISTS gcf2_validator_rounds (
                  network_id TEXT NOT NULL, epoch INTEGER NOT NULL,
                  height INTEGER NOT NULL, validator_id TEXT NOT NULL,
                  highest_round INTEGER NOT NULL,
                  PRIMARY KEY(network_id,epoch,height,validator_id)
                );
                CREATE TABLE IF NOT EXISTS gcf2_candidate_locks (
                  network_id TEXT NOT NULL, epoch INTEGER NOT NULL,
                  height INTEGER NOT NULL, vote_type TEXT NOT NULL,
                  validator_id TEXT NOT NULL, candidate_digest TEXT NOT NULL,
                  first_round INTEGER NOT NULL,
                  PRIMARY KEY(network_id,epoch,height,vote_type,validator_id)
                );
                CREATE TABLE IF NOT EXISTS gcf2_finality_certificates (
                  network_id TEXT NOT NULL, epoch INTEGER NOT NULL,
                  height INTEGER NOT NULL, candidate_digest TEXT NOT NULL,
                  certificate_json TEXT NOT NULL, certificate_digest TEXT NOT NULL,
                  PRIMARY KEY(network_id,epoch,height),
                  UNIQUE(candidate_digest), UNIQUE(certificate_digest)
                );
                CREATE TABLE IF NOT EXISTS gcf2_polcs (
                  candidate_digest TEXT PRIMARY KEY,
                  network_id TEXT NOT NULL, epoch INTEGER NOT NULL,
                  height INTEGER NOT NULL, round INTEGER NOT NULL,
                  parent_hash TEXT NOT NULL, polc_json TEXT NOT NULL,
                  polc_digest TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL
                );
            """)

    def _connect(self):
        db = sqlite3.connect(self.database, timeout=15, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=15000")
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

    def _trusted_parent(self, height: int) -> str:
        try:
            parent = self.resolve_active_parent(height)
        except Exception as exc:
            raise GCFError("GCF2_ACTIVE_PARENT_UNAVAILABLE") from exc
        if not isinstance(parent, str) or len(parent) != 64:
            raise GCFError("GCF2_ACTIVE_PARENT_UNAVAILABLE")
        try:
            if len(bytes.fromhex(parent)) != 32:
                raise ValueError("length")
        except ValueError as exc:
            raise GCFError("GCF2_ACTIVE_PARENT_INVALID") from exc
        return parent.lower()

    def _proposal(self, digest: str) -> dict:
        with self.gcf1_engine._db() as db:
            proposal = self.gcf1_engine._proposal(db, digest)
        return proposal

    def _reject_cross_version_slot(self, db, vote: Mapping[str, Any]) -> None:
        # GCF/1 locks are height/phase/validator scoped. Rejecting across all
        # rounds is intentionally conservative and prevents version downgrade
        # or dual-domain signing for one logical height/phase.
        exists = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='vote_locks'"
        ).fetchone()
        if exists:
            row = db.execute(
                """SELECT 1 FROM vote_locks WHERE network_id=? AND epoch=?
                   AND height=? AND vote_type=? AND validator_id=? LIMIT 1""",
                (vote["network_id"], vote["epoch"], vote["height"],
                 vote["vote_type"], vote["validator_id"]),
            ).fetchone()
            if row:
                raise GCFError("GCF2_CROSS_VERSION_VOTE_SLOT_ALREADY_USED")

    def submit_vote(self, vote: Mapping[str, Any]) -> dict:
        if not isinstance(vote, Mapping):
            raise GCFError("GCF2_VOTE_FIELDS_INVALID")
        candidate_digest = vote.get("candidate_digest")
        proposal = None
        if vote.get("vote_kind") == "CANDIDATE":
            if not isinstance(candidate_digest, str):
                raise GCFError("GCF2_CANDIDATE_DIGEST_REQUIRED")
            proposal = self._proposal(candidate_digest)
        normalized = verify_vote(
            vote, validator_set=self.validator_set, clock=self.clock,
            proposal=proposal,
        )
        active_parent = self._trusted_parent(normalized["height"])
        if normalized["parent_hash"] != active_parent:
            raise GCFError("GCF2_ACTIVE_PARENT_MISMATCH")
        if proposal is not None and proposal.get("parent_hash") != active_parent:
            raise GCFError("GCF2_CANDIDATE_PARENT_NOT_ACTIVE")

        vote_digest = sha256_hex(VOTE_DOMAIN + canonical_bytes(normalized))
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                self._reject_cross_version_slot(db, normalized)
                finalized = db.execute(
                    """SELECT candidate_digest FROM gcf2_finality_certificates
                       WHERE network_id=? AND epoch=? AND height=? LIMIT 1""",
                    (normalized["network_id"], normalized["epoch"], normalized["height"]),
                ).fetchone()
                if finalized is not None:
                    raise GCFError("GCF2_HEIGHT_ALREADY_FINALIZED")
                gcf1_finalized = db.execute(
                    """SELECT 1 FROM certificates c JOIN proposals p
                       ON p.candidate_digest=c.candidate_digest
                       WHERE p.network_id=? AND p.epoch=? AND p.height=? LIMIT 1""",
                    (normalized["network_id"], normalized["epoch"], normalized["height"]),
                ).fetchone()
                if gcf1_finalized is not None:
                    raise GCFError("GCF2_GCF1_HEIGHT_ALREADY_FINALIZED")
                round_state = db.execute(
                    """SELECT highest_round FROM gcf2_validator_rounds
                       WHERE network_id=? AND epoch=? AND height=? AND validator_id=?""",
                    (normalized["network_id"], normalized["epoch"],
                     normalized["height"], normalized["validator_id"]),
                ).fetchone()
                if round_state is not None and normalized["round"] < round_state["highest_round"]:
                    raise GCFError("GCF2_VOTE_ROUND_REGRESSION")
                if round_state is None:
                    db.execute(
                        "INSERT INTO gcf2_validator_rounds VALUES(?,?,?,?,?)",
                        (normalized["network_id"], normalized["epoch"],
                         normalized["height"], normalized["validator_id"],
                         normalized["round"]),
                    )
                elif normalized["round"] > round_state["highest_round"]:
                    db.execute(
                        """UPDATE gcf2_validator_rounds SET highest_round=?
                           WHERE network_id=? AND epoch=? AND height=? AND validator_id=?""",
                        (normalized["round"], normalized["network_id"],
                         normalized["epoch"], normalized["height"],
                         normalized["validator_id"]),
                    )
                slot = db.execute(
                    """SELECT vote_digest FROM gcf2_vote_slots
                       WHERE network_id=? AND epoch=? AND height=? AND round=?
                         AND vote_type=? AND validator_id=?""",
                    (normalized["network_id"], normalized["epoch"],
                     normalized["height"], normalized["round"],
                     normalized["vote_type"], normalized["validator_id"]),
                ).fetchone()
                if slot is not None:
                    if slot["vote_digest"] == vote_digest:
                        raise GCFError("GCF2_DUPLICATE_VOTE_SLOT")
                    raise GCFError("GCF2_EQUIVOCATION_SLOT_CONFLICT")

                if normalized["vote_kind"] == "CANDIDATE":
                    lock = db.execute(
                        """SELECT candidate_digest FROM gcf2_candidate_locks
                           WHERE network_id=? AND epoch=? AND height=?
                             AND vote_type=? AND validator_id=?""",
                        (normalized["network_id"], normalized["epoch"],
                         normalized["height"], normalized["vote_type"],
                         normalized["validator_id"]),
                    ).fetchone()
                    if lock is not None and lock["candidate_digest"] != candidate_digest:
                        raise GCFError("GCF2_CANDIDATE_LOCK_CONFLICT")
                    if lock is None:
                        db.execute(
                            """INSERT INTO gcf2_candidate_locks
                               VALUES(?,?,?,?,?,?,?)""",
                            (normalized["network_id"], normalized["epoch"],
                             normalized["height"], normalized["vote_type"],
                             normalized["validator_id"], candidate_digest,
                             normalized["round"]),
                        )

                if (normalized["vote_kind"] == "CANDIDATE"
                        and normalized["vote_type"] == "PRECOMMIT"
                        and normalized["approve"] is True):
                    polc = db.execute(
                        "SELECT polc_digest FROM gcf2_polcs WHERE candidate_digest=?",
                        (candidate_digest,),
                    ).fetchone()
                    if polc is None or polc["polc_digest"] != normalized["polc_digest"]:
                        raise GCFError("GCF2_PRECOMMIT_POLC_NOT_VERIFIED")

                db.execute(
                    """INSERT INTO gcf2_vote_slots
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (normalized["network_id"], normalized["epoch"],
                     normalized["height"], normalized["round"],
                     normalized["vote_type"], normalized["validator_id"],
                     normalized["vote_kind"], candidate_digest,
                     normalized["parent_hash"],
                     canonical_bytes(normalized).decode("utf-8"), vote_digest),
                )
                polc_result = None
                if (normalized["vote_kind"] == "CANDIDATE"
                        and normalized["vote_type"] == "PREVOTE"
                        and normalized["approve"] is True):
                    polc_result = self._maybe_build_polc(db, proposal)
                finality_result = None
                if (normalized["vote_kind"] == "CANDIDATE"
                        and normalized["vote_type"] == "PRECOMMIT"
                        and normalized["approve"] is True):
                    finality_result = self._maybe_build_finality(db, proposal)
                db.execute("COMMIT")
            except Exception:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
        return {
            "accepted": True, "schema": SCHEMA,
            "vote_kind": normalized["vote_kind"],
            "vote_type": normalized["vote_type"],
            "vote_digest": vote_digest,
            "polc": polc_result, "finality": finality_result,
        }

    def _maybe_build_polc(self, db, proposal: Mapping[str, Any]) -> dict | None:
        from src.consensus.gcf import sha256_hex as digest_hex
        candidate_digest = digest_hex(canonical_bytes(proposal))
        rows = db.execute(
            """SELECT vote_json FROM gcf2_vote_slots
               WHERE network_id=? AND epoch=? AND height=? AND round=?
                 AND vote_type='PREVOTE' AND vote_kind='CANDIDATE'
                 AND candidate_digest=?""",
            (proposal["network_id"], proposal["epoch"], proposal["height"],
             proposal["round"], candidate_digest),
        ).fetchall()
        votes = [json.loads(row["vote_json"]) for row in rows]
        affirmative = [v for v in votes if v["approve"] is True]
        weight = self.validator_set.weight_of({v["validator_id"] for v in affirmative})
        if weight < self.validator_set.quorum_weight():
            return None
        affirmative.sort(key=lambda item: item["validator_id"])
        body = {
            "schema": SCHEMA, "network_id": proposal["network_id"],
            "epoch": proposal["epoch"], "height": proposal["height"],
            "round": proposal["round"], "parent_hash": proposal["parent_hash"],
            "candidate_digest": candidate_digest,
            "validator_set_hash": self.validator_set.digest,
            "prevotes": affirmative,
        }
        polc_digest = sha256_hex(POLC_DOMAIN + canonical_bytes(body))
        record = {**body, "polc_digest": polc_digest}
        db.execute(
            """INSERT OR IGNORE INTO gcf2_polcs
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (candidate_digest, body["network_id"], body["epoch"],
             body["height"], body["round"], body["parent_hash"],
             canonical_bytes(record).decode("utf-8"), polc_digest,
             int(self.clock())),
        )
        stored = db.execute(
            "SELECT polc_digest,polc_json FROM gcf2_polcs WHERE candidate_digest=?",
            (candidate_digest,),
        ).fetchone()
        if stored["polc_digest"] != polc_digest:
            raise GCFError("GCF2_POLC_CONFLICT")
        return {"polc_digest": polc_digest, "weight": weight,
                "quorum_weight": self.validator_set.quorum_weight()}

    def get_polc(self, candidate_digest: str) -> dict | None:
        with self._db() as db:
            row = db.execute(
                "SELECT polc_json FROM gcf2_polcs WHERE candidate_digest=?",
                (candidate_digest,),
            ).fetchone()
        return json.loads(row["polc_json"]) if row else None


    def _maybe_build_finality(self, db, proposal: Mapping[str, Any]) -> dict | None:
        candidate_digest = sha256_hex(canonical_bytes(proposal))
        rows = db.execute(
            """SELECT vote_json FROM gcf2_vote_slots
               WHERE network_id=? AND epoch=? AND height=? AND round=?
                 AND vote_type='PRECOMMIT' AND vote_kind='CANDIDATE'
                 AND candidate_digest=?""",
            (proposal["network_id"], proposal["epoch"], proposal["height"],
             proposal["round"], candidate_digest),
        ).fetchall()
        precommits = [json.loads(row["vote_json"]) for row in rows]
        precommits = [vote for vote in precommits if vote["approve"] is True]
        weight = self.validator_set.weight_of({v["validator_id"] for v in precommits})
        if weight < self.validator_set.quorum_weight():
            return None
        precommits.sort(key=lambda item: item["validator_id"])
        polc_row = db.execute(
            "SELECT polc_json FROM gcf2_polcs WHERE candidate_digest=?",
            (candidate_digest,),
        ).fetchone()
        if polc_row is None:
            raise GCFError("GCF2_FINALITY_POLC_MISSING")
        polc = json.loads(polc_row["polc_json"])
        finalized_at = int(self.clock())
        if self._trusted_parent(proposal["height"]) != proposal["parent_hash"]:
            raise GCFError("GCF2_FINALITY_PARENT_NOT_ACTIVE")
        body = {
            "schema": SCHEMA, "network_id": proposal["network_id"],
            "epoch": proposal["epoch"], "height": proposal["height"],
            "round": proposal["round"], "parent_hash": proposal["parent_hash"],
            "candidate_digest": candidate_digest,
            "validator_set_hash": self.validator_set.digest,
            "proposal": dict(proposal),
            "finalized_at": finalized_at, "polc": polc,
            "precommits": precommits,
        }
        certificate_digest = sha256_hex(CERT_DOMAIN + canonical_bytes(body))
        certificate = {**body, "certificate_digest": certificate_digest}

        validators = {
            validator_id: {
                "public_key_hex": validator.public_key_hex,
                "weight": validator.weight,
            }
            for validator_id, validator in self.validator_set.validators.items()
        }
        from src.consensus.gcf2_independent_verifier import verify_finality_certificate
        checked = verify_finality_certificate(
            certificate, network_id=self.validator_set.network_id,
            epoch=self.validator_set.epoch, validators=validators,
            proposal=proposal,
        )
        if not checked.get("valid"):
            raise GCFError("GCF2_INDEPENDENT_FINALITY_VERIFICATION_FAILED")

        gcf1_exists = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='certificates'"
        ).fetchone()
        if gcf1_exists:
            conflict = db.execute(
                """SELECT 1 FROM certificates c JOIN proposals p
                   ON p.candidate_digest=c.candidate_digest
                   WHERE p.network_id=? AND p.epoch=? AND p.height=? LIMIT 1""",
                (proposal["network_id"], proposal["epoch"], proposal["height"]),
            ).fetchone()
            if conflict is not None:
                raise GCFError("GCF2_GCF1_FINALITY_CONFLICT")
        existing = db.execute(
            """SELECT candidate_digest,certificate_digest
               FROM gcf2_finality_certificates
               WHERE network_id=? AND epoch=? AND height=?""",
            (proposal["network_id"], proposal["epoch"], proposal["height"]),
        ).fetchone()
        if existing is not None:
            if (existing["candidate_digest"] != candidate_digest
                    or existing["certificate_digest"] != certificate_digest):
                raise GCFError("GCF2_FINALITY_CONFLICT")
            return {"certificate_digest": certificate_digest,
                    "precommit_weight": weight, "replayed": True}
        db.execute(
            """INSERT INTO gcf2_finality_certificates
               VALUES(?,?,?,?,?,?)""",
            (proposal["network_id"], proposal["epoch"], proposal["height"],
             candidate_digest, canonical_bytes(certificate).decode("utf-8"),
             certificate_digest),
        )
        return {"certificate_digest": certificate_digest,
                "precommit_weight": weight, "replayed": False}

    def get_finality_certificate(self, *, height: int) -> dict | None:
        with self._db() as db:
            row = db.execute(
                """SELECT certificate_json FROM gcf2_finality_certificates
                   WHERE network_id=? AND epoch=? AND height=?""",
                (self.validator_set.network_id, self.validator_set.epoch, height),
            ).fetchone()
        return json.loads(row["certificate_json"]) if row else None
