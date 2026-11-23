"""Durable, certificate-gated GCF round progression controller.

The host scheduler calls poll_timeout(); this module creates a durable
round-change intent but never signs, advances, unlocks, or selects a proposal.
A round advances only after a current-validator-set certificate is verified
and explicitly activated. GCFEngine remains the final vote-admission guard.
"""
from __future__ import annotations

import json
import math
import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Mapping

from src.consensus.gcf import GCFError, canonical_bytes
from src.consensus.pacemaker import (
    MAX_ROUND, PacemakerError, timeout_event,
)
from src.consensus.round_change import verify_round_change_certificate


class RoundProgressionError(ValueError):
    """Invalid or unsafe round progression request."""


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= MAX_ROUND:
        raise RoundProgressionError(label + "_invalid")
    return value


class RoundProgressionController:
    """Coordinates local timeout intents and verified certificate activation.

    Monotonic timer origins are intentionally process-local. On restart the
    operator/runtime must arm the current round again; an already persisted
    pending timeout intent is returned immediately and remains actionable.
    """

    def __init__(self, *, engine: Any, database: str | os.PathLike[str],
                 monotonic: Callable[[], float]):
        if engine is None or not hasattr(engine, "validator_set") or not callable(monotonic):
            raise RoundProgressionError("engine_and_monotonic_clock_required")
        self.engine = engine
        self.database = str(database)
        self.monotonic = monotonic
        self._lock = threading.RLock()
        self._armed: dict[int, tuple[int, float]] = {}
        Path(self.database).parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS progression_state(
                    network_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    height INTEGER NOT NULL,
                    current_round INTEGER NOT NULL,
                    certificate_digest TEXT,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY(network_id,epoch,height)
                );
                CREATE TABLE IF NOT EXISTS timeout_intents(
                    network_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    height INTEGER NOT NULL,
                    source_round INTEGER NOT NULL,
                    target_round INTEGER NOT NULL,
                    timeout_seconds INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('PENDING','ACKNOWLEDGED')),
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY(network_id,epoch,height,source_round)
                );
                CREATE TABLE IF NOT EXISTS progression_certificates(
                    network_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    height INTEGER NOT NULL,
                    target_round INTEGER NOT NULL,
                    certificate_json TEXT NOT NULL,
                    certificate_digest TEXT NOT NULL,
                    PRIMARY KEY(network_id,epoch,height,target_round)
                );
            """)
        try:
            os.chmod(self.database, 0o600)
        except OSError as exc:
            raise RoundProgressionError("progression_database_permissions_failed") from exc

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.database, timeout=15, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=15000")
        try:
            yield db
        finally:
            db.close()

    @property
    def _network(self):
        return self.engine.validator_set.network_id

    @property
    def _epoch(self):
        return self.engine.validator_set.epoch

    def _state(self, db, height: int):
        row = db.execute(
            """SELECT current_round,certificate_digest FROM progression_state
               WHERE network_id=? AND epoch=? AND height=?""",
            (self._network, self._epoch, height),
        ).fetchone()
        if row is None:
            db.execute(
                """INSERT INTO progression_state
                   VALUES(?,?,?,?,NULL,?)""",
                (self._network, self._epoch, height, 0, int(self.engine.clock())),
            )
            return 0, None
        return row["current_round"], row["certificate_digest"]

    def current_round(self, height: int) -> int:
        height = _integer(height, "height", 1)
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                current, _ = self._state(db, height)
                db.execute("COMMIT")
                return current
            except Exception:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise

    def arm(self, *, height: int, round_number: int | None = None,
            started_monotonic: float | None = None) -> dict:
        height = _integer(height, "height", 1)
        with self._lock:
            current = self.current_round(height)
            selected = current if round_number is None else _integer(round_number, "round")
            if selected != current:
                raise RoundProgressionError("cannot_arm_non_current_round")
            started = self.monotonic() if started_monotonic is None else started_monotonic
            if (isinstance(started, bool) or not isinstance(started, (int, float))
                    or not math.isfinite(started) or started < 0):
                raise RoundProgressionError("monotonic_start_invalid")
            self._armed[height] = (selected, float(started))
            return {"armed": True, "height": height, "round": selected}

    def poll_timeout(self, *, height: int, now_monotonic: float | None = None) -> dict | None:
        height = _integer(height, "height", 1)
        with self._lock:
            current = self.current_round(height)
            armed = self._armed.get(height)
            if armed is None or armed[0] != current:
                raise RoundProgressionError("current_round_not_armed")
            now = self.monotonic() if now_monotonic is None else now_monotonic
            try:
                event = timeout_event(
                    height=height, source_round=current,
                    started_monotonic=armed[1], now_monotonic=now,
                )
            except PacemakerError as exc:
                raise RoundProgressionError("timeout_clock_or_round_invalid") from exc
            if event is None:
                return None
            with self._db() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    db.execute(
                        """INSERT OR IGNORE INTO timeout_intents
                           VALUES(?,?,?,?,?,?, 'PENDING', ?)""",
                        (self._network, self._epoch, height, current,
                         event.target_round, event.timeout_seconds,
                         int(self.engine.clock())),
                    )
                    row = db.execute(
                        """SELECT target_round,timeout_seconds,status FROM timeout_intents
                           WHERE network_id=? AND epoch=? AND height=? AND source_round=?""",
                        (self._network, self._epoch, height, current),
                    ).fetchone()
                    db.execute("COMMIT")
                except Exception:
                    if db.in_transaction:
                        db.execute("ROLLBACK")
                    raise
            if row["status"] != "PENDING":
                return None
            return {
                "timeout_due": True, "height": height,
                "source_round": current, "target_round": row["target_round"],
                "timeout_seconds": row["timeout_seconds"],
                "action": "REQUEST_SIGNED_ROUND_CHANGE",
                "signing_authorized": False, "lock_released": False,
            }

    def acknowledge_timeout(self, *, height: int, source_round: int) -> bool:
        height = _integer(height, "height", 1)
        source_round = _integer(source_round, "source_round")
        with self._lock, self._db() as db:
            cursor = db.execute(
                """UPDATE timeout_intents SET status='ACKNOWLEDGED'
                   WHERE network_id=? AND epoch=? AND height=?
                     AND source_round=? AND status='PENDING'""",
                (self._network, self._epoch, height, source_round),
            )
            return cursor.rowcount == 1

    def activate_certificate(self, certificate: Mapping[str, Any], *, height: int) -> dict:
        height = _integer(height, "height", 1)
        if not isinstance(certificate, Mapping):
            raise RoundProgressionError("round_change_certificate_required")
        checked = verify_round_change_certificate(
            certificate, validator_set=self.engine.validator_set,
            height=height, clock=self.engine.clock,
        )
        if not checked.get("valid"):
            raise RoundProgressionError("round_change_certificate_invalid:" + str(checked.get("reason")))
        target = _integer(checked["target_round"], "target_round", 1)
        encoded = canonical_bytes(dict(certificate)).decode("ascii")
        digest = checked["digest"]
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                current, _ = self._state(db, height)
                if target != current + 1:
                    raise RoundProgressionError("certificate_must_advance_exactly_one_round")
                prior = db.execute(
                    """SELECT certificate_digest FROM progression_certificates
                       WHERE network_id=? AND epoch=? AND height=? AND target_round=?""",
                    (self._network, self._epoch, height, target),
                ).fetchone()
                if prior is not None and prior["certificate_digest"] != digest:
                    raise RoundProgressionError("conflicting_certificate_for_round")
                db.execute(
                    """INSERT OR IGNORE INTO progression_certificates
                       VALUES(?,?,?,?,?,?)""",
                    (self._network, self._epoch, height, target, encoded, digest),
                )
                db.execute(
                    """UPDATE progression_state SET current_round=?,certificate_digest=?,updated_at=?
                       WHERE network_id=? AND epoch=? AND height=?""",
                    (target, digest, int(self.engine.clock()),
                     self._network, self._epoch, height),
                )
                db.execute("COMMIT")
            except Exception:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
            self._armed.pop(height, None)
        return {
            "advanced": True, "height": height, "round": target,
            "certificate_digest": digest,
            "lock_released": False, "signing_authorized": False,
        }

    def get_certificate(self, *, height: int, target_round: int) -> dict | None:
        height = _integer(height, "height", 1)
        target_round = _integer(target_round, "target_round", 1)
        with self._db() as db:
            row = db.execute(
                """SELECT certificate_json,certificate_digest FROM progression_certificates
                   WHERE network_id=? AND epoch=? AND height=? AND target_round=?""",
                (self._network, self._epoch, height, target_round),
            ).fetchone()
        if row is None:
            return None
        certificate = json.loads(row["certificate_json"])
        checked = verify_round_change_certificate(
            certificate, validator_set=self.engine.validator_set,
            height=height, clock=self.engine.clock,
        )
        if not checked.get("valid") or checked["digest"] != row["certificate_digest"]:
            raise RoundProgressionError("persisted_certificate_failed_reverification")
        return certificate
