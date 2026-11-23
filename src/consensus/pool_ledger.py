"""Durable append-only API ledger for independently accepted pool shares."""
from __future__ import annotations
import hashlib, json, os, re, sqlite3
from pathlib import Path
from typing import Any, Mapping

ZERO_HASH="0"*64
HEX32=re.compile(r"^[0-9a-f]{64}$")
REQUIRED={"accepted","share_id","network_id","pool_id","job_id","worker_id","proof_hash","work_digest","nonce","accepted_at"}

class PoolLedgerError(ValueError):
    """A pool share cannot be safely committed or the journal failed verification."""

def _canonical(value:Mapping[str,Any])->bytes:
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")

def _connect(path:str)->sqlite3.Connection:
    conn=sqlite3.connect(path,timeout=10.0,isolation_level=None)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    return conn

class PoolShareLedger:
    """Persist verified shares with a hash-chained event journal and replay guard.

    This records accepted work, not transferable balances or external payouts.
    The API is append-only; filesystem/database administrators remain outside
    the protection provided by SQLite triggers and must protect backups.
    """
    def __init__(self,database:str|os.PathLike[str]):
        path=Path(database).expanduser()
        if str(path)==":memory:": raise PoolLedgerError("persistent_database_required")
        path.parent.mkdir(parents=True,exist_ok=True)
        if path.exists() and path.is_symlink(): raise PoolLedgerError("database_symlink_forbidden")
        self.database=str(path)
        with _connect(self.database) as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS pool_events(
              event_id INTEGER PRIMARY KEY AUTOINCREMENT,
              event_type TEXT NOT NULL,
              event_json BLOB NOT NULL,
              previous_hash TEXT NOT NULL CHECK(length(previous_hash)=64),
              event_hash TEXT NOT NULL UNIQUE CHECK(length(event_hash)=64)
            );
            CREATE TABLE IF NOT EXISTS pool_shares(
              share_id TEXT PRIMARY KEY,
              network_id TEXT NOT NULL,
              pool_id TEXT NOT NULL,
              job_id TEXT NOT NULL,
              worker_id TEXT NOT NULL,
              proof_hash TEXT NOT NULL UNIQUE,
              work_digest TEXT NOT NULL,
              nonce INTEGER NOT NULL CHECK(nonce>=0),
              accepted_at INTEGER NOT NULL CHECK(accepted_at>=0),
              event_hash TEXT NOT NULL UNIQUE REFERENCES pool_events(event_hash)
            );
            CREATE TRIGGER IF NOT EXISTS pool_events_no_update
              BEFORE UPDATE ON pool_events BEGIN SELECT RAISE(ABORT,'pool_event_immutable'); END;
            CREATE TRIGGER IF NOT EXISTS pool_events_no_delete
              BEFORE DELETE ON pool_events BEGIN SELECT RAISE(ABORT,'pool_event_immutable'); END;
            CREATE TRIGGER IF NOT EXISTS pool_shares_no_update
              BEFORE UPDATE ON pool_shares BEGIN SELECT RAISE(ABORT,'pool_share_immutable'); END;
            CREATE TRIGGER IF NOT EXISTS pool_shares_no_delete
              BEFORE DELETE ON pool_shares BEGIN SELECT RAISE(ABORT,'pool_share_immutable'); END;
            """)
        try: os.chmod(self.database,0o600)
        except OSError as exc: raise PoolLedgerError("database_permissions_failed") from exc

    def record_accepted_share(self,share:Mapping[str,Any])->dict:
        if not isinstance(share,Mapping) or not REQUIRED.issubset(share) or share.get("accepted") is not True:
            raise PoolLedgerError("independently_verified_share_required")
        record={key:share[key] for key in REQUIRED if key!="accepted"}
        for key in ("share_id","network_id","pool_id","job_id","worker_id","proof_hash","work_digest"):
            if not isinstance(record[key],str) or not record[key]: raise PoolLedgerError(key+"_invalid")
        for key in ("proof_hash","work_digest"):
            if not HEX32.fullmatch(record[key]): raise PoolLedgerError(key+"_invalid")
        nonce,accepted_at=record["nonce"],record["accepted_at"]
        if isinstance(nonce,bool) or not isinstance(nonce,int) or nonce<0: raise PoolLedgerError("nonce_invalid")
        if isinstance(accepted_at,bool) or not isinstance(accepted_at,int) or accepted_at<0: raise PoolLedgerError("accepted_at_invalid")
        conn=_connect(self.database)
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                """SELECT share_id,network_id,pool_id,job_id,worker_id,proof_hash,
                          work_digest,nonce,event_hash
                   FROM pool_shares WHERE proof_hash=?""",
                (record["proof_hash"],),
            ).fetchone()
            if existing is not None:
                expected = (
                    record["share_id"], record["network_id"], record["pool_id"],
                    record["job_id"], record["worker_id"], record["proof_hash"],
                    record["work_digest"], nonce,
                )
                if tuple(existing[:8]) == expected:
                    conn.execute("COMMIT")
                    return {
                        "recorded": True, "replayed": True,
                        "event_hash": existing[8], "share_id": record["share_id"],
                    }
                raise PoolLedgerError("share_replay")
            row=conn.execute("SELECT event_hash FROM pool_events ORDER BY event_id DESC LIMIT 1").fetchone()
            previous=row[0] if row else ZERO_HASH
            event={"event_type":"pool.share.accepted","share":record}
            encoded=_canonical(event)
            event_hash=hashlib.sha256(bytes.fromhex(previous)+encoded).hexdigest()
            conn.execute("INSERT INTO pool_events(event_type,event_json,previous_hash,event_hash) VALUES(?,?,?,?)",("pool.share.accepted",encoded,previous,event_hash))
            conn.execute("""INSERT INTO pool_shares
              (share_id,network_id,pool_id,job_id,worker_id,proof_hash,work_digest,nonce,accepted_at,event_hash)
              VALUES(?,?,?,?,?,?,?,?,?,?)""",
              (record["share_id"],record["network_id"],record["pool_id"],record["job_id"],record["worker_id"],record["proof_hash"],record["work_digest"],nonce,accepted_at,event_hash))
            conn.execute("COMMIT")
            return {"recorded":True,"event_hash":event_hash,"share_id":record["share_id"]}
        except PoolLedgerError:
            if conn.in_transaction: conn.execute("ROLLBACK")
            raise
        except sqlite3.IntegrityError as exc:
            if conn.in_transaction: conn.execute("ROLLBACK")
            raise PoolLedgerError("share_replay_or_integrity_conflict") from exc
        except Exception:
            if conn.in_transaction: conn.execute("ROLLBACK")
            raise
        finally: conn.close()

    def verify_chain(self)->bool:
        """Verify event hashes and one-to-one correspondence with share rows."""
        with _connect(self.database) as conn:
            events=conn.execute(
                "SELECT event_type,event_json,previous_hash,event_hash FROM pool_events ORDER BY event_id"
            ).fetchall()
            shares=conn.execute(
                "SELECT share_id,network_id,pool_id,job_id,worker_id,proof_hash,work_digest,nonce,accepted_at,event_hash FROM pool_shares"
            ).fetchall()
        if len(events)!=len(shares):
            return False
        by_event={row[9]:row[:9] for row in shares}
        previous=ZERO_HASH
        required=REQUIRED-{"accepted"}
        for event_type,encoded,stored_previous,stored_hash in events:
            raw=bytes(encoded)
            if stored_previous!=previous or hashlib.sha256(bytes.fromhex(previous)+raw).hexdigest()!=stored_hash:
                return False
            try:
                event=json.loads(raw.decode("ascii"))
            except (UnicodeDecodeError,ValueError,TypeError):
                return False
            try:
                canonical_event=_canonical(event)
            except (TypeError,ValueError):
                return False
            if canonical_event!=raw or set(event)!={"event_type","share"}:
                return False
            if event_type!="pool.share.accepted" or event.get("event_type")!=event_type:
                return False
            record=event.get("share")
            if not isinstance(record,dict) or set(record)!=required:
                return False
            row=by_event.get(stored_hash)
            if row is None:
                return False
            fields=("share_id","network_id","pool_id","job_id","worker_id",
                    "proof_hash","work_digest","nonce","accepted_at")
            if tuple(record[key] for key in fields)!=tuple(row):
                return False
            previous=stored_hash
        return True

    def get_share(self, *, share_id: str, proof_hash: str) -> dict | None:
        """Look up an already committed share for safe idempotent request recovery."""
        with _connect(self.database) as conn:
            row = conn.execute(
                """SELECT share_id,network_id,pool_id,job_id,worker_id,proof_hash,
                          work_digest,nonce,accepted_at,event_hash
                   FROM pool_shares WHERE share_id=? AND proof_hash=?""",
                (share_id, proof_hash),
            ).fetchone()
        if row is None:
            return None
        keys = ("share_id","network_id","pool_id","job_id","worker_id",
                "proof_hash","work_digest","nonce","accepted_at","event_hash")
        return dict(zip(keys, row))

    def list_shares(self,worker_id:str|None=None)->list[dict]:
        with _connect(self.database) as conn:
            if worker_id is None:
                rows=conn.execute("SELECT share_id,network_id,pool_id,job_id,worker_id,proof_hash,work_digest,nonce,accepted_at,event_hash FROM pool_shares ORDER BY accepted_at,share_id").fetchall()
            else:
                rows=conn.execute("SELECT share_id,network_id,pool_id,job_id,worker_id,proof_hash,work_digest,nonce,accepted_at,event_hash FROM pool_shares WHERE worker_id=? ORDER BY accepted_at,share_id",(worker_id,)).fetchall()
        keys=("share_id","network_id","pool_id","job_id","worker_id","proof_hash","work_digest","nonce","accepted_at","event_hash")
        return [dict(zip(keys,row)) for row in rows]
