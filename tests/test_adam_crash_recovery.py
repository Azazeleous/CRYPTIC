"""Crash-recovery regression: kill a writer with an uncommitted WAL transaction.

This is process-crash evidence only. It does NOT simulate loss of power, volatile
controller caches, storage firmware failure, or filesystem corruption.
"""
import hashlib
import multiprocessing
import tempfile
import time
import unittest
from pathlib import Path

from src.adam.commit_store import AdamCommitStore


def _hold_uncommitted_transaction(database: str, ready) -> None:
    import sqlite3
    conn = sqlite3.connect(database, timeout=10, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("BEGIN IMMEDIATE")
    state = b"uncommitted-crash-probe"
    conn.execute(
        "INSERT INTO adam_commits VALUES(?,?,?,?,?,?,?)",
        (1, "a" * 64, "0" * 64, hashlib.sha256(state).hexdigest(),
         "b" * 64, state, "{}"),
    )
    ready.set()
    time.sleep(60)


class AdamCrashRecoveryTests(unittest.TestCase):
    def test_killed_uncommitted_writer_recovers_and_committed_state_reopens(self):
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "adam-crash.sqlite3")
            store = AdamCommitStore(database)
            context = multiprocessing.get_context("spawn")
            ready = context.Event()
            process = context.Process(
                target=_hold_uncommitted_transaction, args=(database, ready)
            )
            process.start()
            try:
                self.assertTrue(ready.wait(15), "writer did not reach open transaction")
                process.kill()
                process.join(10)
                self.assertFalse(process.is_alive(), "writer process did not terminate")
                self.assertEqual(store.verify_chain()["height"], 0)
            finally:
                if process.is_alive():
                    process.kill()
                    process.join(10)

            state = b"committed-after-crash"
            state_hash = hashlib.sha256(state).hexdigest()
            store.commit(
                height=1, candidate_digest="c" * 64, parent_hash="0" * 64,
                state_bytes=state, certificate_digest="d" * 64,
                receipt={"probe": "committed"},
            )
            reopened = AdamCommitStore(database)
            self.assertEqual(reopened.verify_chain()["height"], 1)
            self.assertEqual(reopened.get_commit(1)["state_hash"], state_hash)
            self.assertEqual(reopened.get_commit(1)["state_bytes"], state)


if __name__ == "__main__":
    unittest.main()
