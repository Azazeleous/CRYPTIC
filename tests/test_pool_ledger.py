import tempfile,unittest
from pathlib import Path
from src.consensus.pool_ledger import PoolLedgerError,PoolShareLedger

class PoolLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.ledger=PoolShareLedger(Path(self.tmp.name)/"pool.sqlite3")
        self.share={"accepted":True,"share_id":"a"*64,"network_id":"hccgn-test","pool_id":"gaia-internal","job_id":"b"*32,"worker_id":"worker-a","proof_hash":"c"*64,"work_digest":"d"*64,"nonce":7,"accepted_at":1002}
    def tearDown(self): self.tmp.cleanup()
    def test_records_verified_share_and_verifies_event_chain(self):
        result=self.ledger.record_accepted_share(self.share)
        self.assertTrue(result["recorded"])
        self.assertTrue(self.ledger.verify_chain())
        self.assertEqual(len(self.ledger.list_shares("worker-a")),1)
    def test_duplicate_proof_is_rejected(self):
        self.ledger.record_accepted_share(self.share)
        with self.assertRaisesRegex(PoolLedgerError,"replay"):
            self.ledger.record_accepted_share(self.share)
    def test_unverified_share_cannot_be_recorded(self):
        changed=dict(self.share); changed["accepted"]=False
        with self.assertRaisesRegex(PoolLedgerError,"verified"):
            self.ledger.record_accepted_share(changed)
    def test_event_rows_are_immutable_through_database_api(self):
        self.ledger.record_accepted_share(self.share)
        import sqlite3
        with sqlite3.connect(self.ledger.database) as conn:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("DELETE FROM pool_events")
    def test_tampered_event_chain_is_detected(self):
        self.ledger.record_accepted_share(self.share)
        import sqlite3
        with sqlite3.connect(self.ledger.database) as conn:
            conn.execute("DROP TRIGGER pool_events_no_update")
            conn.execute("UPDATE pool_events SET event_json=? WHERE event_id=1",(b"{}",))
        self.assertFalse(self.ledger.verify_chain())

if __name__=="__main__": unittest.main()
