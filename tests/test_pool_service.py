import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.consensus.pool_ledger import PoolShareLedger
from src.mining.pool_service import PoolCoordinator, PoolServiceError
from src.mining.pool_worker import execute_pool_job


class PoolCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        private = Ed25519PrivateKey.generate()
        self.private_hex = private.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption()
        ).hex()
        self.public_hex = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        self.now = 1000
        self.ledger = PoolShareLedger(self.root / "shares.sqlite3")
        self.pool = PoolCoordinator(
            database=self.root / "jobs.sqlite3",
            share_ledger=self.ledger,
            issuer_private_key_hex=self.private_hex,
            issuer_id="issuer", pool_id="gaia-internal",
            network_id="hccgn-test",
            trusted_issuer_public_key_hex=self.public_hex,
            resolve_active_target=lambda boundary: b"\xff" * 32,
            clock=lambda: self.now,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def issue(self):
        return self.pool.issue_job(
            worker_id="worker-a", height=1, epoch=1, lifetime_seconds=120,
            parent_hash="00" * 32, payload_hash="11" * 32,
            primary_stride=3037, compact_stride=5,
            nonce_start=0, max_attempts=8,
        )

    def test_issue_submit_and_measure_durable_state(self):
        job = self.issue()
        submission = execute_pool_job(
            job, trusted_issuer_public_key_hex=self.public_hex,
            expected_issuer_id="issuer", expected_pool_id="gaia-internal",
            expected_network_id="hccgn-test", worker_id="worker-a", now=self.now,
        )
        result = self.pool.submit_share(
            submission, authenticated_worker_id="worker-a"
        )
        self.assertTrue(result["accepted"])
        self.assertEqual(result["worker_id"], "worker-a")
        status = self.pool.status()
        self.assertTrue(status["healthy"])
        self.assertEqual(status["jobs_active"], 1)
        self.assertEqual(status["shares_accepted"], 1)

    def test_revoked_job_cannot_submit(self):
        job = self.issue()
        submission = execute_pool_job(
            job, trusted_issuer_public_key_hex=self.public_hex,
            expected_issuer_id="issuer", expected_pool_id="gaia-internal",
            expected_network_id="hccgn-test", worker_id="worker-a", now=self.now,
        )
        self.assertTrue(self.pool.revoke_job(job["job_id"]))
        with self.assertRaisesRegex(PoolServiceError, "job_revoked"):
            self.pool.submit_share(submission, authenticated_worker_id="worker-a")

    def test_transport_identity_must_match_submission(self):
        job = self.issue()
        submission = execute_pool_job(
            job, trusted_issuer_public_key_hex=self.public_hex,
            expected_issuer_id="issuer", expected_pool_id="gaia-internal",
            expected_network_id="hccgn-test", worker_id="worker-a", now=self.now,
        )
        with self.assertRaisesRegex(PoolServiceError, "worker_identity"):
            self.pool.submit_share(submission, authenticated_worker_id="worker-b")

    def test_policy_unavailable_fails_job_issuance(self):
        self.pool.resolve_active_target = lambda boundary: None
        with self.assertRaisesRegex(PoolServiceError, "active_target_unavailable"):
            self.issue()


if __name__ == "__main__":
    unittest.main()
