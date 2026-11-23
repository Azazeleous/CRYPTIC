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

    def issue(self, **overrides):
        params = {
            "worker_id": "worker-a", "height": 1, "epoch": 1,
            "lifetime_seconds": 120, "parent_hash": "00" * 32,
            "payload_hash": "11" * 32, "primary_stride": 3037,
            "compact_stride": 5, "nonce_start": 0, "max_attempts": 8,
        }
        params.update(overrides)
        return self.pool.issue_job(**params)

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
        with self.assertRaisesRegex(PoolServiceError, "not_assigned_to_worker"):
            self.pool.submit_share(submission, authenticated_worker_id="worker-b")

    def test_job_is_only_retrievable_by_assigned_worker(self):
        job = self.issue()
        with self.assertRaisesRegex(PoolServiceError, "not_assigned_to_worker"):
            self.pool.get_job(job["job_id"], authenticated_worker_id="worker-b")
        self.assertEqual(
            self.pool.get_job(job["job_id"], authenticated_worker_id="worker-a")["job_id"],
            job["job_id"],
        )

    def test_policy_unavailable_fails_job_issuance(self):
        self.pool.resolve_active_target = lambda boundary: None
        with self.assertRaisesRegex(PoolServiceError, "active_target_unavailable"):
            self.issue()

    def test_overlapping_nonce_ranges_are_rejected_across_workers(self):
        self.issue(worker_id="worker-a", nonce_start=0, max_attempts=8)
        with self.assertRaisesRegex(PoolServiceError, "nonce_range_overlap"):
            self.issue(worker_id="worker-b", nonce_start=4, max_attempts=8)
        disjoint = self.issue(worker_id="worker-b", nonce_start=8, max_attempts=8)
        self.assertEqual(disjoint["nonce_start"], 8)

    def test_revoked_job_does_not_release_its_nonce_range(self):
        first = self.issue()
        self.pool.revoke_job(first["job_id"])
        with self.assertRaisesRegex(PoolServiceError, "nonce_range_overlap"):
            self.issue(worker_id="worker-b", nonce_start=0, max_attempts=8)

    def test_expired_job_transitions_durably_and_survives_restart(self):
        job = self.issue()
        self.now = job["expires_at"] + 1
        self.assertEqual(self.pool.expire_jobs(), 1)
        status = self.pool.status()
        self.assertEqual(status["jobs_expired"], 1)
        self.assertEqual(status["jobs_active"], 0)
        restarted = PoolCoordinator(
            database=self.root / "jobs.sqlite3",
            share_ledger=self.ledger,
            issuer_private_key_hex=self.private_hex,
            issuer_id="issuer", pool_id="gaia-internal",
            network_id="hccgn-test",
            trusted_issuer_public_key_hex=self.public_hex,
            resolve_active_target=lambda boundary: b"\xff" * 32,
            clock=lambda: self.now,
        )
        self.assertEqual(restarted.status()["jobs_expired"], 1)
        with self.assertRaisesRegex(PoolServiceError, "job_expired"):
            restarted.get_job(job["job_id"], authenticated_worker_id="worker-a")

    def test_expired_job_cannot_accept_a_late_share(self):
        job = self.issue()
        submission = execute_pool_job(
            job, trusted_issuer_public_key_hex=self.public_hex,
            expected_issuer_id="issuer", expected_pool_id="gaia-internal",
            expected_network_id="hccgn-test", worker_id="worker-a", now=self.now,
        )
        self.now = job["expires_at"] + 1
        with self.assertRaisesRegex(PoolServiceError, "job_expired"):
            self.pool.submit_share(submission, authenticated_worker_id="worker-a")

    def test_committed_share_retry_recovers_after_job_expiry(self):
        job = self.issue()
        submission = execute_pool_job(
            job, trusted_issuer_public_key_hex=self.public_hex,
            expected_issuer_id="issuer", expected_pool_id="gaia-internal",
            expected_network_id="hccgn-test", worker_id="worker-a", now=self.now,
        )
        first = self.pool.submit_share(
            submission, authenticated_worker_id="worker-a"
        )
        self.now = job["expires_at"] + 1
        retry = self.pool.submit_share(
            submission, authenticated_worker_id="worker-a"
        )
        self.assertTrue(retry["accepted"])
        self.assertTrue(retry["replayed"])
        self.assertEqual(retry["share_id"], first["share_id"])
        self.assertEqual(retry["event_hash"], first["event_hash"])
        self.assertTrue(self.ledger.verify_chain())

    def test_nonce_reservations_support_full_uint64_boundary(self):
        start = (1 << 64) - 8
        job = self.issue(nonce_start=start, max_attempts=8)
        self.assertEqual(job["nonce_start"], start)
        self.assertEqual(job["nonce_start"] + job["max_attempts"], 1 << 64)


if __name__ == "__main__":
    unittest.main()
