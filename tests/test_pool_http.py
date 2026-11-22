import io
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.consensus.pool_ledger import PoolShareLedger
from src.mining.pool_http import PoolWSGI
from src.mining.pool_service import PoolCoordinator
from src.mining.pool_worker import execute_pool_job


class PoolWSGITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        key = Ed25519PrivateKey.generate()
        private_hex = key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption()
        ).hex()
        self.public_hex = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        self.now = 1000
        self.coordinator = PoolCoordinator(
            database=root / "jobs.sqlite3",
            share_ledger=PoolShareLedger(root / "shares.sqlite3"),
            issuer_private_key_hex=private_hex, issuer_id="issuer",
            pool_id="gaia-internal", network_id="hccgn-test",
            trusted_issuer_public_key_hex=self.public_hex,
            resolve_active_target=lambda boundary: b"\xff" * 32,
            clock=lambda: self.now,
        )
        self.job = self.coordinator.issue_job(
            worker_id="worker-a", height=1, epoch=1, lifetime_seconds=120,
            parent_hash="00" * 32, payload_hash="11" * 32,
            primary_stride=3037, compact_stride=5,
            nonce_start=0, max_attempts=8,
        )
        self.app = PoolWSGI(
            self.coordinator,
            worker_authenticator=lambda environ: environ["trusted.worker_id"],
        )

    def tearDown(self):
        self.tmp.cleanup()

    def request(self, method, path, body=None, *, worker="worker-a",
                content_type="application/json"):
        raw = body if isinstance(body, bytes) else (
            json.dumps(body, separators=(",", ":")).encode() if body is not None else b""
        )
        environ = {
            "REQUEST_METHOD": method, "PATH_INFO": path,
            "CONTENT_TYPE": content_type, "CONTENT_LENGTH": str(len(raw)),
            "wsgi.input": io.BytesIO(raw), "trusted.worker_id": worker,
            "HTTP_X_WORKER_ID": "attacker-controlled-value",
        }
        captured = {}
        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = headers
        payload = b"".join(self.app(environ, start_response))
        return captured["status"], json.loads(payload.decode("utf-8"))

    def test_authenticated_worker_can_fetch_active_job(self):
        status, payload = self.request("GET", "/v1/pool/jobs/" + self.job["job_id"])
        self.assertEqual(status, "200 OK")
        self.assertEqual(payload["job_id"], self.job["job_id"])

    def test_other_authenticated_worker_cannot_fetch_assigned_job(self):
        status, payload = self.request(
            "GET", "/v1/pool/jobs/" + self.job["job_id"], worker="worker-b"
        )
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(payload["error"], "job_not_assigned_to_worker")

    def test_submission_uses_authenticated_identity_not_header(self):
        submission = execute_pool_job(
            self.job, trusted_issuer_public_key_hex=self.public_hex,
            expected_issuer_id="issuer", expected_pool_id="gaia-internal",
            expected_network_id="hccgn-test", worker_id="worker-a", now=self.now,
        )
        status, payload = self.request("POST", "/v1/pool/shares", submission)
        self.assertEqual(status, "202 Accepted")
        self.assertTrue(payload["accepted"])

    def test_authentication_failure_is_401(self):
        app = PoolWSGI(self.coordinator, worker_authenticator=lambda _env: (_ for _ in ()).throw(ValueError()))
        environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/v1/pool/jobs/" + self.job["job_id"]}
        captured = {}
        body = b"".join(app(environ, lambda status, _headers: captured.update(status=status)))
        self.assertEqual(captured["status"], "401 Unauthorized")
        self.assertIn(b"WORKER_AUTHENTICATION_FAILED", body)

    def test_duplicate_json_keys_are_rejected(self):
        status, payload = self.request(
            "POST", "/v1/pool/shares",
            b'{"schema":"CRYPTIC-POOL-SUBMISSION/1","schema":"attacker"}',
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(payload["error"], "request_json_duplicate_key")


if __name__ == "__main__":
    unittest.main()
