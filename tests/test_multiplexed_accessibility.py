import base64
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from storage.sparsebundle import SparseBundle
from src.consensus.pool_ledger import PoolShareLedger
from src.mining.pool_service import PoolCoordinator
from src.mining.pool_worker import execute_pool_job
from src.runtime.multiplexed_accessibility import (
    MultiplexedAccessibilityRuntime,
    MultiplexedCommandError,
)
from src.sos.sparsebundle_mount import SparseBundleMountManager


class MultiplexedAccessibilityRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        key = Ed25519PrivateKey.generate()
        self.private_hex = key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ).hex()
        self.public_hex = key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ).hex()
        self.now = 1000
        self.pool = PoolCoordinator(
            database=self.root / "jobs.sqlite3",
            share_ledger=PoolShareLedger(self.root / "shares.sqlite3"),
            issuer_private_key_hex=self.private_hex,
            issuer_id="issuer",
            pool_id="gaia-pool",
            network_id="hccgn-test",
            trusted_issuer_public_key_hex=self.public_hex,
            resolve_active_target=lambda _boundary: b"\xff" * 32,
            clock=lambda: self.now,
        )
        bundle = SparseBundle.create(
            self.root / "bundle",
            {"data": {"name": "Data", "role": "data", "size": 65536}},
            chunk_size=4096,
        )
        events = []
        self.events = events
        mounts = SparseBundleMountManager(
            bundle=bundle,
            authorize=lambda principal, _capability, _resource: principal == "operator",
            audit=lambda event: events.append(dict(event)) or True,
            clock=lambda: self.now,
        )
        self.runtime = MultiplexedAccessibilityRuntime(
            database=self.root / "commands.sqlite3",
            pool=self.pool,
            mounts=mounts,
            authorize=lambda principal, _capability, _resource: principal == "operator",
            audit=lambda event: events.append(dict(event)) or True,
            clock=lambda: self.now,
        )
        self.counter = 0

    def tearDown(self):
        self.tmp.cleanup()

    def command(self, operation, capability, payload, *, command_id=None):
        self.counter += 1
        return {
            "schema": "GAIA-MULTIPLEXED-COMMAND/1",
            "command_id": command_id or f"{self.counter:032x}",
            "correlation_id": "a" * 32,
            "principal": "operator",
            "capability": capability,
            "operation": operation,
            "payload": payload,
        }

    def dispatch(self, envelope):
        return self.runtime.dispatch(
            envelope,
            authenticated_principal="operator",
            authenticated_worker_id="worker-a",
        )

    def test_pool_job_issue_worker_submit_and_status(self):
        job_command = self.command(
            "pool.issue_job", "pool.job.issue",
            {
                "worker_id": "worker-a", "height": 1, "epoch": 1,
                "lifetime_seconds": 120, "parent_hash": "00" * 32,
                "payload_hash": "11" * 32, "primary_stride": 3037,
                "compact_stride": 5, "nonce_start": 0, "max_attempts": 8,
            },
        )
        issued = self.dispatch(job_command)
        self.assertEqual(issued["status"], "completed")
        job = issued["result"]["job"]
        submission = execute_pool_job(
            job,
            trusted_issuer_public_key_hex=self.public_hex,
            expected_issuer_id="issuer",
            expected_pool_id="gaia-pool",
            expected_network_id="hccgn-test",
            worker_id="worker-a",
            now=self.now,
        )
        accepted = self.dispatch(self.command(
            "pool.submit_share", "pool.share.submit",
            {"submission": submission},
        ))
        self.assertTrue(accepted["result"]["accepted"])
        status = self.dispatch(self.command(
            "pool.status", "pool.status.read", {},
        ))
        self.assertEqual(status["result"]["shares_accepted"], 1)
        self.assertTrue(status["result"]["healthy"])

    def test_sos_mount_read_write_and_unmount(self):
        mounted = self.dispatch(self.command(
            "sos.mount", "sos.mount.write",
            {
                "partition_id": "data", "mountpoint": "/workspace/data",
                "mode": "rw", "lease_seconds": 60,
            },
        ))
        mount_id = mounted["result"]["mount"]["mount_id"]
        written = self.dispatch(self.command(
            "sos.write", "sos.mount.write",
            {
                "mount_id": mount_id, "offset": 12,
                "data_b64": base64.b64encode(b"GAIA").decode("ascii"),
            },
        ))
        self.assertEqual(written["result"]["bytes"], 4)
        read = self.dispatch(self.command(
            "sos.read", "sos.mount.read",
            {"mount_id": mount_id, "offset": 12, "length": 4},
        ))
        self.assertEqual(base64.b64decode(read["result"]["data_b64"]), b"GAIA")
        removed = self.dispatch(self.command(
            "sos.unmount", "sos.mount.unmount", {"mount_id": mount_id},
        ))
        self.assertTrue(removed["result"]["unmounted"])

    def test_completed_command_is_idempotently_replayed(self):
        envelope = self.command("pool.status", "pool.status.read", {})
        first = self.dispatch(envelope)
        event_count = len(self.events)
        second = self.dispatch(envelope)
        self.assertEqual(first, second)
        self.assertEqual(len(self.events), event_count)

    def test_command_id_cannot_be_reused_for_different_payload(self):
        command_id = "f" * 32
        first = self.command("pool.status", "pool.status.read", {}, command_id=command_id)
        self.dispatch(first)
        changed = dict(first)
        changed["payload"] = {"unexpected": True}
        with self.assertRaisesRegex(
            MultiplexedCommandError, "command_id_reused_with_different_request"
        ):
            self.dispatch(changed)

    def test_transport_identity_must_match_envelope_principal(self):
        envelope = self.command("pool.status", "pool.status.read", {})
        with self.assertRaisesRegex(
            MultiplexedCommandError, "authenticated_principal_mismatch"
        ):
            self.runtime.dispatch(
                envelope,
                authenticated_principal="different-user",
                authenticated_worker_id="worker-a",
            )

    def test_unknown_operation_is_rejected_before_execution(self):
        envelope = self.command("os.shell", "os.shell", {"command": "id"})
        with self.assertRaisesRegex(
            MultiplexedCommandError, "command_operation_not_allowed|command_capability_mismatch"
        ):
            self.dispatch(envelope)


if __name__ == "__main__":
    unittest.main()
