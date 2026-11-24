import tempfile
import unittest
from pathlib import Path

from storage.sparsebundle import SparseBundle
from src.sos.sparsebundle_mount import (
    SparseBundleMountError,
    SparseBundleMountManager,
)


class SparseBundleMountTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.bundle = SparseBundle.create(
            Path(self.tmp.name) / "bundle",
            {"data": {"name": "Data", "role": "data", "size": 65536}},
            chunk_size=4096,
        )
        self.now = [1000]
        self.events = []
        self.permissions = {"sos.mount.read", "sos.mount.write"}

        def authorize(principal, capability, resource):
            return principal == "operator" and capability in self.permissions

        def audit(event):
            self.events.append(dict(event))
            return True

        self.manager = SparseBundleMountManager(
            bundle=self.bundle,
            authorize=authorize,
            audit=audit,
            clock=lambda: self.now[0],
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_authorized_read_write_mount_round_trip(self):
        mount = self.manager.mount(
            principal="operator", partition_id="data",
            mountpoint="/workspace/data", mode="rw", lease_seconds=60,
        )
        generation = self.manager.write(
            mount.mount_id, principal="operator", offset=7, data=b"GAIA",
        )
        self.assertEqual(generation, 1)
        self.assertEqual(
            self.manager.read(mount.mount_id, principal="operator", offset=7, length=4),
            b"GAIA",
        )
        self.assertEqual(self.manager.status()["active_mounts"], 1)
        self.assertIn("sos.mount.write", [row["event_type"] for row in self.events])

    def test_read_only_mount_rejects_write(self):
        mount = self.manager.mount(
            principal="operator", partition_id="data",
            mountpoint="/workspace/readonly", mode="ro",
        )
        with self.assertRaisesRegex(SparseBundleMountError, "mount_read_only"):
            self.manager.write(mount.mount_id, principal="operator", offset=0, data=b"x")

    def test_mount_requires_explicit_capability(self):
        self.permissions.clear()
        with self.assertRaisesRegex(SparseBundleMountError, "mount_authorization_denied"):
            self.manager.mount(
                principal="operator", partition_id="data",
                mountpoint="/workspace/data",
            )

    def test_mount_is_bound_to_principal(self):
        mount = self.manager.mount(
            principal="operator", partition_id="data",
            mountpoint="/workspace/data",
        )
        with self.assertRaisesRegex(SparseBundleMountError, "mount_principal_mismatch"):
            self.manager.read(mount.mount_id, principal="other", offset=0, length=1)

    def test_lease_expiry_revokes_mount(self):
        mount = self.manager.mount(
            principal="operator", partition_id="data",
            mountpoint="/workspace/data", lease_seconds=1,
        )
        self.now[0] = 1001
        with self.assertRaisesRegex(SparseBundleMountError, "mount_lease_expired"):
            self.manager.read(mount.mount_id, principal="operator", offset=0, length=1)
        self.assertEqual(self.manager.status()["active_mounts"], 0)

    def test_audit_failure_prevents_mount(self):
        manager = SparseBundleMountManager(
            bundle=self.bundle,
            authorize=lambda *_: True,
            audit=lambda _: False,
            clock=lambda: self.now[0],
        )
        with self.assertRaisesRegex(SparseBundleMountError, "mount_audit_not_committed"):
            manager.mount(
                principal="operator", partition_id="data",
                mountpoint="/workspace/data",
            )
        self.assertEqual(manager.status()["active_mounts"], 0)


if __name__ == "__main__":
    unittest.main()
