import base64
import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.extensions.manifest import (
    MANIFEST_DOMAIN,
    ExtensionManifestError,
    canonical_json,
    verify_extension_manifest,
)
from src.sos.virtual_computer import (
    GRANT_DOMAIN,
    VirtualComputer,
    VirtualComputerError,
    verify_capability_grant,
)
from storage.sparsebundle import SparseBundle
from src.sos.sparsebundle_mount import SparseBundleMountManager


def keypair():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    return private, public


def signed_manifest(private, artifact, *, now, extension_id="demo.notes"):
    unsigned = {
        "schema": "CRYPTIC-EXTENSION/1",
        "extension_id": extension_id,
        "version": "1.0.0",
        "publisher_id": "publisher-test",
        "description": "Declarative test extension",
        "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
        "requested_capabilities": [
            "filesystem.delete", "filesystem.list", "filesystem.mount.list",
            "filesystem.mount.read", "filesystem.mount.unmount", "filesystem.mount.write",
            "filesystem.read", "filesystem.write", "process.invoke",
        ],
        "issued_at": now - 1,
        "expires_at": now + 3600,
    }
    return {
        **unsigned,
        "signature": base64.b64encode(
            private.sign(MANIFEST_DOMAIN + canonical_json(unsigned))
        ).decode("ascii"),
    }


def signed_grant(private, *, now, extension_id="demo.notes", resources=None,
                 capabilities=None, grant_id="a" * 32):
    unsigned = {
        "schema": "CRYPTIC-SOS-CAPABILITY-GRANT/1",
        "grant_id": grant_id,
        "extension_id": extension_id,
        "signer_id": "operator-root",
        "capabilities": capabilities or [
            "filesystem.delete", "filesystem.list", "filesystem.mount.list",
            "filesystem.mount.read", "filesystem.mount.unmount", "filesystem.mount.write",
            "filesystem.read", "filesystem.write", "process.invoke",
        ],
        "resources": ["docs/"] if resources is None else resources,
        "issued_at": now - 1,
        "expires_at": now + 600,
        "nonce": "b" * 32,
    }
    return {
        **unsigned,
        "signature": base64.b64encode(
            private.sign(GRANT_DOMAIN + canonical_json(unsigned))
        ).decode("ascii"),
    }


class ExtensionManifestTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_800_000_000
        self.private, self.public = keypair()
        self.artifact = b"opaque extension package bytes"
        self.trust = {"publisher-test": self.public}
        self.manifest = signed_manifest(self.private, self.artifact, now=self.now)

    def test_signed_manifest_and_artifact_verify(self):
        verified = verify_extension_manifest(
            self.manifest, self.artifact, self.trust, now=self.now,
        )
        self.assertEqual(verified.extension_id, "demo.notes")
        self.assertEqual(verified.requested_capabilities[-1], "process.invoke")

    def test_artifact_substitution_is_rejected(self):
        with self.assertRaisesRegex(ExtensionManifestError, "artifact_digest_mismatch"):
            verify_extension_manifest(
                self.manifest, self.artifact + b"tamper", self.trust, now=self.now,
            )

    def test_manifest_mutation_invalidates_signature(self):
        altered = {**self.manifest, "description": "changed after signing"}
        with self.assertRaisesRegex(ExtensionManifestError, "manifest_signature_invalid"):
            verify_extension_manifest(altered, self.artifact, self.trust, now=self.now)

    def test_untrusted_publisher_and_expired_manifest_fail_closed(self):
        with self.assertRaisesRegex(ExtensionManifestError, "publisher_not_trusted"):
            verify_extension_manifest(self.manifest, self.artifact, {}, now=self.now)
        with self.assertRaisesRegex(ExtensionManifestError, "manifest_expired"):
            verify_extension_manifest(self.manifest, self.artifact, self.trust, now=self.now + 4000)


class VirtualComputerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = 1_800_000_000
        self.publisher_private, self.publisher_public = keypair()
        self.operator_private, self.operator_public = keypair()
        self.artifact = b"extension bytes are data, not executable code"
        self.manifest = signed_manifest(self.publisher_private, self.artifact, now=self.now)
        self.grant = signed_grant(self.operator_private, now=self.now)
        self.bundle = SparseBundle.create(
            Path(self.temp.name) / "system.bundle",
            {"data": {"name": "Data", "role": "data", "size": 65536}},
            chunk_size=4096,
        )
        self.mount_events = []
        self.mount_provider = SparseBundleMountManager(
            bundle=self.bundle,
            authorize=lambda principal, capability, _resource: (
                principal == "demo.notes" and capability in {
                    "sos.mount.read", "sos.mount.write"
                }
            ),
            audit=lambda event: self.mount_events.append(dict(event)) or True,
            clock=lambda: self.now,
        )
        self.computer = VirtualComputer(
            Path(self.temp.name) / "sos.sqlite3",
            publisher_trust={"publisher-test": self.publisher_public},
            authority_trust={"operator-root": self.operator_public},
            clock=lambda: self.now,
            mount_provider=self.mount_provider,
        )
        self.computer.install_extension(self.manifest, self.artifact)
        self.computer.activate_grant(self.grant)

    def test_virtual_filesystem_commands_and_audit_chain(self):
        written = self.computer.run(
            "demo.notes", "a" * 32, ["write", "docs/readme.txt", "hello virtual world"],
        )
        self.assertEqual(written.status, "completed", written.stderr)
        self.assertEqual(len(written.stdout), 64)

        read = self.computer.run("demo.notes", "a" * 32, ["cat", "docs/readme.txt"])
        self.assertEqual(read.stdout, "hello virtual world")
        listed = self.computer.run("demo.notes", "a" * 32, ["ls", "docs"])
        self.assertEqual(listed.stdout, "docs/readme.txt")
        digest = self.computer.run("demo.notes", "a" * 32, ["sha256", "docs/readme.txt"])
        self.assertEqual(digest.stdout, hashlib.sha256(b"hello virtual world").hexdigest())
        self.assertTrue(self.computer.verify_audit_chain())
        self.assertGreaterEqual(len(self.computer.audit_events()), 5)

    def test_sparsebundle_partition_is_mounted_through_virtual_terminal(self):
        mounted = self.computer.run(
            "demo.notes", "a" * 32,
            ["mount", "data", "docs/data", "rw", "60"],
        )
        self.assertEqual(mounted.status, "completed", mounted.stderr)
        mount_id = mounted.stdout.split()[1]

        written = self.computer.run(
            "demo.notes", "a" * 32,
            ["mwrite", "docs/data", "12", base64.b64encode(b"HCCGN").decode("ascii")],
        )
        self.assertEqual(written.status, "completed", written.stderr)

        read = self.computer.run(
            "demo.notes", "a" * 32, ["mread", "docs/data", "12", "5"],
        )
        self.assertEqual(read.status, "completed", read.stderr)
        self.assertEqual(base64.b64decode(read.stdout), b"HCCGN")

        listed = self.computer.run("demo.notes", "a" * 32, ["mounts"])
        self.assertIn(mount_id, listed.stdout)
        removed = self.computer.run("demo.notes", "a" * 32, ["umount", mount_id])
        self.assertEqual(removed.status, "completed", removed.stderr)
        self.assertEqual(self.mount_provider.status()["active_mounts"], 0)
        self.assertTrue(self.computer.verify_audit_chain())
        self.assertIn("sos.mount.created", [event["event_type"] for event in self.mount_events])

    def test_virtual_terminal_mount_write_requires_write_capability(self):
        limited = signed_grant(
            self.operator_private, now=self.now,
            capabilities=[
                "filesystem.mount.read", "process.invoke",
            ],
            resources=["docs/"], grant_id="d" * 32,
        )
        self.computer.activate_grant(limited)
        result = self.computer.run(
            "demo.notes", "d" * 32,
            ["mount", "data", "docs/data", "rw", "60"],
        )
        self.assertEqual(result.status, "denied")
        self.assertIn("capability_denied:filesystem.mount.write", result.stderr)

    def test_resource_scope_and_path_traversal_are_denied(self):
        denied = self.computer.run("demo.notes", "a" * 32, ["cat", "private/secret.txt"])
        self.assertEqual(denied.status, "denied")
        self.assertIn("resource_scope_denied", denied.stderr)
        traversal = self.computer.run("demo.notes", "a" * 32, ["write", "../escape.txt", "no"])
        self.assertEqual(traversal.status, "denied")
        self.assertIn("path_traversal", traversal.stderr)
        self.assertTrue(self.computer.verify_audit_chain())

    def test_unregistered_shell_or_code_execution_is_not_available(self):
        result = self.computer.run("demo.notes", "a" * 32, ["python", "-c", "print(1)"])
        self.assertEqual(result.status, "denied")
        self.assertIn("virtual_command_not_allowed", result.stderr)

    def test_grant_revocation_takes_effect_immediately(self):
        self.assertTrue(self.computer.revoke_grant("a" * 32, actor="operator"))
        result = self.computer.run("demo.notes", "a" * 32, ["help"])
        self.assertEqual(result.status, "denied")
        self.assertIn("capability_grant_revoked", result.stderr)
        self.assertTrue(self.computer.verify_audit_chain())

    def test_grant_cannot_exceed_manifest_requested_capabilities(self):
        altered = signed_grant(
            self.operator_private, now=self.now,
            capabilities=["filesystem.write", "process.invoke"],
            resources=["docs/"], grant_id="c" * 32,
        )
        verified_manifest = verify_extension_manifest(
            self.manifest, self.artifact,
            {"publisher-test": self.publisher_public}, now=self.now,
        )
        invalid = {
            **altered,
            "capabilities": ["filesystem.write", "network.admin", "process.invoke"],
        }
        with self.assertRaisesRegex(VirtualComputerError, "exceeds_manifest"):
            verify_capability_grant(
                invalid, {"operator-root": self.operator_public},
                verified_manifest, now=self.now,
            )

    def test_command_budget_exceeded_rolls_back_file_write(self):
        tiny_budget = VirtualComputer(
            Path(self.temp.name) / "tiny.sqlite3",
            publisher_trust={"publisher-test": self.publisher_public},
            authority_trust={"operator-root": self.operator_public},
            clock=lambda: self.now,
            command_budget_seconds=1e-12,
        )
        tiny_budget.install_extension(self.manifest, self.artifact)
        tiny_budget.activate_grant(self.grant)
        result = tiny_budget.run(
            "demo.notes", "a" * 32, ["write", "docs/too-slow.txt", "must rollback"],
        )
        self.assertEqual(result.status, "denied")
        self.assertIn("command_budget_exceeded", result.stderr)
        check = tiny_budget.run("demo.notes", "a" * 32, ["cat", "docs/too-slow.txt"])
        self.assertEqual(check.status, "denied")
        self.assertIn("virtual_file_not_found", check.stderr)

    def test_audit_tampering_is_detected_and_blocks_following_writes(self):
        self.computer.run("demo.notes", "a" * 32, ["write", "docs/one.txt", "one"])
        with sqlite3.connect(self.computer.database) as connection:
            connection.execute(
                "UPDATE audit_events SET event_json=? WHERE sequence=1",
                ('{"sequence":1,"tampered":true}',),
            )
        self.assertFalse(self.computer.verify_audit_chain())
        with self.assertRaisesRegex(VirtualComputerError, "audit_chain_integrity_failure"):
            self.computer.run("demo.notes", "a" * 32, ["write", "docs/two.txt", "two"])


if __name__ == "__main__":
    unittest.main()
