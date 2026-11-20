import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from src.mining.provenance_trust import create_trust_snapshot
from src.mining.root_of_trust import (
    RootOfTrustError, create_root_manifest, create_root_rotation,
    create_signed_policy_snapshot, verify_root_manifest,
    verify_root_rotation, verify_signed_policy_snapshot,
)

def keypair():
    private = Ed25519PrivateKey.generate()
    raw_private = private.private_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()).hex()
    raw_public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
    return raw_private, raw_public

class RootOfTrustTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b, self.c, self.recovery = keypair(), keypair(), keypair(), keypair()
        self.root = create_root_manifest(
            [self.a[1], self.b[1], self.c[1]], threshold=2,
            recovery_public_keys=[self.recovery[1]], recovery_threshold=1)
        self.pin = self.root["root_fingerprint"]
        self.snapshot = create_trust_snapshot(
            [{"issuer_id": "issuer-1", "public_key_hex": self.a[1]}], created_at=100)

    def test_root_manifest_is_deterministic_and_valid(self):
        again = create_root_manifest(
            [self.c[1], self.a[1], self.b[1]], threshold=2,
            recovery_public_keys=[self.recovery[1]], recovery_threshold=1)
        self.assertEqual(self.root, again)
        self.assertTrue(verify_root_manifest(self.root)["valid"])

    def test_root_manifest_detects_tampering(self):
        altered = dict(self.root); altered["threshold"] = 1
        self.assertEqual(verify_root_manifest(altered)["reason"], "root_fingerprint_mismatch")

    def test_root_requires_valid_thresholds(self):
        with self.assertRaises(RootOfTrustError): create_root_manifest([self.a[1]], threshold=2)
        with self.assertRaises(RootOfTrustError): create_root_manifest([self.a[1]], threshold=True)

    def test_duplicate_root_key_rejected(self):
        with self.assertRaises(RootOfTrustError): create_root_manifest([self.a[1], self.a[1]], threshold=1)

    def test_signed_policy_requires_root_quorum(self):
        env = create_signed_policy_snapshot(self.snapshot, self.root, [self.a[0], self.b[0]], sequence=1)
        result = verify_signed_policy_snapshot(env, self.snapshot, self.root, pinned_root_fingerprint=self.pin)
        self.assertTrue(result["valid"]); self.assertEqual(result["valid_signer_count"], 2)

    def test_policy_fails_without_threshold(self):
        env = create_signed_policy_snapshot(self.snapshot, self.root, [self.a[0]], sequence=1)
        result = verify_signed_policy_snapshot(env, self.snapshot, self.root, pinned_root_fingerprint=self.pin)
        self.assertFalse(result["valid"]); self.assertEqual(result["reason"], "policy_quorum_not_met")

    def test_policy_rejects_wrong_independent_pin(self):
        env = create_signed_policy_snapshot(self.snapshot, self.root, [self.a[0], self.b[0]], sequence=1)
        result = verify_signed_policy_snapshot(env, self.snapshot, self.root, pinned_root_fingerprint="0"*64)
        self.assertEqual(result["reason"], "root_pin_mismatch")

    def test_policy_detects_snapshot_tampering(self):
        env = create_signed_policy_snapshot(self.snapshot, self.root, [self.a[0], self.b[0]], sequence=1)
        altered = dict(self.snapshot); altered["version"] = 2
        result = verify_signed_policy_snapshot(env, altered, self.root, pinned_root_fingerprint=self.pin)
        self.assertEqual(result["reason"], "trust_snapshot_invalid")

    def test_policy_anti_rollback_floor(self):
        env = create_signed_policy_snapshot(self.snapshot, self.root, [self.a[0], self.b[0]],
            sequence=2, previous_policy_digest="a"*64)
        result = verify_signed_policy_snapshot(env, self.snapshot, self.root,
            pinned_root_fingerprint=self.pin, minimum_sequence=3)
        self.assertEqual(result["reason"], "policy_rollback")

    def test_policy_predecessor_link_is_checked(self):
        env = create_signed_policy_snapshot(self.snapshot, self.root, [self.a[0], self.b[0]],
            sequence=2, previous_policy_digest="a"*64)
        result = verify_signed_policy_snapshot(env, self.snapshot, self.root,
            pinned_root_fingerprint=self.pin, minimum_sequence=2,
            expected_previous_policy_digest="b"*64)
        self.assertEqual(result["reason"], "policy_chain_mismatch")

    def test_policy_rejects_duplicate_signatures(self):
        env = create_signed_policy_snapshot(self.snapshot, self.root, [self.a[0], self.b[0]], sequence=1)
        env["signatures"][1] = dict(env["signatures"][0])
        result = verify_signed_policy_snapshot(env, self.snapshot, self.root, pinned_root_fingerprint=self.pin)
        self.assertFalse(result["valid"]); self.assertEqual(result["valid_signer_count"], 1)

    def test_policy_v2_requires_complete_snapshot_history(self):
        first = self.snapshot
        second = create_trust_snapshot(
            [{"issuer_id": "issuer-1", "public_key_hex": self.a[1]}], version=2,
            created_at=200, previous_snapshot_digest=first["snapshot_digest"])
        with self.assertRaises(RootOfTrustError):
            create_signed_policy_snapshot(second, self.root, [self.a[0], self.b[0]], sequence=1)
        env = create_signed_policy_snapshot(second, self.root, [self.a[0], self.b[0]],
            sequence=1, snapshot_history=[first])
        result = verify_signed_policy_snapshot(env, second, self.root,
            pinned_root_fingerprint=self.pin, snapshot_history=[first])
        self.assertTrue(result["valid"])
        missing = verify_signed_policy_snapshot(env, second, self.root, pinned_root_fingerprint=self.pin)
        self.assertEqual(missing["reason"], "trust_snapshot_chain_unverified")

    def test_root_rotation_requires_old_and_new_quorums(self):
        n1, n2, n3 = keypair(), keypair(), keypair()
        new = create_root_manifest([n1[1], n2[1], n3[1]], threshold=2,
            epoch=2, previous_root_fingerprint=self.pin)
        transition = create_root_rotation(self.root, new, [self.a[0], self.b[0]], [n1[0], n2[0]])
        result = verify_root_rotation(transition, self.root, pinned_old_root_fingerprint=self.pin)
        self.assertTrue(result["valid"]); self.assertEqual(result["new_root_fingerprint"], new["root_fingerprint"])

    def test_root_rotation_fails_without_old_quorum(self):
        n1, n2 = keypair(), keypair()
        new = create_root_manifest([n1[1], n2[1]], threshold=2, epoch=2, previous_root_fingerprint=self.pin)
        transition = create_root_rotation(self.root, new, [self.a[0]], [n1[0], n2[0]])
        result = verify_root_rotation(transition, self.root, pinned_old_root_fingerprint=self.pin)
        self.assertEqual(result["reason"], "old_root_authorization_not_met")

    def test_root_rotation_fails_without_new_key_possession(self):
        n1, n2 = keypair()
        new = create_root_manifest([n1[1], n2[1]], threshold=2, epoch=2, previous_root_fingerprint=self.pin)
        transition = create_root_rotation(self.root, new, [self.a[0], self.b[0]], [n1[0]])
        result = verify_root_rotation(transition, self.root, pinned_old_root_fingerprint=self.pin)
        self.assertEqual(result["reason"], "new_root_possession_not_met")

    def test_root_rotation_rejects_wrong_epoch(self):
        n1, n2 = keypair(), keypair()
        bad = create_root_manifest([n1[1], n2[1]], threshold=2, epoch=3, previous_root_fingerprint=self.pin)
        with self.assertRaises(RootOfTrustError):
            create_root_rotation(self.root, bad, [self.a[0], self.b[0]], [n1[0], n2[0]])

    def test_recovery_threshold_can_authorize_rotation(self):
        n1, n2 = keypair(), keypair()
        new = create_root_manifest([n1[1], n2[1]], threshold=2, epoch=2, previous_root_fingerprint=self.pin)
        transition = create_root_rotation(self.root, new, [self.recovery[0]], [n1[0], n2[0]], authorization="recovery")
        result = verify_root_rotation(transition, self.root, pinned_old_root_fingerprint=self.pin)
        self.assertTrue(result["valid"]); self.assertEqual(result["authorization"], "recovery")

    def test_transition_tampering_is_rejected(self):
        n1, n2 = keypair(), keypair()
        new = create_root_manifest([n1[1], n2[1]], threshold=2, epoch=2, previous_root_fingerprint=self.pin)
        transition = create_root_rotation(self.root, new, [self.a[0], self.b[0]], [n1[0], n2[0]])
        transition["authorization"] = "recovery"
        result = verify_root_rotation(transition, self.root, pinned_old_root_fingerprint=self.pin)
        self.assertFalse(result["valid"])

    def test_rotation_requires_independent_old_pin(self):
        n1, n2 = keypair(), keypair()
        new = create_root_manifest([n1[1], n2[1]], threshold=2, epoch=2, previous_root_fingerprint=self.pin)
        transition = create_root_rotation(self.root, new, [self.a[0], self.b[0]], [n1[0], n2[0]])
        result = verify_root_rotation(transition, self.root, pinned_old_root_fingerprint="f"*64)
        self.assertEqual(result["reason"], "old_root_pin_mismatch")

if __name__ == "__main__":
    unittest.main()
