import copy
import unittest

try:
    import cryptography  # noqa: F401
except ImportError:
    cryptography = None

from src.mining.provenance_attestation import (
    create_attestation,
    generate_ed25519_keypair,
    trust_store_entry,
)
from src.mining.provenance_trust import (
    TrustLifecycleError,
    create_trust_snapshot,
    revoke_trust_key,
    rotate_trust_key,
    verify_attestation_current,
    verify_attestation_historical,
    verify_attestation_quorum,
    verify_trust_snapshot,
    verify_trust_snapshot_chain,
)


@unittest.skipIf(cryptography is None, "optional cryptography package is not installed")
class ProvenanceTrustLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.key_a = generate_ed25519_keypair()
        self.key_b = generate_ed25519_keypair()
        self.key_c = generate_ed25519_keypair()
        self.entry_a = trust_store_entry("issuer-a", self.key_a["public_key_hex"])
        self.entry_b = trust_store_entry("issuer-b", self.key_b["public_key_hex"])
        self.snapshot_v1 = create_trust_snapshot(
            [self.entry_a, self.entry_b], version=1, created_at=100
        )

    def _attestation(self, issuer, key, digest="a" * 64, issued_at=150):
        return create_attestation(
            issuer_id=issuer,
            private_key_hex=key["private_key_hex"],
            subject_schema="cryptic.provenance-federation.v1",
            subject_id="federation-root-1",
            subject_digest=digest,
            issued_at=issued_at,
        )

    def test_snapshot_digest_and_canonical_entries_verify(self):
        result = verify_trust_snapshot(self.snapshot_v1)
        self.assertTrue(result["valid"])
        self.assertEqual(result["issuer_key_count"], 2)

    def test_snapshot_tampering_is_detected(self):
        altered = copy.deepcopy(self.snapshot_v1)
        altered["issuers"][0]["issuer_id"] = "attacker"
        self.assertEqual(
            verify_trust_snapshot(altered)["reason"],
            "snapshot_digest_mismatch",
        )

    def test_snapshot_chain_requires_and_checks_previous_snapshot(self):
        rotated = rotate_trust_key(
            self.snapshot_v1,
            issuer_id="issuer-a",
            old_key_fingerprint=self.key_a["key_fingerprint"],
            new_public_key_hex=self.key_c["public_key_hex"],
            effective_at=200,
            created_at=210,
        )
        standalone = verify_trust_snapshot(rotated)
        self.assertTrue(standalone["valid"])
        self.assertFalse(standalone["chain_link_verified"])
        self.assertTrue(verify_trust_snapshot(rotated, self.snapshot_v1)["valid"])
        wrong_previous = copy.deepcopy(self.snapshot_v1)
        wrong_previous["created_at"] = 99
        wrong_previous["snapshot_digest"] = "f" * 64
        self.assertFalse(verify_trust_snapshot(rotated, wrong_previous)["valid"])

    def test_three_version_snapshot_chain_verifies_sequentially(self):
        second = revoke_trust_key(
            self.snapshot_v1,
            issuer_id="issuer-a",
            key_fingerprint=self.key_a["key_fingerprint"],
            effective_at=180,
            created_at=190,
        )
        third = rotate_trust_key(
            second,
            issuer_id="issuer-b",
            old_key_fingerprint=self.key_b["key_fingerprint"],
            new_public_key_hex=self.key_c["public_key_hex"],
            effective_at=220,
            created_at=230,
            snapshot_history=[self.snapshot_v1],
        )
        result = verify_trust_snapshot_chain([self.snapshot_v1, second, third])
        self.assertTrue(result["valid"])
        self.assertEqual(result["version"], 3)
        self.assertEqual(result["snapshot_count"], 3)
        self.assertFalse(verify_trust_snapshot_chain([self.snapshot_v1, third])["valid"])
        self.assertFalse(verify_trust_snapshot_chain([second, third])["valid"])

    def test_snapshot_cannot_be_advanced_without_verified_history(self):
        second = revoke_trust_key(
            self.snapshot_v1,
            issuer_id="issuer-a",
            key_fingerprint=self.key_a["key_fingerprint"],
            effective_at=180,
            created_at=190,
        )
        with self.assertRaises(TrustLifecycleError):
            rotate_trust_key(
                second,
                issuer_id="issuer-b",
                old_key_fingerprint=self.key_b["key_fingerprint"],
                new_public_key_hex=self.key_c["public_key_hex"],
                effective_at=220,
                created_at=230,
            )

    def test_rotation_preserves_historical_signature_but_rejects_current(self):
        old_attestation = self._attestation("issuer-a", self.key_a, issued_at=150)
        rotated = rotate_trust_key(
            self.snapshot_v1,
            issuer_id="issuer-a",
            old_key_fingerprint=self.key_a["key_fingerprint"],
            new_public_key_hex=self.key_c["public_key_hex"],
            effective_at=200,
            created_at=210,
        )
        self.assertTrue(verify_attestation_historical(old_attestation, rotated, snapshot_history=[self.snapshot_v1])["valid"])
        self.assertEqual(
            verify_attestation_current(old_attestation, rotated, snapshot_history=[self.snapshot_v1])["reason"],
            "issuer_key_revoked",
        )
        new_attestation = self._attestation("issuer-a", self.key_c, issued_at=205)
        self.assertTrue(verify_attestation_current(new_attestation, rotated, snapshot_history=[self.snapshot_v1])["valid"])

    def test_v2_snapshot_verification_requires_full_history(self):
        rotated = rotate_trust_key(
            self.snapshot_v1,
            issuer_id="issuer-a",
            old_key_fingerprint=self.key_a["key_fingerprint"],
            new_public_key_hex=self.key_c["public_key_hex"],
            effective_at=200,
            created_at=210,
        )
        attestation = self._attestation("issuer-a", self.key_c, issued_at=205)
        result = verify_attestation_current(attestation, rotated)
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "trust_snapshot_chain_unverified")

    def test_attestation_outside_key_validity_is_rejected(self):
        rotated = rotate_trust_key(
            self.snapshot_v1,
            issuer_id="issuer-a",
            old_key_fingerprint=self.key_a["key_fingerprint"],
            new_public_key_hex=self.key_c["public_key_hex"],
            effective_at=200,
            created_at=210,
        )
        late_old_signature = self._attestation("issuer-a", self.key_a, issued_at=201)
        self.assertEqual(
            verify_attestation_historical(late_old_signature, rotated, snapshot_history=[self.snapshot_v1])["reason"],
            "attestation_outside_key_validity",
        )

    def test_revocation_is_append_only_and_historical_policy_survives(self):
        attestation = self._attestation("issuer-b", self.key_b, issued_at=120)
        revoked = revoke_trust_key(
            self.snapshot_v1,
            issuer_id="issuer-b",
            key_fingerprint=self.key_b["key_fingerprint"],
            effective_at=180,
            created_at=190,
        )
        self.assertIsNone(self.snapshot_v1["issuers"][1]["revoked_at"])
        self.assertEqual(revoked["version"], 2)
        self.assertTrue(verify_attestation_historical(attestation, revoked, snapshot_history=[self.snapshot_v1])["valid"])
        self.assertFalse(verify_attestation_current(attestation, revoked, snapshot_history=[self.snapshot_v1])["valid"])

    def test_rotation_rejects_unknown_old_key_and_duplicate_new_key(self):
        with self.assertRaises(TrustLifecycleError):
            rotate_trust_key(
                self.snapshot_v1,
                issuer_id="issuer-a",
                old_key_fingerprint="0" * 64,
                new_public_key_hex=self.key_c["public_key_hex"],
                effective_at=200,
                created_at=210,
            )
        with self.assertRaises(TrustLifecycleError):
            rotate_trust_key(
                self.snapshot_v1,
                issuer_id="issuer-a",
                old_key_fingerprint=self.key_a["key_fingerprint"],
                new_public_key_hex=self.key_b["public_key_hex"],
                effective_at=200,
                created_at=210,
            )

    def test_quorum_requires_distinct_issuers_for_same_subject(self):
        attestations = [
            self._attestation("issuer-a", self.key_a),
            self._attestation("issuer-b", self.key_b),
        ]
        result = verify_attestation_quorum(
            attestations, self.snapshot_v1, threshold=2
        )
        self.assertTrue(result["valid"])
        self.assertEqual(result["valid_signer_count"], 2)

    def test_quorum_accepts_rotated_key_with_complete_snapshot_history(self):
        rotated = rotate_trust_key(
            self.snapshot_v1,
            issuer_id="issuer-a",
            old_key_fingerprint=self.key_a["key_fingerprint"],
            new_public_key_hex=self.key_c["public_key_hex"],
            effective_at=200,
            created_at=210,
        )
        attestations = [
            self._attestation("issuer-a", self.key_c, issued_at=205),
            self._attestation("issuer-b", self.key_b, issued_at=205),
        ]
        result = verify_attestation_quorum(
            attestations,
            rotated,
            threshold=2,
            snapshot_history=[self.snapshot_v1],
        )
        self.assertTrue(result["valid"])
        self.assertEqual(result["valid_signer_count"], 2)

    def test_duplicate_issuer_cannot_satisfy_quorum(self):
        attestations = [
            self._attestation("issuer-a", self.key_a),
            self._attestation("issuer-a", self.key_a),
        ]
        result = verify_attestation_quorum(
            attestations, self.snapshot_v1, threshold=2
        )
        self.assertFalse(result["valid"])
        self.assertEqual(result["valid_signer_count"], 1)
        self.assertEqual(result["rejected"][0]["reason"], "duplicate_quorum_issuer")

    def test_subject_mismatch_cannot_satisfy_quorum(self):
        attestations = [
            self._attestation("issuer-a", self.key_a, digest="a" * 64),
            self._attestation("issuer-b", self.key_b, digest="b" * 64),
        ]
        result = verify_attestation_quorum(
            attestations, self.snapshot_v1, threshold=2
        )
        self.assertFalse(result["valid"])
        self.assertEqual(result["valid_signer_count"], 1)
        self.assertEqual(result["rejected"][0]["reason"], "subject_mismatch")

    def test_quorum_requires_consistent_purpose(self):
        first = self._attestation("issuer-a", self.key_a)
        second = create_attestation(
            issuer_id="issuer-b",
            private_key_hex=self.key_b["private_key_hex"],
            subject_schema="cryptic.provenance-federation.v1",
            subject_id="federation-root-1",
            subject_digest="a" * 64,
            issued_at=150,
            purpose="different-purpose",
        )
        result = verify_attestation_quorum(
            [first, second], self.snapshot_v1, threshold=2
        )
        self.assertFalse(result["valid"])
        self.assertEqual(result["valid_signer_count"], 1)
        self.assertEqual(result["rejected"][0]["reason"], "purpose_mismatch")

    def test_future_scheduled_revocation_remains_active_in_snapshot_state(self):
        scheduled = revoke_trust_key(
            self.snapshot_v1,
            issuer_id="issuer-a",
            key_fingerprint=self.key_a["key_fingerprint"],
            effective_at=300,
            created_at=250,
        )
        attestation = self._attestation("issuer-a", self.key_a, issued_at=220)
        self.assertTrue(verify_attestation_current(attestation, scheduled, snapshot_history=[self.snapshot_v1])["valid"])

    def test_future_effective_rotation_preserves_old_key_until_activation(self):
        scheduled = rotate_trust_key(
            self.snapshot_v1,
            issuer_id="issuer-a",
            old_key_fingerprint=self.key_a["key_fingerprint"],
            new_public_key_hex=self.key_c["public_key_hex"],
            effective_at=300,
            created_at=250,
        )
        old_attestation = self._attestation("issuer-a", self.key_a, issued_at=220)
        new_attestation = self._attestation("issuer-a", self.key_c, issued_at=320)
        history = [self.snapshot_v1]
        self.assertTrue(verify_attestation_current(
            old_attestation, scheduled, snapshot_history=history
        )["valid"])
        self.assertEqual(
            verify_attestation_current(
                new_attestation, scheduled, snapshot_history=history
            )["reason"],
            "issuer_key_not_yet_active",
        )

    def test_quorum_rejects_invalid_snapshot(self):
        altered = copy.deepcopy(self.snapshot_v1)
        altered["snapshot_digest"] = "0" * 64
        result = verify_attestation_quorum(
            [self._attestation("issuer-a", self.key_a)],
            altered,
            threshold=1,
        )
        self.assertFalse(result["valid"])
        self.assertEqual(result["rejected"][0]["reason"], "trust_snapshot_invalid")

    def test_invalid_timestamps_and_versions_fail_closed(self):
        with self.assertRaises(TrustLifecycleError):
            create_trust_snapshot([self.entry_a], version=0, created_at=1)
        with self.assertRaises(TrustLifecycleError):
            create_trust_snapshot([self.entry_a], version=2, created_at=1)
        with self.assertRaises(TrustLifecycleError):
            revoke_trust_key(
                self.snapshot_v1,
                issuer_id="issuer-a",
                key_fingerprint=self.key_a["key_fingerprint"],
                effective_at=-1,
                created_at=140,
            )


if __name__ == "__main__":
    unittest.main()
