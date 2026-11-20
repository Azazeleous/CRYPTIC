import copy
import unittest

try:
    import cryptography  # noqa: F401
except ImportError:
    cryptography = None

from src.mining.provenance_attestation import (
    SCHEMA,
    TRUST_SCHEMA,
    create_attestation,
    generate_ed25519_keypair,
    trust_store_entry,
    verify_attestation,
)


@unittest.skipIf(cryptography is None, "optional cryptography package is not installed")
class ProvenanceAttestationTests(unittest.TestCase):
    def setUp(self):
        self.keys = generate_ed25519_keypair()
        self.entry = trust_store_entry("archive-owner-a", self.keys["public_key_hex"])
        self.trust = {
            "schema": TRUST_SCHEMA,
            "issuers": [self.entry],
        }
        self.attestation = create_attestation(
            issuer_id="archive-owner-a",
            private_key_hex=self.keys["private_key_hex"],
            subject_schema="cryptic.provenance-federation.v1",
            subject_id="federation-2026-01",
            subject_digest="a" * 64,
            issued_at=1_800_000_000,
        )

    def test_valid_signature_and_trusted_issuer(self):
        result = verify_attestation(self.attestation, self.trust)
        self.assertTrue(result["valid"])
        self.assertEqual(result["issuer_id"], "archive-owner-a")
        self.assertEqual(result["subject"]["digest"], "a" * 64)

    def test_tampered_payload_is_rejected(self):
        altered = copy.deepcopy(self.attestation)
        altered["payload"]["subject"]["digest"] = "b" * 64
        self.assertEqual(
            verify_attestation(altered, self.trust)["reason"],
            "attestation_id_mismatch",
        )

    def test_signature_tampering_is_rejected(self):
        altered = copy.deepcopy(self.attestation)
        altered["signature"] = altered["signature"][:-4] + "AAAA"
        result = verify_attestation(altered, self.trust)
        self.assertFalse(result["valid"])

    def test_unknown_issuer_is_rejected(self):
        trust = {"schema": TRUST_SCHEMA, "issuers": []}
        self.assertEqual(
            verify_attestation(self.attestation, trust)["reason"],
            "issuer_key_not_trusted",
        )

    def test_revoked_key_is_rejected(self):
        trust = copy.deepcopy(self.trust)
        trust["issuers"][0]["status"] = "revoked"
        self.assertEqual(
            verify_attestation(self.attestation, trust)["reason"],
            "issuer_key_revoked_or_inactive",
        )

    def test_fingerprint_mismatch_is_rejected(self):
        trust = copy.deepcopy(self.trust)
        trust["issuers"][0]["key_fingerprint"] = "0" * 64
        self.assertEqual(
            verify_attestation(self.attestation, trust)["reason"],
            "issuer_key_not_trusted",
        )

    def test_wrong_public_key_cannot_verify_signature(self):
        other = generate_ed25519_keypair()
        trust = {
            "schema": TRUST_SCHEMA,
            "issuers": [trust_store_entry("archive-owner-a", other["public_key_hex"])],
        }
        self.assertEqual(
            verify_attestation(self.attestation, trust)["reason"],
            "issuer_key_not_trusted",
        )

    def test_duplicate_trust_entries_fail_closed(self):
        trust = {
            "schema": TRUST_SCHEMA,
            "issuers": [self.entry, copy.deepcopy(self.entry)],
        }
        self.assertEqual(
            verify_attestation(self.attestation, trust)["reason"],
            "issuer_key_not_trusted",
        )

    def test_bad_digest_and_timestamp_rejected_before_signing(self):
        common = {
            "issuer_id": "archive-owner-a",
            "private_key_hex": self.keys["private_key_hex"],
            "subject_schema": "cryptic.provenance-federation.v1",
            "subject_id": "federation-2026-01",
            "issued_at": 1,
        }
        with self.assertRaises(ValueError):
            create_attestation(**common, subject_digest="NOT-A-DIGEST")
        with self.assertRaises(ValueError):
            create_attestation(**{**common, "issued_at": True}, subject_digest="a" * 64)


if __name__ == "__main__":
    unittest.main()
