"""Functional tests for FIPS 203 ML-KEM-768 and FIPS 204 ML-DSA-65 provider APIs."""
import unittest

from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65

from src.ingestion.pq_security import (
    MLKEM768,
    MLDSA65,
    ML_KEM_768_SIZES,
    ML_DSA_65_SIZES,
    PQProviderError,
    open_envelope,
    seal_for_recipient,
    sign_research_receipt,
    verify_research_receipt,
)


class PQSecurityTests(unittest.TestCase):
    def test_provider_parameter_sizes_match_fips_203_and_204(self):
        self.assertEqual(ml_kem_768.PUBLIC_KEY_SIZE, ML_KEM_768_SIZES["public_key"])
        self.assertEqual(ml_kem_768.SECRET_KEY_SIZE, ML_KEM_768_SIZES["secret_key"])
        self.assertEqual(ml_kem_768.CIPHERTEXT_SIZE, ML_KEM_768_SIZES["ciphertext"])
        self.assertEqual(ml_kem_768.SHARED_SECRET_SIZE, ML_KEM_768_SIZES["shared_secret"])
        self.assertEqual(ml_dsa_65.PUBLIC_KEY_SIZE, ML_DSA_65_SIZES["public_key"])
        self.assertEqual(ml_dsa_65.SECRET_KEY_SIZE, ML_DSA_65_SIZES["secret_key"])
        self.assertEqual(ml_dsa_65.SIGNATURE_SIZE, ML_DSA_65_SIZES["signature"])

    def test_ml_kem_768_encapsulation_decapsulation_agree(self):
        pair = MLKEM768.keygen()
        ciphertext, sender_secret = MLKEM768.encapsulate(pair.public_key)
        receiver_secret = MLKEM768.decapsulate(pair.secret_key, ciphertext)
        self.assertEqual(sender_secret, receiver_secret)
        self.assertEqual(len(sender_secret), 32)

    def test_ml_kem_rejects_wrong_lengths(self):
        with self.assertRaisesRegex(ValueError, "public_key_length"):
            MLKEM768.encapsulate(b"bad")
        with self.assertRaisesRegex(ValueError, "secret_key_length"):
            MLKEM768.decapsulate(b"bad", bytes(1088))
        with self.assertRaisesRegex(ValueError, "ciphertext_length"):
            MLKEM768.decapsulate(bytes(2400), b"bad")

    def test_ml_dsa_65_sign_verify_context_and_reject_tampering(self):
        pair = MLDSA65.keygen()
        message = b"CRYPTIC research receipt v1"
        context = b"CRYPTIC-RESEARCH-RECEIPT-v1"
        signature = MLDSA65.sign(pair.secret_key, message, context=context)
        self.assertEqual(len(signature), 3309)
        self.assertTrue(MLDSA65.verify(pair.public_key, message, signature, context=context))
        self.assertFalse(MLDSA65.verify(pair.public_key, message + b"!", signature, context=context))
        self.assertFalse(MLDSA65.verify(pair.public_key, message, signature, context=b"wrong-context"))
        self.assertFalse(MLDSA65.verify(pair.public_key, message, signature[:-1], context=context))

    def test_ml_dsa_context_limit_is_enforced(self):
        pair = MLDSA65.keygen()
        with self.assertRaisesRegex(ValueError, "255_bytes"):
            MLDSA65.sign(pair.secret_key, b"message", context=bytes(256))

    def test_kem_derived_aead_envelope_roundtrip(self):
        pair = MLKEM768.keygen()
        aad = b"CRYPTIC transport v1"
        context = b"cryptic/transport/test"
        plaintext = b"research data; not a secret fixture"
        envelope = seal_for_recipient(pair.public_key, plaintext,
                                      associated_data=aad, context=context)
        self.assertEqual(open_envelope(pair.secret_key, envelope,
                                       associated_data=aad, context=context), plaintext)

    def test_aead_rejects_wrong_aad_or_context(self):
        pair = MLKEM768.keygen()
        envelope = seal_for_recipient(pair.public_key, b"payload",
                                      associated_data=b"aad", context=b"ctx")
        with self.assertRaisesRegex(PQProviderError, "authentication_failed"):
            open_envelope(pair.secret_key, envelope, associated_data=b"changed", context=b"ctx")
        with self.assertRaisesRegex(PQProviderError, "authentication_failed"):
            open_envelope(pair.secret_key, envelope, associated_data=b"aad", context=b"other")

    def test_receipt_signing_helpers(self):
        pair = MLDSA65.keygen()
        receipt = b'{"schema":"cryptic.receipt.v1","accepted":true}'
        signature = sign_research_receipt(pair.secret_key, receipt)
        self.assertTrue(verify_research_receipt(pair.public_key, receipt, signature))
        self.assertFalse(verify_research_receipt(pair.public_key, receipt + b" ", signature))

    def test_provider_output_length_invariants(self):
        pair = MLDSA65.keygen()
        with self.assertRaisesRegex(ValueError, "secret_key_length"):
            MLDSA65.sign(b"bad", b"message")
        with self.assertRaisesRegex(ValueError, "public_key_length"):
            MLDSA65.verify(b"bad", b"message", bytes(3309))


if __name__ == "__main__":
    unittest.main()
