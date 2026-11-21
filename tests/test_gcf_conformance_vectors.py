import hashlib
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.consensus.gcf import (
    GCFError, ValidatorSet, canonical_bytes as producer_canonical_bytes,
    public_key_hex,
)
from src.consensus.independent_verifier import (
    IndependentVerificationError, canonical_bytes as verifier_canonical_bytes,
)
from src.consensus.peer_transport import GCFPeerNode, PeerTransportError


class GCFCanonicalConformanceTests(unittest.TestCase):
    def test_canonical_object_known_answer(self):
        value = {"b": 2, "a": 1}
        expected = b'{"a":1,"b":2}'
        self.assertEqual(producer_canonical_bytes(value), expected)
        self.assertEqual(verifier_canonical_bytes(value), expected)

    def test_sha256_known_answer(self):
        self.assertEqual(
            hashlib.sha256(b"abc").hexdigest(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_unicode_values_are_utf8_and_keys_are_ascii(self):
        value = {"label": "GAIA Ω"}
        expected = '{"label":"GAIA Ω"}'.encode("utf-8")
        self.assertEqual(producer_canonical_bytes(value), expected)
        self.assertEqual(verifier_canonical_bytes(value), expected)
        with self.assertRaises(GCFError):
            producer_canonical_bytes({"Ω": "value"})
        with self.assertRaises(IndependentVerificationError):
            verifier_canonical_bytes({"Ω": "value"})

    def test_floats_and_nan_are_rejected_by_both_profiles(self):
        for encoder, error in (
            (producer_canonical_bytes, GCFError),
            (verifier_canonical_bytes, IndependentVerificationError),
        ):
            with self.assertRaises(error):
                encoder({"value": 0.25})
            with self.assertRaises(error):
                encoder({"value": float("nan")})

    def test_producer_and_independent_verifier_serialization_match_nested_fixture(self):
        fixture = {
            "schema": "GCF/1",
            "network_id": "gaia-testnet",
            "epoch": 1,
            "weights": [1, 2, 3],
            "metadata": {"justice": "GAIA-JUSTICE/1", "active": True},
        }
        self.assertEqual(producer_canonical_bytes(fixture), verifier_canonical_bytes(fixture))


class PeerIdentityConformanceTests(unittest.TestCase):
    def test_node_private_key_must_match_validator_set_entry(self):
        key = Ed25519PrivateKey.generate()
        private = key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ).hex()
        other = Ed25519PrivateKey.generate()
        other_public = other.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ).hex()
        vset = ValidatorSet("gaia-testnet", 1, {
            "node-a": {"public_key_hex": other_public, "weight": 1},
        })
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(
                PeerTransportError, "LOCAL_PRIVATE_KEY_DOES_NOT_MATCH_VALIDATOR_ID"
            ):
                GCFPeerNode(
                    engine=object(), validator_set=vset, node_id="node-a",
                    private_key_hex=private, peer_certificate_fingerprints={},
                    replay_db_path=Path(temp) / "replay.sqlite3",
                )


if __name__ == "__main__":
    unittest.main()
