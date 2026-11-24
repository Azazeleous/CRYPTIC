import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.consensus.runtime import (
    RuntimeConfigurationError, build_consensus_runtime,
)


class GCF2RuntimeCompositionTests(unittest.TestCase):
    def test_gcf2_runtime_requires_injected_trusted_parent_resolver(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                RuntimeConfigurationError,
                "gcf2_requires_trusted_active_parent_resolver",
            ):
                build_consensus_runtime(
                    network_id="gaia-testnet", epoch=1, validators={},
                    data_dir=Path(directory) / "runtime",
                    god_trust_root_path=Path(directory) / "root.pub",
                    god_signer_id="root", sequence_anchor=None,
                    policy_evidence_verifier=None,
                    justice_evidence_verifier=None,
                    require_external_anchor=False,
                    enable_gcf2_vote_store=True,
                )

    def test_runtime_composes_gcf2_store_with_explicit_anchor_activator(self):
        class Anchor:
            def read_sequence(self, network_id):
                return None

            def advance_sequence(self, network_id, sequence, policy_hash, *, certificate=None):
                return False

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = Ed25519PrivateKey.generate()
            public = key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw,
            ).hex()
            root_key = root / "root.pub"
            root_key.write_bytes(bytes.fromhex(public))
            root_key.chmod(0o600)
            runtime = build_consensus_runtime(
                network_id="gaia-testnet", epoch=1,
                validators={"v0": {"public_key_hex": public, "weight": 1}},
                data_dir=root / "runtime", god_trust_root_path=root_key,
                god_signer_id="root", sequence_anchor=Anchor(),
                policy_evidence_verifier=None,
                justice_evidence_verifier=None,
                require_external_anchor=False,
                enable_gcf2_vote_store=True,
                gcf2_active_parent_resolver=lambda _height: "00" * 32,
            )
            self.assertIsNotNone(runtime.gcf2_vote_store)
            self.assertIs(runtime.http.gcf2_vote_store, runtime.gcf2_vote_store)
            self.assertTrue(callable(runtime.gcf2_vote_store.finality_activator))

    def test_gcf2_runtime_enable_flag_must_be_boolean(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                RuntimeConfigurationError, "gcf2_enable_flag_invalid"
            ):
                build_consensus_runtime(
                    network_id="gaia-testnet", epoch=1, validators={},
                    data_dir=Path(directory) / "runtime",
                    god_trust_root_path=Path(directory) / "root.pub",
                    god_signer_id="root", sequence_anchor=None,
                    policy_evidence_verifier=None,
                    justice_evidence_verifier=None,
                    require_external_anchor=False,
                    enable_gcf2_vote_store=1,
                )


if __name__ == "__main__":
    unittest.main()
