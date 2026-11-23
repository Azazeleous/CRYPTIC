import tempfile
import unittest
from pathlib import Path

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
