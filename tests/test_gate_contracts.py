import os
import stat
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.consensus.gcf import GCFEngine, GateResult, _require_int
from src.consensus.independent_verifier import _integer, IndependentVerificationError
from src.consensus.runtime import (
    RuntimeConfigurationError, build_consensus_runtime,
    load_pinned_ed25519_public_key,
)
from src.governance.justice_adapter import JusticeEvidenceVerifier


class GateContractTests(unittest.TestCase):
    def test_consensus_integer_values_fit_sqlite_signed_range(self):
        maximum = (1 << 63) - 1
        self.assertEqual(_require_int(maximum, "height", 1), maximum)
        with self.assertRaisesRegex(ValueError, "height"):
            _require_int(maximum + 1, "height", 1)
        self.assertEqual(_integer(maximum, "HEIGHT", 1), maximum)
        with self.assertRaisesRegex(IndependentVerificationError, "HEIGHT_INVALID_INTEGER"):
            _integer(maximum + 1, "HEIGHT", 1)

    def test_gcf_gate_accepts_only_exact_boolean_or_valid_gate_result(self):
        engine = object.__new__(GCFEngine)
        self.assertTrue(engine._gate(lambda: True).allowed)
        self.assertFalse(engine._gate(lambda: 1).allowed)
        self.assertFalse(engine._gate(lambda: object()).allowed)
        self.assertTrue(engine._gate(lambda: GateResult(True, "authorized")).allowed)
        self.assertFalse(engine._gate(lambda: GateResult(1, "bad")).allowed)
        self.assertFalse(engine._gate(lambda: (_ for _ in ()).throw(RuntimeError())).allowed)

    def test_justice_verifiers_must_return_exact_true(self):
        commitment = {
            "justice_profile": "GAIA-JUSTICE/1",
            "policy_hash": "11" * 32,
            "policy_audit_hash": "22" * 32,
            "evidence_root": "33" * 32,
            "transition_hash": "44" * 32,
            "value_accounting_hash": "55" * 32,
            "challenge_state_hash": "66" * 32,
        }
        proposal = {"justice_commitment": commitment}
        verifier = JusticeEvidenceVerifier(
            policy_verifier=lambda *_: "yes",
            evidence_verifier=lambda *_: True,
        )
        self.assertFalse(verifier(proposal).allowed)
        verifier = JusticeEvidenceVerifier(
            policy_verifier=lambda *_: True,
            evidence_verifier=lambda *_: True,
        )
        self.assertTrue(verifier(proposal).allowed)


class RuntimeCompositionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.key_path = self.root / "god-root.pub"
        self.key_path.write_bytes(public)
        os.chmod(self.key_path, 0o600)

    def tearDown(self):
        self.temp.cleanup()

    class Anchor:
        def __init__(self): self.values = {}
        def read_sequence(self, network_id): return self.values.get(network_id)
        def advance_sequence(self, network_id, sequence, policy_hash):
            current = self.values.get(network_id)
            if current is not None and sequence <= current[0]:
                return False
            self.values[network_id] = (sequence, policy_hash)
            return True

    def test_runtime_composes_all_components_and_keeps_missing_authorities_denied(self):
        runtime = build_consensus_runtime(
            network_id="gaia-testnet", epoch=1,
            validators={"validator-a": {
                "public_key_hex": "11" * 32, "weight": 1,
            }},
            data_dir=self.root / "data",
            god_trust_root_path=self.key_path,
            god_signer_id="GOD-ROOT-1",
            sequence_anchor=self.Anchor(),
            god_gate=None,
            policy_evidence_verifier=None,
            justice_evidence_verifier=None,
            consensus_endpoint="https://consensus.invalid",
        )
        self.assertIs(runtime.http.apex_validator, runtime.apex)
        self.assertFalse(runtime.god_gate("gcf.propose", {}).allowed)
        self.assertFalse(runtime.justice_gate({
            "justice_commitment": {},
        }).allowed)

    def test_runtime_requires_external_anchor_by_default(self):
        with self.assertRaisesRegex(RuntimeConfigurationError, "external_sequence_anchor_required"):
            build_consensus_runtime(
                network_id="gaia-testnet", epoch=1, validators={},
                data_dir=self.root / "data2",
                god_trust_root_path=self.key_path, god_signer_id="GOD-ROOT-1",
                sequence_anchor=None, god_gate=None,
                policy_evidence_verifier=None, justice_evidence_verifier=None,
                consensus_endpoint="https://consensus.invalid",
            )

    def test_trust_root_rejects_group_or_world_writable_file(self):
        os.chmod(self.key_path, 0o666)
        with self.assertRaisesRegex(RuntimeConfigurationError, "group_or_world_writable"):
            load_pinned_ed25519_public_key(self.key_path)


if __name__ == "__main__":
    unittest.main()
