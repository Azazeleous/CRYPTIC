"""Fail-closed justice evidence adapter for GAIA-JUSTICE/1 commitments."""
from __future__ import annotations

from typing import Any, Callable, Mapping

from src.consensus.gcf import GateResult


REQUIRED_COMMITMENTS = {
    "justice_profile", "policy_hash", "policy_audit_hash", "evidence_root",
    "transition_hash", "value_accounting_hash", "challenge_state_hash",
}


class JusticeEvidenceVerifier:
    """Validates commitment shape, then delegates evidence checks to trusted engines.

    policy_verifier(commitment, proposal) and evidence_verifier(commitment, proposal)
    must independently retrieve and validate the referenced evidence. Digests alone
    are not treated as proof that a justice check passed.
    """
    def __init__(self, policy_verifier: Callable | None = None,
                 evidence_verifier: Callable | None = None):
        self.policy_verifier = policy_verifier
        self.evidence_verifier = evidence_verifier

    def __call__(self, proposal: Mapping[str, Any]) -> GateResult:
        commitment = proposal.get("justice_commitment")
        if not isinstance(commitment, Mapping) or set(commitment) != REQUIRED_COMMITMENTS:
            return GateResult(False, "JUSTICE_COMMITMENT_SCHEMA_INVALID")
        if commitment.get("justice_profile") != "GAIA-JUSTICE/1":
            return GateResult(False, "JUSTICE_PROFILE_UNSUPPORTED")
        for field in REQUIRED_COMMITMENTS - {"justice_profile"}:
            value = commitment.get(field)
            if not isinstance(value, str) or len(value) != 64:
                return GateResult(False, f"JUSTICE_{field.upper()}_INVALID")
            try:
                bytes.fromhex(value)
            except ValueError:
                return GateResult(False, f"JUSTICE_{field.upper()}_INVALID")
        if self.policy_verifier is None or self.evidence_verifier is None:
            return GateResult(False, "JUSTICE_EVIDENCE_VERIFIERS_NOT_CONFIGURED")
        try:
            if not self.policy_verifier(commitment, proposal):
                return GateResult(False, "JUSTICE_POLICY_NOT_VERIFIED")
            if not self.evidence_verifier(commitment, proposal):
                return GateResult(False, "JUSTICE_EVIDENCE_NOT_VERIFIED")
        except Exception:
            return GateResult(False, "JUSTICE_VERIFICATION_ERROR")
        return GateResult(True, "JUSTICE_EVIDENCE_VERIFIED")
