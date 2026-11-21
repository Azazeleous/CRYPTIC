"""HCCGN proof-provider boundary for GCF/1.

The canonical newly defined HCCGN-WORK/1 profile is implemented in
hccgn_work.py. Deployments connect its HCCGNWorkProofProvider with an
independent proof-envelope resolver and authenticated active-target resolver.
This adapter pins the profile ID and the proposal proof commitment.
"""
from __future__ import annotations

from typing import Any, Mapping

from src.consensus.gcf import GateResult


class HCCGNVerifierAdapter:
    """Fail-closed adapter to a separately implemented HCCGN verifier.

    Provider contract:
      verify_proof_hash(proof_hash, proposal) -> mapping with:
        valid: exactly True
        profile_id: exact configured profile identifier
        proof_hash: same 32-byte hex digest as the proposal commitment

    HCCGNWorkProofProvider implements the HCCGN-WORK/1 parser and verifier.
    The deployment supplies proof-envelope retrieval and authenticated active
    target resolution. This adapter pins the profile and proposal commitment.
    """
    def __init__(self, provider: Any | None = None, *, profile_id: str | None = None):
        self.provider = provider
        self.profile_id = profile_id

    def __call__(self, proposal: Mapping[str, Any]) -> GateResult:
        if self.provider is None:
            return GateResult(False, "HCCGN_PROOF_PROVIDER_NOT_CONNECTED")
        if not isinstance(self.profile_id, str) or not self.profile_id:
            return GateResult(False, "HCCGN_CANONICAL_PROFILE_NOT_PINNED")
        proof_hash = proposal.get("proof_hash")
        if not isinstance(proof_hash, str) or len(proof_hash) != 64:
            return GateResult(False, "HCCGN_PROOF_COMMITMENT_INVALID")
        try:
            result = self.provider.verify_proof_hash(proof_hash, proposal)
        except Exception:
            return GateResult(False, "HCCGN_PROVIDER_ERROR")
        if not isinstance(result, Mapping):
            return GateResult(False, "HCCGN_PROVIDER_RESPONSE_INVALID")
        if result.get("valid") is not True:
            return GateResult(False, "HCCGN_PROOF_REJECTED")
        if result.get("profile_id") != self.profile_id:
            return GateResult(False, "HCCGN_PROFILE_MISMATCH")
        if result.get("proof_hash") != proof_hash:
            return GateResult(False, "HCCGN_PROOF_HASH_MISMATCH")
        return GateResult(True, "HCCGN_PROOF_VERIFIED")
