"""Adapter to the existing host-authoritative GOD network gate.

The Sovereign Operating System GOD v1 gate currently recognizes a finite
capability allowlist that does not include GCF consensus submission. This
adapter therefore denies by default until that upstream gate explicitly adds
and authorizes the GCF capability. It never reads or copies the private policy.
"""
from __future__ import annotations

import os
from typing import Any, Mapping

from src.consensus.gcf import GateResult


class GODNetworkAuthorizer:
    CAPABILITY = "gcf.consensus.propose"

    def __init__(self, god_gate: Any | None = None, *, endpoint: str | None = None):
        self.god_gate = god_gate
        self.endpoint = endpoint if endpoint is not None else os.getenv("GCF_CONSENSUS_ENDPOINT", "")

    def __call__(self, requested_capability: str, proposal: Mapping[str, Any]) -> GateResult:
        if requested_capability != "gcf.propose":
            return GateResult(False, "GOD_CAPABILITY_SCOPE_MISMATCH")
        if self.god_gate is None:
            return GateResult(False, "GOD_GATE_NOT_CONNECTED")
        if not self.endpoint:
            return GateResult(False, "GCF_CONSENSUS_ENDPOINT_NOT_CONFIGURED")
        if not callable(getattr(self.god_gate, "runnable", None)):
            return GateResult(False, "GOD_GATE_RUNNABLE_INTERFACE_MISSING")
        try:
            decision = self.god_gate.runnable(self.CAPABILITY, self.endpoint)
        except Exception:
            return GateResult(False, "GOD_GATE_EVALUATION_ERROR")
        if not isinstance(decision, Mapping) or decision.get("allowed") is not True:
            reason = decision.get("reason", "GOD_POLICY_DENIED") if isinstance(decision, Mapping) else "GOD_POLICY_INVALID_RESPONSE"
            return GateResult(False, str(reason)[:160])
        return GateResult(True, "GOD_AUTHORIZED_GCF_PROPOSAL")

class ValidatorSetProposalAuthorizer:
    """Authorize proposal admission from the active validator-set policy.

    This replaces a separate GOD network round-trip for the GCF proposal gate.
    It does not grant finality: GCF still requires its existing weighted
    PREVOTE and PRECOMMIT quorum (> 2/3) before a candidate can finalize.
    """

    def __init__(self, validator_set: Any):
        if (not isinstance(getattr(validator_set, "network_id", None), str)
                or not isinstance(getattr(validator_set, "epoch", None), int)
                or not isinstance(getattr(validator_set, "validators", None), Mapping)):
            raise ValueError("validator_set_policy_invalid")
        self.validator_set = validator_set

    def __call__(self, requested_capability: str,
                 proposal: Mapping[str, Any]) -> GateResult:
        if requested_capability != "gcf.propose":
            return GateResult(False, "VALIDATOR_POLICY_CAPABILITY_SCOPE_MISMATCH")
        if not isinstance(proposal, Mapping):
            return GateResult(False, "VALIDATOR_POLICY_PROPOSAL_INVALID")
        if (proposal.get("network_id") != self.validator_set.network_id
                or proposal.get("epoch") != self.validator_set.epoch):
            return GateResult(False, "VALIDATOR_POLICY_NETWORK_OR_EPOCH_MISMATCH")
        validator_id = proposal.get("proposer_id")
        proposer_key = proposal.get("proposer_public_key")
        validator = self.validator_set.validators.get(validator_id)
        if validator is None:
            return GateResult(False, "PROPOSER_NOT_IN_ACTIVE_VALIDATOR_SET")
        if (not isinstance(proposer_key, str)
                or proposer_key != validator.public_key_hex):
            return GateResult(False, "PROPOSER_KEY_DOES_NOT_MATCH_VALIDATOR_SET")
        return GateResult(True, "ACTIVE_VALIDATOR_PROPOSER")
