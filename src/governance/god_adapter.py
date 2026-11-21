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
