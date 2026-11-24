"""Production-oriented composition helpers for GCF/1 and the HCCGN pool.

The caller supplies an already configured ConsensusRuntime. Missing proof,
validator, governance, justice, target-policy, or anchor providers fail closed.
GCF/2 certificates require a separate verifier and are not silently accepted.
"""
from __future__ import annotations

import hashlib
import time
from typing import Any, Callable, Mapping

from src.consensus.gcf import canonical_bytes, verify_finality_certificate
from src.consensus.pool_ledger import PoolShareLedger
from src.mining.pool_service import PoolCoordinator


class PoolRuntimeConfigurationError(ValueError):
    """The consensus-to-pool composition is incomplete or inconsistent."""



def build_adam_finalized_state_verifier(
    adam_store: Any,
) -> Callable[[Mapping[str, Any], Mapping[str, Any]], bool]:
    """Verify that the exact GCF certificate was durably committed by ADAM.

    AdamCommitStore.get_commit() revalidates the full append-only height/parent
    chain and the stored state bytes before returning a commitment.
    """
    getter = getattr(adam_store, "get_commit", None)
    if not callable(getter):
        raise PoolRuntimeConfigurationError("adam_commit_store_required")

    def verify(certificate: Mapping[str, Any], proposal: Mapping[str, Any]) -> bool:
        try:
            height = proposal.get("height")
            if isinstance(height, bool) or not isinstance(height, int) or height < 1:
                return False
            committed = getter(height)
            if not isinstance(committed, Mapping):
                return False
            certificate_digest = hashlib.sha256(
                b"GCF/1|FINALITY-CERTIFICATE" + bytes([0]) + canonical_bytes(dict(certificate))
            ).hexdigest()
            return (
                committed.get("height") == height
                and committed.get("candidate_digest") == certificate.get("candidate_digest")
                and committed.get("parent_hash") == proposal.get("parent_hash")
                and committed.get("state_hash") == proposal.get("payload_hash")
                and committed.get("certificate_digest") == certificate_digest
            )
        except Exception:
            return False

    return verify

def build_gcf1_pool_finality_verifier(
    *,
    hccgn_verifier: Callable,
    god_authorizer: Callable,
    justice_verifier: Callable,
    clock: Callable[[], float] = time.time,
    finalized_state_verifier: Callable[[Mapping[str, Any], Mapping[str, Any]], bool] | None = None,
    anchor_verifier: Callable[[Mapping[str, Any], Mapping[str, Any]], bool] | None = None,
) -> Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]]:
    """Create the independent GCF/1 certificate verifier used by pool settlement.

    GCF's cryptographic verifier checks the validator-set digest, proposer and
    vote signatures, proof-of-lock, and strictly greater-than-two-thirds
    PREVOTE/PRECOMMIT weights. The injected HCCGN, governance, and justice
    gates and a separate durable ADAM/APEX state-commit verifier are required.
    If a proposal binds an external anchor sequence, that anchor is checked too.
    """
    for name, provider in (
        ("hccgn_verifier", hccgn_verifier),
        ("god_authorizer", god_authorizer),
        ("justice_verifier", justice_verifier),
        ("finalized_state_verifier", finalized_state_verifier),
        ("clock", clock),
    ):
        if not callable(provider):
            raise PoolRuntimeConfigurationError(name + "_required")

    def verify(
        certificate: Mapping[str, Any],
        proposal: Mapping[str, Any],
    ) -> dict:
        fail = lambda reason: {
            "valid": False, "finalized": False, "reason": reason,
        }
        if not isinstance(certificate, Mapping) or certificate.get("schema") != "GCF/1":
            return fail("gcf1_certificate_required")
        embedded = certificate.get("proposal")
        if not isinstance(embedded, Mapping) or not isinstance(proposal, Mapping):
            return fail("finality_proposal_required")
        try:
            if canonical_bytes(dict(embedded)) != canonical_bytes(dict(proposal)):
                return fail("finality_proposal_mismatch")
        except Exception:
            return fail("finality_proposal_invalid")

        if "anchor_sequence" in proposal:
            if anchor_verifier is None:
                return fail("finality_anchor_verifier_not_configured")
            try:
                if anchor_verifier(certificate, proposal) is not True:
                    return fail("finality_anchor_not_confirmed")
            except Exception:
                return fail("finality_anchor_verification_failed")

        result = verify_finality_certificate(
            certificate,
            hccgn_verifier=hccgn_verifier,
            god_authorizer=god_authorizer,
            justice_verifier=justice_verifier,
            clock=clock,
        )
        if not isinstance(result, Mapping) or result.get("valid") is not True:
            reason = result.get("reason", "finality_certificate_invalid") if isinstance(result, Mapping) else "finality_verifier_response_invalid"
            return fail(str(reason))
        try:
            committed = finalized_state_verifier(certificate, proposal)
        except Exception:
            return fail("canonical_state_commit_verification_failed")
        if committed is not True:
            return fail("canonical_state_commit_not_confirmed")
        response = {**dict(result), "valid": True, "finalized": True}
        if "anchor_sequence" in proposal:
            response["anchor_sequence"] = proposal["anchor_sequence"]
        return response

    return verify


def build_pool_coordinator(
    *,
    consensus_runtime: Any,
    database: str,
    share_ledger: PoolShareLedger,
    issuer_private_key_hex: str,
    issuer_id: str,
    pool_id: str,
    trusted_issuer_public_key_hex: str,
    settlement_database: str,
    trusted_reward_policy_public_key_hex: str,
    clock: Callable[[], int] | None = None,
    anchor_verifier: Callable[[Mapping[str, Any], Mapping[str, Any]], bool] | None = None,
    max_submissions_per_minute: int = 120,
) -> PoolCoordinator:
    """Compose active target policy, GCF proof/finality gates, and pool ledgers.

    The target resolver is the consensus runtime's signed active-target policy.
    The settlement verifier is built from that runtime's HCCGN, governance,
    and justice gates. The reward-policy signer remains an independent trust
    root supplied by the deployment.
    """
    required = ("target_policy", "hccgn_gate", "proposal_authorizer", "justice_gate", "engine")
    if any(not hasattr(consensus_runtime, field) for field in required):
        raise PoolRuntimeConfigurationError("consensus_runtime_incomplete")
    target_policy = consensus_runtime.target_policy
    engine = consensus_runtime.engine
    validator_set = getattr(engine, "validator_set", None)
    resolver = getattr(target_policy, "resolve", None)
    if not callable(resolver) or validator_set is None:
        raise PoolRuntimeConfigurationError("active_target_policy_or_validator_set_missing")
    network_id = getattr(validator_set, "network_id", None)
    if not isinstance(network_id, str) or not network_id:
        raise PoolRuntimeConfigurationError("consensus_network_invalid")
    effective_clock = clock or getattr(engine, "clock", None) or time.time

    verifier = build_gcf1_pool_finality_verifier(
        hccgn_verifier=consensus_runtime.hccgn_gate,
        god_authorizer=consensus_runtime.proposal_authorizer,
        justice_verifier=consensus_runtime.justice_gate,
        clock=effective_clock,
        finalized_state_verifier=build_adam_finalized_state_verifier(
            getattr(consensus_runtime, "adam_store", None)
        ),
        anchor_verifier=anchor_verifier,
    )
    coordinator = PoolCoordinator(
        database=database,
        share_ledger=share_ledger,
        issuer_private_key_hex=issuer_private_key_hex,
        issuer_id=issuer_id,
        pool_id=pool_id,
        network_id=network_id,
        trusted_issuer_public_key_hex=trusted_issuer_public_key_hex,
        resolve_active_target=resolver,
        clock=effective_clock,
        max_submissions_per_minute=max_submissions_per_minute,
    )
    coordinator.configure_settlement_ledger(
        database=settlement_database,
        trusted_reward_policy_public_key_hex=trusted_reward_policy_public_key_hex,
        verify_finality_certificate=verifier,
    )
    return coordinator
