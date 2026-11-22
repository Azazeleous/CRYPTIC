"""End-to-end HCCGN policy update orchestration over GCF finality.

This coordinator composes existing production boundaries; it does not collect
remote votes itself. Validators submit PREVOTE/PRECOMMIT through GCFWSGI or the
peer transport. Only a certificate finalized by the local GCF engine can be
passed into the independently verifying sequence-anchor client.
"""
from __future__ import annotations

import secrets
import time
from typing import Any, Callable, Mapping

from src.consensus.gcf import GCFError, GCFEngine, ZERO_HASH
from src.consensus.hccgn_registry import (
    HCCGNActiveTargetPolicy, HCCGNRegistryError, HCCGNSequenceAnchor,
)
from src.governance.remote_providers import make_proposal_with_signer


class PolicyUpdateError(ValueError):
    """A policy update cannot safely advance to the next state."""


class GCFPolicyUpdateCoordinator:
    """Prepare, finalize, and install one signed HCCGN policy transition.

    The caller distributes the returned proposal to validators. Validators
    submit signed PREVOTE and PRECOMMIT messages through the existing GCF
    endpoint. This coordinator never fabricates peer votes or quorum.
    """

    def __init__(
        self,
        *,
        engine: GCFEngine,
        target_policy: HCCGNActiveTargetPolicy,
        sequence_anchor: HCCGNSequenceAnchor,
        proposer_id: str,
        proposer_signer: Any,
        clock: Callable[[], float] = time.time,
    ):
        if not isinstance(proposer_id, str) or not proposer_id:
            raise PolicyUpdateError("proposer_id_invalid")
        if not callable(getattr(proposer_signer, "sign", None)):
            raise PolicyUpdateError("proposer_signer_invalid")
        if not isinstance(getattr(proposer_signer, "public_key_hex", None), str):
            raise PolicyUpdateError("proposer_signer_public_key_invalid")
        if engine.validator_set.network_id == "":
            raise PolicyUpdateError("validator_network_invalid")
        self.engine = engine
        self.target_policy = target_policy
        self.sequence_anchor = sequence_anchor
        self.proposer_id = proposer_id
        self.proposer_signer = proposer_signer
        self.clock = clock

    def prepare(
        self,
        snapshot: Mapping[str, Any],
        *,
        proof_hash: str,
        justice_commitment: Mapping[str, Any],
        height: int,
        round: int = 0,
        expires_at: int | None = None,
        nonce: str | None = None,
    ) -> dict:
        """Verify policy material, bind it to anchor state, and submit proposal."""
        try:
            policy_hash = self.target_policy.digest_snapshot(snapshot)
            network_id = snapshot["network_id"]
            sequence = snapshot["sequence"]
            validator_set = self.engine.validator_set
            if network_id != validator_set.network_id:
                raise PolicyUpdateError("policy_network_validator_set_mismatch")
            if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
                raise PolicyUpdateError("policy_sequence_invalid")
            anchored = self.sequence_anchor.read_sequence(network_id)
            if anchored is None:
                previous_hash = ZERO_HASH
                previous_sequence = 0
            else:
                if (not isinstance(anchored, tuple) or len(anchored) != 2
                        or not isinstance(anchored[0], int)
                        or isinstance(anchored[0], bool)
                        or anchored[0] < 1
                        or not isinstance(anchored[1], str)
                        or len(anchored[1]) != 64):
                    raise PolicyUpdateError("anchor_state_invalid")
                try:
                    bytes.fromhex(anchored[1])
                except ValueError as exc:
                    raise PolicyUpdateError("anchor_state_invalid") from exc
                previous_sequence, previous_hash = anchored
            if sequence <= previous_sequence:
                raise PolicyUpdateError("policy_sequence_not_advancing")
            now = int(self.clock())
            expiry = now + 300 if expires_at is None else expires_at
            proposal = make_proposal_with_signer(
                signer=self.proposer_signer,
                network_id=network_id,
                epoch=validator_set.epoch,
                height=height,
                round=round,
                parent_hash=previous_hash,
                payload_hash=policy_hash,
                proof_hash=proof_hash,
                justice_commitment=dict(justice_commitment),
                proposer_id=self.proposer_id,
                nonce=nonce or secrets.token_hex(24),
                issued_at=now,
                expires_at=expiry,
                anchor_sequence=sequence,
            )
            accepted = self.engine.submit_proposal(proposal)
            return {
                "accepted": True,
                "candidate_digest": accepted["candidate_digest"],
                "proposal": proposal,
                "policy_hash": policy_hash,
                "previous_anchor_sequence": previous_sequence,
                "previous_anchor_hash": previous_hash,
                "anchor_sequence": sequence,
                "network_id": network_id,
                "epoch": validator_set.epoch,
                "status": accepted["status"],
                "next": "collect_validator_prevotes_then_precommits",
            }
        except (GCFError, HCCGNRegistryError) as exc:
            raise PolicyUpdateError(str(exc)) from exc

    def finalize_and_install(
        self,
        snapshot: Mapping[str, Any],
        *,
        candidate_digest: str,
    ) -> dict:
        """Require real GCF finality, then install with its exact certificate."""
        try:
            expected_policy_hash = self.target_policy.digest_snapshot(snapshot)
            finalized = self.engine.finalize(candidate_digest)
            certificate = finalized["certificate"]
            proposal = certificate["proposal"]
            if (proposal.get("network_id") != snapshot.get("network_id")
                    or proposal.get("payload_hash") != expected_policy_hash
                    or proposal.get("anchor_sequence") != snapshot.get("sequence")):
                raise PolicyUpdateError("finality_certificate_policy_binding_mismatch")
            anchored = self.sequence_anchor.read_sequence(snapshot["network_id"])
            expected_parent = ZERO_HASH if anchored is None else anchored[1]
            if proposal.get("parent_hash") != expected_parent:
                raise PolicyUpdateError("finality_certificate_parent_anchor_mismatch")
            installed_hash = self.target_policy.install(
                snapshot, finality_certificate=certificate,
            )
            if installed_hash != expected_policy_hash:
                raise PolicyUpdateError("installed_policy_digest_mismatch")
            current = self.sequence_anchor.read_sequence(snapshot["network_id"])
            if current != (snapshot["sequence"], expected_policy_hash):
                raise PolicyUpdateError("anchor_postcondition_failed")
            return {
                "installed": True,
                "network_id": snapshot["network_id"],
                "sequence": snapshot["sequence"],
                "policy_hash": installed_hash,
                "candidate_digest": candidate_digest,
                "certificate_digest": finalized["certificate_digest"],
                "precommit_weight": finalized["precommit_weight"],
                "anchor": {"sequence": current[0], "policy_hash": current[1]},
            }
        except (GCFError, HCCGNRegistryError) as exc:
            raise PolicyUpdateError(str(exc)) from exc
