"""Explicit composition root for the GCF/HCCGN/ADAM reference runtime.

Trust material and authority providers are injected by the deployment. This
module never manufactures GOD keys, anchor state, validator identities, or
justice evidence. Missing authority integrations remain fail-closed.
"""
from __future__ import annotations

import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from src.adam.commit_store import AdamCommitStore, APEXValidator
from src.consensus.gcf import GCFEngine, ValidatorSet
from src.consensus.gcf2_engine import GCF2VoteStore
from src.consensus.signer_guard import ConsensusSigningGuard
from src.consensus.hccgn_adapter import HCCGNVerifierAdapter
from src.consensus.hccgn_registry import (
    HCCGNActiveTargetPolicy, HCCGNProofStore, HCCGNSequenceAnchor,
)
from src.consensus.hccgn_work import HCCGNWorkProofProvider, PROFILE_ID
from src.consensus.http_api import GCFWSGI
from src.consensus.policy_update import GCFPolicyUpdateCoordinator
from src.consensus.round_progression import RoundProgressionController
from src.consensus.round_orchestrator import RoundChangeOrchestrator
from src.governance.god_adapter import ValidatorSetProposalAuthorizer
from src.governance.justice_adapter import JusticeEvidenceVerifier
from src.governance.remote_providers import load_independently_pinned_root


class RuntimeConfigurationError(ValueError):
    """The composition root cannot safely construct the requested runtime."""


def build_consensus_lock_transition_verifier(
    *, engine: GCFEngine, validator_set: ValidatorSet, clock: Callable[[], float],
) -> Callable[[str, int, Mapping[str, Any], Mapping[str, Any]], bool]:
    """Verify a signer lock transition against persisted proposals and a POLC."""
    from src.consensus.round_change import value_digest, verify_round_change_certificate

    def verify(prior_digest, prior_round, next_vote, evidence):
        if not isinstance(evidence, Mapping) or not isinstance(next_vote, Mapping):
            return False
        try:
            prior_proposal = engine._proposal(
                engine._db_context_for_read(), prior_digest
            )
        except Exception:
            # Use the engine's read helper without relying on an open transaction.
            try:
                with engine._db() as db:
                    prior_proposal = engine._proposal(db, prior_digest)
            except Exception:
                return False
        try:
            with engine._db() as db:
                next_proposal = engine._proposal(db, next_vote["candidate_digest"])
            if (next_proposal.get("round") != next_vote.get("round")
                    or next_proposal.get("height") != next_vote.get("height")
                    or next_proposal.get("network_id") != next_vote.get("network_id")
                    or next_proposal.get("epoch") != next_vote.get("epoch")
                    or next_proposal.get("round_change_certificate") != dict(evidence)):
                return False
            checked = verify_round_change_certificate(
                evidence, validator_set=validator_set,
                height=next_proposal["height"], clock=clock,
            )
            if (not checked.get("valid")
                    or checked.get("target_round") != next_proposal["round"]):
                return False
            if value_digest(prior_proposal) == value_digest(next_proposal):
                return True
            highest = checked.get("highest_polc")
            return (
                highest is not None
                and checked.get("highest_polc_round") is not None
                and checked["highest_polc_round"] > prior_round
                and value_digest(highest["proposal"]) == value_digest(next_proposal)
            )
        except Exception:
            return False

    return verify


def build_gcf2_sequence_anchor_activator(
    *, sequence_anchor: HCCGNSequenceAnchor, network_id: str,
) -> Callable[[Mapping[str, Any]], Mapping[str, Any]]:
    """Build an idempotent GCF/2-to-sequence-anchor activation adapter."""
    if (not callable(getattr(sequence_anchor, "read_sequence", None))
            or not callable(getattr(sequence_anchor, "advance_sequence", None))):
        raise RuntimeConfigurationError("gcf2_sequence_anchor_adapter_invalid")
    if not isinstance(network_id, str) or not network_id:
        raise RuntimeConfigurationError("gcf2_sequence_anchor_network_invalid")

    def activate(certificate: Mapping[str, Any]) -> Mapping[str, Any]:
        proposal = certificate.get("proposal") if isinstance(certificate, Mapping) else None
        if not isinstance(proposal, Mapping):
            raise RuntimeConfigurationError("gcf2_anchor_proposal_missing")
        sequence = proposal.get("anchor_sequence")
        parent_hash = proposal.get("parent_hash")
        policy_hash = proposal.get("payload_hash")
        if (isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1
                or not isinstance(parent_hash, str) or len(parent_hash) != 64
                or not isinstance(policy_hash, str) or len(policy_hash) != 64):
            raise RuntimeConfigurationError("gcf2_anchor_proposal_context_invalid")
        try:
            bytes.fromhex(parent_hash)
            bytes.fromhex(policy_hash)
            current = sequence_anchor.read_sequence(network_id)
        except Exception as exc:
            raise RuntimeConfigurationError("gcf2_anchor_state_unavailable") from exc
        if current is None:
            current_sequence, current_hash = 0, "0" * 64
        else:
            if (not isinstance(current, tuple) or len(current) != 2
                    or isinstance(current[0], bool) or not isinstance(current[0], int)
                    or current[0] < 0 or not isinstance(current[1], str)
                    or len(current[1]) != 64):
                raise RuntimeConfigurationError("gcf2_anchor_state_invalid")
            current_sequence, current_hash = current[0], current[1].lower()
        certificate_digest = certificate.get("certificate_digest")
        if (current_sequence == sequence and current_hash == policy_hash.lower()):
            return {
                "accepted": True, "finalized": True, "replayed": True,
                "anchor_sequence": sequence,
                "certificate_digest": certificate_digest,
            }
        if sequence != current_sequence + 1:
            raise RuntimeConfigurationError("gcf2_anchor_sequence_not_next")
        if parent_hash.lower() != current_hash:
            raise RuntimeConfigurationError("gcf2_anchor_parent_mismatch")
        envelope = {
            "schema": "GCF/2-ANCHOR-ENVELOPE/1",
            "proposal": dict(proposal), "certificate": dict(certificate),
        }
        try:
            accepted = sequence_anchor.advance_sequence(
                network_id, sequence, policy_hash.lower(), certificate=envelope,
            )
            observed = sequence_anchor.read_sequence(network_id)
        except Exception as exc:
            raise RuntimeConfigurationError("gcf2_anchor_advance_failed") from exc
        if accepted is not True or observed != (sequence, policy_hash.lower()):
            raise RuntimeConfigurationError("gcf2_anchor_advance_not_confirmed")
        return {
            "accepted": True, "finalized": True, "replayed": False,
            "anchor_sequence": sequence, "certificate_digest": certificate_digest,
        }

    return activate


def load_pinned_ed25519_public_key(path: str | os.PathLike[str]) -> bytes:
    """Load a 32-byte raw or 64-character hex key without following a symlink."""
    key_path = Path(path).expanduser()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(key_path, flags)
    except OSError as exc:
        raise RuntimeConfigurationError("god_trust_root_unavailable_or_symlink") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeConfigurationError("god_trust_root_must_be_regular_file")
        if info.st_mode & 0o022:
            raise RuntimeConfigurationError("god_trust_root_group_or_world_writable")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise RuntimeConfigurationError("god_trust_root_owner_mismatch")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(4097)
        if len(raw) > 4096:
            raise RuntimeConfigurationError("god_trust_root_file_too_large")
    finally:
        os.close(descriptor)
    if len(raw) != 32:
        raw = raw.strip()
    if len(raw) == 64:
        try:
            raw = bytes.fromhex(raw.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise RuntimeConfigurationError("god_trust_root_encoding_invalid") from exc
    if len(raw) != 32:
        raise RuntimeConfigurationError("god_trust_root_length_invalid")
    return raw

@dataclass(frozen=True)
class ConsensusRuntime:
    proof_store: HCCGNProofStore
    target_policy: HCCGNActiveTargetPolicy
    work_provider: HCCGNWorkProofProvider
    hccgn_gate: HCCGNVerifierAdapter
    justice_gate: JusticeEvidenceVerifier
    proposal_authorizer: ValidatorSetProposalAuthorizer
    engine: GCFEngine
    adam_store: AdamCommitStore
    apex: APEXValidator
    policy_update: GCFPolicyUpdateCoordinator | None
    round_progression: RoundProgressionController
    round_orchestrator: RoundChangeOrchestrator | None
    gcf2_vote_store: GCF2VoteStore | None
    signer_guard: ConsensusSigningGuard | None
    http: GCFWSGI

    @property
    def god_gate(self) -> ValidatorSetProposalAuthorizer:
        """Backward-compatible alias; proposal admission is validator-set policy."""
        return self.proposal_authorizer


def build_consensus_runtime(
    *,
    network_id: str,
    epoch: int,
    validators: Mapping[str, Mapping[str, Any]],
    data_dir: str | os.PathLike[str],
    god_trust_root_path: str | os.PathLike[str],
    god_signer_id: str,
    god_trust_root_fingerprint: str | None = None,
    sequence_anchor: HCCGNSequenceAnchor | None,
    god_gate: Any | None = None,
    policy_evidence_verifier: Callable | None,
    justice_evidence_verifier: Callable | None,
    consensus_endpoint: str | None = None,
    clock=None,
    require_external_anchor: bool = True,
    policy_update_proposer_id: str | None = None,
    policy_update_signer: Any | None = None,
    policy_update_peer_mesh: Any | None = None,
    local_validator_id: str | None = None,
    round_change_signer: Callable | None = None,
    round_change_broadcaster: Callable | None = None,
    enable_gcf2_vote_store: bool = False,
    gcf2_active_parent_resolver: Callable[[int], str | None] | None = None,
    consensus_sign_bytes: Callable[[bytes], bytes] | None = None,
    gcf2_finality_activator: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
) -> ConsensusRuntime:
    """Build the complete local runtime around operator-supplied trust services.

    Proposal admission is local to the active validator set. The independent
    sequence anchor, HCCGN trust root, validator key custody, and justice
    evidence providers remain separate deployment trust boundaries.
    """
    if not isinstance(network_id, str) or not network_id:
        raise RuntimeConfigurationError("network_id_invalid")
    if not isinstance(god_signer_id, str) or not god_signer_id:
        raise RuntimeConfigurationError("god_signer_id_invalid")
    if require_external_anchor and sequence_anchor is None:
        raise RuntimeConfigurationError("external_sequence_anchor_required")
    if (policy_update_proposer_id is None) != (policy_update_signer is None):
        raise RuntimeConfigurationError("policy_update_proposer_and_signer_must_be_paired")
    if policy_update_signer is not None and sequence_anchor is None:
        raise RuntimeConfigurationError("policy_update_requires_sequence_anchor")
    if not isinstance(enable_gcf2_vote_store, bool):
        raise RuntimeConfigurationError("gcf2_enable_flag_invalid")
    if enable_gcf2_vote_store and not callable(gcf2_active_parent_resolver):
        raise RuntimeConfigurationError("gcf2_requires_trusted_active_parent_resolver")
    if consensus_sign_bytes is not None and (not callable(consensus_sign_bytes) or local_validator_id is None):
        raise RuntimeConfigurationError("consensus_signer_requires_local_validator_and_provider")
    if policy_update_peer_mesh is not None and policy_update_signer is None:
        raise RuntimeConfigurationError("policy_update_peer_mesh_requires_coordinator")
    round_orchestrator_args = (local_validator_id, round_change_signer, round_change_broadcaster)
    if any(item is not None for item in round_orchestrator_args) and not all(
        item is not None for item in round_orchestrator_args
    ):
        raise RuntimeConfigurationError("round_orchestrator_requires_validator_signer_and_broadcaster")
    root = Path(data_dir).expanduser()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root_info = root.lstat()
    if not root.is_dir() or root.is_symlink():
        raise RuntimeConfigurationError("runtime_data_dir_must_be_real_directory")
    if root_info.st_mode & 0o077:
        raise RuntimeConfigurationError("runtime_data_dir_permissions_must_be_private")
    if hasattr(os, "getuid") and root_info.st_uid != os.getuid():
        raise RuntimeConfigurationError("runtime_data_dir_owner_mismatch")
    if require_external_anchor:
        if (not isinstance(god_trust_root_fingerprint, str)
                or len(god_trust_root_fingerprint) != 64):
            raise RuntimeConfigurationError("independent_god_root_fingerprint_required")
        try:
            bytes.fromhex(god_trust_root_fingerprint)
        except ValueError as exc:
            raise RuntimeConfigurationError("independent_god_root_fingerprint_invalid") from exc
        try:
            public_key = load_independently_pinned_root(
                str(god_trust_root_path),
                expected_fingerprint=god_trust_root_fingerprint,
                expected_signer_id=god_signer_id,
            )
        except Exception as exc:
            raise RuntimeConfigurationError("independent_god_root_pin_invalid") from exc
    else:
        public_key = load_pinned_ed25519_public_key(god_trust_root_path)

    policy_kwargs = {
        "trusted_public_key": public_key,
        "trusted_signer_id": god_signer_id,
        "sequence_anchor": sequence_anchor,
        "require_external_anchor": require_external_anchor,
    }
    if clock is not None:
        policy_kwargs["clock"] = clock

    proof_store = HCCGNProofStore(root / "hccgn-proofs.sqlite3")
    target_policy = HCCGNActiveTargetPolicy(
        root / "hccgn-target-policy.sqlite3", **policy_kwargs
    )
    work_provider = HCCGNWorkProofProvider(
        resolve_proof=proof_store.get,
        resolve_target=target_policy.resolve,
    )
    hccgn_gate = HCCGNVerifierAdapter(work_provider, profile_id=PROFILE_ID)
    justice_gate = JusticeEvidenceVerifier(
        policy_verifier=policy_evidence_verifier,
        evidence_verifier=justice_evidence_verifier,
    )
    validator_set = ValidatorSet(network_id, epoch, validators)
    # Proposal admission is governed by the configured validator set. The
    # independent GCF PREVOTE/PRECOMMIT weighted quorum still controls finality.
    # god_gate is retained as a compatibility argument but is not consulted.
    god_authorizer = ValidatorSetProposalAuthorizer(validator_set)
    engine_kwargs = {
        "hccgn_verifier": hccgn_gate,
        "god_authorizer": god_authorizer,
        "justice_verifier": justice_gate,
    }
    if clock is not None:
        engine_kwargs["clock"] = clock
    engine = GCFEngine(root / "gcf.sqlite3", validator_set, **engine_kwargs)
    signer_guard = None
    if consensus_sign_bytes is not None:
        local_validator = validator_set.validators.get(local_validator_id)
        if local_validator is None:
            raise RuntimeConfigurationError("consensus_signer_local_validator_unknown")
        signer_guard = ConsensusSigningGuard(
            database=root / "gcf.sqlite3", network_id=network_id,
            epoch=epoch, validator_id=local_validator_id,
            public_key_hex=local_validator.public_key_hex,
            sign_bytes=consensus_sign_bytes,
            verify_lock_transition=build_consensus_lock_transition_verifier(
                engine=engine, validator_set=validator_set,
                clock=clock or time.time,
            ),
        )
    if gcf2_finality_activator is not None and not callable(gcf2_finality_activator):
        raise RuntimeConfigurationError("gcf2_finality_activator_invalid")
    if not enable_gcf2_vote_store and gcf2_finality_activator is not None:
        raise RuntimeConfigurationError("gcf2_finality_activator_requires_gcf2")
    finality_activator = gcf2_finality_activator
    if enable_gcf2_vote_store and finality_activator is None and sequence_anchor is not None:
        finality_activator = build_gcf2_sequence_anchor_activator(
            sequence_anchor=sequence_anchor, network_id=network_id,
        )
    gcf2_vote_store = None
    if enable_gcf2_vote_store:
        gcf2_vote_store = GCF2VoteStore(
            database=root / "gcf.sqlite3", validator_set=validator_set,
            gcf1_engine=engine,
            resolve_active_parent=gcf2_active_parent_resolver,
            clock=clock or time.time,
            finality_activator=finality_activator,
        )
    adam_store = AdamCommitStore(root / "adam.sqlite3")
    apex = APEXValidator(
        adam_store, hccgn_verifier=hccgn_gate,
        god_authorizer=god_authorizer, justice_verifier=justice_gate,
    )
    policy_update = None
    if policy_update_signer is not None:
        policy_update = GCFPolicyUpdateCoordinator(
            engine=engine,
            target_policy=target_policy,
            sequence_anchor=sequence_anchor,
            proposer_id=policy_update_proposer_id,
            proposer_signer=policy_update_signer,
            peer_mesh=policy_update_peer_mesh,
            clock=clock or time.time,
        )
    round_progression = RoundProgressionController(
        engine=engine, database=root / "round-progression.sqlite3",
        monotonic=time.monotonic,
    )
    round_orchestrator = None
    if local_validator_id is not None:
        round_orchestrator = RoundChangeOrchestrator(
            engine=engine, controller=round_progression,
            validator_id=local_validator_id,
            sign_round_change=round_change_signer,
            broadcast_round_change=round_change_broadcaster,
            clock=clock or time.time,
        )
    http = GCFWSGI(engine, apex_validator=apex, gcf2_vote_store=gcf2_vote_store)
    for database_path in (
        root / "hccgn-proofs.sqlite3", root / "hccgn-target-policy.sqlite3",
        root / "gcf.sqlite3", root / "adam.sqlite3",
        root / "round-progression.sqlite3",
    ):
        try:
            os.chmod(database_path, 0o600)
        except OSError as exc:
            raise RuntimeConfigurationError("runtime_database_permissions_failed") from exc
    return ConsensusRuntime(
        proof_store, target_policy, work_provider, hccgn_gate, justice_gate,
        god_authorizer, engine, adam_store, apex, policy_update,
        round_progression, round_orchestrator, gcf2_vote_store, signer_guard, http,
    )
