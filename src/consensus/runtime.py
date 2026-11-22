"""Explicit composition root for the GCF/HCCGN/ADAM reference runtime.

Trust material and authority providers are injected by the deployment. This
module never manufactures GOD keys, anchor state, validator identities, or
justice evidence. Missing authority integrations remain fail-closed.
"""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from src.adam.commit_store import AdamCommitStore, APEXValidator
from src.consensus.gcf import GCFEngine, ValidatorSet
from src.consensus.hccgn_adapter import HCCGNVerifierAdapter
from src.consensus.hccgn_registry import (
    HCCGNActiveTargetPolicy, HCCGNProofStore, HCCGNSequenceAnchor,
)
from src.consensus.hccgn_work import HCCGNWorkProofProvider, PROFILE_ID
from src.consensus.http_api import GCFWSGI
from src.governance.god_adapter import ValidatorSetProposalAuthorizer
from src.governance.justice_adapter import JusticeEvidenceVerifier
from src.governance.remote_providers import load_independently_pinned_root


class RuntimeConfigurationError(ValueError):
    """The composition root cannot safely construct the requested runtime."""


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
    god_gate: ValidatorSetProposalAuthorizer
    engine: GCFEngine
    adam_store: AdamCommitStore
    apex: APEXValidator
    http: GCFWSGI


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
    god_gate: Any | None,
    policy_evidence_verifier: Callable | None,
    justice_evidence_verifier: Callable | None,
    consensus_endpoint: str | None = None,
    clock=None,
    require_external_anchor: bool = True,
) -> ConsensusRuntime:
    """Build the complete local runtime around operator-supplied trust services.

    This is a composition layer, not a substitute for the actual GOD gate,
    hardware/remote monotonic anchor, validator key custody, or evidence engines.
    """
    if not isinstance(network_id, str) or not network_id:
        raise RuntimeConfigurationError("network_id_invalid")
    if not isinstance(god_signer_id, str) or not god_signer_id:
        raise RuntimeConfigurationError("god_signer_id_invalid")
    if require_external_anchor and sequence_anchor is None:
        raise RuntimeConfigurationError("external_sequence_anchor_required")
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
    adam_store = AdamCommitStore(root / "adam.sqlite3")
    apex = APEXValidator(
        adam_store, hccgn_verifier=hccgn_gate,
        god_authorizer=god_authorizer, justice_verifier=justice_gate,
    )
    http = GCFWSGI(engine, apex_validator=apex)
    for database_path in (
        root / "hccgn-proofs.sqlite3", root / "hccgn-target-policy.sqlite3",
        root / "gcf.sqlite3", root / "adam.sqlite3",
    ):
        try:
            os.chmod(database_path, 0o600)
        except OSError as exc:
            raise RuntimeConfigurationError("runtime_database_permissions_failed") from exc
    return ConsensusRuntime(
        proof_store, target_policy, work_provider, hccgn_gate, justice_gate,
        god_authorizer, engine, adam_store, apex, http,
    )
