"""Unified, profile-safe CRYPTIC mining orchestration.

The engine unifies scheduling, bounded execution, measurement, and independent
verification. It deliberately does NOT unify consensus preimages: SHA-256d/80,
the four-lane SHA-256 reference profile, and HCCGN-WORK/1 remain distinct,
versioned algorithms with their own serialization and target semantics.
"""
from __future__ import annotations

import base64
import os
import time
from dataclasses import asdict, dataclass
from typing import Any, Mapping

from mining.miner import mine_four_lane, verify_candidate as verify_four_lane
from src.consensus.hccgn_work import HCCGNWorkHeader, mine_nonce, verify_proof
from src.mining.sha256d import scan_nonce_range, verify_candidate as verify_sha256d

PROFILE_SHA256D_80 = "sha256d-80-v1"
PROFILE_FOUR_LANE_SHA256 = "four-lane-sha256-v1"
PROFILE_HCCGN_WORK = "hccgn-work-v1"
SUPPORTED_PROFILES = (
    PROFILE_SHA256D_80,
    PROFILE_FOUR_LANE_SHA256,
    PROFILE_HCCGN_WORK,
)
DEFAULT_MAX_ATTEMPTS = 1_000_000
HARD_MAX_ATTEMPTS = 100_000_000


class MiningEngineError(ValueError):
    """Invalid or unsupported mining request."""


@dataclass(frozen=True)
class MiningReceipt:
    schema: str
    profile_id: str
    status: str
    verified: bool
    attempts: int
    elapsed_seconds: float
    hashes_per_second: float
    workers: int
    candidate: Mapping[str, Any] | None
    verification: Mapping[str, Any]
    metrics: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "profile_id": self.profile_id,
            "status": self.status,
            "verified": self.verified,
            "attempts": self.attempts,
            "elapsed_seconds": self.elapsed_seconds,
            "hashes_per_second": self.hashes_per_second,
            "workers": self.workers,
            "candidate": dict(self.candidate) if self.candidate is not None else None,
            "verification": dict(self.verification),
            "metrics": dict(self.metrics),
        }


def _bounded_attempts(value: int, *, maximum: int = HARD_MAX_ATTEMPTS) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MiningEngineError("max_attempts_must_be_integer")
    if not 1 <= value <= maximum:
        raise MiningEngineError("max_attempts_out_of_bounds")
    return value


def _workers(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise MiningEngineError("workers_must_be_positive_integer")
    return min(value, max(1, os.cpu_count() or 1))


def _receipt(
    *,
    profile: str,
    started: float,
    attempts: int,
    workers: int,
    candidate: Mapping[str, Any] | None,
    verified: bool,
    verification: Mapping[str, Any],
    metrics: Mapping[str, Any] | None = None,
) -> MiningReceipt:
    elapsed = max(time.perf_counter() - started, 1e-12)
    return MiningReceipt(
        schema="CRYPTIC-MINING-RECEIPT/1",
        profile_id=profile,
        status="verified_candidate" if candidate is not None and verified
        else "no_candidate" if candidate is None and verified
        else "verification_failed",
        verified=verified,
        attempts=attempts,
        elapsed_seconds=elapsed,
        hashes_per_second=attempts / elapsed,
        workers=workers,
        candidate=candidate,
        verification=verification,
        metrics=dict(metrics or {}),
    )


class UnifiedMiningEngine:
    """Explicit profile router for the repository's three proof pipelines.

    A request must name its consensus profile. There is no heuristic auto-detect
    and no fallback between profiles because their wire formats are not
    interchangeable.
    """

    @staticmethod
    def profiles() -> tuple[str, ...]:
        return SUPPORTED_PROFILES

    def mine(
        self,
        profile_id: str,
        *,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        workers: int = 1,
        chunk_size: int = 50_000,
        **inputs: Any,
    ) -> MiningReceipt:
        if profile_id not in SUPPORTED_PROFILES:
            raise MiningEngineError("mining_profile_unsupported")
        bound = _bounded_attempts(max_attempts)
        worker_count = _workers(workers)
        if profile_id == PROFILE_SHA256D_80:
            return self._mine_sha256d(
                max_attempts=bound, workers=worker_count,
                chunk_size=chunk_size, **inputs,
            )
        if profile_id == PROFILE_FOUR_LANE_SHA256:
            return self._mine_four_lane(
                max_attempts=bound, workers=min(worker_count, 4), **inputs,
            )
        if worker_count != 1:
            raise MiningEngineError("hccgn_work_v1_requires_single_worker")
        return self._mine_hccgn(
            max_attempts=bound, **inputs,
        )

    def _mine_sha256d(
        self, *, header: bytes, target: int, start_nonce: int = 0,
        max_attempts: int, workers: int, chunk_size: int,
    ) -> MiningReceipt:
        if isinstance(start_nonce, bool) or not isinstance(start_nonce, int) or start_nonce < 0:
            raise MiningEngineError("nonce_start_invalid")
        if not isinstance(chunk_size, int) or isinstance(chunk_size, bool) or chunk_size < 1:
            raise MiningEngineError("chunk_size_invalid")
        stop_nonce = start_nonce + max_attempts
        if stop_nonce > (1 << 32):
            raise MiningEngineError("sha256d_nonce_range_overflow")
        started = time.perf_counter()
        result = scan_nonce_range(
            header, target, start_nonce, stop_nonce,
            workers=workers, chunk_size=chunk_size, optimized=True,
            max_candidates=1,
        )
        candidates = []
        for item in result.candidates:
            if not verify_sha256d(header, item, target):
                return _receipt(
                    profile=PROFILE_SHA256D_80, started=started,
                    attempts=result.attempts, workers=result.workers,
                    candidate={"nonce": item.nonce, "digest_hex": item.digest_hex},
                    verified=False,
                    verification={"valid": False, "reason": "independent_sha256d_verification_failed"},
                    metrics={"chunks_completed": result.chunks_completed,
                             "final_chunk_size": result.final_chunk_size},
                )
            candidates.append({
                "nonce": item.nonce, "digest_hex": item.digest_hex,
                "hash_value": item.hash_value, "target": item.target,
            })
        candidate = candidates[0] if candidates else None
        return _receipt(
            profile=PROFILE_SHA256D_80, started=started,
            attempts=result.attempts, workers=result.workers,
            candidate=candidate, verified=True,
            verification={"valid": True, "method": "independent_full_header_sha256d"},
            metrics={
                "chunks_completed": result.chunks_completed,
                "final_chunk_size": result.final_chunk_size,
                "retained_candidate_count": len(candidates),
                "nonce_range": [start_nonce, stop_nonce],
            },
        )

    def _mine_four_lane(
        self, *, header: bytes, target: int, start_nonce: int = 0,
        max_attempts: int, workers: int,
    ) -> MiningReceipt:
        if isinstance(start_nonce, bool) or not isinstance(start_nonce, int) or start_nonce < 0:
            raise MiningEngineError("nonce_start_invalid")
        started = time.perf_counter()
        result = mine_four_lane(header, start_nonce, max_attempts, target, workers=workers)
        candidate = None
        valid = True
        verification: dict[str, Any] = {
            "valid": True, "method": "independent_four_lane_candidate_recompute",
        }
        if result is not None:
            valid = verify_four_lane(header, result, target)
            candidate = asdict(result)
            if not valid:
                verification = {
                    "valid": False, "reason": "independent_four_lane_verification_failed",
                }
        return _receipt(
            profile=PROFILE_FOUR_LANE_SHA256, started=started,
            attempts=max_attempts, workers=workers,
            candidate=candidate, verified=valid,
            verification=verification,
            metrics={"nonce_start": start_nonce, "scheduled_ordinals": max_attempts},
        )

    def _mine_hccgn(
        self, *, header: HCCGNWorkHeader, network_id: str,
        start_nonce: int = 0, max_attempts: int,
    ) -> MiningReceipt:
        if not isinstance(header, HCCGNWorkHeader):
            raise MiningEngineError("hccgn_header_object_required")
        if not isinstance(network_id, str) or not network_id:
            raise MiningEngineError("hccgn_network_id_required")
        started = time.perf_counter()
        solved, digest, proof, proof_hash, attempts, _kernel_seconds = mine_nonce(
            header, start_nonce=start_nonce, max_attempts=max_attempts,
        )
        checked = verify_proof(
            proof, expected_network_id=network_id,
            expected_target=solved.target,
        )
        valid = (
            checked.get("valid") is True
            and checked.get("work_digest") == digest.hex()
            and checked.get("proof_hash") == proof_hash
            and checked.get("nonce") == solved.nonce
        )
        candidate = {
            "nonce": solved.nonce,
            "header_hex": solved.encode().hex(),
            "work_digest_hex": digest.hex(),
            "proof_b64": base64.b64encode(proof).decode("ascii"),
            "proof_hash": proof_hash,
        }
        return _receipt(
            profile=PROFILE_HCCGN_WORK, started=started,
            attempts=attempts, workers=1,
            candidate=candidate, verified=valid,
            verification={
                "valid": valid,
                "method": "canonical_hccgn_work_v1_proof_verifier",
                "proof_hash": proof_hash,
            },
            metrics={"nonce_start": start_nonce, "nonce_end": solved.nonce},
        )

