"""Four-lane GAIA/NEXUS local proof-trophy solver.

This mines a local SHA-256d challenge and records portable proof trophies.
It is not an HCCGN network adapter and does not claim network acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .gaia_fabric import (
    build_lane_plan,
    compute_difficulty_stratified_guarantees,
    discrete_divergence,
    hodge_star_sign,
    schlafli_cycle,
)
from .receipt_wallet import append_to_wallet, create_receipt
from .sha256d import (
    Candidate,
    double_sha256,
    scan_nonce_range,
    serialize_header_with_nonce,
    verify_candidate,
)
from .trophy_manifest import create_manifest, export_manifest

UINT32_LIMIT = 1 << 32
UINT256_LIMIT = 1 << 256
DEFAULT_WALLET = "~/.cryptic/trophies/wallet.jsonl"
DEFAULT_MANIFESTS = "~/.cryptic/trophies/manifests"


def target_for_difficulty(difficulty: int) -> int:
    """Return an inclusive 256-bit target with exactly 2**(-difficulty) success probability."""
    if isinstance(difficulty, bool) or not isinstance(difficulty, int) or not 1 <= difficulty <= 255:
        raise ValueError("difficulty must be an integer in [1, 255]")
    return ((1 << 256) - 1) >> difficulty


def attempts_for_confidence(difficulty: int, confidence: float) -> int:
    """Exact geometric-trial budget for at least the requested success probability."""
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be between zero and one")
    p = 2.0 ** (-difficulty)
    return math.ceil(math.log1p(-confidence) / math.log1p(-p))


def build_trophy_header(
    challenge_id: str,
    seed: str,
    ruleset_id: str,
    timestamp: int,
    run_id: str,
    version: int = 1,
) -> bytes:
    """Build a canonical 76-byte local challenge prefix for the 80-byte SHA-256d kernel."""
    if not challenge_id.strip() or not seed.strip() or not ruleset_id.strip() or not run_id.strip():
        raise ValueError("challenge_id, seed, ruleset_id, and run_id must be nonempty")
    if not 0 <= timestamp < UINT32_LIMIT:
        raise ValueError("timestamp must fit an unsigned 32-bit integer")
    if not 0 <= version < UINT32_LIMIT:
        raise ValueError("version must fit an unsigned 32-bit integer")

    challenge_material = (
        b"CRYPTIC-GAIA-TROPHY-CHALLENGE-v1\0"
        + challenge_id.encode("utf-8")
        + b"\0"
        + run_id.encode("ascii")
    )
    challenge_hash = hashlib.sha256(challenge_material).digest()
    seed_hash = hashlib.sha256(b"CRYPTIC-GAIA-TROPHY-SEED-v1\0" + seed.encode("utf-8")).digest()
    ruleset_tag = hashlib.sha256(b"CRYPTIC-GAIA-TROPHY-RULESET-v1\0" + ruleset_id.encode("utf-8")).digest()[:4]
    prefix = (
        version.to_bytes(4, "little")
        + challenge_hash
        + seed_hash
        + timestamp.to_bytes(4, "little")
        + ruleset_tag
    )
    if len(prefix) != 76:
        raise AssertionError("local trophy header prefix must be exactly 76 bytes")
    return prefix + b"\0\0\0\0"


def _scan_reverse_chunk(
    header: bytes,
    target: int,
    start_nonce: int,
    stop_nonce: int,
) -> list[Candidate]:
    """Independent reference kernel scanning a half-open range in descending nonce order."""
    found: list[Candidate] = []
    for nonce in range(stop_nonce - 1, start_nonce - 1, -1):
        digest = double_sha256(serialize_header_with_nonce(header, nonce))
        value = int.from_bytes(digest, "little")
        if value <= target:
            found.append(Candidate(nonce, digest.hex(), value, target))
    return found


def scan_reverse_nonce_range(
    header: bytes,
    target: int,
    start_nonce: int,
    stop_nonce: int,
    *,
    workers: int = 1,
    chunk_size: int = 50_000,
) -> dict[str, Any]:
    """Scan a finite range from high to low using the independent full-header kernel."""
    if not 0 <= start_nonce <= stop_nonce <= UINT32_LIMIT:
        raise ValueError("nonce range must satisfy 0 <= start <= stop <= 2**32")
    if workers < 1 or chunk_size < 1:
        raise ValueError("workers and chunk_size must be positive")
    if len(header) != 80:
        raise ValueError("header must be exactly 80 bytes")
    if not 0 <= target < UINT256_LIMIT:
        raise ValueError("target must be in [0, 2**256)")

    started = time.perf_counter()
    chunks: list[tuple[int, int]] = []
    cursor = stop_nonce
    while cursor > start_nonce:
        left = max(start_nonce, cursor - chunk_size)
        chunks.append((left, cursor))
        cursor = left

    candidates: list[Candidate] = []
    worker_count = min(workers, max(1, os.cpu_count() or 1))
    if worker_count == 1 or len(chunks) <= 1:
        for left, right in chunks:
            candidates.extend(_scan_reverse_chunk(header, target, left, right))
        used_workers = 1 if chunks else 0
    elif chunks:
        from concurrent.futures import ProcessPoolExecutor

        with ProcessPoolExecutor(max_workers=worker_count) as executor:
            for found in executor.map(
                _scan_reverse_chunk,
                [header] * len(chunks),
                [target] * len(chunks),
                [item[0] for item in chunks],
                [item[1] for item in chunks],
            ):
                candidates.extend(found)
        used_workers = worker_count
    else:
        used_workers = 0

    elapsed = max(time.perf_counter() - started, 1e-12)
    return {
        "start_nonce": start_nonce,
        "stop_nonce": stop_nonce,
        "attempts": stop_nonce - start_nonce,
        "elapsed_seconds": elapsed,
        "hashes_per_second": (stop_nonce - start_nonce) / elapsed,
        "workers": used_workers,
        "chunks_completed": len(chunks),
        "candidates": tuple(sorted(candidates, key=lambda item: item.nonce)),
        "direction": "reverse",
        "kernel": "independent_full_header_reference",
    }


def mine_trophy_ladder(
    *,
    challenge_id: str,
    seed: str,
    min_difficulty: int = 4,
    max_difficulty: int = 16,
    confidence: float = 0.99,
    start_nonce: int = 0,
    max_attempts: int | None = None,
    workers: int = 4,
    chunk_size: int = 50_000,
    wallet_id: str = "local:gaia-nexus",
    ruleset_id: str = "cryptic-gaia-trophy-v1",
    wallet_file: str | os.PathLike[str] = DEFAULT_WALLET,
    manifest_dir: str | os.PathLike[str] = DEFAULT_MANIFESTS,
    window_seconds: int = 3600,
) -> dict[str, Any]:
    """Mine a nested difficulty ladder and persist independently verified trophies."""
    if not 1 <= min_difficulty <= max_difficulty <= 16:
        raise ValueError("trophy difficulty range must satisfy 1 <= min <= max <= 16")
    if workers < 1 or chunk_size < 1 or window_seconds < 1:
        raise ValueError("workers, chunk_size, and window_seconds must be positive")
    if not 0 <= start_nonce < UINT32_LIMIT:
        raise ValueError("start_nonce must be in [0, 2**32)")
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be between zero and one")

    planned_attempts = attempts_for_confidence(max_difficulty, confidence)
    attempts = planned_attempts if max_attempts is None else int(max_attempts)
    if attempts < 1 or start_nonce + attempts > UINT32_LIMIT:
        raise ValueError("attempt budget must be positive and remain within the 32-bit nonce space")

    run_started = int(time.time())
    monotonic_started = time.perf_counter()
    run_id = secrets.token_hex(16)
    header = build_trophy_header(challenge_id, seed, ruleset_id, run_started, run_id)
    stop_nonce = start_nonce + attempts
    lane_plan = build_lane_plan(start_nonce, stop_nonce, f"{challenge_id}:{run_id}")
    minimum_target = target_for_difficulty(min_difficulty)

    l1 = lane_plan["lanes"]["L1"]
    l3 = lane_plan["lanes"]["L3"]
    l1_workers = max(1, (workers + 1) // 2)
    l3_workers = max(1, workers // 2)

    def run_forward() -> Any:
        return scan_nonce_range(
            header,
            minimum_target,
            l1["start_nonce"],
            l1["stop_nonce"],
            workers=l1_workers,
            chunk_size=chunk_size,
            optimized=True,
        )

    def run_reverse() -> Any:
        return scan_reverse_nonce_range(
            header,
            minimum_target,
            l3["start_nonce"],
            l3["stop_nonce"],
            workers=l3_workers,
            chunk_size=chunk_size,
        )

    if workers == 1:
        forward_result = run_forward()
        reverse_result = run_reverse()
    else:
        with ThreadPoolExecutor(max_workers=2) as executor:
            forward_future = executor.submit(run_forward)
            reverse_future = executor.submit(run_reverse)
            forward_result = forward_future.result()
            reverse_result = reverse_future.result()

    forward_candidates = list(forward_result.candidates)
    reverse_candidates = list(reverse_result["candidates"])

    # L2 and L4 are shadow lanes: they independently recompute every candidate.
    l2_verified = all(verify_candidate(header, candidate) for candidate in reversed(forward_candidates))
    l4_verified = all(verify_candidate(header, candidate) for candidate in reverse_candidates)
    if not l2_verified or not l4_verified:
        raise RuntimeError("shadow-lane verification failed; no trophy receipts will be promoted")

    all_candidates = sorted(
        forward_candidates + reverse_candidates,
        key=lambda item: item.nonce,
    )
    run_finished = int(time.time())
    elapsed = max(time.perf_counter() - monotonic_started, 1e-12)
    attempts_per_second = attempts / elapsed

    lane_evidence = {
        "L1": {
            "ticket": l1["ticket"],
            "role": "compute",
            "direction": "forward",
            "range": [l1["start_nonce"], l1["stop_nonce"]],
            "attempts": forward_result.attempts,
            "hashes_per_second": forward_result.hashes_per_second,
            "workers": forward_result.workers,
            "chunks_completed": forward_result.chunks_completed,
            "shadow_lane": "L2",
            "shadow_verified": l2_verified,
            "candidates_found": len(forward_candidates),
        },
        "L2": {
            "ticket": lane_plan["lanes"]["L2"]["ticket"],
            "role": "shadow_verify",
            "direction": "reverse",
            "verified_candidates": len(forward_candidates),
            "verification_passed": l2_verified,
        },
        "L3": {
            "ticket": l3["ticket"],
            "role": "compute",
            "direction": "reverse",
            "range": [l3["start_nonce"], l3["stop_nonce"]],
            "attempts": reverse_result["attempts"],
            "hashes_per_second": reverse_result["hashes_per_second"],
            "workers": reverse_result["workers"],
            "chunks_completed": reverse_result["chunks_completed"],
            "shadow_lane": "L4",
            "shadow_verified": l4_verified,
            "candidates_found": len(reverse_candidates),
            "kernel": reverse_result["kernel"],
        },
        "L4": {
            "ticket": lane_plan["lanes"]["L4"]["ticket"],
            "role": "shadow_verify",
            "direction": "forward",
            "verified_candidates": len(reverse_candidates),
            "verification_passed": l4_verified,
        },
    }

    guarantees = compute_difficulty_stratified_guarantees(
        max_difficulty,
        attempts=attempts,
        confidence=confidence,
    )
    star_cycle = schlafli_cycle(5, 2)
    geometry_attestation = {
        "schlafli_symbol": "{5/2}",
        "schlafli_cycle": list(star_cycle),
        "unit_cycle_divergence": list(discrete_divergence(5, 2, [1] * 5)),
        "hodge_star_signs": {
            "dimension_3_degree_1": hodge_star_sign(3, 1),
            "dimension_4_degree_1": hodge_star_sign(4, 1),
            "dimension_4_degree_2": hodge_star_sign(4, 2),
        },
        "scope": "discrete graph and Hodge-star parity checks only; no full manifold cohomology claim",
    }
    wallet_path = Path(wallet_file).expanduser()
    manifests_path = Path(manifest_dir).expanduser()
    trophies: list[dict[str, Any]] = []
    window_start = max(0, run_started - 5)
    window_end = run_started + window_seconds

    for difficulty in range(min_difficulty, max_difficulty + 1):
        target = target_for_difficulty(difficulty)
        candidate = next((item for item in all_candidates if item.hash_value <= target), None)
        if candidate is None:
            continue

        tier_candidate = Candidate(
            nonce=candidate.nonce,
            digest_hex=candidate.digest_hex,
            hash_value=candidate.hash_value,
            target=target,
        )
        tier_ruleset = f"{ruleset_id}:difficulty-{difficulty:02d}"
        metrics = {
            "solver": "GAIA-NEXUS-INSTANT-SOLVER",
            "solver_version": "1.0.0",
            "run_id": run_id,
            "challenge_id": challenge_id,
            "difficulty": difficulty,
            "maximum_difficulty_requested": max_difficulty,
            "confidence_requested": confidence,
            "attempts_scanned": attempts,
            "elapsed_seconds": elapsed,
            "aggregate_hashes_per_second": attempts_per_second,
            "difficulty_guarantees": guarantees,
            "lane_evidence": lane_evidence,
            "arithmetic_fabric": lane_plan,
            "geometry_attestation": geometry_attestation,
            "routing_semantics": "routing metadata only; every nonce in the assigned interval is scanned exactly once",
        }
        receipt = create_receipt(
            header=header,
            candidate=tier_candidate,
            wallet_id=wallet_id,
            ruleset_id=tier_ruleset,
            window_start=window_start,
            window_end=window_end,
            accepted_at=run_finished,
            work_metrics=metrics,
        )
        append_to_wallet(receipt, wallet_path)
        manifest = create_manifest(receipt)
        manifest_path = manifests_path / f"{receipt['receipt_id']}.json"
        export_manifest(manifest, manifest_path)
        trophies.append({
            "difficulty": difficulty,
            "nonce": candidate.nonce,
            "digest_hex": candidate.digest_hex,
            "target_hex": f"{target:064x}",
            "receipt_id": receipt["receipt_id"],
            "manifest_path": str(manifest_path),
            "network_acceptance": "not_claimed",
            "valuation": None,
        })

    expected_levels = max_difficulty - min_difficulty + 1
    return {
        "schema": "cryptic.gaia-instant-solver-run.v1",
        "status": "complete" if len(trophies) == expected_levels else ("partial" if trophies else "no_trophies_found"),
        "run_id": run_id,
        "challenge_id": challenge_id,
        "ruleset_id": ruleset_id,
        "difficulty_range": [min_difficulty, max_difficulty],
        "confidence_requested": confidence,
        "attempts_planned": attempts,
        "attempts_scanned": attempts,
        "nonce_range": [start_nonce, stop_nonce],
        "aggregate_hashes_per_second": attempts_per_second,
        "elapsed_seconds": elapsed,
        "candidates_at_minimum_difficulty": len(all_candidates),
        "shadow_verification": {
            "L2": l2_verified,
            "L4": l4_verified,
        },
        "trophies_earned": trophies,
        "trophy_count": len(trophies),
        "expected_trophy_count": expected_levels,
        "wallet_file": str(wallet_path),
        "manifest_directory": str(manifests_path),
        "network_acceptance": "not_claimed_local_proof_trophies_only",
        "hccgn_consensus": "not_connected_protocol_adapter_required",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Mine a local GAIA/NEXUS SHA-256d proof-trophy difficulty ladder"
    )
    parser.add_argument("--challenge-id", required=True)
    parser.add_argument("--seed", required=True, help="public challenge seed; never use a wallet secret")
    parser.add_argument("--min-difficulty", type=int, default=4)
    parser.add_argument("--max-difficulty", type=int, default=16)
    parser.add_argument("--confidence", type=float, default=0.99)
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--attempts", type=int, default=None)
    parser.add_argument("--workers", type=int, default=min(4, max(1, os.cpu_count() or 1)))
    parser.add_argument("--chunk-size", type=int, default=50_000)
    parser.add_argument("--wallet-id", default="local:gaia-nexus")
    parser.add_argument("--ruleset-id", default="cryptic-gaia-trophy-v1")
    parser.add_argument("--wallet", default=DEFAULT_WALLET)
    parser.add_argument("--manifests", default=DEFAULT_MANIFESTS)
    parser.add_argument("--window-seconds", type=int, default=3600)
    args = parser.parse_args(argv)

    try:
        report = mine_trophy_ladder(
            challenge_id=args.challenge_id,
            seed=args.seed,
            min_difficulty=args.min_difficulty,
            max_difficulty=args.max_difficulty,
            confidence=args.confidence,
            start_nonce=args.start,
            max_attempts=args.attempts,
            workers=args.workers,
            chunk_size=args.chunk_size,
            wallet_id=args.wallet_id,
            ruleset_id=args.ruleset_id,
            wallet_file=args.wallet,
            manifest_dir=args.manifests,
            window_seconds=args.window_seconds,
        )
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        parser.exit(2, f"solver error: {type(exc).__name__}: {exc}\n")

    print(json.dumps(report, sort_keys=True, indent=2))
    return 0 if report["trophy_count"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
