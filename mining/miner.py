"""Reference SHA-256 proof-of-work miner with four independent lanes.

The consensus preimage is exactly header || uint64_be(nonce). Barrel-roll
transforms are deliberately outside this function and cannot alter consensus.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib

from .scheduler import LANE_COUNT, lane_ordinals, nonce_for_ordinal

MAX_NONCE = (1 << 64) - 1
MAX_TARGET = (1 << 256) - 1


@dataclass(frozen=True)
class MiningResult:
    nonce: int
    digest: str
    lane_id: int
    ordinal: int
    attempts: int


def candidate_digest(header: bytes, nonce: int) -> bytes:
    if not isinstance(header, bytes):
        raise TypeError("header must be bytes")
    if isinstance(nonce, bool) or not isinstance(nonce, int) or not 0 <= nonce <= MAX_NONCE:
        raise ValueError("nonce must fit uint64")
    return hashlib.sha256(header + nonce.to_bytes(8, "big")).digest()


def verify_candidate(header: bytes, result: MiningResult, target: int) -> bool:
    if not isinstance(result, MiningResult):
        return False
    if isinstance(target, bool) or not isinstance(target, int) or not 0 <= target <= MAX_TARGET:
        return False
    if (isinstance(result.lane_id, bool) or not isinstance(result.lane_id, int)
            or not 0 <= result.lane_id < LANE_COUNT):
        return False
    if (isinstance(result.ordinal, bool) or not isinstance(result.ordinal, int)
            or result.ordinal < 0):
        return False
    if (isinstance(result.attempts, bool) or not isinstance(result.attempts, int)
            or result.attempts < 1):
        return False
    try:
        digest = candidate_digest(header, result.nonce)
    except (TypeError, ValueError):
        return False
    return (
        isinstance(result.digest, str)
        and digest.hex() == result.digest
        and int.from_bytes(digest, "big") <= target
    )


def _mine_lane(header: bytes, start_nonce: int, count: int, target: int, lane_id: int):
    best_hit = None
    attempts = 0
    # Lanes 1 and 2 traverse their disjoint assignments in reverse order.
    # Keep only the lowest-ordinal hit: memory stays O(1) per lane even when
    # every candidate qualifies under a permissive target.
    for ordinal in lane_ordinals(lane_id, count, LANE_COUNT, reverse=lane_id in (1, 2)):
        nonce = nonce_for_ordinal(start_nonce, ordinal)
        if nonce > MAX_NONCE:
            raise OverflowError("scheduled nonce exceeds uint64")
        digest = candidate_digest(header, nonce)
        attempts += 1
        if int.from_bytes(digest, "big") <= target:
            if best_hit is None or ordinal < best_hit.ordinal:
                best_hit = MiningResult(nonce, digest.hex(), lane_id, ordinal, attempts)
    return best_hit, attempts


def mine_four_lane(
    header: bytes, start_nonce: int, count: int, target: int, *,
    workers: int = LANE_COUNT,
) -> MiningResult | None:
    """Search a finite candidate window; return the earliest scheduled valid hit.

    All lanes evaluate their disjoint ordinals. The result is independently
    reproducible with verify_candidate. This finite-window reference miner is
    intended for correctness and benchmarking, not a network pool client.
    """
    if not isinstance(header, bytes):
        raise TypeError("header must be bytes")
    if isinstance(start_nonce, bool) or not isinstance(start_nonce, int) or start_nonce < 0:
        raise ValueError("start_nonce must be a non-negative integer")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ValueError("count must be a non-negative integer")
    if isinstance(target, bool) or not isinstance(target, int) or not 0 <= target <= MAX_TARGET:
        raise ValueError("target must be a 256-bit unsigned integer")
    if isinstance(workers, bool) or not isinstance(workers, int) or workers < 1:
        raise ValueError("workers must be a positive integer")
    if count == 0:
        return None
    with ThreadPoolExecutor(max_workers=min(workers, LANE_COUNT)) as pool:
        futures = [
            pool.submit(_mine_lane, header, start_nonce, count, target, lane)
            for lane in range(LANE_COUNT)
        ]
        lane_results = [future.result() for future in futures]
    hits = [hit for hit, _ in lane_results if hit is not None]
    if not hits:
        return None
    winner = min(hits, key=lambda item: item.ordinal)
    total_attempts = sum(attempts for _, attempts in lane_results)
    return MiningResult(
        winner.nonce, winner.digest, winner.lane_id, winner.ordinal, total_attempts
    )
