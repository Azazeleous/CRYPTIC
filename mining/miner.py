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
    if not isinstance(nonce, int) or not 0 <= nonce <= MAX_NONCE:
        raise ValueError("nonce must fit uint64")
    return hashlib.sha256(header + nonce.to_bytes(8, "big")).digest()


def verify_candidate(header: bytes, result: MiningResult, target: int) -> bool:
    if not isinstance(result, MiningResult) or not isinstance(target, int) or not 0 <= target <= MAX_TARGET:
        return False
    try:
        digest = candidate_digest(header, result.nonce)
    except (TypeError, ValueError):
        return False
    return digest.hex() == result.digest and int.from_bytes(digest, "big") <= target


def _mine_lane(header: bytes, start_nonce: int, count: int, target: int, lane_id: int):
    hits = []
    attempts = 0
    # Lanes 2 and 3 traverse their disjoint assignments in reverse order.
    for ordinal in lane_ordinals(lane_id, count, LANE_COUNT, reverse=lane_id in (1, 2)):
        nonce = nonce_for_ordinal(start_nonce, ordinal)
        if nonce > MAX_NONCE:
            raise OverflowError("scheduled nonce exceeds uint64")
        digest = candidate_digest(header, nonce)
        attempts += 1
        if int.from_bytes(digest, "big") <= target:
            hits.append(MiningResult(nonce, digest.hex(), lane_id, ordinal, attempts))
    return hits, attempts


def mine_four_lane(header: bytes, start_nonce: int, count: int, target: int) -> MiningResult | None:
    """Search a finite candidate window; return the earliest scheduled valid hit.

    All lanes evaluate their disjoint ordinals. The result is independently
    reproducible with verify_candidate. This finite-window reference miner is
    intended for correctness and benchmarking, not a network pool client.
    """
    if not isinstance(header, bytes):
        raise TypeError("header must be bytes")
    if not isinstance(start_nonce, int) or start_nonce < 0:
        raise ValueError("start_nonce must be non-negative")
    if not isinstance(count, int) or count < 0:
        raise ValueError("count must be non-negative")
    if not isinstance(target, int) or not 0 <= target <= MAX_TARGET:
        raise ValueError("target must be a 256-bit unsigned integer")
    if count == 0:
        return None
    with ThreadPoolExecutor(max_workers=LANE_COUNT) as pool:
        futures = [pool.submit(_mine_lane, header, start_nonce, count, target, lane) for lane in range(LANE_COUNT)]
        lane_results = [future.result() for future in futures]
    hits = [hit for lane_hits, _ in lane_results for hit in lane_hits]
    if not hits:
        return None
    winner = min(hits, key=lambda item: item.ordinal)
    total_attempts = sum(attempts for _, attempts in lane_results)
    return MiningResult(winner.nonce, winner.digest, winner.lane_id, winner.ordinal, total_attempts)
