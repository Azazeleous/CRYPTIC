"""Deterministic, non-overlapping four-lane nonce scheduling."""
from __future__ import annotations

PROFILE_MODULUS = 97_152
PROFILE_MULTIPLIER = 3_037
PROFILE_INCREMENT = 1
LANE_COUNT = 4


def traversal_index(position: int) -> int:
    """Full-period affine traversal index over the 97,152-slot profile."""
    if not isinstance(position, int) or position < 0:
        raise ValueError("position must be a non-negative integer")
    return (PROFILE_MULTIPLIER * (position % PROFILE_MODULUS) + PROFILE_INCREMENT) % PROFILE_MODULUS


def nonce_for_ordinal(start_nonce: int, ordinal: int) -> int:
    """Map a global ordinal to a unique nonce using affine-window traversal."""
    if not isinstance(start_nonce, int) or start_nonce < 0:
        raise ValueError("start_nonce must be a non-negative integer")
    if not isinstance(ordinal, int) or ordinal < 0:
        raise ValueError("ordinal must be a non-negative integer")
    epoch, position = divmod(ordinal, PROFILE_MODULUS)
    return start_nonce + epoch * PROFILE_MODULUS + traversal_index(position)


def lane_ordinals(lane_id: int, count: int, lane_count: int = LANE_COUNT, reverse: bool = False):
    """Yield a lane's disjoint ordinals, optionally in reverse order."""
    if not isinstance(lane_count, int) or lane_count < 1:
        raise ValueError("lane_count must be positive")
    if not isinstance(lane_id, int) or not 0 <= lane_id < lane_count:
        raise ValueError("lane_id must be within lane_count")
    if not isinstance(count, int) or count < 0:
        raise ValueError("count must be non-negative")
    positions = range(lane_id, count, lane_count)
    return reversed(positions) if reverse else positions


def lane_nonces(start_nonce: int, lane_id: int, count: int, lane_count: int = LANE_COUNT):
    return (nonce_for_ordinal(start_nonce, ordinal) for ordinal in lane_ordinals(lane_id, count, lane_count))
