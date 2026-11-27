"""Deterministic, non-overlapping four-lane nonce scheduling."""
from __future__ import annotations

PROFILE_MODULUS = 97_152
PROFILE_MULTIPLIER = 3_037
PROFILE_INCREMENT = 1
LANE_COUNT = 4


def _require_integer(value: int, name: str, minimum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")


def traversal_index(position: int) -> int:
    """Full-period affine traversal index over the 97,152-slot profile."""
    _require_integer(position, "position", 0)
    return (PROFILE_MULTIPLIER * (position % PROFILE_MODULUS) + PROFILE_INCREMENT) % PROFILE_MODULUS


def nonce_for_ordinal(start_nonce: int, ordinal: int) -> int:
    """Map a global ordinal to a unique nonce using affine-window traversal."""
    _require_integer(start_nonce, "start_nonce", 0)
    _require_integer(ordinal, "ordinal", 0)
    epoch, position = divmod(ordinal, PROFILE_MODULUS)
    return start_nonce + epoch * PROFILE_MODULUS + traversal_index(position)


def lane_ordinals(lane_id: int, count: int, lane_count: int = LANE_COUNT, reverse: bool = False):
    """Yield a lane's disjoint ordinals, optionally in reverse order."""
    _require_integer(lane_count, "lane_count", 1)
    _require_integer(lane_id, "lane_id", 0)
    _require_integer(count, "count", 0)
    if lane_id >= lane_count:
        raise ValueError("lane_id must be within lane_count")
    if not isinstance(reverse, bool):
        raise ValueError("reverse must be a boolean")
    positions = range(lane_id, count, lane_count)
    return reversed(positions) if reverse else positions


def lane_nonces(start_nonce: int, lane_id: int, count: int, lane_count: int = LANE_COUNT):
    return (nonce_for_ordinal(start_nonce, ordinal) for ordinal in lane_ordinals(lane_id, count, lane_count))
