"""Bounded, deterministic GCF/1 local pacemaker timing policy.

This module computes local timeout deadlines only. It does not sign messages,
advance consensus state, release locks, create certificates, or choose values.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

INITIAL_TIMEOUT_SECONDS = 5
MAX_TIMEOUT_SECONDS = 60
MAX_ROUND = (1 << 63) - 1


class PacemakerError(ValueError):
    """Invalid local pacemaker input."""


def _round(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_ROUND:
        raise PacemakerError("round must be a non-negative bounded integer")
    return value


def timeout_seconds(round_number: int) -> int:
    """Return min(5 * 2**round_number, 60), without unbounded exponentiation."""
    r = _round(round_number)
    if r >= 4:
        return MAX_TIMEOUT_SECONDS
    return min(INITIAL_TIMEOUT_SECONDS * (1 << r), MAX_TIMEOUT_SECONDS)


def timeout_deadline(round_number: int, started_monotonic: float) -> float:
    """Compute a local monotonic deadline; wall-clock timestamps are not accepted."""
    _round(round_number)
    if (isinstance(started_monotonic, bool)
            or not isinstance(started_monotonic, (int, float))
            or not math.isfinite(started_monotonic)
            or started_monotonic < 0):
        raise PacemakerError("started_monotonic must be a finite non-negative number")
    return float(started_monotonic) + timeout_seconds(round_number)


@dataclass(frozen=True)
class TimeoutEvent:
    height: int
    source_round: int
    target_round: int
    timeout_seconds: int
    deadline_monotonic: float


def timeout_event(*, height: int, source_round: int,
                  started_monotonic: float, now_monotonic: float) -> TimeoutEvent | None:
    """Return a timeout signal when due; never performs a consensus transition."""
    if isinstance(height, bool) or not isinstance(height, int) or not 1 <= height <= MAX_ROUND:
        raise PacemakerError("height must be a positive bounded integer")
    source = _round(source_round)
    if source >= MAX_ROUND:
        raise PacemakerError("round space exhausted")
    deadline = timeout_deadline(source, started_monotonic)
    if (isinstance(now_monotonic, bool)
            or not isinstance(now_monotonic, (int, float))
            or not math.isfinite(now_monotonic)
            or now_monotonic < started_monotonic):
        raise PacemakerError("now_monotonic must be finite and not precede start")
    if now_monotonic < deadline:
        return None
    return TimeoutEvent(
        height=height,
        source_round=source,
        target_round=source + 1,
        timeout_seconds=timeout_seconds(source),
        deadline_monotonic=deadline,
    )
