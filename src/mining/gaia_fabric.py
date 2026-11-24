"""GAIA/NEXUS deterministic arithmetic and graph-routing fabric.

This module supplies reversible indexing and diagnostic geometry. It does not
alter a proof-of-work digest, reduce the search space, or invert a hash.
"""
from __future__ import annotations

import hashlib
import math
from math import gcd
from typing import Any

PRIMARY_MODULUS = 97_152
PRIMARY_TOTIENT = 28_160
COMPACT_MODULUS = 1_518
COMPACT_TOTIENT = 440
CAYLEY_MODULUS = 4_096
CAYLEY_STEP = 799
V5_SIDE = 5
V5_NODE_COUNT = V5_SIDE ** 4
PROPOSED_LAMBDA2 = (3.0 - math.sqrt(5.0)) / 2.0


def reduced_residues(modulus: int) -> tuple[int, ...]:
    """Return the reduced residue system in canonical ascending order."""
    if isinstance(modulus, bool) or not isinstance(modulus, int) or modulus < 2:
        raise ValueError("modulus must be an integer >= 2")
    return tuple(value for value in range(1, modulus) if gcd(value, modulus) == 1)


def verify_arithmetic_fabric() -> dict[str, Any]:
    """Recompute the project modulus and totient invariants."""
    primary = reduced_residues(PRIMARY_MODULUS)
    compact = reduced_residues(COMPACT_MODULUS)
    return {
        "primary_modulus": PRIMARY_MODULUS,
        "primary_totient_expected": PRIMARY_TOTIENT,
        "primary_totient_actual": len(primary),
        "primary_valid": len(primary) == PRIMARY_TOTIENT,
        "compact_modulus": COMPACT_MODULUS,
        "compact_totient_expected": COMPACT_TOTIENT,
        "compact_totient_actual": len(compact),
        "compact_valid": len(compact) == COMPACT_TOTIENT,
        "prime_anchors": [2, 3, 11, 23],
    }


def select_coprime_stride(modulus: int, seed: str | bytes) -> int:
    """Choose a deterministic stride coprime to modulus."""
    if isinstance(modulus, bool) or not isinstance(modulus, int) or modulus < 2:
        raise ValueError("modulus must be an integer >= 2")
    if not isinstance(seed, (str, bytes)) or not seed:
        raise ValueError("seed must be a non-empty string or bytes")
    raw = seed.encode("utf-8") if isinstance(seed, str) else seed
    candidate = int.from_bytes(hashlib.sha256(raw).digest()[:8], "big") % modulus
    candidate = max(1, candidate)
    for _ in range(modulus):
        if gcd(candidate, modulus) == 1:
            return candidate
        candidate = (candidate + 1) % modulus
        if candidate == 0:
            candidate = 1
    raise RuntimeError("no coprime stride found")


def route_ordinal(ordinal: int, anchor: int, stride: int, modulus: int = PRIMARY_TOTIENT) -> dict[str, int]:
    """Map a nonnegative ordinal bijectively within each residue epoch."""
    for name, value in (("ordinal", ordinal), ("anchor", anchor), ("stride", stride), ("modulus", modulus)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be an integer")
    if ordinal < 0 or modulus < 2:
        raise ValueError("ordinal must be nonnegative and modulus must be >= 2")
    if not 0 <= anchor < modulus:
        raise ValueError("anchor is outside the routing modulus")
    if gcd(stride, modulus) != 1:
        raise ValueError("stride must be coprime to the routing modulus")
    epoch, offset = divmod(ordinal, modulus)
    residue = (anchor + offset * stride) % modulus
    return {"epoch": epoch, "residue": residue}


def inverse_route(route: dict[str, int], anchor: int, stride: int, modulus: int = PRIMARY_TOTIENT) -> int:
    """Recover the original ordinal from a route record."""
    if not isinstance(route, dict) or set(route) != {"epoch", "residue"}:
        raise ValueError("route must contain exactly epoch and residue")
    epoch, residue = route["epoch"], route["residue"]
    for name, value in (("epoch", epoch), ("residue", residue), ("anchor", anchor), ("stride", stride), ("modulus", modulus)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be an integer")
    if modulus < 2 or epoch < 0 or not 0 <= anchor < modulus or not 0 <= residue < modulus or gcd(stride, modulus) != 1:
        raise ValueError("invalid route record or non-coprime stride")
    offset = ((residue - anchor) * pow(stride, -1, modulus)) % modulus
    return epoch * modulus + offset


def cayley_position(ordinal: int, step: int = CAYLEY_STEP, modulus: int = CAYLEY_MODULUS) -> int:
    """Return a deterministic Cayley-cycle position."""
    for name, value in (("ordinal", ordinal), ("step", step), ("modulus", modulus)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be an integer")
    if ordinal < 0 or modulus < 2 or gcd(step, modulus) != 1:
        raise ValueError("ordinal must be nonnegative and step coprime to modulus")
    return (ordinal * step) % modulus


def v5_coordinates(node_id: int) -> tuple[int, int, int, int]:
    """Decode IDs 0..624 into the project's {-2,-1,0,1,2}^4 lattice."""
    if isinstance(node_id, bool) or not isinstance(node_id, int) or not 0 <= node_id < V5_NODE_COUNT:
        raise ValueError("V5 node_id must be in [0, 624]")
    return (
        (node_id // 125) % 5 - 2,
        (node_id // 25) % 5 - 2,
        (node_id // 5) % 5 - 2,
        node_id % 5 - 2,
    )


def schlafli_cycle(p: int, q: int) -> tuple[int, ...]:
    """Construct the vertex order for a regular {p/q} star traversal."""
    if isinstance(p, bool) or isinstance(q, bool) or not isinstance(p, int) or not isinstance(q, int):
        raise TypeError("p and q must be integers")
    if p < 3 or not 1 <= q < p or gcd(p, q) != 1:
        raise ValueError("require p >= 3, 1 <= q < p, and gcd(p,q) == 1")
    cycle = []
    current = 0
    for _ in range(p):
        cycle.append(current)
        current = (current + q) % p
    if current != 0 or len(set(cycle)) != p:
        raise AssertionError("coprime Schlaefli traversal failed to close exactly once")
    return tuple(cycle)


def discrete_divergence(p: int, q: int, edge_flows: list[float] | tuple[float, ...]) -> tuple[float, ...]:
    """Compute Bf for directed star-cycle edges i -> (i+q) mod p."""
    cycle = schlafli_cycle(p, q)
    if len(edge_flows) != len(cycle):
        raise ValueError("one flow value is required for every directed edge")
    divergence = [0.0] * p
    for source, flow in zip(cycle, edge_flows):
        destination = (source + q) % p
        divergence[source] -= float(flow)
        divergence[destination] += float(flow)
    return tuple(divergence)


def hodge_star_sign(dimension: int, degree: int) -> int:
    """Return the Riemannian Hodge-star square sign (-1)^(k(n-k))."""
    if dimension < 0 or degree < 0 or degree > dimension:
        raise ValueError("require 0 <= degree <= dimension")
    return -1 if (degree * (dimension - degree)) % 2 else 1


def compute_difficulty_stratified_guarantees(
    difficulty: int,
    attempts: int | None = None,
    confidence: float = 0.99,
    tail_multiplier: float = 2.0,
    lambda2: float = PROPOSED_LAMBDA2,
) -> dict[str, Any]:
    """Return exact geometric-work calculations and clearly labeled bounds."""
    if isinstance(difficulty, bool) or not isinstance(difficulty, int) or not 1 <= difficulty <= 256:
        raise ValueError("difficulty must be an integer in [1, 256]")
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be between zero and one")
    if tail_multiplier <= 1.0:
        raise ValueError("tail_multiplier must be greater than one")
    if lambda2 <= 0.0:
        raise ValueError("lambda2 must be positive")

    success_probability = 2.0 ** (-difficulty)
    expected_trials = 2 ** difficulty
    required_trials = math.ceil(math.log1p(-confidence) / math.log1p(-success_probability))
    measured_attempts = required_trials if attempts is None else int(attempts)
    if measured_attempts < 0:
        raise ValueError("attempts must be nonnegative")

    exact_success = -math.expm1(measured_attempts * math.log1p(-success_probability))
    exact_tail = math.exp(measured_attempts * math.log1p(-success_probability))
    k = float(tail_multiplier)
    markov_upper = min(1.0, 1.0 / k)
    chebyshev_upper = min(1.0, (1.0 - success_probability) / ((k - 1.0) ** 2))
    exponential_tail_bound = math.exp(-measured_attempts * success_probability)
    tail_threshold_trials = math.ceil(k * expected_trials)
    exponential_tail_at_multiplier = math.exp(-k)
    mixing_heuristic = math.ceil(difficulty * math.log(2.0) / lambda2)

    if difficulty <= 6:
        regime = "low"
    elif difficulty <= 11:
        regime = "standard"
    else:
        regime = "hardened"

    return {
        "difficulty": difficulty,
        "regime": regime,
        "single_trial_success_probability": success_probability,
        "expected_trials": expected_trials,
        "confidence_requested": confidence,
        "attempts_for_requested_confidence": required_trials,
        "attempts_evaluated": measured_attempts,
        "exact_probability_of_at_least_one_solution": exact_success,
        "exact_geometric_tail_probability": exact_tail,
        "markov_upper_bound_at_multiplier": markov_upper,
        "chebyshev_upper_bound_at_multiplier": chebyshev_upper,
        "geometric_exponential_tail_upper_bound": exponential_tail_bound,
        "tail_multiplier": k,
        "tail_threshold_trials": tail_threshold_trials,
        "geometric_exponential_bound_at_multiplier": exponential_tail_at_multiplier,
        "spectral_gap_input": lambda2,
        "spectral_mixing_schedule_heuristic": mixing_heuristic,
        "spectral_bound_status": "heuristic_until_lambda2_is_verified_for_the_selected_transition_operator",
    }


def build_lane_plan(start: int, stop: int, seed: str) -> dict[str, Any]:
    """Create two disjoint compute ranges and two paired shadow-verification lanes."""
    if (isinstance(start, bool) or not isinstance(start, int)
            or isinstance(stop, bool) or not isinstance(stop, int)
            or not 0 <= start <= stop <= (1 << 32)):
        raise ValueError("nonce interval must satisfy 0 <= start <= stop <= 2**32")
    if not isinstance(seed, str) or not seed:
        raise ValueError("seed must be a non-empty string")
    midpoint = start + (stop - start) // 2
    ranges = {
        "L1": (start, midpoint),
        "L2": (start, midpoint),
        "L3": (midpoint, stop),
        "L4": (midpoint, stop),
    }
    roles = {
        "L1": ("compute", "forward", None),
        "L2": ("shadow_verify", "reverse", "L1"),
        "L3": ("compute", "reverse", None),
        "L4": ("shadow_verify", "forward", "L3"),
    }
    stride = select_coprime_stride(PRIMARY_TOTIENT, seed)
    anchor = int.from_bytes(hashlib.sha256(seed.encode("utf-8")).digest()[8:16], "big") % PRIMARY_TOTIENT
    lanes = {}
    for index, lane_id in enumerate(("L1", "L2", "L3", "L4")):
        role, direction, shadow_of = roles[lane_id]
        route = route_ordinal(index, anchor, stride)
        ticket_material = f"{seed}|{lane_id}|{ranges[lane_id][0]}|{ranges[lane_id][1]}|{role}|{direction}"
        ticket = hashlib.sha256(ticket_material.encode("utf-8")).hexdigest()
        lanes[lane_id] = {
            "ticket": ticket,
            "role": role,
            "direction": direction,
            "shadow_of": shadow_of,
            "start_nonce": ranges[lane_id][0],
            "stop_nonce": ranges[lane_id][1],
            "route": route,
            "route_inverse": inverse_route(route, anchor, stride),
            "cayley_position": cayley_position(index),
            "v5_node_id": index,
            "v5_coordinates": list(v5_coordinates(index)),
        }
    return {
        "primary_modulus": PRIMARY_MODULUS,
        "primary_totient": PRIMARY_TOTIENT,
        "compact_modulus": COMPACT_MODULUS,
        "compact_totient": COMPACT_TOTIENT,
        "anchor": anchor,
        "stride": stride,
        "stride_inverse": pow(stride, -1, PRIMARY_TOTIENT),
        "lanes": lanes,
        "search_space_partition": "L1 and L3 are disjoint; L2 and L4 independently verify their paired candidates",
        "routing_effect": "metadata_only_no_nonce_candidates_are_skipped",
    }


def v5_node_id(coordinates: tuple[int, int, int, int] | list[int]) -> int:
    """Encode a four-dimensional V5 lattice coordinate into ID 0..624."""
    if not isinstance(coordinates, (tuple, list)) or len(coordinates) != 4:
        raise ValueError("V5 coordinates must contain four integers")
    if any(isinstance(value, bool) or not isinstance(value, int) or not -2 <= value <= 2
           for value in coordinates):
        raise ValueError("V5 coordinates must be integers in [-2, 2]")
    x, y, z, t = coordinates
    return 125 * (x + 2) + 25 * (y + 2) + 5 * (z + 2) + (t + 2)


def v5_neighbors(node_id: int) -> tuple[int, ...]:
    """Return sorted nearest-neighbor IDs in the 5^4 lattice."""
    point = list(v5_coordinates(node_id))
    neighbors = []
    for axis in range(4):
        for delta in (-1, 1):
            candidate = point.copy()
            candidate[axis] += delta
            if -2 <= candidate[axis] <= 2:
                neighbors.append(v5_node_id(candidate))
    return tuple(sorted(neighbors))


def v5_lattice_summary() -> dict[str, Any]:
    """Return exact finite-lattice topology counts and degree distribution."""
    degree_counts = {degree: 0 for degree in range(4, 9)}
    directed_edges = 0
    for node_id in range(V5_NODE_COUNT):
        degree = len(v5_neighbors(node_id))
        degree_counts[degree] += 1
        directed_edges += degree
    origin = v5_node_id((0, 0, 0, 0))
    return {
        "dimensions": 4, "side_length": V5_SIDE, "node_count": V5_NODE_COUNT,
        "undirected_edge_count": directed_edges // 2,
        "degree_distribution": {str(k): v for k, v in degree_counts.items() if v},
        "origin_node_id": origin, "origin_coordinates": list(v5_coordinates(origin)),
        "verified": directed_edges % 2 == 0 and directed_edges // 2 == 2000
            and sum(degree_counts.values()) == V5_NODE_COUNT,
    }


def verify_lane_plan(plan: dict[str, Any], *, start: int, stop: int, seed: str) -> dict[str, Any]:
    """Independently verify all four lane tickets, pairings, routes, and lattice IDs."""
    failures: list[str] = []
    try:
        expected = build_lane_plan(start, stop, seed)
        if not isinstance(plan, dict) or set(plan) != set(expected):
            return {"valid": False, "failures": ["plan_schema_mismatch"]}
        for key in ("primary_modulus", "primary_totient", "compact_modulus",
                    "compact_totient", "anchor", "stride", "stride_inverse",
                    "search_space_partition", "routing_effect"):
            if plan.get(key) != expected[key]:
                failures.append(f"{key}_mismatch")
        lanes = plan.get("lanes")
        if not isinstance(lanes, dict) or set(lanes) != {"L1", "L2", "L3", "L4"}:
            return {"valid": False, "failures": failures + ["lane_registry_mismatch"]}
        for lane_id, expected_lane in expected["lanes"].items():
            actual = lanes.get(lane_id)
            if not isinstance(actual, dict) or actual != expected_lane:
                failures.append(f"{lane_id}_ticket_or_metadata_mismatch")
        tickets = [lanes[lane_id].get("ticket") for lane_id in ("L1", "L2", "L3", "L4")]
        if len(set(tickets)) != 4:
            failures.append("lane_tickets_not_unique")
        if lanes.get("L2", {}).get("shadow_of") != "L1":
            failures.append("L2_shadow_pairing_mismatch")
        if lanes.get("L4", {}).get("shadow_of") != "L3":
            failures.append("L4_shadow_pairing_mismatch")
        if lanes.get("L1", {}).get("stop_nonce") != lanes.get("L3", {}).get("start_nonce"):
            failures.append("compute_ranges_not_contiguous")
        if lanes.get("L1", {}).get("start_nonce") != start or lanes.get("L3", {}).get("stop_nonce") != stop:
            failures.append("compute_ranges_do_not_cover_request")
    except (KeyError, TypeError, ValueError) as exc:
        failures.append(f"verification_error:{type(exc).__name__}")
    return {"valid": not failures, "failures": failures, "lane_count": 4}
