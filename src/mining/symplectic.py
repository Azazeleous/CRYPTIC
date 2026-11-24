"""Continuous and finite-lattice symplectic phase-space engines.

The continuous engine uses kick-drift-kick Störmer-Verlet for separable
Hamiltonians. The finite engine composes exact modular symplectic shears and
uses the resulting bijection only to order a bounded mining nonce window.
No proof preimage, target, or consensus rule is changed.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

SCHEDULE_SEQUENTIAL = "sequential-v1"
SCHEDULE_SYMPLECTIC = "symplectic-phase-space-v1"
MAX_PHASE_STEPS = 1_000_000
MAX_SYMPLECTIC_WINDOW = 10_000_000
MAX_SCHEDULE_VERIFY = 1_000_000


def _finite_vector(values: Sequence[float], field: str) -> tuple[float, ...]:
    if not isinstance(values, (tuple, list)) or not values:
        raise ValueError(f"{field}_must_be_nonempty_vector")
    if any(isinstance(value, bool) for value in values):
        raise ValueError(f"{field}_must_be_numeric_not_boolean")
    result = tuple(float(value) for value in values)
    if not all(math.isfinite(value) for value in result):
        raise ValueError(f"{field}_must_be_finite")
    return result


@dataclass(frozen=True)
class PhaseState:
    q: tuple[float, ...]
    p: tuple[float, ...]
    time: float = 0.0

    def __post_init__(self) -> None:
        q = _finite_vector(self.q, "position")
        p = _finite_vector(self.p, "momentum")
        if len(q) != len(p):
            raise ValueError("phase_dimension_mismatch")
        if not math.isfinite(float(self.time)):
            raise ValueError("time_must_be_finite")
        object.__setattr__(self, "q", q)
        object.__setattr__(self, "p", p)
        object.__setattr__(self, "time", float(self.time))


@dataclass(frozen=True)
class SeparableHamiltonian:
    """H(q,p) = V(q) + sum_i p_i**2 / (2*m_i)."""
    potential: Callable[[tuple[float, ...]], float]
    gradient: Callable[[tuple[float, ...]], Sequence[float]]
    masses: tuple[float, ...]

    def __post_init__(self) -> None:
        if not callable(self.potential) or not callable(self.gradient):
            raise ValueError("hamiltonian_potential_and_gradient_required")
        masses = _finite_vector(self.masses, "masses")
        if any(mass <= 0.0 for mass in masses):
            raise ValueError("masses_must_be_positive")
        object.__setattr__(self, "masses", masses)

    def energy(self, state: PhaseState) -> float:
        if len(state.q) != len(self.masses):
            raise ValueError("phase_dimension_mismatch")
        value = float(self.potential(state.q))
        kinetic = sum(p * p / (2.0 * mass) for p, mass in zip(state.p, self.masses))
        energy = value + kinetic
        if not math.isfinite(energy):
            raise ValueError("hamiltonian_energy_non_finite")
        return energy


def leapfrog_step(system: SeparableHamiltonian, state: PhaseState, step_size: float) -> PhaseState:
    """One reversible, symplectic kick-drift-kick Störmer-Verlet step."""
    dt = float(step_size)
    if not math.isfinite(dt) or dt == 0.0:
        raise ValueError("step_size_must_be_finite_nonzero")
    if len(state.q) != len(system.masses):
        raise ValueError("phase_dimension_mismatch")
    grad0 = _finite_vector(system.gradient(state.q), "gradient")
    if len(grad0) != len(state.q):
        raise ValueError("gradient_dimension_mismatch")
    p_half = tuple(p - 0.5 * dt * g for p, g in zip(state.p, grad0))
    q_next = tuple(q + dt * ph / mass for q, ph, mass in zip(state.q, p_half, system.masses))
    grad1 = _finite_vector(system.gradient(q_next), "gradient")
    if len(grad1) != len(state.q):
        raise ValueError("gradient_dimension_mismatch")
    p_next = tuple(ph - 0.5 * dt * g for ph, g in zip(p_half, grad1))
    return PhaseState(q_next, p_next, state.time + dt)


def integrate_trajectory(
    system: SeparableHamiltonian, initial: PhaseState, *, step_size: float, steps: int,
) -> tuple[PhaseState, ...]:
    if isinstance(steps, bool) or not isinstance(steps, int) or not 0 <= steps <= MAX_PHASE_STEPS:
        raise ValueError("steps_out_of_bounds")
    if len(initial.q) != len(system.masses):
        raise ValueError("phase_dimension_mismatch")
    dt = float(step_size)
    if not math.isfinite(dt) or dt == 0.0:
        raise ValueError("step_size_must_be_finite_nonzero")
    states = [initial]
    current = initial
    for _ in range(steps):
        current = leapfrog_step(system, current, dt)
        states.append(current)
    return tuple(states)


@dataclass(frozen=True)
class DiscretePhasePoint:
    q: int
    p: int


@dataclass(frozen=True)
class DiscreteSymplecticMap:
    """Exact symplectic shear composition over Z_m.

    p' = p + kick*q; q' = q + drift*p' (mod m).
    Each shear has determinant one; the composition preserves dq wedge dp.
    """
    modulus: int
    drift: int
    kick: int

    def __post_init__(self) -> None:
        for name, value in (("modulus", self.modulus), ("drift", self.drift), ("kick", self.kick)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name}_must_be_integer")
        if self.modulus < 2:
            raise ValueError("modulus_must_be_at_least_two")
        object.__setattr__(self, "drift", self.drift % self.modulus)
        object.__setattr__(self, "kick", self.kick % self.modulus)

    def _validate(self, point: DiscretePhasePoint) -> None:
        if (not isinstance(point, DiscretePhasePoint)
                or isinstance(point.q, bool) or isinstance(point.p, bool)
                or not isinstance(point.q, int) or not isinstance(point.p, int)
                or not 0 <= point.q < self.modulus or not 0 <= point.p < self.modulus):
            raise ValueError("phase_point_out_of_range")

    def forward(self, point: DiscretePhasePoint) -> DiscretePhasePoint:
        self._validate(point)
        p1 = (point.p + self.kick * point.q) % self.modulus
        q1 = (point.q + self.drift * p1) % self.modulus
        return DiscretePhasePoint(q1, p1)

    def inverse(self, point: DiscretePhasePoint) -> DiscretePhasePoint:
        self._validate(point)
        q0 = (point.q - self.drift * point.p) % self.modulus
        p0 = (point.p - self.kick * q0) % self.modulus
        return DiscretePhasePoint(q0, p0)

    def preserves_form(self, left: DiscretePhasePoint, right: DiscretePhasePoint) -> bool:
        self._validate(left)
        self._validate(right)
        before = (left.q * right.p - left.p * right.q) % self.modulus
        a, b = self.forward(left), self.forward(right)
        after = (a.q * b.p - a.p * b.q) % self.modulus
        return before == after


def phase_space_parameters(count: int, *, drift: int, kick: int) -> dict[str, int | str]:
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_SYMPLECTIC_WINDOW:
        raise ValueError("candidate_window_out_of_bounds")
    for name, value in (("drift", drift), ("kick", kick)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name}_must_be_integer")
    modulus = max(2, math.isqrt(count - 1) + 1)
    return {
        "profile_id": SCHEDULE_SYMPLECTIC,
        "modulus": modulus,
        "drift": int(drift) % modulus,
        "kick": int(kick) % modulus,
        "phase_space_points": modulus * modulus,
        "candidate_window": count,
        "filtered_points": modulus * modulus - count,
    }


def iter_symplectic_ordinals(count: int, *, drift: int, kick: int) -> Iterable[int]:
    """Yield every ordinal in [0,count) exactly once in symplectic order.

    A square modular phase-space tile is permuted bijectively. Filtering the
    final partial tile yields exactly the requested finite window.
    """
    params = phase_space_parameters(count, drift=drift, kick=kick)
    modulus = int(params["modulus"])
    transform = DiscreteSymplecticMap(modulus, int(params["drift"]), int(params["kick"]))
    produced = 0
    for ordinal in range(modulus * modulus):
        point = DiscretePhasePoint(ordinal // modulus, ordinal % modulus)
        mapped = transform.forward(point)
        candidate_ordinal = mapped.q * modulus + mapped.p
        if candidate_ordinal < count:
            produced += 1
            yield candidate_ordinal
    if produced != count:
        raise AssertionError("symplectic_schedule_coverage_failure")


def verify_symplectic_schedule(count: int, *, drift: int, kick: int) -> dict[str, int | bool | str]:
    """Exhaustively verify coverage for a bounded candidate window."""
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_SCHEDULE_VERIFY:
        raise ValueError("verification_window_out_of_bounds")
    values = tuple(iter_symplectic_ordinals(count, drift=drift, kick=kick))
    unique = len(set(values))
    return {
        "profile_id": SCHEDULE_SYMPLECTIC,
        "candidate_window": count,
        "emitted": len(values),
        "unique": unique,
        "minimum": min(values) if values else -1,
        "maximum": max(values) if values else -1,
        "complete": len(values) == count and unique == count and set(values) == set(range(count)),
    }
