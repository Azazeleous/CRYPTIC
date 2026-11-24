"""CRYPTIC mining primitives and GAIA/NEXUS local trophy solver."""

from .sha256d import Candidate, ScanResult, double_sha256, scan_nonce_range, verify_candidate
from .gaia_fabric import (
    build_lane_plan,
    compute_difficulty_stratified_guarantees,
    discrete_divergence,
    hodge_star_sign,
    schlafli_cycle,
    verify_arithmetic_fabric,
)
from .trophy_solver import mine_trophy_ladder, target_for_difficulty
from .symplectic import (
    SCHEDULE_SEQUENTIAL,
    SCHEDULE_SYMPLECTIC,
    DiscretePhasePoint,
    DiscreteSymplecticMap,
    PhaseState,
    SeparableHamiltonian,
    integrate_trajectory,
    iter_symplectic_ordinals,
    leapfrog_step,
    phase_space_parameters,
    verify_symplectic_schedule,
)

__all__ = [
    "Candidate",
    "ScanResult",
    "double_sha256",
    "scan_nonce_range",
    "verify_candidate",
    "build_lane_plan",
    "compute_difficulty_stratified_guarantees",
    "discrete_divergence",
    "hodge_star_sign",
    "schlafli_cycle",
    "verify_arithmetic_fabric",
    "mine_trophy_ladder",
    "target_for_difficulty",
    "SCHEDULE_SEQUENTIAL",
    "SCHEDULE_SYMPLECTIC",
    "DiscretePhasePoint",
    "DiscreteSymplecticMap",
    "PhaseState",
    "SeparableHamiltonian",
    "integrate_trajectory",
    "iter_symplectic_ordinals",
    "leapfrog_step",
    "phase_space_parameters",
    "verify_symplectic_schedule",
]
