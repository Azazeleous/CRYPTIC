import math
import unittest

from src.mining.symplectic import (
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


class SymplecticPhaseSpaceTests(unittest.TestCase):
    def test_public_package_exports_symplectic_engine(self):
        from src.mining import (
            SCHEDULE_SYMPLECTIC as public_schedule,
            DiscreteSymplecticMap as public_map,
            SeparableHamiltonian as public_hamiltonian,
        )
        self.assertEqual(public_schedule, "symplectic-phase-space-v1")
        self.assertIs(public_map, DiscreteSymplecticMap)
        self.assertIs(public_hamiltonian, SeparableHamiltonian)

    def test_discrete_map_is_bijective_and_inverse_round_trips(self):
        transform = DiscreteSymplecticMap(17, drift=3, kick=5)
        outputs = set()
        for q in range(17):
            for p in range(17):
                point = DiscretePhasePoint(q, p)
                mapped = transform.forward(point)
                outputs.add((mapped.q, mapped.p))
                self.assertEqual(transform.inverse(mapped), point)
        self.assertEqual(len(outputs), 17 * 17)

    def test_discrete_map_preserves_canonical_two_form(self):
        transform = DiscreteSymplecticMap(19, drift=7, kick=11)
        points = (
            DiscretePhasePoint(1, 2),
            DiscretePhasePoint(4, 9),
            DiscretePhasePoint(17, 5),
        )
        for left in points:
            for right in points:
                self.assertTrue(transform.preserves_form(left, right))

    def test_symplectic_schedule_covers_arbitrary_finite_windows(self):
        for count in (1, 2, 3, 4, 5, 8, 9, 10, 31, 32, 100, 1025):
            report = verify_symplectic_schedule(count, drift=3037, kick=5)
            self.assertTrue(report["complete"], report)
            values = tuple(iter_symplectic_ordinals(count, drift=3037, kick=5))
            self.assertEqual(set(values), set(range(count)))

    def test_schedule_parameters_are_measured_and_bounded(self):
        params = phase_space_parameters(65_537, drift=3037, kick=5)
        self.assertEqual(params["candidate_window"], 65_537)
        self.assertGreaterEqual(params["phase_space_points"], 65_537)
        self.assertLess(params["filtered_points"], 2 * int(math.sqrt(65_537)) + 2)

    def test_leapfrog_is_reversible_under_negative_step(self):
        omega = 1.3
        system = SeparableHamiltonian(
            potential=lambda q: 0.5 * omega * omega * q[0] * q[0],
            gradient=lambda q: (omega * omega * q[0],),
            masses=(1.0,),
        )
        initial = PhaseState((0.7,), (0.2,), 2.0)
        forward = leapfrog_step(system, initial, 0.01)
        recovered = leapfrog_step(system, forward, -0.01)
        self.assertAlmostEqual(recovered.q[0], initial.q[0], places=12)
        self.assertAlmostEqual(recovered.p[0], initial.p[0], places=12)
        self.assertAlmostEqual(recovered.time, initial.time, places=12)

    def test_leapfrog_preserves_area_for_harmonic_oscillator(self):
        omega = 1.1
        dt = 0.07
        a = 1.0 - 0.5 * dt * dt * omega * omega
        b = dt
        c = -dt * omega * omega * (1.0 - 0.25 * dt * dt * omega * omega)
        d = a
        determinant = a * d - b * c
        self.assertAlmostEqual(determinant, 1.0, places=14)

    def test_energy_error_is_bounded_over_finite_trajectory(self):
        omega = 1.0
        system = SeparableHamiltonian(
            potential=lambda q: 0.5 * omega * omega * q[0] * q[0],
            gradient=lambda q: (omega * omega * q[0],),
            masses=(1.0,),
        )
        initial = PhaseState((1.0,), (0.0,))
        states = integrate_trajectory(system, initial, step_size=0.01, steps=10_000)
        initial_energy = system.energy(initial)
        errors = [abs(system.energy(state) - initial_energy) for state in states]
        self.assertLess(max(errors), 1e-4)

    def test_boolean_and_noninteger_schedule_parameters_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "drift_must_be_integer"):
            phase_space_parameters(8, drift=True, kick=5)
        with self.assertRaisesRegex(ValueError, "kick_must_be_integer"):
            phase_space_parameters(8, drift=3, kick=5.5)

    def test_invalid_phase_parameters_fail_closed(self):
        with self.assertRaises(ValueError):
            DiscreteSymplecticMap(1, 1, 1)
        with self.assertRaises(ValueError):
            integrate_trajectory(
                SeparableHamiltonian(lambda q: 0.0, lambda q: (0.0,), (1.0,)),
                PhaseState((0.0,), (0.0,)), step_size=0.1, steps=1_000_001,
            )


if __name__ == "__main__":
    unittest.main()
