"""Tests for exact SHA-256 inverse primitives."""
import random
import unittest

from src.ingestion.sha256_inverse import (
    expand_message_schedule,
    reverse_message_schedule,
    sha256_round_forward,
    sha256_round_inverse,
)


class Sha256InverseTests(unittest.TestCase):
    def test_round_inverse_for_all_64_round_positions(self):
        rng = random.Random(0xA2A2)
        state = tuple(rng.getrandbits(32) for _ in range(8))
        schedule = [rng.getrandbits(32) for _ in range(64)]
        constants = [rng.getrandbits(32) for _ in range(64)]
        current = state
        states = [state]
        for index in range(64):
            current = sha256_round_forward(
                current, schedule_word=schedule[index],
                round_constant=constants[index],
            )
            states.append(current)
        for index in range(63, -1, -1):
            current = sha256_round_inverse(
                current, schedule_word=schedule[index],
                round_constant=constants[index],
            )
            self.assertEqual(current, states[index])
        self.assertEqual(current, state)

    def test_schedule_round_trip_from_terminal_sixteen_words(self):
        rng = random.Random(0xF16E)
        first = [rng.getrandbits(32) for _ in range(16)]
        expanded = expand_message_schedule(first)
        reconstructed = reverse_message_schedule(expanded[48:])
        self.assertEqual(reconstructed, expanded)
        self.assertEqual(reconstructed[:16], tuple(first))

    def test_invalid_schedule_boundary_rejected(self):
        with self.assertRaisesRegex(ValueError, "16_words"):
            reverse_message_schedule([1, 2, 3])
        with self.assertRaisesRegex(ValueError, "uint32"):
            expand_message_schedule([0] * 15 + [-1])


if __name__ == "__main__":
    unittest.main()
