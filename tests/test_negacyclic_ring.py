"""Reference tests for negacyclic polynomial arithmetic."""
import random
import unittest

from src.ingestion.negacyclic_ring import (
    RingParameterError,
    centered_coefficients,
    negacyclic_multiply,
    negacyclic_shift,
    verify_negacyclic_identities,
)


class NegacyclicRingTests(unittest.TestCase):
    def test_parameter_profiles_and_fundamental_identities(self):
        rng = random.Random(0xA256)
        for n, q in ((256, 3329), (256, 8380417)):
            poly = tuple(rng.randrange(q) for _ in range(n))
            checks = verify_negacyclic_identities(poly, n=n, q=q)
            self.assertTrue(all(checks.values()), checks)

    def test_x_to_n_is_negative_identity_and_x_to_2n_is_identity(self):
        poly = tuple((i * 17 + 5) % 3329 for i in range(256))
        self.assertEqual(
            negacyclic_shift(poly, 256),
            tuple((-value) % 3329 for value in poly),
        )
        self.assertEqual(negacyclic_shift(poly, 512), poly)

    def test_monomial_multiplication_wraps_with_negative_sign(self):
        x_255 = [0] * 256
        x_255[255] = 1
        x = [0] * 256
        x[1] = 1
        product = negacyclic_multiply(x_255, x)
        self.assertEqual(product[0], 3328)
        self.assertEqual(sum(value != 0 for value in product), 1)

    def test_centered_representatives(self):
        self.assertEqual(centered_coefficients((0, 1, 1664, 1665, 3328), 3329),
                         (0, 1, 1664, -1664, -1))

    def test_invalid_dimensions_and_coefficients_rejected(self):
        with self.assertRaises(RingParameterError):
            negacyclic_shift([0] * 3, 1, n=4, q=17)
        with self.assertRaises(RingParameterError):
            negacyclic_multiply([0] * 4, [0, 0, 0, 17], n=4, q=17)
        with self.assertRaises(RingParameterError):
            negacyclic_shift([0] * 4, True, n=4, q=17)


if __name__ == "__main__":
    unittest.main()
