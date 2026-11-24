import unittest
from src.verification.unbound_inverse import UnboundInverseModule, verify_left_inverse


class UnboundInverseTests(unittest.TestCase):
    def setUp(self):
        self.forward = lambda x: (3 * x + 2) % 17
        self.inverse = lambda y: (6 * (y - 2)) % 17
        self.solver = UnboundInverseModule(self.inverse, self.forward)

    def test_right_and_left_inverse_identities_over_complete_finite_domain(self):
        for value in range(17):
            receipt = self.solver.solve(self.forward(value))
            self.assertTrue(receipt.accepted, receipt.reason)
            self.assertEqual(receipt.reconstructed, value)
            self.assertTrue(verify_left_inverse(value, self.forward, self.inverse))

    def test_wrong_inverse_is_rejected(self):
        receipt = UnboundInverseModule(lambda y: (y + 1) % 17, self.forward).solve(5)
        self.assertFalse(receipt.accepted)
        self.assertEqual(receipt.reason, "forward_reconstruction_mismatch")

    def test_operator_failure_returns_unaccepted_receipt(self):
        bad = lambda _y: (_ for _ in ()).throw(RuntimeError())
        receipt = UnboundInverseModule(bad, self.forward).solve(7)
        self.assertFalse(receipt.accepted)
        self.assertEqual(receipt.reason, "inverse_or_forward_error:RuntimeError")

    def test_non_callable_operators_are_rejected(self):
        with self.assertRaisesRegex(TypeError, "operators_must_be_callable"):
            UnboundInverseModule(None, self.forward)


if __name__ == "__main__":
    unittest.main()
