"""Bounded Berlekamp-Welch decoding for GF(256) evaluation codes."""
from __future__ import annotations

from dataclasses import dataclass

from .gf256 import poly_divmod, poly_eval, power, solve_linear_system


class BerlekampWelchError(ValueError):
    """The supplied evaluation points cannot be decoded within the error bound."""


@dataclass(frozen=True)
class PolynomialDecode:
    coefficients: tuple[int, ...]
    corrected_values: tuple[int, ...]
    error_positions: tuple[int, ...]


def decode_evaluations(
    points: list[int] | tuple[int, ...],
    values: list[int] | tuple[int, ...],
    *,
    degree: int,
    max_errors: int,
) -> PolynomialDecode:
    """Recover a polynomial of degree < degree despite at most max_errors errors.

    Coefficients are returned in ascending order. The decoder uses the
    Berlekamp-Welch Q(x)=f(x)E(x) construction and rejects non-unique solutions.
    """
    if len(points) != len(values) or not points:
        raise BerlekampWelchError("points_and_values_length_mismatch")
    if isinstance(degree, bool) or not isinstance(degree, int) or degree < 1:
        raise BerlekampWelchError("degree_invalid")
    if isinstance(max_errors, bool) or not isinstance(max_errors, int) or max_errors < 0:
        raise BerlekampWelchError("max_errors_invalid")
    if len(points) < degree + 2 * max_errors:
        raise BerlekampWelchError("insufficient_evaluations_for_error_bound")
    if any(isinstance(x, bool) or not isinstance(x, int) or not 0 <= x < 256 for x in points):
        raise BerlekampWelchError("evaluation_point_invalid")
    if any(isinstance(y, bool) or not isinstance(y, int) or not 0 <= y < 256 for y in values):
        raise BerlekampWelchError("evaluation_value_invalid")
    if len(set(points)) != len(points):
        raise BerlekampWelchError("evaluation_points_not_distinct")

    for error_count in range(max_errors + 1):
        q_count = degree + error_count
        unknowns = q_count + error_count
        matrix: list[list[int]] = []
        rhs: list[int] = []
        for x, y in zip(points, values):
            powers = [power(x, exponent) for exponent in range(max(q_count, error_count + 1))]
            matrix.append(
                powers[:q_count]
                + [y * 0 ^ (0) for _ in ()]
                + [__import__("builtins").int(0) for _ in ()]
            )
            matrix[-1] = powers[:q_count] + [
                _gf_mul(y, powers[j]) for j in range(error_count)
            ]
            rhs.append(_gf_mul(y, powers[error_count]))
        try:
            solution = solve_linear_system(matrix, rhs)
        except ValueError:
            continue
        q_poly = solution[:q_count]
        e_poly = solution[q_count:] + [1]
        polynomial, remainder = poly_divmod(q_poly, e_poly)
        if remainder != [0] or len(polynomial) > degree:
            continue
        corrected = tuple(poly_eval(polynomial, x) for x in points)
        errors = tuple(i for i, (actual, expected) in enumerate(zip(values, corrected))
                       if actual != expected)
        if len(errors) <= error_count:
            coefficients = tuple(polynomial + [0] * (degree - len(polynomial)))
            return PolynomialDecode(coefficients, corrected, errors)
    raise BerlekampWelchError("no_unique_polynomial_within_error_bound")


def _gf_mul(a: int, b: int) -> int:
    from .gf256 import mul
    return mul(a, b)
