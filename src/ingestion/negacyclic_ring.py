"""Reference arithmetic for R_q = Z_q[X]/(X^n + 1).

This module is a mathematical oracle for tests and experiment commitments.
It is not an ML-KEM or ML-DSA implementation and is not constant-time.
"""
from __future__ import annotations

from collections.abc import Sequence

SUPPORTED_PROFILES = {
    "ML-KEM-768": (256, 3329),
    "ML-DSA-65": (256, 8380417),
}


class RingParameterError(ValueError):
    """Invalid ring dimensions, modulus, or coefficient vector."""


def _validate_ring(n: int, q: int) -> None:
    if isinstance(n, bool) or not isinstance(n, int) or n <= 0:
        raise RingParameterError("ring_degree_must_be_positive_integer")
    if isinstance(q, bool) or not isinstance(q, int) or q <= 2:
        raise RingParameterError("modulus_must_be_integer_greater_than_two")


def _validate_poly(poly: Sequence[int], n: int, q: int, label: str) -> tuple[int, ...]:
    if not isinstance(poly, (list, tuple)) or len(poly) != n:
        raise RingParameterError(f"{label}_must_have_{n}_coefficients")
    if any(
        isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < q
        for value in poly
    ):
        raise RingParameterError(f"{label}_coefficients_must_be_canonical_mod_q")
    return tuple(poly)


def centered_coefficients(poly: Sequence[int], q: int) -> tuple[int, ...]:
    if isinstance(q, bool) or not isinstance(q, int) or q <= 2:
        raise RingParameterError("modulus_must_be_integer_greater_than_two")
    return tuple(value - q if value > q // 2 else value for value in poly)


def negacyclic_shift(poly: Sequence[int], exponent: int, *, n: int = 256,
                     q: int = 3329) -> tuple[int, ...]:
    """Compute X**exponent * poly modulo X**n + 1 and q."""
    _validate_ring(n, q)
    values = _validate_poly(poly, n, q, "polynomial")
    if isinstance(exponent, bool) or not isinstance(exponent, int):
        raise RingParameterError("exponent_must_be_integer")
    shift = exponent % (2 * n)
    out = [0] * n
    for index, value in enumerate(values):
        destination = index + shift
        wraps, position = divmod(destination, n)
        out[position] = (-value if wraps & 1 else value) % q
    return tuple(out)


def negacyclic_multiply(left: Sequence[int], right: Sequence[int], *,
                        n: int = 256, q: int = 3329) -> tuple[int, ...]:
    """Multiply two polynomials in Z_q[X]/(X^n + 1), O(n^2) reference path."""
    _validate_ring(n, q)
    a = _validate_poly(left, n, q, "left")
    b = _validate_poly(right, n, q, "right")
    out = [0] * n
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            if bj == 0:
                continue
            degree = i + j
            if degree < n:
                out[degree] = (out[degree] + ai * bj) % q
            else:
                out[degree - n] = (out[degree - n] - ai * bj) % q
    return tuple(out)


def monomial_product(poly: Sequence[int], exponent: int, *,
                     n: int = 256, q: int = 3329) -> tuple[int, ...]:
    """Reference equality check target: multiply by X**exponent."""
    monomial = [0] * n
    shift = exponent % (2 * n)
    monomial[shift % n] = 1 if shift < n else q - 1
    return negacyclic_multiply(poly, monomial, n=n, q=q)


def verify_negacyclic_identities(poly: Sequence[int], *,
                                 n: int = 256, q: int = 3329) -> dict[str, bool]:
    """Check X^n=-1, X^(2n)=1, and monomial multiply/shift equivalence."""
    values = _validate_poly(poly, n, q, "polynomial")
    half = negacyclic_shift(values, n, n=n, q=q)
    full = negacyclic_shift(values, 2 * n, n=n, q=q)
    negative = tuple((-value) % q for value in values)
    monomial_ok = all(
        monomial_product(values, exponent, n=n, q=q)
        == negacyclic_shift(values, exponent, n=n, q=q)
        for exponent in (0, 1, n - 1, n, n + 1, 2 * n - 1, 2 * n)
    )
    return {
        "x_n_equals_minus_one": half == negative,
        "x_2n_equals_one": full == values,
        "monomial_multiplication_matches_shift": monomial_ok,
    }
