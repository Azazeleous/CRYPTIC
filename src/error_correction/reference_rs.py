"""Independent GF(256) reference implementation for RS verification.

This module deliberately does not import the production GF(256), polynomial,
or Berlekamp-Welch helpers. It uses bitwise field multiplication and its own
Gaussian elimination so a second implementation can independently verify the
production decoder's output.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

_PRIMITIVE = 0x11D


class ReferenceReedSolomonError(ValueError):
    """The independent reference decoder rejected its inputs or result."""


@dataclass(frozen=True)
class ReferenceDecode:
    coefficients: tuple[int, ...]
    corrected_values: bytes
    error_positions: tuple[int, ...]


def _element(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 255:
        raise ReferenceReedSolomonError("gf256_element_invalid")
    return value


def _mul(left: int, right: int) -> int:
    left, right = _element(left), _element(right)
    result = 0
    while right:
        if right & 1:
            result ^= left
        right >>= 1
        left <<= 1
        if left & 0x100:
            left ^= _PRIMITIVE
    return result


def _pow(value: int, exponent: int) -> int:
    value = _element(value)
    if isinstance(exponent, bool) or not isinstance(exponent, int) or exponent < 0:
        raise ReferenceReedSolomonError("gf256_exponent_invalid")
    result = 1
    while exponent:
        if exponent & 1:
            result = _mul(result, value)
        value = _mul(value, value)
        exponent >>= 1
    return result


def _inverse(value: int) -> int:
    value = _element(value)
    if value == 0:
        raise ReferenceReedSolomonError("gf256_zero_inverse")
    return _pow(value, 254)


def _trim(poly: Sequence[int]) -> list[int]:
    result = [_element(value) for value in poly]
    while len(result) > 1 and result[-1] == 0:
        result.pop()
    return result or [0]


def _evaluate(poly: Sequence[int], point: int) -> int:
    point = _element(point)
    result = 0
    for coefficient in reversed(_trim(poly)):
        result = _mul(result, point) ^ coefficient
    return result


def _divide(dividend: Sequence[int], divisor: Sequence[int]) -> tuple[list[int], list[int]]:
    work = _trim(dividend)
    denominator = _trim(divisor)
    if denominator == [0]:
        raise ReferenceReedSolomonError("polynomial_division_by_zero")
    if len(work) < len(denominator):
        return [0], work
    quotient = [0] * (len(work) - len(denominator) + 1)
    denominator_inverse = _inverse(denominator[-1])
    while len(work) >= len(denominator) and work != [0]:
        offset = len(work) - len(denominator)
        factor = _mul(work[-1], denominator_inverse)
        quotient[offset] = factor
        for index, coefficient in enumerate(denominator):
            work[offset + index] ^= _mul(factor, coefficient)
        work = _trim(work)
    return _trim(quotient), _trim(work)


def _solve(matrix: Sequence[Sequence[int]], rhs: Sequence[int]) -> list[int]:
    if not matrix or len(matrix) != len(rhs):
        raise ReferenceReedSolomonError("linear_system_dimensions_invalid")
    columns = len(matrix[0])
    if columns == 0 or any(len(row) != columns for row in matrix):
        raise ReferenceReedSolomonError("linear_system_shape_invalid")
    augmented = [
        [_element(value) for value in row] + [_element(rhs[index])]
        for index, row in enumerate(matrix)
    ]
    pivot_columns: list[int] = []
    pivot_row = 0
    for column in range(columns):
        pivot = next(
            (row for row in range(pivot_row, len(augmented))
             if augmented[row][column] != 0),
            None,
        )
        if pivot is None:
            continue
        augmented[pivot_row], augmented[pivot] = augmented[pivot], augmented[pivot_row]
        scale = _inverse(augmented[pivot_row][column])
        augmented[pivot_row] = [_mul(value, scale) for value in augmented[pivot_row]]
        for row in range(len(augmented)):
            if row == pivot_row:
                continue
            factor = augmented[row][column]
            if factor:
                augmented[row] = [
                    left ^ _mul(factor, right)
                    for left, right in zip(augmented[row], augmented[pivot_row])
                ]
        pivot_columns.append(column)
        pivot_row += 1
        if pivot_row == len(augmented):
            break
    if any(all(value == 0 for value in row[:columns]) and row[columns]
           for row in augmented):
        raise ReferenceReedSolomonError("linear_system_inconsistent")
    if len(pivot_columns) != columns:
        raise ReferenceReedSolomonError("linear_system_not_unique")
    solution = [0] * columns
    for row, column in enumerate(pivot_columns):
        solution[column] = augmented[row][columns]
    return solution


def encode_evaluations_reference(
    coefficients: Sequence[int], points: Sequence[int],
) -> bytes:
    if not coefficients or not points:
        raise ReferenceReedSolomonError("evaluation_input_empty")
    polynomial = _trim(coefficients)
    return bytes(_evaluate(polynomial, point) for point in points)


def decode_evaluations_reference(
    points: Sequence[int],
    values: Sequence[int],
    *,
    degree: int,
    max_errors: int,
) -> ReferenceDecode:
    if len(points) != len(values) or not points:
        raise ReferenceReedSolomonError("points_values_length_mismatch")
    if (isinstance(degree, bool) or not isinstance(degree, int) or degree < 1
            or isinstance(max_errors, bool) or not isinstance(max_errors, int)
            or max_errors < 0):
        raise ReferenceReedSolomonError("decoder_parameters_invalid")
    x_values = tuple(_element(value) for value in points)
    y_values = tuple(_element(value) for value in values)
    if len(set(x_values)) != len(x_values):
        raise ReferenceReedSolomonError("evaluation_points_not_distinct")
    if len(x_values) < degree + 2 * max_errors:
        raise ReferenceReedSolomonError("insufficient_evaluations")

    for error_count in range(max_errors + 1):
        q_count = degree + error_count
        matrix: list[list[int]] = []
        rhs: list[int] = []
        for x, y in zip(x_values, y_values):
            powers = [1]
            for _ in range(q_count):
                powers.append(_mul(powers[-1], x))
            matrix.append(
                powers[:q_count]
                + [_mul(y, powers[index]) for index in range(error_count)]
            )
            rhs.append(_mul(y, powers[error_count]))
        try:
            solution = _solve(matrix, rhs)
            numerator = solution[:q_count]
            locator = solution[q_count:] + [1]
            polynomial, remainder = _divide(numerator, locator)
        except ReferenceReedSolomonError:
            continue
        if remainder != [0] or len(polynomial) > degree:
            continue
        corrected = bytes(_evaluate(polynomial, x) for x in x_values)
        errors = tuple(
            index for index, (received, recovered) in enumerate(zip(y_values, corrected))
            if received != recovered
        )
        if len(errors) <= error_count:
            padded = tuple(polynomial + [0] * (degree - len(polynomial)))
            return ReferenceDecode(padded, corrected, errors)
    raise ReferenceReedSolomonError("no_unique_polynomial_within_error_bound")
