"""GF(256) arithmetic and polynomial utilities over x^8+x^4+x^3+x^2+1."""
from __future__ import annotations

PRIMITIVE_POLYNOMIAL = 0x11D
FIELD_ORDER = 256
MULTIPLICATIVE_ORDER = 255

_EXP = [0] * 512
_LOG = [0] * 256
_value = 1
for _i in range(255):
    _EXP[_i] = _value
    _LOG[_value] = _i
    _value <<= 1
    if _value & 0x100:
        _value ^= PRIMITIVE_POLYNOMIAL
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _element(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 256:
        raise ValueError("GF(256) elements must be integers in [0, 255]")
    return value


def add(a: int, b: int) -> int:
    return _element(a) ^ _element(b)


def mul(a: int, b: int) -> int:
    a, b = _element(a), _element(b)
    if not a or not b:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def inv(value: int) -> int:
    value = _element(value)
    if value == 0:
        raise ZeroDivisionError("zero has no multiplicative inverse in GF(256)")
    return _EXP[255 - _LOG[value]]


def div(a: int, b: int) -> int:
    a, b = _element(a), _element(b)
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(256)")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def power(value: int, exponent: int) -> int:
    value = _element(value)
    if isinstance(exponent, bool) or not isinstance(exponent, int):
        raise TypeError("GF(256) exponent must be an integer")
    if exponent < 0:
        return power(inv(value), -exponent)
    if exponent == 0:
        return 1
    if value == 0:
        return 0
    return _EXP[(_LOG[value] * exponent) % 255]


def alpha_power(exponent: int) -> int:
    if isinstance(exponent, bool) or not isinstance(exponent, int):
        raise TypeError("exponent must be an integer")
    return _EXP[exponent % 255]


def poly_trim(poly: list[int] | tuple[int, ...]) -> list[int]:
    result = [_element(x) for x in poly]
    while len(result) > 1 and result[-1] == 0:
        result.pop()
    return result or [0]


def poly_add(a: list[int], b: list[int]) -> list[int]:
    size = max(len(a), len(b))
    out = [0] * size
    for i in range(size):
        out[i] = (a[i] if i < len(a) else 0) ^ (b[i] if i < len(b) else 0)
    return poly_trim(out)


def poly_scale(poly: list[int], scalar: int) -> list[int]:
    scalar = _element(scalar)
    return poly_trim([mul(x, scalar) for x in poly])


def poly_mul(a: list[int], b: list[int]) -> list[int]:
    a, b = poly_trim(a), poly_trim(b)
    if a == [0] or b == [0]:
        return [0]
    out = [0] * (len(a) + len(b) - 1)
    for i, left in enumerate(a):
        for j, right in enumerate(b):
            out[i + j] ^= mul(left, right)
    return poly_trim(out)


def poly_eval(poly: list[int] | tuple[int, ...], x: int) -> int:
    x = _element(x)
    acc = 0
    for coefficient in reversed(poly_trim(poly)):
        acc = mul(acc, x) ^ coefficient
    return acc


def poly_divmod(dividend: list[int], divisor: list[int]) -> tuple[list[int], list[int]]:
    work, divisor = poly_trim(dividend), poly_trim(divisor)
    if divisor == [0]:
        raise ZeroDivisionError("polynomial division by zero")
    if len(work) < len(divisor):
        return [0], work
    quotient = [0] * (len(work) - len(divisor) + 1)
    for offset in range(len(work) - len(divisor), -1, -1):
        lead = work[offset + len(divisor) - 1]
        if lead:
            factor = div(lead, divisor[-1])
            quotient[offset] = factor
            for j, coefficient in enumerate(divisor):
                work[offset + j] ^= mul(factor, coefficient)
    remainder = poly_trim(work[:len(divisor) - 1] or [0])
    return poly_trim(quotient), remainder


def solve_linear_system(matrix: list[list[int]], rhs: list[int]) -> list[int]:
    """Solve a possibly overdetermined full-column-rank system over GF(256)."""
    if len(matrix) != len(rhs) or not matrix:
        raise ValueError("matrix and right-hand side dimensions do not match")
    columns = len(matrix[0])
    if columns == 0 or any(len(row) != columns for row in matrix):
        raise ValueError("matrix must have a nonzero, consistent column count")
    augmented = [
        [_element(x) for x in row] + [_element(value)]
        for row, value in zip(matrix, rhs)
    ]
    pivot_columns: list[int] = []
    pivot_row = 0
    for column in range(columns):
        selected = next(
            (r for r in range(pivot_row, len(augmented))
             if augmented[r][column] != 0),
            None,
        )
        if selected is None:
            continue
        augmented[pivot_row], augmented[selected] = augmented[selected], augmented[pivot_row]
        scale = inv(augmented[pivot_row][column])
        augmented[pivot_row] = [mul(x, scale) for x in augmented[pivot_row]]
        for r in range(len(augmented)):
            if r == pivot_row:
                continue
            factor = augmented[r][column]
            if factor:
                augmented[r] = [
                    left ^ mul(factor, right)
                    for left, right in zip(augmented[r], augmented[pivot_row])
                ]
        pivot_columns.append(column)
        pivot_row += 1
        if pivot_row == len(augmented):
            break
    for row in augmented:
        if all(value == 0 for value in row[:columns]) and row[columns] != 0:
            raise ValueError("linear system is inconsistent")
    if len(pivot_columns) != columns:
        raise ValueError("linear system does not have a unique solution")
    solution = [0] * columns
    for row_index, column in enumerate(pivot_columns):
        solution[column] = augmented[row_index][columns]
    return solution
