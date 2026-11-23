"""QC-LDPC parity checks and normalized min-sum decoding.

The parity-check matrix is built from circulant shifts in a base matrix.
The final parity blocks must form an identity matrix of zero-shift circulants,
which gives this profile a deterministic systematic encoder.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Sequence


class QCLDPCError(ValueError):
    """Invalid QC-LDPC parameters or input."""


@dataclass(frozen=True)
class QCLDPCDecode:
    bits: tuple[int, ...]
    converged: bool
    iterations: int
    syndrome_weight: int


DEFAULT_BASE_MATRIX = (
    (0, 1, -1, 2, 0, -1, -1, -1),
    (-1, 0, 1, -1, -1, 0, -1, -1),
    (2, -1, 0, 1, -1, -1, 0, -1),
    (1, 2, 3, 0, -1, -1, -1, 0),
)


class QCParityCheck:
    """Structured QC-LDPC code with a systematic message/parity partition."""

    def __init__(self, base_matrix: Sequence[Sequence[int]], lift: int):
        if isinstance(lift, bool) or not isinstance(lift, int) or lift < 2:
            raise QCLDPCError("lifting_factor_must_be_at_least_two")
        matrix = tuple(tuple(row) for row in base_matrix)
        if not matrix or not matrix[0]:
            raise QCLDPCError("base_matrix_must_not_be_empty")
        rows, columns = len(matrix), len(matrix[0])
        if columns <= rows or any(len(row) != columns for row in matrix):
            raise QCLDPCError("base_matrix_dimensions_invalid")
        for row in matrix:
            for shift in row:
                if isinstance(shift, bool) or not isinstance(shift, int) or shift < -1 or shift >= lift:
                    raise QCLDPCError("circulant_shift_out_of_range")
        parity_start = columns - rows
        for r in range(rows):
            for c in range(rows):
                expected = 0 if r == c else -1
                if matrix[r][parity_start + c] != expected:
                    raise QCLDPCError("parity_partition_must_be_identity_circulants")
        self.base_matrix = matrix
        self.lift = lift
        self.base_rows = rows
        self.base_columns = columns
        self.message_blocks = columns - rows
        self.message_bits = self.message_blocks * lift
        self.parity_bits = rows * lift
        self.codeword_bits = columns * lift
        checks: list[tuple[int, ...]] = []
        for row in matrix:
            for index in range(lift):
                neighbors = tuple(
                    column * lift + ((index + shift) % lift)
                    for column, shift in enumerate(row) if shift >= 0
                )
                checks.append(neighbors)
        self.check_to_variables = tuple(checks)

    @classmethod
    def default(cls, lift: int = 64) -> "QCParityCheck":
        return cls(DEFAULT_BASE_MATRIX, lift)

    def _bits(self, values: Sequence[int], expected: int, name: str) -> tuple[int, ...]:
        if len(values) != expected:
            raise QCLDPCError(name + "_length_invalid")
        result = tuple(values)
        if any(isinstance(bit, bool) or not isinstance(bit, int) or bit not in (0, 1)
               for bit in result):
            raise QCLDPCError(name + "_must_contain_bits")
        return result

    def encode(self, message_bits: Sequence[int]) -> tuple[int, ...]:
        message = self._bits(message_bits, self.message_bits, "message")
        parity = [0] * self.parity_bits
        for row_block, row in enumerate(self.base_matrix):
            for index in range(self.lift):
                value = 0
                for column, shift in enumerate(row[:self.message_blocks]):
                    if shift >= 0:
                        value ^= message[column * self.lift + ((index + shift) % self.lift)]
                parity[row_block * self.lift + index] = value
        codeword = message + tuple(parity)
        if any(self.syndrome(codeword)):
            raise QCLDPCError("encoder_internal_syndrome_failure")
        return codeword

    def syndrome(self, codeword_bits: Sequence[int]) -> tuple[int, ...]:
        bits = self._bits(codeword_bits, self.codeword_bits, "codeword")
        return tuple(_xor(bits[index] for index in neighbors)
                     for neighbors in self.check_to_variables)

    def decode(
        self,
        channel_llr: Sequence[float],
        *,
        max_iterations: int = 30,
        normalization: float = 0.8,
    ) -> QCLDPCDecode:
        if len(channel_llr) != self.codeword_bits:
            raise QCLDPCError("llr_length_invalid")
        if isinstance(max_iterations, bool) or not isinstance(max_iterations, int) or max_iterations < 1:
            raise QCLDPCError("max_iterations_invalid")
        if (not isinstance(normalization, (int, float)) or isinstance(normalization, bool)
                or not math.isfinite(normalization) or not 0 < normalization <= 1):
            raise QCLDPCError("normalization_must_be_in_0_1")
        try:
            channel = tuple(float(value) for value in channel_llr)
        except (TypeError, ValueError, OverflowError) as exc:
            raise QCLDPCError("llr_values_must_be_finite_numbers") from exc
        if any(not math.isfinite(value) for value in channel):
            raise QCLDPCError("llr_values_must_be_finite_numbers")
        check_messages = [[0.0] * len(neighbors) for neighbors in self.check_to_variables]
        posterior = list(channel)
        hard = tuple(0 if value >= 0 else 1 for value in posterior)
        syndrome_weight = sum(self.syndrome(hard))
        if syndrome_weight == 0:
            return QCLDPCDecode(hard, True, 0, 0)

        for iteration in range(1, max_iterations + 1):
            posterior = list(channel)
            for check_index, neighbors in enumerate(self.check_to_variables):
                for edge, variable in enumerate(neighbors):
                    posterior[variable] += check_messages[check_index][edge]

            updated: list[list[float]] = []
            for check_index, neighbors in enumerate(self.check_to_variables):
                incoming = [
                    posterior[variable] - check_messages[check_index][edge]
                    for edge, variable in enumerate(neighbors)
                ]
                outgoing = [0.0] * len(neighbors)
                for edge in range(len(neighbors)):
                    others = [value for j, value in enumerate(incoming) if j != edge]
                    if not others:
                        continue
                    sign = -1.0 if sum(value < 0 for value in others) % 2 else 1.0
                    magnitude = min(abs(value) for value in others)
                    outgoing[edge] = normalization * sign * magnitude
                updated.append(outgoing)
            check_messages = updated
            posterior = list(channel)
            for check_index, neighbors in enumerate(self.check_to_variables):
                for edge, variable in enumerate(neighbors):
                    posterior[variable] += check_messages[check_index][edge]
            hard = tuple(0 if value >= 0 else 1 for value in posterior)
            syndrome_weight = sum(self.syndrome(hard))
            if syndrome_weight == 0:
                return QCLDPCDecode(hard, True, iteration, 0)
        return QCLDPCDecode(hard, False, max_iterations, syndrome_weight)


def _xor(values) -> int:
    result = 0
    for value in values:
        result ^= value
    return result
