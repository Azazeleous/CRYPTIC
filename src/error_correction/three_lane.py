"""Three-lane correction with independent Reed-Solomon re-verification."""
from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Sequence

from .pipeline import CorrectionStack, CorrectionStackError
from .reference_rs import (
    ReferenceReedSolomonError,
    decode_evaluations_reference,
    encode_evaluations_reference,
)
from .reed_solomon import ReedSolomonError


class ThreeLaneCorrectionError(ValueError):
    """No independently verified two-lane correction agreement was reached."""


@dataclass(frozen=True)
class ThreeLaneReceipt:
    message: bytes
    output_sha256: str
    agreeing_lanes: tuple[str, ...]
    failed_lanes: tuple[tuple[str, str], ...]
    lane_digests: tuple[tuple[str, str], ...]
    verified: bool


class ThreeLaneCorrection:
    """Require a two-of-three agreement across distinct decode paths.

    Lane 1 performs the full QC-LDPC -> production Reed-Solomon stack.
    Lane 2 bypasses QC decoding and applies the production RS decoder to
    systematic information bits.
    Lane 3 independently decodes those same symbols using a separate
    bitwise-GF(256) implementation with its own polynomial solver.

    Any accepted candidate is re-encoded by both RS implementations and by
    the QC encoder. A single lane cannot authorize output.
    """

    def __init__(self, stack: CorrectionStack):
        if not isinstance(stack, CorrectionStack):
            raise ThreeLaneCorrectionError("correction_stack_required")
        self.stack = stack

    def _normalize_llr(self, values: Sequence[float]) -> tuple[float, ...]:
        try:
            if len(values) != self.stack.qc.codeword_bits:
                raise ThreeLaneCorrectionError("llr_length_invalid")
        except TypeError as exc:
            raise ThreeLaneCorrectionError("llr_sequence_required") from exc
        normalized = []
        for value in values:
            if isinstance(value, bool):
                raise ThreeLaneCorrectionError("llr_values_must_be_finite_numbers")
            try:
                number = float(value)
            except (TypeError, ValueError, OverflowError) as exc:
                raise ThreeLaneCorrectionError(
                    "llr_values_must_be_finite_numbers"
                ) from exc
            if not math.isfinite(number):
                raise ThreeLaneCorrectionError("llr_values_must_be_finite_numbers")
            normalized.append(number)
        return tuple(normalized)

    def _hard_information_word(self, llr: tuple[float, ...]) -> bytes:
        hard = tuple(0 if value >= 0 else 1 for value in llr)
        information = hard[:self.stack.qc.message_bits]
        if len(information) % 8:
            raise ThreeLaneCorrectionError("information_bits_not_byte_aligned")
        return bytes(
            sum(information[offset + bit] << (7 - bit) for bit in range(8))
            for offset in range(0, len(information), 8)
        )

    def decode(
        self,
        channel_llr: Sequence[float],
        *,
        max_iterations: int = 30,
        normalization: float = 0.8,
    ) -> ThreeLaneReceipt:
        if (isinstance(max_iterations, bool) or not isinstance(max_iterations, int)
                or max_iterations < 1):
            raise ThreeLaneCorrectionError("max_iterations_invalid")
        if (isinstance(normalization, bool) or not isinstance(normalization, (int, float))
                or not math.isfinite(normalization) or not 0 < normalization <= 1):
            raise ThreeLaneCorrectionError("normalization_invalid")
        llr = self._normalize_llr(channel_llr)
        codec = self.stack.reed_solomon
        hard_word = self._hard_information_word(llr)
        outcomes: dict[str, tuple[bytes, bytes]] = {}
        failures: list[tuple[str, str]] = []

        try:
            layered = self.stack.decode(
                llr, max_iterations=max_iterations, normalization=normalization
            )
            outcomes["layered_qc_rs"] = (
                layered.message, codec.encode(layered.message)
            )
        except (CorrectionStackError, ReedSolomonError, ValueError) as exc:
            failures.append(("layered_qc_rs", str(exc)))

        try:
            direct = codec.decode(hard_word)
            outcomes["direct_rs"] = (
                direct.message, direct.corrected_codeword
            )
        except ReedSolomonError as exc:
            failures.append(("direct_rs", str(exc)))

        try:
            reference = decode_evaluations_reference(
                codec.points, hard_word, degree=codec.k,
                max_errors=codec.max_errors,
            )
            reference_message = bytes(reference.coefficients)
            reference_word = encode_evaluations_reference(
                reference.coefficients, codec.points
            )
            if reference_word != reference.corrected_values:
                raise ReferenceReedSolomonError("reference_reencoding_mismatch")
            outcomes["independent_reference_rs"] = (
                reference_message, reference_word
            )
        except ReferenceReedSolomonError as exc:
            failures.append(("independent_reference_rs", str(exc)))

        # Reject any lane whose own corrected codeword is not the exact output
        # of both encoders. This also detects divergence between implementations.
        for lane, (message, corrected_word) in tuple(outcomes.items()):
            try:
                production_word = codec.encode(message)
                reference_word = encode_evaluations_reference(message, codec.points)
                if (len(message) != codec.k or corrected_word != production_word
                        or corrected_word != reference_word):
                    raise ThreeLaneCorrectionError("lane_reencoding_mismatch")
            except (ReedSolomonError, ReferenceReedSolomonError,
                    ThreeLaneCorrectionError) as exc:
                del outcomes[lane]
                failures.append((lane, str(exc)))

        groups: dict[tuple[bytes, bytes], list[str]] = {}
        for lane, result in outcomes.items():
            groups.setdefault(result, []).append(lane)
        majorities = [(result, lanes) for result, lanes in groups.items() if len(lanes) >= 2]
        if len(majorities) != 1:
            raise ThreeLaneCorrectionError("no_two_lane_agreement")

        (message, corrected_word), agreeing = majorities[0]
        # Final independent codeword checks precede the receipt.
        if (codec.encode(message) != corrected_word
                or encode_evaluations_reference(message, codec.points) != corrected_word):
            raise ThreeLaneCorrectionError("final_rs_reverification_failed")
        try:
            encoded_bits = self.stack.encode(message)
        except CorrectionStackError as exc:
            raise ThreeLaneCorrectionError("final_qc_reencoding_failed") from exc
        if any(self.stack.qc.syndrome(encoded_bits)):
            raise ThreeLaneCorrectionError("final_qc_syndrome_failed")

        lane_digests = tuple(sorted(
            (lane, hashlib.sha256(result[0]).hexdigest())
            for lane, result in outcomes.items()
        ))
        return ThreeLaneReceipt(
            message=message,
            output_sha256=hashlib.sha256(message).hexdigest(),
            agreeing_lanes=tuple(sorted(agreeing)),
            failed_lanes=tuple(sorted(failures)),
            lane_digests=lane_digests,
            verified=True,
        )
