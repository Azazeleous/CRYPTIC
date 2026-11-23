"""QC-LDPC -> Reed-Solomon correction with independent re-verification."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Sequence

from .qc_ldpc import QCParityCheck, QCLDPCError
from .reed_solomon import ReedSolomonCode, ReedSolomonError


class CorrectionStackError(ValueError):
    """The layered correction pipeline could not verify a recovered message."""


@dataclass(frozen=True)
class CorrectionReceipt:
    message: bytes
    output_sha256: str
    qc_iterations: int
    qc_syndrome_weight: int
    rs_error_positions: tuple[int, ...]
    verified: bool


class CorrectionStack:
    """Encode RS symbols as QC-LDPC information bits and verify both layers."""

    def __init__(self, qc: QCParityCheck, reed_solomon: ReedSolomonCode):
        if qc.message_bits != reed_solomon.n * 8:
            raise CorrectionStackError("qc_message_capacity_must_equal_rs_codeword_bits")
        self.qc = qc
        self.reed_solomon = reed_solomon

    def encode(self, message: bytes | bytearray) -> tuple[int, ...]:
        payload = bytes(message)
        if len(payload) != self.reed_solomon.k:
            raise CorrectionStackError("payload_length_must_equal_rs_k")
        rs_word = self.reed_solomon.encode(payload)
        bits = tuple((byte >> shift) & 1 for byte in rs_word for shift in range(7, -1, -1))
        return self.qc.encode(bits)

    def decode(
        self,
        channel_llr: Sequence[float],
        *,
        max_iterations: int = 30,
        normalization: float = 0.8,
    ) -> CorrectionReceipt:
        try:
            qc_result = self.qc.decode(
                channel_llr, max_iterations=max_iterations, normalization=normalization
            )
        except QCLDPCError as exc:
            raise CorrectionStackError("qc_decode_rejected:" + str(exc)) from exc
        if not qc_result.converged:
            raise CorrectionStackError("qc_ldpc_failed_to_converge")
        if any(self.qc.syndrome(qc_result.bits)):
            raise CorrectionStackError("qc_syndrome_reverification_failed")

        information = qc_result.bits[:self.qc.message_bits]
        rs_word = bytes(
            sum(information[offset + bit] << (7 - bit) for bit in range(8))
            for offset in range(0, len(information), 8)
        )
        try:
            rs_result = self.reed_solomon.decode(rs_word)
        except ReedSolomonError as exc:
            raise CorrectionStackError("reed_solomon_decode_rejected:" + str(exc)) from exc
        if self.reed_solomon.encode(rs_result.message) != rs_result.corrected_codeword:
            raise CorrectionStackError("reed_solomon_reencoding_check_failed")
        return CorrectionReceipt(
            message=rs_result.message,
            output_sha256=hashlib.sha256(rs_result.message).hexdigest(),
            qc_iterations=qc_result.iterations,
            qc_syndrome_weight=0,
            rs_error_positions=rs_result.error_positions,
            verified=True,
        )
