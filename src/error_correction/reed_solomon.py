"""Reed-Solomon evaluation code over GF(256), decoded by Berlekamp-Welch."""
from __future__ import annotations

from dataclasses import dataclass

from .berlekamp_welch import BerlekampWelchError, decode_evaluations
from .gf256 import alpha_power


class ReedSolomonError(ValueError):
    """A Reed-Solomon word is invalid or exceeds its correction capacity."""


@dataclass(frozen=True)
class ReedSolomonDecode:
    message: bytes
    corrected_codeword: bytes
    error_positions: tuple[int, ...]


class ReedSolomonCode:
    """An (n,k) evaluation code; message bytes are polynomial coefficients.

    This is a non-systematic evaluation profile: the k message bytes are the
    ascending GF(256) coefficients and the n code symbols are evaluations at
    alpha**0 through alpha**(n-1). It corrects up to floor((n-k)/2) unknown
    symbol errors. Erasure decoding is intentionally not claimed.
    """

    def __init__(self, n: int, k: int):
        if isinstance(n, bool) or isinstance(k, bool) or not isinstance(n, int) or not isinstance(k, int):
            raise ReedSolomonError("code_dimensions_must_be_integers")
        if not 1 <= k < n <= 255:
            raise ReedSolomonError("require_1_le_k_lt_n_le_255")
        self.n = n
        self.k = k
        self.max_errors = (n - k) // 2
        self.points = tuple(alpha_power(i) for i in range(n))

    def encode(self, message: bytes | bytearray) -> bytes:
        data = bytes(message)
        if len(data) != self.k:
            raise ReedSolomonError("message_length_must_equal_k")
        from .gf256 import poly_eval
        return bytes(poly_eval(data, point) for point in self.points)

    def decode(self, received: bytes | bytearray) -> ReedSolomonDecode:
        codeword = bytes(received)
        if len(codeword) != self.n:
            raise ReedSolomonError("codeword_length_must_equal_n")
        try:
            result = decode_evaluations(
                self.points, codeword, degree=self.k, max_errors=self.max_errors
            )
        except BerlekampWelchError as exc:
            raise ReedSolomonError(str(exc)) from exc
        message = bytes(result.coefficients)
        corrected = self.encode(message)
        if corrected != bytes(result.corrected_values):
            raise ReedSolomonError("independent_reencoding_check_failed")
        return ReedSolomonDecode(message, corrected, result.error_positions)
