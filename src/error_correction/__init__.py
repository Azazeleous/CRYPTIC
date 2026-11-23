"""Structured error-correction primitives for CRYPTIC."""
from .berlekamp_welch import BerlekampWelchError, PolynomialDecode, decode_evaluations
from .gf256 import PRIMITIVE_POLYNOMIAL
from .pipeline import CorrectionReceipt, CorrectionStack, CorrectionStackError
from .qc_ldpc import DEFAULT_BASE_MATRIX, QCParityCheck, QCLDPCDecode, QCLDPCError
from .reed_solomon import ReedSolomonCode, ReedSolomonDecode, ReedSolomonError
from .storage import ChunkStore, ChunkStoreError, StoredManifest

__all__ = [
    "BerlekampWelchError", "CorrectionReceipt", "CorrectionStack",
    "CorrectionStackError", "DEFAULT_BASE_MATRIX", "PRIMITIVE_POLYNOMIAL",
    "PolynomialDecode", "QCParityCheck", "QCLDPCDecode", "QCLDPCError",
    "ReedSolomonCode", "ReedSolomonDecode", "ReedSolomonError",
    "ChunkStore", "ChunkStoreError", "StoredManifest", "decode_evaluations",
]
