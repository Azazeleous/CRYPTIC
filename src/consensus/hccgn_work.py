"""Canonical HCCGN-WORK/1 binary header and proof verifier.

This is a newly defined profile, not a Bitcoin header or a historical HCCGN
format. Consensus callers must pin the active target independently.
"""
from __future__ import annotations

import hashlib
import math
import struct
import time
from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping

PROFILE_ID = "HCCGN-WORK/1"
HEADER_MAGIC = b"HCCGNW01"
PROOF_MAGIC = b"HCCGN-PROOF/1\x00"
WORK_DOMAIN = b"HCCGN-WORK/1\x00"
HEADER_FORMAT = ">8sH32sQQQ32s32sIIIHQ32s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
PRIMARY_MODULUS = 97_152
COMPACT_MODULUS = 1_518

class HCCGNWorkError(ValueError):
    pass

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def network_hash(network_id: str) -> bytes:
    if not isinstance(network_id, str) or not network_id:
        raise HCCGNWorkError("network_id_invalid")
    return sha256(network_id.encode("utf-8"))

def _u(value: Any, bits: int, field: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise HCCGNWorkError(f"{field}_must_be_integer")
    if value < minimum or value >= (1 << bits):
        raise HCCGNWorkError(f"{field}_out_of_range")
    return value

def _b32(value: bytes, field: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise HCCGNWorkError(f"{field}_must_be_32_bytes")
    return value

@dataclass(frozen=True)
class HCCGNWorkHeader:
    network_id_hash: bytes
    height: int
    sequence: int
    timestamp: int
    parent_hash: bytes
    payload_hash: bytes
    primary_stride: int
    compact_stride: int
    nonce: int
    target: bytes
    version: int = 1

    def encode(self) -> bytes:
        _u(self.version, 16, "version", 1)
        if self.version != 1:
            raise HCCGNWorkError("work_version_unsupported")
        _b32(self.network_id_hash, "network_id_hash")
        _b32(self.parent_hash, "parent_hash")
        _b32(self.payload_hash, "payload_hash")
        _b32(self.target, "target")
        _u(self.height, 64, "height", 1)
        _u(self.sequence, 64, "sequence", 1)
        _u(self.timestamp, 64, "timestamp")
        _u(self.nonce, 64, "nonce")
        _u(self.primary_stride, 32, "primary_stride", 1)
        _u(self.compact_stride, 16, "compact_stride", 1)
        if self.primary_stride >= PRIMARY_MODULUS or math.gcd(self.primary_stride, PRIMARY_MODULUS) != 1:
            raise HCCGNWorkError("primary_stride_not_coprime")
        if self.compact_stride >= COMPACT_MODULUS or math.gcd(self.compact_stride, COMPACT_MODULUS) != 1:
            raise HCCGNWorkError("compact_stride_not_coprime")
        return struct.pack(HEADER_FORMAT, HEADER_MAGIC, self.version, self.network_id_hash,
            self.height, self.sequence, self.timestamp, self.parent_hash, self.payload_hash,
            PRIMARY_MODULUS, COMPACT_MODULUS, self.primary_stride, self.compact_stride,
            self.nonce, self.target)

    @classmethod
    def decode(cls, raw: bytes) -> 'HCCGNWorkHeader':
        if not isinstance(raw, bytes) or len(raw) != HEADER_SIZE:
            raise HCCGNWorkError("header_length_invalid")
        values = struct.unpack(HEADER_FORMAT, raw)
        (magic, version, network_id_hash, height, sequence, timestamp, parent_hash,
         payload_hash, primary_modulus, compact_modulus, primary_stride,
         compact_stride, nonce, target) = values
        if magic != HEADER_MAGIC:
            raise HCCGNWorkError("header_magic_invalid")
        if version != 1:
            raise HCCGNWorkError("work_version_unsupported")
        if primary_modulus != PRIMARY_MODULUS or compact_modulus != COMPACT_MODULUS:
            raise HCCGNWorkError("residue_modulus_mismatch")
        header = cls(network_id_hash, height, sequence, timestamp, parent_hash, payload_hash,
                     primary_stride, compact_stride, nonce, target, version)
        header.encode()
        return header

def work_digest(header_bytes: bytes) -> bytes:
    if not isinstance(header_bytes, bytes) or len(header_bytes) != HEADER_SIZE:
        raise HCCGNWorkError("header_length_invalid")
    return sha256(WORK_DOMAIN + header_bytes)

def build_proof(header: HCCGNWorkHeader) -> bytes:
    raw = header.encode()
    return PROOF_MAGIC + struct.pack('>H', len(raw)) + raw + work_digest(raw)

def proof_commitment(proof: bytes) -> str:
    return sha256(proof).hex()

def verify_proof(proof: bytes, *, expected_network_id: str, expected_target: bytes,
                 proposal: Mapping[str, Any] | None = None) -> dict:
    if not isinstance(proof, bytes) or not proof.startswith(PROOF_MAGIC):
        raise HCCGNWorkError("proof_envelope_magic_invalid")
    cursor = len(PROOF_MAGIC)
    if len(proof) < cursor + 2:
        raise HCCGNWorkError("proof_envelope_truncated")
    (length,) = struct.unpack('>H', proof[cursor:cursor + 2])
    cursor += 2
    if length != HEADER_SIZE or len(proof) != cursor + length + 32:
        raise HCCGNWorkError("proof_envelope_length_invalid")
    raw = proof[cursor:cursor + length]
    supplied_digest = proof[cursor + length:]
    header = HCCGNWorkHeader.decode(raw)
    actual_digest = work_digest(raw)
    if supplied_digest != actual_digest:
        raise HCCGNWorkError("work_digest_mismatch")
    expected_target = _b32(expected_target, "active_target")
    if header.target != expected_target:
        raise HCCGNWorkError("active_target_mismatch")
    if header.network_id_hash != network_hash(expected_network_id):
        raise HCCGNWorkError("network_id_mismatch")
    if proposal is not None:
        bindings = ((header.height, proposal.get('height'), 'height'),
                    (header.sequence, proposal.get('epoch'), 'sequence/epoch'),
                    (header.timestamp, proposal.get('issued_at'), 'timestamp'),
                    (header.parent_hash.hex(), proposal.get('parent_hash'), 'parent_hash'),
                    (header.payload_hash.hex(), proposal.get('payload_hash'), 'payload_hash'))
        for actual, expected, label in bindings:
            if actual != expected:
                raise HCCGNWorkError(f"proposal_{label}_mismatch")
    digest_integer = int.from_bytes(actual_digest, 'big')
    target_integer = int.from_bytes(expected_target, 'big')
    if digest_integer > target_integer:
        raise HCCGNWorkError("work_target_not_met")
    projection = int.from_bytes(actual_digest[:8], 'big')
    primary_inverse = pow(header.primary_stride, -1, PRIMARY_MODULUS)
    compact_inverse = pow(header.compact_stride, -1, COMPACT_MODULUS)
    primary_index = ((header.nonce % PRIMARY_MODULUS) * header.primary_stride) % PRIMARY_MODULUS
    compact_index = ((header.nonce % COMPACT_MODULUS) * header.compact_stride) % COMPACT_MODULUS
    if (primary_index * primary_inverse) % PRIMARY_MODULUS != header.nonce % PRIMARY_MODULUS:
        raise HCCGNWorkError("primary_inverse_identity_failed")
    if (compact_index * compact_inverse) % COMPACT_MODULUS != header.nonce % COMPACT_MODULUS:
        raise HCCGNWorkError("compact_inverse_identity_failed")
    return {'valid': True, 'profile_id': PROFILE_ID, 'work_digest': actual_digest.hex(),
        'proof_hash': proof_commitment(proof), 'primary_quotient': projection // PRIMARY_MODULUS,
        'primary_residue': projection % PRIMARY_MODULUS, 'compact_quotient': projection // COMPACT_MODULUS,
        'compact_residue': projection % COMPACT_MODULUS, 'primary_index': primary_index,
        'compact_index': compact_index, 'primary_inverse': primary_inverse,
        'compact_inverse': compact_inverse, 'nonce': header.nonce, 'target': expected_target.hex()}

class HCCGNWorkProofProvider:
    def __init__(self, resolve_proof: Callable[[str], bytes | None],
                 resolve_target: Callable[[Mapping[str, Any]], bytes | None]):
        self.resolve_proof = resolve_proof
        self.resolve_target = resolve_target

    def verify_proof_hash(self, proof_hash: str, proposal: Mapping[str, Any]) -> dict:
        try:
            if not isinstance(proof_hash, str) or len(proof_hash) != 64:
                return {'valid': False, 'reason': 'proof_hash_invalid'}
            proof = self.resolve_proof(proof_hash)
            target = self.resolve_target(proposal)
            if not isinstance(proof, bytes) or target is None:
                return {'valid': False, 'reason': 'proof_or_target_unavailable'}
            if proof_commitment(proof) != proof_hash:
                return {'valid': False, 'reason': 'proof_commitment_mismatch'}
            result = verify_proof(proof, expected_network_id=proposal['network_id'],
                                  expected_target=target, proposal=proposal)
            return result
        except Exception as exc:
            return {'valid': False, 'reason': f'verification_error:{type(exc).__name__}'}


def mine_nonce(
    header: HCCGNWorkHeader,
    *,
    start_nonce: int = 0,
    max_attempts: int = 10_000_000,
    schedule_profile: str = "sequential-v1",
) -> tuple[HCCGNWorkHeader, bytes, bytes, str, int, float]:
    """Mine a bounded nonce interval and independently preserve HCCGN-WORK/1.

    The optional symplectic schedule changes only candidate visitation order.
    Every visited nonce remains inside the caller's signed half-open interval;
    the encoded header, work digest, and consensus target are unchanged.
    """
    _u(start_nonce, 64, "start_nonce")
    _u(max_attempts, 64, "max_attempts", 1)
    if start_nonce + max_attempts > (1 << 64):
        raise HCCGNWorkError("nonce_range_overflow")

    if schedule_profile == "sequential-v1":
        nonce_offsets = range(max_attempts)
    elif schedule_profile == "symplectic-phase-space-v1":
        try:
            from src.mining.symplectic import iter_symplectic_ordinals, phase_space_parameters
            phase_space_parameters(
                max_attempts, drift=header.primary_stride, kick=header.compact_stride,
            )
            nonce_offsets = iter_symplectic_ordinals(
                max_attempts,
                drift=header.primary_stride,
                kick=header.compact_stride,
            )
        except Exception as exc:
            raise HCCGNWorkError("symplectic_schedule_invalid") from exc
    else:
        raise HCCGNWorkError("nonce_schedule_profile_unsupported")

    raw = header.encode()
    target_int = int.from_bytes(header.target, "big")
    stream = bytearray(WORK_DOMAIN + raw)
    nonce_field_offset = len(WORK_DOMAIN) + 144
    prefix_size = 128
    midstate = hashlib.sha256(stream[:prefix_size])
    tail = stream[prefix_size:]
    tail_nonce_offset = nonce_field_offset - prefix_size
    pack_u64_into = struct.Struct(">Q").pack_into
    started = time.perf_counter()

    for attempts, offset in enumerate(nonce_offsets, start=1):
        nonce = start_nonce + offset
        pack_u64_into(tail, tail_nonce_offset, nonce)
        current = midstate.copy()
        current.update(tail)
        digest = current.digest()
        if int.from_bytes(digest, "big") <= target_int:
            solved = replace(header, nonce=nonce)
            proof = build_proof(solved)
            proof_hash = proof_commitment(proof)
            elapsed = time.perf_counter() - started
            return solved, digest, proof, proof_hash, attempts, elapsed

    raise RuntimeError(f"No valid nonce found within {max_attempts:,} attempts.")
