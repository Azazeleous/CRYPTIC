"""Bitcoin-compatible SHA-256d proof-of-work scanner.

Scans caller-supplied 80-byte headers over finite nonce ranges. No pool,
wallet, payout, or background service is configured.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import asdict, dataclass
from typing import Iterable

UINT32_LIMIT = 1 << 32
UINT256_LIMIT = 1 << 256
HEADER_SIZE = 80


@dataclass(frozen=True)
class Candidate:
    nonce: int
    digest_hex: str
    hash_value: int
    target: int


@dataclass(frozen=True)
class ScanResult:
    start_nonce: int
    stop_nonce: int
    attempts: int
    elapsed_seconds: float
    hashes_per_second: float
    workers: int
    chunks_completed: int
    final_chunk_size: int
    candidates: tuple[Candidate, ...]

    def to_dict(self) -> dict:
        return {
            "start_nonce": self.start_nonce,
            "stop_nonce": self.stop_nonce,
            "attempts": self.attempts,
            "elapsed_seconds": self.elapsed_seconds,
            "hashes_per_second": self.hashes_per_second,
            "workers": self.workers,
            "chunks_completed": self.chunks_completed,
            "final_chunk_size": self.final_chunk_size,
            "candidates": [asdict(item) for item in self.candidates],
        }


def _validate_header(header: bytes) -> bytes:
    value = bytes(header)
    if len(value) != HEADER_SIZE:
        raise ValueError("header must be exactly 80 bytes")
    return value


def _validate_target(target: int) -> int:
    if isinstance(target, bool) or not isinstance(target, int):
        raise TypeError("target must be an integer")
    if target < 0 or target >= UINT256_LIMIT:
        raise ValueError("target must be in [0, 2**256)")
    return target


def _validate_range(start_nonce: int, stop_nonce: int) -> None:
    if isinstance(start_nonce, bool) or not isinstance(start_nonce, int):
        raise TypeError("start_nonce must be an integer")
    if isinstance(stop_nonce, bool) or not isinstance(stop_nonce, int):
        raise TypeError("stop_nonce must be an integer")
    if not (0 <= start_nonce <= stop_nonce <= UINT32_LIMIT):
        raise ValueError("nonce range must satisfy 0 <= start <= stop <= 2**32")


def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(bytes(data)).digest()).digest()


def serialize_header_with_nonce(header: bytes, nonce: int) -> bytes:
    value = bytearray(_validate_header(header))
    if isinstance(nonce, bool) or not isinstance(nonce, int) or not 0 <= nonce < UINT32_LIMIT:
        raise ValueError("nonce must be an unsigned 32-bit integer")
    struct.pack_into("<I", value, 76, nonce)
    return bytes(value)


def verify_candidate(header: bytes, candidate: Candidate | dict, target: int | None = None) -> bool:
    """Independently recompute using the straightforward full-header path."""
    header = _validate_header(header)
    if isinstance(candidate, dict):
        nonce = int(candidate["nonce"])
        claimed_digest = str(candidate["digest_hex"]).lower()
        claimed_value = int(candidate["hash_value"])
        candidate_target = int(candidate.get("target", target if target is not None else -1))
    else:
        nonce = candidate.nonce
        claimed_digest = candidate.digest_hex.lower()
        claimed_value = candidate.hash_value
        candidate_target = candidate.target
    effective_target = _validate_target(candidate_target if target is None else target)
    digest = double_sha256(serialize_header_with_nonce(header, nonce))
    value = int.from_bytes(digest, "little")
    return digest.hex() == claimed_digest and value == claimed_value and value <= effective_target


def _scan_chunk(
    header: bytes,
    target: int,
    start_nonce: int,
    stop_nonce: int,
    optimized: bool = True,
) -> list[Candidate]:
    _validate_range(start_nonce, stop_nonce)
    header = _validate_header(header)
    target = _validate_target(target)
    candidates: list[Candidate] = []

    if optimized:
        prefix_state = hashlib.sha256()
        prefix_state.update(header[:64])
        suffix = header[64:76]
        for nonce in range(start_nonce, stop_nonce):
            first_round = prefix_state.copy()
            first_round.update(suffix)
            first_round.update(struct.pack("<I", nonce))
            digest = hashlib.sha256(first_round.digest()).digest()
            value = int.from_bytes(digest, "little")
            if value <= target:
                candidates.append(Candidate(nonce, digest.hex(), value, target))
    else:
        mutable = bytearray(header)
        for nonce in range(start_nonce, stop_nonce):
            struct.pack_into("<I", mutable, 76, nonce)
            digest = double_sha256(mutable)
            value = int.from_bytes(digest, "little")
            if value <= target:
                candidates.append(Candidate(nonce, digest.hex(), value, target))
    return candidates


def _scan_chunk_timed(
    header: bytes,
    target: int,
    start_nonce: int,
    stop_nonce: int,
    optimized: bool,
) -> tuple[list[Candidate], float]:
    started = time.perf_counter()
    found = _scan_chunk(header, target, start_nonce, stop_nonce, optimized)
    return found, max(time.perf_counter() - started, 1e-12)


def scan_nonce_range(
    header: bytes,
    target: int,
    start_nonce: int,
    stop_nonce: int,
    *,
    workers: int = 1,
    chunk_size: int = 50_000,
    optimized: bool = True,
    target_chunk_seconds: float = 0.05,
) -> ScanResult:
    """Scan a finite half-open nonce range with bounded adaptive scheduling.

    Parallel workers receive at most one outstanding chunk each. When a chunk
    completes, the scheduler uses its measured processing time to resize the
    next chunk toward target_chunk_seconds, within bounded size limits.
    """
    header = _validate_header(header)
    target = _validate_target(target)
    _validate_range(start_nonce, stop_nonce)
    if isinstance(workers, bool) or not isinstance(workers, int) or workers < 1:
        raise ValueError("workers must be a positive integer")
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size < 1:
        raise ValueError("chunk_size must be a positive integer")
    if not isinstance(target_chunk_seconds, (int, float)) or target_chunk_seconds <= 0:
        raise ValueError("target_chunk_seconds must be positive")

    cpu_count = max(1, os.cpu_count() or 1)
    worker_count = min(workers, cpu_count)
    attempts = stop_nonce - start_nonce
    started = time.perf_counter()

    if attempts == 0:
        elapsed = max(time.perf_counter() - started, 1e-12)
        return ScanResult(start_nonce, stop_nonce, 0, elapsed, 0.0, 0, 0, chunk_size, ())

    candidates: list[Candidate] = []
    chunks_completed = 0
    final_chunk_size = chunk_size

    if worker_count == 1 or attempts <= chunk_size:
        cursor = start_nonce
        while cursor < stop_nonce:
            right = min(cursor + chunk_size, stop_nonce)
            candidates.extend(_scan_chunk(header, target, cursor, right, optimized))
            chunks_completed += 1
            cursor = right
        used_workers = 1
    else:
        min_chunk_size = max(1, chunk_size // 4)
        max_chunk_size = min(1_000_000, max(chunk_size, chunk_size * 8))
        current_chunk_size = min(chunk_size, max_chunk_size)
        cursor = start_nonce
        pending = {}

        with ProcessPoolExecutor(max_workers=worker_count) as executor:
            while cursor < stop_nonce and len(pending) < worker_count:
                right = min(cursor + current_chunk_size, stop_nonce)
                future = executor.submit(
                    _scan_chunk_timed, header, target, cursor, right, optimized
                )
                pending[future] = (cursor, right)
                cursor = right

            while pending:
                completed, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in completed:
                    pending.pop(future)
                    found, chunk_elapsed = future.result()
                    candidates.extend(found)
                    chunks_completed += 1

                    scale = float(target_chunk_seconds) / chunk_elapsed
                    scale = max(0.5, min(2.0, scale))
                    current_chunk_size = int(current_chunk_size * scale)
                    current_chunk_size = max(
                        min_chunk_size, min(max_chunk_size, current_chunk_size)
                    )

                    if cursor < stop_nonce:
                        right = min(cursor + current_chunk_size, stop_nonce)
                        next_future = executor.submit(
                            _scan_chunk_timed, header, target, cursor, right, optimized
                        )
                        pending[next_future] = (cursor, right)
                        cursor = right

        final_chunk_size = current_chunk_size
        used_workers = worker_count

    elapsed = max(time.perf_counter() - started, 1e-12)
    return ScanResult(
        start_nonce, stop_nonce, attempts, elapsed, attempts / elapsed,
        used_workers, chunks_completed, final_chunk_size,
        tuple(sorted(candidates, key=lambda item: item.nonce))
    )


def _parse_int(value: str) -> int:
    return int(value, 0)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bounded SHA-256d proof-of-work scanner")
    parser.add_argument("--header-hex", required=True, help="exactly 160 hexadecimal characters")
    parser.add_argument("--target", required=True, type=_parse_int, help="256-bit integer, decimal or 0x-prefixed")
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--stop", type=int, default=100_000)
    parser.add_argument("--workers", type=int, default=min(4, max(1, os.cpu_count() or 1)))
    parser.add_argument("--chunk-size", type=int, default=50_000)
    parser.add_argument("--reference", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        result = scan_nonce_range(
            bytes.fromhex(args.header_hex), args.target, args.start, args.stop,
            workers=args.workers, chunk_size=args.chunk_size,
            optimized=not args.reference,
        )
    except (ValueError, TypeError) as exc:
        parser.error(str(exc))
    print(json.dumps(result.to_dict(), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
