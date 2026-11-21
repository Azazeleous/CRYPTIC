#!/usr/bin/env python3
"""Measure the actual HCCGN-WORK/1 midstate hashing kernel.

This is a kernel benchmark, not a target/difficulty claim. It independently
checks the final optimized digest against a full hashlib SHA-256 invocation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import time

from src.consensus.hccgn_work import (
    HCCGNWorkHeader, WORK_DOMAIN, network_hash, work_digest,
)

MAX_U64 = (1 << 64) - 1


def run_benchmark(attempts: int, start_nonce: int) -> dict:
    if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts < 1:
        raise ValueError("attempts must be a positive integer")
    if isinstance(start_nonce, bool) or not isinstance(start_nonce, int) or not 0 <= start_nonce <= MAX_U64:
        raise ValueError("start_nonce must be uint64")
    if start_nonce + attempts - 1 > MAX_U64:
        raise ValueError("nonce range overflows uint64")

    header = HCCGNWorkHeader(
        network_id_hash=network_hash("hccgn-benchmark"),
        height=1, sequence=1, timestamp=1_800_000_000,
        parent_hash=bytes.fromhex("11" * 32),
        payload_hash=bytes.fromhex("22" * 32),
        primary_stride=5, compact_stride=7, nonce=start_nonce,
        target=bytes(32),
    )
    stream = bytearray(WORK_DOMAIN + header.encode())
    prefix = hashlib.sha256(stream[:128])
    tail = stream[128:]
    nonce_offset = len(WORK_DOMAIN) + 144 - 128
    pack_u64_into = struct.Struct(">Q").pack_into

    started = time.perf_counter()
    digest = b""
    for offset in range(attempts):
        nonce = start_nonce + offset
        pack_u64_into(tail, nonce_offset, nonce)
        current = prefix.copy()
        current.update(tail)
        digest = current.digest()
    elapsed = time.perf_counter() - started

    final_header = HCCGNWorkHeader(
        network_id_hash=header.network_id_hash, height=header.height,
        sequence=header.sequence, timestamp=header.timestamp,
        parent_hash=header.parent_hash, payload_hash=header.payload_hash,
        primary_stride=header.primary_stride, compact_stride=header.compact_stride,
        nonce=start_nonce + attempts - 1, target=header.target,
    )
    reference = work_digest(final_header.encode())
    if digest != reference:
        raise RuntimeError("midstate_reference_mismatch")

    return {
        "profile": "HCCGN-WORK/1",
        "kernel": "sha256-midstate-128-byte-prefix",
        "attempts": attempts,
        "start_nonce": start_nonce,
        "end_nonce": start_nonce + attempts - 1,
        "elapsed_seconds": elapsed,
        "hashes_per_second": attempts / elapsed if elapsed > 0 else None,
        "last_digest": digest.hex(),
        "full_hash_reference_match": True,
        "target_search_performed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attempts", type=int, default=100_000)
    parser.add_argument("--start-nonce", type=int, default=0)
    args = parser.parse_args()
    print(json.dumps(run_benchmark(args.attempts, args.start_nonce), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
