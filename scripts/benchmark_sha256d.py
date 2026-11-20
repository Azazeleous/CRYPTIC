"""Fixed-work benchmark comparing reference and optimized SHA-256d kernels."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.mining.sha256d import scan_nonce_range


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attempts", type=int, default=100_000)
    parser.add_argument("--workers", type=int, default=min(4, max(1, os.cpu_count() or 1)))
    parser.add_argument("--chunk-size", type=int, default=10_000)
    args = parser.parse_args()
    if args.attempts < 1 or args.workers < 1 or args.chunk_size < 1:
        parser.error("attempts, workers, and chunk-size must be positive")

    header = bytes(range(80))
    target = 0
    start, stop = 0, args.attempts
    configurations = [
        ("reference_single", 1, False),
        ("optimized_single", 1, True),
        ("optimized_parallel", args.workers, True),
    ]
    results = []
    for name, workers, optimized in configurations:
        run = scan_nonce_range(
            header, target, start, stop, workers=workers,
            chunk_size=args.chunk_size, optimized=optimized,
        )
        results.append({
            "name": name,
            "attempts": run.attempts,
            "elapsed_seconds": run.elapsed_seconds,
            "hashes_per_second": run.hashes_per_second,
            "workers": run.workers,
            "candidate_count": len(run.candidates),
        })

    baseline = results[0]["hashes_per_second"]
    for item in results:
        item["speedup_vs_reference"] = item["hashes_per_second"] / baseline if baseline else None

    print(json.dumps({
        "benchmark": "sha256d-fixed-range",
        "header_hex": header.hex(),
        "target": target,
        "nonce_range": [start, stop],
        "results": results,
        "comparison_note": (
            "This is a local kernel comparison, not a measurement against "
            "the original HCCGN miner or a mining pool."
        ),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
