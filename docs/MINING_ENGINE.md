# CRYPTIC Mining Engine — SHA-256d CPU Baseline

## Scope

This branch adds a bounded SHA-256d proof-of-work scanner for caller-supplied
80-byte block headers. It is a CPU implementation and benchmark foundation,
not an ASIC/GPU miner and not a Stratum pool client.

The scanner serializes the 32-bit nonce in little-endian order at bytes 76–79,
computes SHA256(SHA256(header)), interprets the digest as a little-endian
256-bit integer for target comparison, scans finite half-open nonce ranges,
reuses the SHA-256 state after the first 64 header bytes, optionally partitions
work across a bounded process pool, and independently recomputes candidates.

## Optimization

An 80-byte header has a fixed first 76 bytes for a given work item. SHA-256
processes the first 64 bytes as one block. The optimized kernel hashes those
64 bytes once, copies that state for each nonce, then adds bytes 64–75 and the
4-byte nonce. This avoids reprocessing the fixed first block for every nonce.
The second SHA-256 remains a full hash. This is an implementation optimization,
not a change to SHA-256 or a reversal of its digest.

## Commands

Run tests:

    python -m unittest discover -s tests -p 'test_*.py' -v

Run the fixed-work benchmark:

    python scripts/benchmark_sha256d.py --attempts 100000 --workers 4

Run a bounded scan with an 80-byte header:

    python -m src.mining.sha256d --header-hex HEX160 --target 0xTARGET --start 0 --stop 100000 --workers 4

## Benchmark protocol

The benchmark compares the straightforward full-header reference kernel,
the optimized prefix-state kernel in one process, and the optimized kernel
with bounded multiprocessing. All configurations use the same header, target,
and nonce interval. Results include attempts, elapsed time, hashes/second,
worker count, candidate count, and speedup relative to the reference run.
Repeat each configuration on the same host and compare medians.

## Comparison limitation

The selected CRYPTIC repository's capability ledger describes an architecture
scaffold and does not identify an existing miner implementation. The original
HCCGN miner source was not present in the repository paths inspected for this
branch. This benchmark therefore supplies an internal reference comparison;
it cannot establish superiority over the original HCCGN miner until that
implementation is added as a baseline adapter and both are run on the same host.

## Operational boundaries

No pool endpoint, wallet, payout address, credential, or background service
is configured. Use finite work ranges and only compute resources you are
authorized to use. Worker count is clamped to the host's logical CPU count.
Local hash calculations do not establish accepted shares, rewards,
profitability, or network-level compatibility.

## Evidence status

Source, tests, and benchmark commands are committed on a feature branch.
Tests and benchmarks are supplied but have not been executed by these
GitHub file-write operations.
