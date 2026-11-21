# CRYPTIC Mining Architecture

## Scope and status

This document defines the first reference mining implementation. It is a finite-window SHA-256 proof-of-work engine for correctness tests and throughput benchmarking. It is not yet a production pool client, a coin-specific consensus implementation, or a claim of profitable mining.

## Consensus invariant

The reference candidate digest is:

    SHA256(canonical_header_bytes || uint64_be(nonce))

The target is an unsigned 256-bit integer and a candidate is valid only when:

    int(digest) <= target

A real chain adapter must supply the exact canonical header serialization, hash function, nonce width/endianness, target encoding, and any consensus-specific rules. The reference miner must not silently alter difficulty or the target.

## Four-lane scheduler

Four workers receive disjoint global ordinals. Lane 1 and lane 4 traverse their assigned ordinals forward; lane 2 and lane 3 traverse their assigned ordinals in reverse. Each ordinal is mapped to a nonce through the 97,152-slot affine traversal profile:

    index(i) = (3037 * i + 1) mod 97152

The parameters satisfy the full-period linear-congruential conditions for this modulus. The profile is a deterministic scheduling permutation, not a cryptographic random-number generator.

Ordinals are partitioned by residue class modulo four, so the lanes are disjoint and collectively cover the finite candidate window. For windows larger than 97,152, a monotonically increasing epoch offset prevents nonce reuse.

## Barrel-roll transforms

The framing module provides:
- fixed-width ROTL/ROTR;
- byte-array circular rotation;
- four-way round-robin interleave/deinterleave;
- lane-order rotation;
- a composed reversible frame transform.

The inverse applies operations in reverse order. These transforms may be used for workload framing, diagnostics, and round-trip verification. They do not alter the proof-of-work preimage and do not increase hash probability.

## Worker and result semantics

Each worker hashes each candidate independently. The four-worker finite-window implementation evaluates exactly the requested number of unique candidates and chooses the valid result with the lowest global ordinal. The reported attempt count is the total number of candidates actually hashed by all four workers.

The verifier recomputes the digest from the original header and returned nonce. A result is not accepted merely because a worker reported success.

## Performance measurements

Record at least:
- wall-clock duration;
- candidates attempted;
- verified hashes per second;
- per-lane attempts and elapsed time;
- CPU and memory utilization;
- target and header identity;
- software revision and runtime version.

Compare against a sequential baseline using the same candidate bytes, hash function, and target. Python threads are a correctness/concurrency reference, not a claim of GPU acceleration; SHA-256 throughput may require native extensions, multiprocessing, or hardware-specific kernels after profiling.

## Safety and correctness boundaries

- No private keys, wallet secrets, signing keys, or transactions are required by this reference miner.
- No mining-pool credentials are embedded in source or configuration.
- A mining result is independently checked before ledger commitment.
- A custom scheduler or reversible transform cannot change consensus rules.
- Network/pool integration remains a separate adapter with explicit authorization and protocol-specific tests.
