# GCF/1 — Five-Stage Completion Track

Base: main after PR #31 merge  
Base commit: 5a97b992750747b55a2e1ce88787688856b36aa4  
Work branch: feat/gcf-adam-mainline

This document tracks the five previously agreed stages after the initial GCF/1 reference implementation. Status labels distinguish executable code from deployment and protocol dependencies.

## Stage 1 — Independent consensus/finality verifier

Status: implemented (E3); CI run 44916647888 passed.

Added \`src/consensus/independent_verifier.py\`. It independently reconstructs the constrained GCF/1 canonical JSON profile, verifies proposer and validator Ed25519 signatures, recomputes the validator-set digest, checks duplicate validator identities, validates PREVOTE quorum and POLC digest, validates PRECOMMIT lock references and strict weighted quorum, and checks certificate metadata.

It does not instantiate \`GCFEngine\` or call its private proposal/vote validation functions. ADAM/APEX now uses this verifier as its acceptance authority. External HCCGN, GOD, and justice gates remain required and fail closed.

## Stage 2 — Canonical HCCGN proof integration

Status: implemented and CI-tested (E3); PR workflow run 44919550338 passed 245 tests (2 skipped), including all 11 HCCGN-WORK/1 tests.

Added \`src/consensus/hccgn_adapter.py\`. It requires a separately implemented provider to resolve the proposal's proof hash, verify the canonical work header and digest, apply the target comparison, and return a profile identifier and matching proof commitment. Missing providers, missing pinned profile IDs, mismatched profiles, and mismatched proof hashes are denied.

The supplied project source \`Correct HCCGN Integration Equation (2).txt\` specifies computational graph and residue-space context, including primary modulus 97,152, totient 28,160, compact modulus 1,518, totient 440, and forward/reverse coprime traversal. It explicitly distinguishes reversible index reconstruction from SHA-256 inversion. The supplied \`Branch · Valuate Ancestry Solver\` material describes a shared computation record containing input, algorithm parameters, hash output, quotient/residue, stride/inverse, candidate result, and target.

The uploaded source supplies the exact field semantics and midstate miner strategy; HCCGN-WORK/1 adopts that 184-byte binary layout while explicitly defining its GCF network bindings and independently authenticated target rule. This remains a newly versioned profile, not a claim about prior wire behavior. The existing 80-byte Bitcoin SHA-256d scanner remains separate. PR workflow run 44919550338 passed the full suite: 245 tests, 2 skipped, including known-answer digest/commitment, low-target rejection, proposal binding, midstate/full-hash equivalence, bounded mining, tamper and nonce-overflow tests. The branch now adds a content-addressed SQLite proof store, Ed25519-signed target-policy snapshots with network/profile/sequence/expiry/height/epoch binding, and a standard-library Go verifier for the Python known-answer vector. The new Python and Go tests are pending the current PR workflow. The actual GOD root remains an out-of-band deployment input; database-local anti-rollback still needs an external monotonic checkpoint.

## Stage 3 — Distributed validator networking

Status: authenticated direct-peer transport and loopback mutual-TLS integration test implemented (E3); deployment and mesh liveness remain open.

Added \`src/consensus/peer_transport.py\`:
- Mutual TLS with required client certificates and TLS 1.2 minimum.
- Certificate SHA-256 fingerprint allowlist mapped to validator IDs.
- Ed25519-signed GCF-P2P/1 envelopes.
- Peer identity bound to the configured validator signing key.
- Bounded 1 MiB length-prefixed frames.
- Timestamp window, persistent message-ID replay protection, duplicate JSON-key rejection.
- Proposal and vote dispatch into the GCF engine.

This is direct peer transport, not a complete production BFT network. Peer discovery, topology/gossip, retransmission policy, round-change/timeouts, partition recovery, operational key rotation, and a multi-host deployment test remain open. The transport does not make a validator eligible unless the GCF HCCGN/GOD/justice gates also pass.

## Stage 4 — Complete ADAM/APEX commitment integration

Status: integration extended and CI-tested (E3); deployment review remains open.

ADAM/APEX now uses the standalone finality verifier rather than the engine's internal verifier. The WSGI adapter accepts \`POST /v1/adam/commit\` with a finality certificate and base64 state bytes, exposes \`GET /v1/adam/head\`, and exposes \`GET /v1/adam/commits/{height}\` for integrity-checked recovery. The commit path remains transactional and enforces state digest, contiguous height, and parent-state continuity.

The HTTP JSON parser rejects duplicate object keys. Domain validation errors from ADAM are returned as conflicts. The adapter remains intended to be mounted behind authenticated TLS; authentication is not implemented inside this WSGI class.

## Stage 5 — Protocol conformance and recovery testing

Status: expanded deterministic and loopback TLS conformance tests passed (E3); latest PR CI run 44919550338 passed 245 tests (2 skipped), including 11 HCCGN profile tests; production conformance remains open.

Added \`tests/test_gcf_independent_network.py\` for:
- Independent verification of certificates generated by the reference engine.
- Missing external gate denial.
- Certificate tampering and duplicate validator rejection.
- ADAM independent-verifier commitment.
- HCCGN provider/profile/hash binding.
- Peer envelope dispatch, replay rejection, authenticated identity mismatch, and an end-to-end loopback mutual-TLS send/receive.
- Duplicate JSON key rejection and ADAM endpoint behavior.
- ADAM HTTP commit and head recovery.

Added \`tests/test_gcf_conformance_vectors.py\` for canonical serialization known answers, SHA-256 known answer, UTF-8 value handling, ASCII key enforcement, float/NaN rejection, producer/verifier serialization agreement, and peer private-key/validator identity binding.

Earlier CI run 44916647888 passed 234 tests (2 skipped). After adding HCCGN-WORK/1, PR run 44919550338 passed 245 tests (2 skipped) and completed the bounded SHA-256d benchmark. The HCCGN-specific tests validate the known-answer vector, low target rejection, target pinning, proposal binding, stride checks, tamper rejection, midstate/full-hash equivalence across multiple nonces, and bounded mining. The loopback mutual-TLS test validates certificate-chain checking, client-certificate identity allowlisting, server fingerprint pinning, signed envelope dispatch, and bounded frame exchange.

Additional required tests before production:
- Independent cross-language vectors from a finalized GCF/1 wire specification.
- HCCGN known-answer work-header/digest/target vectors (Python and Go implementations now share the vector; CI result pending).
- Validator-set transition and epoch activation.
- Live mutual-TLS multi-node interoperability and network partition/round-change tests.
- ADAM crash injection, WAL recovery, duplicate commit, and filesystem durability review.
- GOD policy activation/rollback and GAIA-JUSTICE independent evidence-provider tests.
- Security review of key custody, transport exposure, and validator operations.

## New correctness fixes discovered during stage work

- Transactional GCF database operations now use a closing database context manager; Python's SQLite connection context manager commits/rolls back but does not itself close the connection.
- HTTP JSON parsing rejects duplicate object keys instead of silently accepting the last value.
- Certificate height, round, total weight, and precommit weight are checked as strict integers by the independent verifier.

## Acceptance boundary

A successful local CI run demonstrates the implemented code and tests. It does not demonstrate live HCCGN proof compatibility, a deployed distributed validator mesh, authorization by the operator's actual GOD policy, production justice evidence, or production storage durability.

Stage 2 is E3 for the Python reference implementation and its in-repository known-answer tests. Do not mark it production-complete until authenticated proof storage, active-target policy resolution, GOD-authorized activation, and independent cross-language profile interoperability are verified. Do not mark Stage 3 production-complete until live multi-node interoperability, failure recovery, and security review pass.

The Architect / Nexus / Cryptic News LLC / Project: The Nexus Generation: GaiaSSoul / SERIES: The Nexus of Gaia / ID: 137451921129154222|040592|433855274


## Additional code-boundary completion

The branch now includes `src/consensus/runtime.py` as the composition root. It connects the durable HCCGN proof store, signed active-target policy resolver, HCCGN proof provider and adapter, GOD authorization adapter, GAIA-JUSTICE evidence adapter, GCF engine, ADAM store, APEX validator, and WSGI API. The GOD Ed25519 public key is loaded from an operator-provisioned regular file; symlinks, group/world-writable files, owner mismatch, and invalid key lengths are rejected. The runtime requires an injected external monotonic sequence-anchor provider by default. It does not manufacture trust material or authorize missing providers.

GCF gate results now accept only the exact boolean `True` or a well-formed `GateResult(allowed=True, reason=<string>)`; arbitrary truthy values fail closed. GAIA-JUSTICE policy/evidence callbacks likewise require exact `True`. The legacy finality helper uses the same strict result rule. GCF and independent certificate-verifier integer fields are bounded to SQLite's signed 64-bit range, including aggregate validator weight.

ADAM now rejects non-byte state inputs and state payloads above 1 MiB, validates digest formats, and rechecks the entire persisted chain (contiguous heights, parent links, state digests and receipt JSON) before head/recovery reads and before appending a new commitment. A tampered historical record blocks recovery rather than allowing a later intact row to mask it.

These are code and deterministic-test additions. CI for the new head is pending; external GOD/APEX trust-root provisioning, an independently protected anchor implementation, live GAIA-JUSTICE evidence services, and real validator-mesh operations remain deployment dependencies.


## Latest expanded CI evidence

Workflow run: `44922018143`  
Commit: `9eb5647ea7c6efe90439f8d2f484b379161ebab6`  
Result: successful.

- Python unit suite: 267 passed, 2 skipped.
- Independent Go HCCGN-WORK/1 conformance vectors: passed, including high-target acceptance and low-target rejection.
- HCCGN midstate benchmark: 100,000 hashes in 0.03964745 seconds; 2,522,230 hashes/second on the GitHub-hosted runner; full-hash reference matched.
- Existing bounded SHA-256d benchmark: passed separately; it remains a distinct local trophy-miner benchmark.

This evidence verifies the reference implementation and deterministic CI environment. It is not a hardware benchmark for the user's devices, not a target-search performance claim, and not proof of a live validator network.

## Follow-up hardening — trust, justice, and ADAM (2026-11-21)

The code-level portion of stages 2, 3, and 4 has been extended and reverified:

- APEX now validates that state input is bytes-like and within the 1 MiB limit before hashing or invoking finality verification. It no longer coerces arbitrary values with `bytes(value)`.
- GAIA-JUSTICE commitment digests must use canonical lowercase 64-character hexadecimal encoding. Missing providers, provider exceptions, and any result other than the exact boolean `True` remain denials.
- ADAM tests now cover WAL-backed close/reopen recovery, a database-triggered insert failure with transaction rollback followed by successful recovery, and APEX rejection of non-byte state input.
- The test run confirms the new recovery and justice cases execute successfully.

Latest CI evidence:
- Workflow run: `44939293680` (mining-engine-tests), successful.
- Commit: `9085160216e85cf0729ed6517d8b8334d070049e`.
- Python suite: 270 tests run, 2 skipped; all non-skipped tests passed.
- The two skips are live EVM and Solana RPC checks because their endpoint environment variables are not configured.
- HCCGN Go conformance and both bounded benchmark steps completed successfully in the same workflow.

Still external, and therefore not honestly completable by repository code alone:
- Provision the real GOD-authorized Ed25519 public root and its authenticated activation/rotation process.
- Implement and operate a genuinely independent monotonic sequence anchor (hardware-backed or separately protected service); the in-memory test anchor is test-only.
- Connect actual GAIA-JUSTICE policy/evidence retrieval services and validate their authority, provenance, freshness, and failure behavior.
- Perform power-loss/process-kill crash testing and storage/filesystem durability review on the deployment filesystem; the CI trigger test proves transactional rollback and reopen recovery, not physical power-loss guarantees.
- Complete live multi-host validator and key-custody security review.

Stage 2/4 code boundaries are strengthened and CI-tested; production trust, justice authority, and physical durability remain deployment gates. Do not label them production-complete until the external evidence above is recorded.

