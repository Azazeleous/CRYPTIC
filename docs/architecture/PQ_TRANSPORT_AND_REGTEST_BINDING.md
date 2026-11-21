# PQ Transport Adapters and Research-Bound Regtest

Status: implementation contract and research-regtest integration; production cryptographic provider integration remains pending.

## 1. Separation of concerns

CRYPTIC uses four distinct layers:

1. **Polynomial-ring mathematics** — exact arithmetic in \(R_q=\mathbb Z_q[X]/(X^{256}+1)\), including negacyclic multiplication and parameterized test vectors.
2. **Post-quantum cryptography** — standardized key establishment and signatures supplied by a vetted provider. The ring arithmetic/visualizer is not itself ML-KEM or ML-DSA.
3. **Transport adapters** — explicitly enrolled HTTPS, WebSocket, WebRTC, or other protocol adapters. Each advertises byte limits, authentication, deadline enforcement, and supported KEM profiles.
4. **Blockchain research regtest** — finite SHA-256d nonce search, coordinator verification, and a reproducible receipt. It does not claim to be a Bitcoin Core node, consensus implementation, digest inverter, or live network miner.

## 2. PQ cryptography contract

Initial target profiles:

- **ML-KEM-768** (FIPS 203) for establishing a shared secret.
- **ML-DSA-65** (FIPS 204) for signing adapter manifests and research receipts.

Review current NIST publication errata and deployment requirements before final profile selection. The KEM shared secret must be passed to a separately specified KDF and authenticated symmetric encryption construction. Never use a KEM shared secret directly as an application encryption key.

The Python adapter registry is a provider-neutral contract. It does not implement lattice cryptography and does not accept locally invented ML-KEM-like operations as substitutes for FIPS implementations. A production provider must supply interoperable test vectors, key/ciphertext length checks, constant-time implementation review, secure randomness, key lifecycle rules, and independent conformance testing before enablement.

No downgrade is permitted: if a route requires ML-KEM-768 and no enrolled adapter supports it, selection fails closed. A classical-only route is not a fallback for a PQ-required session.

## 3. Adapter lifecycle and reliability

The module src/ingestion/pq_transport_adapters.py provides:

- explicit adapter registration (no implicit module imports);
- capability-based deterministic selection;
- optional caller-supplied adapter allowlists;
- explicit preparation before deadline-bound exchange;
- request/response byte caps;
- absolute monotonic deadline checks before and after exchange;
- explicit close/unregister lifecycle;
- fail-closed behavior when a security capability is missing.

This contract reduces configuration ambiguity; it cannot guarantee that a network will never fail. Each concrete adapter must independently implement DNS/TLS validation, peer authentication, cancellation, bounded reads, retry policy, and telemetry. Retries must not silently change the security profile or endpoint identity.

## 4. Experiment commitment in the regtest header

research_commitment.py canonicalizes JSON-compatible experiment metadata, hashes it with the domain separator CRYPTIC-RESEARCH-EXPERIMENT-V1 followed by a NUL byte, and can bind the 32-byte digest into bytes 36..67 of a 76-byte header prefix (the 80-byte header's merkle-root slot).

When experiment_commitment is passed to run_four_lane_regtest, the coordinator verifies that the declared commitment matches that header slot. An accepted receipt records both the commitment and the prefix digest.

This is a research commitment, not automatically a valid transaction merkle root. A future Bitcoin Core regtest integration must construct actual transactions, coinbase commitment data, the transaction merkle tree, and a consensus-valid block template before claiming node acceptance.

The regtest discards a proposed winner if independent verification and worker shutdown reach the acceptance deadline before receipt acceptance. Cleanup can still add wall-clock time; the deadline is an acceptance boundary, not a claim of hard real-time process termination.

## 5. Relationship to the browser hypercube source

The uploaded browser source currently demonstrates:
- X^256 = -1 and X^512 = +1 in the negacyclic ring;
- negacyclic monomial shifts and polynomial multiplication;
- a custom SHA-256d midstate worker;
- a browser terminal that dispatches only its built-in commands.

It does not currently provide ML-KEM, ML-DSA, a general-purpose operating-system shell, or Bitcoin consensus validation. The q=3329 and q=8380417 selectors are parameter visualizations, not complete KEM/DSA parameter implementations.

The browser miner's custom header and DAG/IVC/BFT visualizations should be treated as a separate experimental chain until serialization and consensus rules are specified and cross-verified against the Python reference and, later, a local node.

## 6. Public and gated deployment boundary

The public CRYPTIC page should expose the read-only research visualizer, architecture, papers, provenance, and reproducible non-secret test vectors. The SOS background visual can be mounted as a presentation layer.

Mining/regtest controls, private adapters, local filesystem access, credentials, and research execution endpoints remain behind an authenticated and explicitly authorized environment. The browser terminal is not an operating-system terminal and must never be presented as one.

Cloudflare Tunnel is a suitable origin-routing layer for a private service: it establishes outbound-only connections and avoids exposing the origin IP. Cloudflare documents post-quantum encrypted Tunnel connections. This protects the Cloudflare-to-origin tunnel path; it does not replace application-level ML-KEM key establishment, ML-DSA identity signatures, authorization, or end-to-end data validation.

## 7. Acceptance gates

- [x] Deterministic experiment metadata commitment.
- [x] Commitment binding and verification in the regtest header prefix.
- [x] Four-lane candidate independently recomputed by the coordinator.
- [x] Late candidate rejected at the acceptance boundary.
- [x] Capability-gated adapter registry with no silent PQ downgrade.
- [x] Request/response size and deadline checks at the registry boundary.
- [ ] Production ML-KEM provider with NIST-aligned known-answer tests.
- [ ] Production ML-DSA provider and signed adapter-manifest verification.
- [ ] Concrete HTTPS/WebSocket/WebRTC adapters and protocol conformance tests.
- [ ] Bitcoin Core local regtest node integration and accepted-block verification.
- [ ] Public-page CSP/dependency audit and SOS visual integration.
- [ ] Cloudflare Tunnel/Access deployment verification and origin access tests.
- [ ] LaTeX research pipeline, reproducible PDF generation, and paper-to-commit provenance.

The governing invariant remains: Boundary — Nothing executes beyond its time. Capacity — Nothing claims capacity without measurement. Correctness — Nothing claims correctness without verification.
