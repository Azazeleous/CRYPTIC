# GCF/1 + ADAM/APEX — Executable Consensus and Commitment Core

Status: new implementation on feat/gcf-adam-apex-consensus-v1. This is executable protocol code, not an import of the visual APEX console.

## Implemented modules

- src/consensus/gcf.py: constrained canonical consensus JSON, Ed25519 proposal/vote signatures, replay-safe proposal admission, weighted PREVOTE/PRECOMMIT rounds, proof-of-lock commitment (POLC), validator vote locks, and finality certificates.
- src/consensus/http_api.py: bounded WSGI proposal, vote, finalize, and candidate-status routes.
- src/adam/commit_store.py: SQLite WAL/FULL-synchronous append-only state commitments, parent-hash/height continuity, integrity-checked recovery, and APEX validation authority.
- src/governance/god_adapter.py: adapter to the host GOD gate; requests the gcf.consensus.propose capability.
- src/governance/justice_adapter.py: GAIA-JUSTICE/1 commitment validation plus independently injected policy/evidence verifiers.
- tests/test_gcf_adam_consensus.py and tests/test_gcf_adapters_http.py: deterministic protocol, storage, adapter, and WSGI tests.

## GCF/1 wire profile (new implementation profile)

Proposal endpoint: POST /v1/consensus/proposals
Vote endpoint: POST /v1/consensus/votes
Finalize endpoint: POST /v1/consensus/finalize/{candidate_digest}
Status endpoint: GET /v1/consensus/candidates/{candidate_digest}

The WSGI adapter enforces application/json, a 1 MiB body limit, complete body reads, and duplicate-key rejection. It does not implement client authentication or TLS. Mount it only behind authenticated TLS infrastructure and do not expose it publicly until deployment controls are reviewed.

Proposal fields:
schema, network_id, epoch, height, round, parent_hash, payload_hash, proof_hash, justice_commitment, issued_at, expires_at, proposer_id, proposer_public_key, nonce, signature.

Vote fields:
schema, network_id, epoch, height, round, candidate_digest, validator_id, vote_type, approve, polc_digest, issued_at, signature.

Signatures are Ed25519 over domain-separated canonical JSON. The constrained canonical profile uses sorted ASCII object keys, UTF-8 strings, compact separators, and integer-only numeric values. Floating-point values are rejected. This is not claimed to be a complete RFC 8785 implementation.

Quorum is strictly greater than two thirds: floor(2 * total_weight / 3) + 1.

A PRECOMMIT approval is accepted only when it carries the digest of a verified PREVOTE quorum for the same candidate and validator-set hash. Validator vote locks persist network, epoch, height, round, vote phase, and validator identity, rejecting conflicting candidate votes in the same round/phase. Finality certificates contain the proposal, validator-set snapshot, POLC prevotes, and precommit votes.

Proposal expiry is enforced at vote admission. Historical finality certificates remain verifiable after expiry because signature and time-window checks are evaluated against the signed proposal/vote timestamps.

## Fail-closed external verification gates

The engine requires independent implementations for HCCGN proof verification, GOD capability/policy authorization, and GAIA-JUSTICE evidence and transition validation. If a gate is omitted, the default denies.

HCCGN boundary: the supplied project sources describe HCCGN clock, prime/residue, and traversal architecture, but do not provide a normative canonical network work header, digest preimage, target comparison endianness, or known-answer vectors. This implementation does not infer those from CRYPTIC's existing 80-byte Bitcoin SHA-256d scanner. No candidate can be network-accepted until the actual HCCGN verifier is connected.

GOD boundary: no private GOD policy is copied into CRYPTIC. GODNetworkAuthorizer calls the existing host gate's runnable() decision and requests gcf.consensus.propose. The inspected Sovereign Operating System GOD v1 allowlist does not currently include that capability, so the existing gate denies this path. The GOD allowlist and bounded executor must be explicitly extended and reviewed before consensus submission can be authorized. Missing gate, endpoint, or policy continues to deny.

Justice boundary: JusticeEvidenceVerifier validates the exact GAIA-JUSTICE/1 commitment shape, then delegates policy authority/activation and evidence-root verification to injected trusted providers. Commitment hashes alone are not evidence of a passing check. Production policy/evidence providers are not connected.

## ADAM/APEX commitment rules

APEX independently verifies the finality certificate and re-runs all three external gates before commitment. It checks that the supplied state bytes hash to the proposal payload hash, the proposal height is exactly the next ADAM height, and the proposal parent hash equals the current committed state hash. It then stores the state and an ADAM/APEX receipt transactionally.

The database uses WAL mode and FULL synchronous writes. Connections close after each operation. This is a local durable database implementation, not a claim of WORM storage, distributed replication, or crash-proof operation on every filesystem.

## Verification

GitHub Actions run 44915510019 passed 215 unit tests (2 skipped) and the bounded SHA-256d benchmark. A later documentation-only capability-ledger update also passed CI in run 44915563698.

Tests cover signed proposal/vote validation, replay, strict quorum, validator equivocation locks, expiry handling, POLC/finality, certificate tampering, ADAM parent continuity and commitment, WSGI request validation, and fail-closed governance adapters. Test gate callbacks deliberately allow test proposals to exercise consensus mechanics; they are not evidence that real HCCGN, GOD, or justice checks passed.

## Deployment limitations

- No P2P transport, validator discovery, or network gossip.
- No validator-set governance/rotation or authenticated epoch activation.
- No HCCGN network proof verifier until the canonical specification and vectors are supplied.
- No currently authorized GOD capability for GCF proposal submission.
- No production justice-policy evidence engine.
- No complete deterministic state-transition executor or economic accounting rules.
- No timeout/round-change liveness protocol.
- No deployment-grade key custody, HSM integration, or security review.

Do not expose a proposal endpoint publicly until those deployment controls and conformance tests exist.

The Architect / Nexus / Cryptic News LLC / Project: The Nexus Generation: GaiaSSoul / SERIES: The Nexus of Gaia / ID: 137451921129154222|040592|433855274
