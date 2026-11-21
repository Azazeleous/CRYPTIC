# GCF/1 + ADAM/APEX — Executable Consensus and Commitment Core

Status: implementation introduced on \`feat/gcf-adam-apex-consensus-v1\`.
This is a new protocol implementation, not an import of the visual APEX console.

## Implemented modules

- \`src/consensus/gcf.py\`: bounded consensus JSON, Ed25519 proposal/vote signatures, replay-safe proposal admission, weighted PREVOTE/PRECOMMIT rounds, proof-of-lock commitment (POLC), and finality certificates.
- \`src/adam/commit_store.py\`: SQLite WAL/FULL-synchronous append-only state commitments, parent-hash/height continuity, integrity-checked recovery, and APEX validation authority.
- \`tests/test_gcf_adam_consensus.py\`: deterministic protocol tests using ephemeral test keys and explicit test-only gate callbacks.

## GCF/1 wire profile (new implementation profile)

Proposal endpoint contract: \`POST /v1/consensus/proposals\`.
Vote endpoint contract: \`POST /v1/consensus/votes\`.

The bounded WSGI adapter is implemented in `src/consensus/http_api.py`. It exposes the proposal, vote, finalize, and candidate-status routes. Mount it only behind authenticated TLS infrastructure; this adapter does not provide client authentication or a public server launcher.

Proposal fields:
\`schema, network_id, epoch, height, round, parent_hash, payload_hash, proof_hash,
justice_commitment, issued_at, expires_at, proposer_id, proposer_public_key, nonce,
signature\`.

Vote fields:
\`schema, network_id, epoch, height, round, candidate_digest, validator_id,
vote_type, approve, polc_digest, issued_at, signature\`.

Signatures are Ed25519 over domain-separated canonical JSON. The canonical profile
uses sorted ASCII object keys, UTF-8 strings, compact separators, and integer-only
numeric values. Floating-point values are rejected. This is a constrained canonical
JSON profile; it is not claimed to be a complete RFC 8785 implementation.

Quorum is strictly greater than two thirds:
\`floor(2 * total_weight / 3) + 1\`.

A PRECOMMIT approval is accepted only when it carries the digest of a verified
PREVOTE quorum for the same candidate and validator-set hash. A finality certificate
contains the proposal, validator-set snapshot, POLC prevotes, and precommit votes.

## Fail-closed external verification gates

The engine requires independent implementations for:
- HCCGN proof verification
- GOD capability/policy authorization
- GAIA-JUSTICE evidence and transition validation

Each gate is injectable. If omitted, the default denies. The GOD adapter and
justice commitment adapter are implemented, but the production HCCGN verifier,
GOD allowlist extension, and trusted justice evidence providers are not yet
connected. Test callbacks in unit tests are test fixtures only and are not production adapters.

**HCCGN boundary:** the uploaded project sources describe HCCGN clock, prime/residue
and traversal architecture, but do not provide a normative canonical network work
header, digest preimage, target comparison endianness, or known-answer vectors.
Therefore this implementation does not infer those from CRYPTIC's existing
80-byte Bitcoin SHA-256d scanner. No candidate can be network-accepted until a
real HCCGN verifier is connected.

**GOD boundary:** no private GOD policy is copied into CRYPTIC. `GODNetworkAuthorizer`
uses the existing host gate's `runnable()` decision and requests the capability
`gcf.consensus.propose`. The inspected Sovereign Operating System GOD v1 allowlist
does not currently include that capability, so the existing gate denies this path.
The GOD allowlist and its bounded executor must be explicitly extended and reviewed
before consensus submission can be authorized. Missing gate, endpoint, or policy
continues to deny.

## ADAM/APEX commitment rules

APEX independently verifies the finality certificate and re-runs all three external
gates before commitment. It checks that:
- the supplied state bytes hash to the proposal's payload hash;
- the proposal height is exactly the next ADAM height;
- the proposal parent hash equals the current committed state hash;
- the certificate and validation receipt are durably stored in SQLite.

The database uses WAL mode and FULL synchronous writes. This is a local durable
database implementation, not a claim of WORM storage, distributed replication,
or crash-proof operation on every filesystem.

## Deployment limitations

This commit does not yet implement:
- an HTTP service, P2P transport, validator discovery, or network gossip;
- validator-set governance/rotation and authenticated epoch activation;
- an HCCGN network proof verifier;
- a production GOD adapter to the private Sovereign Operating System gate;
- a production justice-policy evidence engine;
- a complete deterministic state-transition executor or economic accounting rules;
- anti-equivocation slashing, timeout/round-change messages, or liveness recovery;
- deployment-grade key custody, HSM integration, or security review.

Do not expose a proposal endpoint publicly until those deployment controls and
conformance tests exist.

## Verification commands

\`\`\`bash
python -m unittest tests.test_gcf_adam_consensus -v
python -m unittest discover -s tests -v
\`\`\`

The test-only callbacks deliberately accept test proposals to exercise consensus
mechanics; they are not proof that real HCCGN, GOD, or justice checks passed.

The Architect / Nexus / Cryptic News LLC / Project: The Nexus Generation: GaiaSSoul / SERIES: The Nexus of Gaia / ID: 137451921129154222|040592|433855274
