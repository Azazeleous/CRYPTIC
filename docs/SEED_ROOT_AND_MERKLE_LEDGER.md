# CRYPTIC Seed Root, Merkle Receipts, and Ledger Integrity

**Status:** implemented in the standalone Python CLI; integration into the runtime remains pending.  
**Format:** \`cryptic-seed-ledger/v1\`  
**Digest:** BLAKE2b-256  
**Canonical path:** \`scripts/cryptic-seed-ledger.py\`

## 1. Seed discovery result and provenance

The repository audit did not find an existing canonical seed value, seed file, Merkle implementation, or ledger-chain implementation. The project notes do define a public arithmetic traversal profile:

\[
N=97152=2^7\cdot3\cdot11\cdot23,\qquad \varphi(N)=28160
\]

This is recorded in the generated root manifest as \`routing_profile\`. It is a deterministic public routing parameter set—not a secret, entropy source, cryptographic key, hash preimage, or means of reversing a digest. The original private seed cannot be inferred from this arithmetic profile or from a digest.

The CLI therefore creates a fresh 32-byte cryptographic seed locally at \`init\`, or imports a user-supplied 32-byte raw seed file. It never prints or commits the seed. The local seed file is \`0600\` on POSIX systems; its containing state directory is \`0700\`.

## 2. Canonicalization and input sanitation

- JSON object keys are sorted and serialized without insignificant whitespace.
- Strings are normalized to Unicode NFC before hashing.
- Duplicate JSON keys are rejected; keys that collide after NFC normalization are rejected.
- NaN and Infinity are rejected because they are not interoperable JSON numbers.
- Event types must match \`[a-z0-9][a-z0-9._-]{0,127}\`.
- Payloads are limited to 1 MiB per event.
- Every record has a monotonic sequence number, UTC timestamp, event type, payload, previous-record hash, record hash, and keyed authenticator.
- The original source text should be retained in the event payload whenever normalization or translation could alter meaning; normalized values must not silently replace source evidence.

Canonicalization is deterministic, not semantic translation. It must not rewrite operators, polarity, operand identity, or command meaning.

## 3. Hash chain and Merkle construction

Each record hash is domain-separated:

\[
H_i=\operatorname{BLAKE2b}_{256}(\texttt{CRYPTIC/LEDGER-RECORD/v1} \parallel C_i)
\]

where \(C_i\) is the canonical record core, including the previous hash. The first previous hash is 64 zero hex characters. The per-record authenticator uses keyed BLAKE2b-256 with the local 32-byte seed and a separate domain label. The public seed commitment is:

\[
S_c=\operatorname{BLAKE2b}_{256}(\texttt{CRYPTIC/SEED-COMMITMENT/v1} \parallel S)
\]

Merkle leaves and internal nodes use distinct domain labels. An odd final node is duplicated at that level. The empty tree has a defined domain-separated root. This prevents leaf/node ambiguity and makes the root deterministic.

A root manifest stores the seed commitment, routing profile, record count, chain tip, Merkle root, format, digest, and checkpoint status. Appending a new event invalidates the previous root checkpoint until \`root\` is run again.

## 4. What the checks prove—and do not prove

- A matching record hash detects record-content changes relative to the chain.
- A matching previous hash detects deletion, insertion, and reordering within the checked chain.
- The keyed authenticator proves possession of the local seed when the record was created.
- The Merkle root commits to the ordered set of record hashes.
- A seed commitment detects replacement of the local seed.

A local attacker who can replace the seed, ledger, and root manifest together can rewrite the complete local history. To make history tamper-evident against that attacker, periodically publish or sign the Merkle root in an independently controlled location (for example, a signed release, external transparency log, or separately administered backup). The CLI marks roots \`local-unanchored\`; it does not pretend that a local root is an external trust anchor.

Loss of the seed prevents verification of keyed record authenticators. Back up the seed securely outside the repository. Never put it in Git, logs, model prompts, screenshots, or ordinary exports.

## 5. Trapdoor and error audit

\`cryptic-seed-ledger.py audit PATH\` performs a heuristic scan for selected high-risk patterns, including dynamic evaluation, shell execution, download-to-shell pipelines, encoded-payload decoders, suspicious literal credential assignments, dynamic imports, runtime code construction, and hidden bidirectional/zero-width Unicode controls.

This is a triage tool, not a proof of safety. It can produce false positives and miss obfuscated or novel behavior. Findings must be reviewed in context. The scanner does not auto-delete or rewrite source because automatic removal can break legitimate code and conceal provenance. Any sanitization change must retain the original file, a diff, the reason, and regression tests.

## 6. CLI

\`\`\`bash
# Create a new local seed and ledger; seed remains private.
python scripts/cryptic-seed-ledger.py --state .cryptic init

# Append a structured event.
python scripts/cryptic-seed-ledger.py --state .cryptic append source.discovered --json '{"source":"provider-x","status":"inspected"}'

# Verify the seed commitment, record chain, authenticators, and current root.
python scripts/cryptic-seed-ledger.py --state .cryptic verify

# Compute and persist the current Merkle root checkpoint.
python scripts/cryptic-seed-ledger.py --state .cryptic root

# Export public manifest and ledger records (never the private seed).
python scripts/cryptic-seed-ledger.py --state .cryptic export ./cryptic-ledger-export.json

# Heuristic source audit.
python scripts/cryptic-seed-ledger.py audit .
\`\`\`

To import an existing seed, provide a file containing exactly 32 raw bytes to \`init --seed-file PATH\`. The file is read locally and is never printed. Do not pass a mnemonic, password, or arbitrary text as though it were a raw 32-byte seed.

## 7. Existing architecture integration points

- \`docs/DATA_MODEL.md\`: add ledger events as provenance-bearing observations.
- \`docs/VERIFICATION.md\`: treat seed commitment, record chain, and Merkle root as separate evidence fields.
- \`docs/REMEDY_ENGINE.md\`: retain original failure records; append remedies and verification outcomes rather than overwriting history.
- \`error-correction/\`: correction output must be reverified against the cryptographic digest and Merkle receipt; error correction is not authentication.
- Runtime API and storage integration are future work. This CLI does not yet create API endpoints, device links, source adapters, or automatic runtime hooks.

## 8. Acceptance evidence

The initial implementation has deterministic unit tests for append/verify, root invalidation after append, tamper detection, seed replacement detection, canonical JSON rejection, event-type validation, heuristic audit detection, and Merkle-root sensitivity. Tests are run with:

\`\`\`bash
python -m unittest discover -s tests -v
python -m py_compile scripts/cryptic-seed-ledger.py tests/unit/test_seed_ledger.py
\`\`\`

A passing local test suite is implementation evidence, not production deployment evidence.
