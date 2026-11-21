# ACVP Conformance and HTTPS Node Canvas — v1

- Status: architecture baseline; implementation and vector execution pending
- Date: 2026-11-21
- Repository: Azazeleous/CRYPTIC
- Branch: feat/acvp-transport-node-canvas
- Scope: FIPS 203 ML-KEM-768, FIPS 204 ML-DSA-65, read-only HTTPS transport, graph-based operator canvas
- Security boundary: no write-capable RPC methods; no user-supplied arbitrary outbound URL execution

## 1. Acceptance language

Keep these evidence states distinct:

1. Schema-checked — vector set parses and conforms to the selected ACVP JSON schema.
2. Executed — the named provider processed the test case.
3. Byte-exact pass/fail — generated output matches expected output exactly, or verification returns the expected boolean.
4. ACVP session accepted — the ACVP server returned a passing disposition for the vector set/session.
5. Algorithm validation listed — the relevant NIST CAVP validation record exists.
6. Cryptographic module validated — a CMVP certificate covers the actual module, version, operational environment, and configuration.

Local unit tests and round-trip tests are not ACVP acceptance. A local vector pass is useful informal evidence, not a validation certificate.

## 2. Normative and procedural sources

- FIPS 203 is the normative algorithm standard for ML-KEM.
- FIPS 204 is the normative algorithm standard for ML-DSA.
- ACVP algorithm JSON specifications define vector-set and response shapes; pin the exact revision used for every run.
- NIST CAVP guidance distinguishes informal development testing using the ACVTS demo/pre-generated vectors from formal validation through an NVLAP-accredited laboratory.
- Record the current FIPS errata/planning-note revision alongside the vector schema revision.

Do not treat a moving Internet-Draft or repository schema as an immutable normative reference. Store the exact source URL, retrieval time, content SHA-256, and selected revision in each run manifest.

## 3. Required algorithm test matrix

### ML-KEM-768 (FIPS 203)

- keyGen AFT: deterministic generation from vector-provided seed material; compare encapsulation and decapsulation key bytes exactly.
- encapDecap AFT: process vector-provided encapsulation/decapsulation inputs; compare ciphertext and shared-secret outputs exactly.
- Validate every supported vector group and parameter-set declaration. Do not substitute random key generation for deterministic vector inputs.
- Keep negative and malformed-input robustness tests supplemental and separate from ACVP AFT coverage.

### ML-DSA-65 (FIPS 204)

- keyGen AFT: deterministic key generation from vector-provided seed; compare public and private key encodings byte-for-byte.
- sigGen AFT: honor the vector group's interface, context, pre-hash/pure mode, deterministic flag, key format, message/mu, and randomness fields; compare signature bytes exactly.
- sigVer AFT: verify each supplied public key/message-or-mu/signature/context tuple and compare the returned boolean with the vector's expected result.
- Keep malformed-signature/context tests supplemental and separate from ACVP vector results.

### Provider gate

The current application wrapper around pqcrypto provides random key generation and ordinary KEM/signature operations. It does not expose the deterministic seed-based interfaces required by ACVP keyGen vectors. It must not be marked ACVP-ready for keyGen until a provider with the required deterministic test interface is integrated and independently checked.

The provider interface must expose explicit, typed operations for each ACVP mode. Missing operations produce UNSUPPORTED, never a generated substitute or a pass. Preserve provider name, version, build identifier, operating system, architecture, and configuration in the manifest.

## 4. Vector harness contract

Input: official ACVP JSON vector-set files, treated as immutable source artifacts.

For each vector set:
- validate algorithm, mode, revision, vsId, testGroups, tgId, testType, parameterSet, and per-case tcId;
- reject duplicate identifiers, malformed hex, missing required fields, unsupported revisions, unsupported test types, and unsupported parameter sets;
- dispatch only to an explicit provider method for that algorithm/mode;
- compare exact byte outputs, not only round-trip equivalence;
- emit one result per test case and one aggregate result per vector set;
- retain source file SHA-256, schema revision, provider identity, run timestamp, elapsed time, and sanitized error category;
- never write secret keys, seeds, shared secrets, or full test inputs into ordinary logs. Retain vectors only as access-controlled test fixtures with checksums.

Required statuses: PASS, FAIL, UNSUPPORTED, INVALID_VECTOR, PROVIDER_ERROR, NOT_RUN.

A run is locally vector-clean only when every required test case is PASS and no required case is UNSUPPORTED, INVALID_VECTOR, PROVIDER_ERROR, or NOT_RUN.

## 5. HTTPS adapter graph

The canvas is a control-plane and evidence visualization. It does not perform privileged network operations in browser JavaScript.

    Canvas Command
         |
    Request Schema + Policy
         |
    Capability / Adapter Registry
         |
    Absolute Deadline Gate
         |
    Supervised HTTPS Worker
      DNS -> TCP -> TLS -> HTTP -> bounded body
         |
    Canonical Decode + Schema Check
         |
    Read-only Method Allowlist
         |
    Observation / Receipt Ledger
         |
    Canvas State + Audit View

Security invariants:
- registered adapter IDs only; the browser never supplies an arbitrary destination URL;
- HTTPS required except explicitly configured loopback-only development endpoints;
- standard certificate-chain and hostname validation remains enabled;
- redirects denied by default;
- DNS, connect, TLS, headers, and body reads are all inside the supervised worker boundary;
- absolute monotonic deadline applies to the complete request;
- request and response byte caps are enforced before decode;
- allowlisted read-only methods only;
- credentials and request bodies are excluded from logs, graph labels, telemetry, and receipts;
- timeout poisons the worker/session and fails closed; no silent in-session restart;
- graph status reflects measured backend state, never optimistic browser-side state.

## 6. HTMX 4.0 canvas interaction

Pin htmx 4.0.2 explicitly; do not use an unversioned CDN URL or npm latest.

Use HTMX for hypermedia control-plane interactions:
- GET /api/canvas/graph — graph definition and measured node status;
- GET /api/canvas/runs/{run_id} — run detail and event history;
- POST /api/canvas/adapters/{adapter_id}/health-check — request a bounded, policy-approved health check;
- POST /api/conformance/vector-runs — enqueue a local vector run against an explicitly selected provider;
- GET /api/conformance/vector-runs/{run_id} — refresh per-case results.

The server validates every action and returns HTML fragments or JSON appropriate to the endpoint. HTMX is not a TLS policy engine, crypto provider, authentication system, or authorization boundary.

HTMX 4 migration rules:
- attribute inheritance is explicit; mark inherited attributes intentionally;
- use standardized event names such as htmx:before:request and htmx:after:request;
- account for changed error-response swap behavior;
- use partial/morph behavior for presentation only, never to infer successful backend execution.

## 7. Graph node data contract

Every node has:
- stable node ID and node type;
- input/output schema IDs;
- capability requirements;
- configured limits: deadline, request bytes, response bytes, concurrency;
- state: idle, queued, running, passed, failed, unsupported, timed_out, disabled;
- start/end timestamps and measured duration when available;
- evidence reference and content digest;
- sanitized error category, if any.

Edges are typed. An edge is valid only when the source output schema matches the destination input schema. A graph cannot be activated if required capabilities are absent or an edge is incompatible.

The UI displays the difference between configured limits and measured values. It must never infer throughput, security strength, provider trust, or conformance from a decorative animation.

## 8. Implementation sequence

1. Freeze this acceptance vocabulary and node/edge schema.
2. Import and checksum official ML-KEM and ML-DSA ACVP vector sets.
3. Integrate a deterministic provider interface; prove deterministic keyGen against vectors before advertising keyGen capability.
4. Implement byte-exact vector dispatch and per-case result receipts.
5. Harden and independently test the whole-request HTTPS worker lifecycle, including poisoned-worker cleanup and direct health-check cleanup.
6. Add the backend graph API and HTMX 4.0.2 canvas.
7. Add end-to-end tests proving graph actions invoke only registered adapters and rendered status matches backend receipts.
8. Use the appropriate NIST/NVLAP process if an official validation listing is required.

## 9. Current repository boundary

The existing open PR #21 branch contains the supervised HTTP implementation together with additional changes outside this document's scope, and it has review feedback that must be resolved before reuse. This work starts from the clean main baseline on feat/acvp-transport-node-canvas. Port only reviewed transport components after lifecycle findings are fixed; do not merge unrelated functionality as a dependency.

## 10. Governing invariants

- Boundary — Nothing executes beyond its time.
- Capacity — Nothing claims capacity without measurement.
- Correctness — Nothing claims correctness without verification.

The canvas is a visualization of these invariants, not a substitute for them.
