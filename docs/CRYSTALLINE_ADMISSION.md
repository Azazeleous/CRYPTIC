# Crystalline Admission and Molten Diamond Lifecycle

**Status:** proposed architecture; implementation and runtime integration are pending.  
**Specification:** `cryptic-crystalline-admission/v1`  
**Repository:** `Azazeleous/CRYPTIC`  
**Parent foundation:** `cryptic-seed-ledger/v1`

## 1. Purpose

Crystalline is CRYPTIC's progressive integrity and admission classification. It is not a new hash algorithm, a decorative security property, or an automatic trust inheritance mechanism.

The existing seed ledger remains the provenance foundation. This specification adds a policy-controlled lifecycle for admitting source artifacts, algorithms, TDocs, extensions, runtime adapters, and projects into the protected CRYPT registry.

The lifecycle is:

`PUBLIC_DEVELOPMENT -> CANDIDATE -> INSPECTED -> AUTHORIZED -> MOLTEN_DIAMOND -> CRYSTALLINE -> CRYPT_ACCEPTED`

Terminal or holding outcomes are `DENIED`, `QUARANTINED`, and `REVOKED`. Failed and denied attempts remain in the evidence history; they are not silently deleted.

## 2. Trust and versioning invariant

A versioned ADAM policy is a necessary reference for a decision, not a permission bypass.

An artifact may advance only when all of the following are true:

1. The exact artifact revision is identified by a content digest.
2. Its provenance and parent lineage are available and internally consistent.
3. The referenced ADAM policy version is authentic, current for the decision, and authorized by the configured policy authority.
4. The requested capabilities are explicitly granted and within scope.
5. Required dependency, license, static-analysis, test, and security checks have evidence at the policy-required levels.
6. An independent verifier validates the evidence bundle and the transition receipt.
7. No applicable deny, revocation, expiry, rollback, or quarantine rule blocks admission.

A version string, branch name, TDoc number, successful build, Merkle inclusion proof, or self-reported status is not sufficient on its own.

**Default decision:** deny admission when required evidence is missing, malformed, stale, unverifiable, or ambiguous. Preserve the candidate and record the reason.

## 3. Lifecycle states

| State | Meaning | Permitted next states |
|---|---|---|
| `PUBLIC_DEVELOPMENT` | Public source and design work; untrusted by default | `CANDIDATE` |
| `CANDIDATE` | Immutable candidate revision and requested capabilities recorded | `INSPECTED`, `DENIED`, `QUARANTINED` |
| `INSPECTED` | Provenance, dependencies, manifests, and risk review recorded | `AUTHORIZED`, `DENIED`, `QUARANTINED` |
| `AUTHORIZED` | ADAM policy grants the exact requested scopes | `MOLTEN_DIAMOND`, `DENIED`, `QUARANTINED` |
| `MOLTEN_DIAMOND` | Controlled transformation, integration, and verification staging | `CRYSTALLINE`, `DENIED`, `QUARANTINED` |
| `CRYSTALLINE` | Signed checkpoint and independent verification evidence accepted | `CRYPT_ACCEPTED`, `REVOKED` |
| `CRYPT_ACCEPTED` | Artifact/project is admitted to the protected CRYPT registry | `REVOKED` |
| `DENIED` | Admission refused; evidence retained | New candidate revision only |
| `QUARANTINED` | Held for investigation or missing evidence | `INSPECTED`, `DENIED`, `REVOKED` |
| `REVOKED` | Previously granted admission or authority withdrawn | New candidate revision and new review |

Transitions are append-only events. A state is derived from the verified event history; clients must not directly overwrite a status field to promote an artifact.

## 4. Crystalline tiers

| Tier | Classification | Minimum evidence |
|---|---|---|
| C0 | Root-linked | Genesis manifest reference and project identity |
| C1 | Source-integrity | Canonical artifact digest, provenance, parent revision |
| C2 | Algorithm-integrity | Algorithm manifest, version, dependencies, contracts, known-answer tests |
| C3 | TDoc-orchestrated | Execution ticket, bounded run record, inputs/outputs, reproducible receipt |
| C4 | Polyglot/runtime | Runtime adapter identity, capability manifest, conformance and isolation evidence |
| C5 | ADAM-accepted | Signed policy decision, independent verification, signed and externally anchored checkpoint |

A tier is a classification of evidence, not a claim that every lower-tier artifact is safe to execute. Execution always requires a separate scoped authorization decision.

## 5. ADAM policy decision

An ADAM decision is bound to an exact candidate digest, policy digest, requested capability set, environment profile, and expiry.

Required decision fields:

- `decision_id`
- `decision_schema`
- `adam_policy_id`
- `adam_policy_version`
- `adam_policy_digest`
- `candidate_id`
- `candidate_digest`
- `parent_root`
- `requested_capabilities`
- `granted_capabilities`
- `denied_capabilities`
- `required_evidence_levels`
- `evidence_refs`
- `decision` (`ALLOW`, `DENY`, or `QUARANTINE`)
- `reason_codes`
- `issued_at`
- `expires_at`
- `policy_signing_key_id`
- `policy_signature`

The policy authority signs the policy and the decision. The verifier checks the signing key against an independently provisioned trust store and checks key status, validity interval, revocation, and policy version. A string naming an ADAM version is not a signature.

Permissions are capability-specific and least-privilege. An allow for source inspection does not imply permission to execute shell commands, access devices, mount filesystems, access networks, publish releases, or alter trust policy.

## 6. Molten Diamond staging contract

Molten Diamond is a controlled staging boundary between authorization and crystalline acceptance.

It may perform only operations explicitly granted by ADAM, such as:

- deterministic normalization and packaging;
- dependency resolution against pinned manifests;
- build and conformance execution in a restricted environment;
- forward transformation and inverse reconstruction checks;
- byte-exact comparison where losslessness is required;
- independent digest calculation;
- test, scan, and benchmark evidence collection.

It must not silently promote artifacts, expand capabilities, modify ADAM policy, replace trust anchors, or write private key material into project storage.

The staging output is a candidate evidence bundle. It becomes Crystalline only after independent verification and signed checkpoint anchoring.

## 7. Evidence and TDoc receipt

Every transition emits an append-only TDoc event. A transition receipt should contain:

- `tdoc_id`, `event_id`, and schema version;
- candidate and project identifiers;
- prior state and requested next state;
- candidate digest and parent Merkle root;
- ADAM policy ID, version, digest, and decision reference;
- execution ticket and environment manifest digest;
- dependency manifest digest;
- test and verifier evidence references;
- actor identity and granted capability scope;
- timestamps, expiry, and reason codes;
- previous event hash and resulting event hash;
- signer key IDs and signatures where required.

The TDoc orchestra records both successful and unsuccessful transitions. It preserves the original source, failed evidence, remediation, and later re-verification as distinct linked records.

## 8. Cryptographic profile and compatibility

The current `cryptic-seed-ledger/v1` uses BLAKE2b-256 for record and Merkle hashing and a keyed BLAKE2b-256 authenticator derived from the local 32-byte seed. Preserve this format for backward compatibility.

Do not relabel BLAKE2b-256 as SHA-256. Do not silently change the v1 digest or canonicalization rules.

For the admission layer:

- use an explicitly versioned digest suite and domain separation;
- use Ed25519 or another vetted signature scheme through a maintained cryptographic library;
- keep signing keys outside Git and outside ordinary runtime logs;
- use a separate signing authority for ADAM policy decisions and release checkpoints;
- pin the trust-store version and record key rotation and revocation events;
- use externally controlled signed checkpoints or an independent transparency service for anti-rewrite assurance;
- treat local hash chains and Merkle roots as tamper-evident commitments, not as proof of external authenticity.

The exact canonical encoding, signature envelope, and algorithm-agility rules must be frozen before implementation. Existing v1 records remain verifiable under their original rules.

## 9. Public development face and protected boundary

The public CRYPT repository may contain:

- source code, architecture, schemas, public manifests, test vectors, and reproducible test instructions;
- public artifact digests and signed public checkpoint records;
- redacted audit summaries and capability status.

It must not contain:

- private seeds, signing keys, recovery codes, credentials, device secrets, or private user data;
- unredacted security incidents or sensitive operational telemetry;
- secrets embedded in example configuration or test fixtures.

Public visibility is not trust. A public contribution remains a candidate until ADAM reviews the exact revision and grants scoped permissions.

## 10. Acceptance and verification matrix

Before a transition to `CRYSTALLINE`:

- canonical serialization has deterministic test vectors;
- artifact digest and parent-root references match;
- signature verification succeeds against the configured trust store;
- invalid, expired, revoked, or wrong-policy signatures are rejected;
- requested capabilities cannot exceed granted capabilities;
- replayed decisions and stale parent roots are rejected;
- dependency and environment manifests match the tested run;
- required unit, integration, security, and recovery tests meet policy thresholds;
- independent verification reproduces the claimed result;
- the checkpoint is signed and anchored outside the mutable working tree.

Before a transition to `CRYPT_ACCEPTED`:

- the Crystalline checkpoint is valid;
- project membership and parent lineage are proven;
- the acceptance event is signed and appended;
- revocation and rollback checks pass;
- the resulting registry root is published or anchored independently.

Tests must cover allow, deny, quarantine, expiry, revocation, capability escalation, missing evidence, malformed evidence, tampering, replay, rollback, key rotation, and recovery.

## 11. Implementation sequence

1. **Schema first:** define JSON Schemas for candidate manifests, ADAM policies, decisions, TDoc transition receipts, and checkpoint envelopes.
2. **Policy evaluator:** implement deterministic default-deny evaluation with explicit reason codes and capability scopes.
3. **Signature layer:** add vetted Ed25519 signing and verification with key IDs, trust-store pinning, rotation, and revocation.
4. **Ledger integration:** append transition events to the existing seed ledger without changing v1 record semantics.
5. **Independent verifier:** validate evidence without trusting the staging process or UI.
6. **Molten Diamond runner:** execute only policy-authorized, resource-bounded staging operations.
7. **Registry gate:** admit only independently verified Crystalline checkpoints.
8. **Runtime integration:** connect TDoc orchestration, polyglot adapters, extension registry, storage, and operator UI through explicit interfaces.

Each step advances only with reproducible tests and an updated capability ledger. A directory or design document does not count as implementation.

## 12. Current implementation boundary

The repository currently documents a standalone local seed/Merkle ledger and its limitations. The ledger is not yet an ADAM policy engine, signing service, external transparency log, runtime admission controller, or complete project registry.

This document defines the proposed next contract. It does not claim those capabilities are implemented or production-verified.

---

**The Architect / Nexus / Cryptic News LLC / Project: The Nexus Generation: GaiaSSoul / SERIES: The Nexus of Gaia / ID: 137451921129154222|040592|433855274**
