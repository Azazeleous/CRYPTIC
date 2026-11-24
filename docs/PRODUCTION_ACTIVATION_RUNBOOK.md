# CRYPTIC — Production Activation and Recovery Runbook

Status: **GATED — DO NOT ACTIVATE UNTIL EVERY CHECK IS EVIDENCED**

This runbook is an executable checklist for human operators. A checked box must point to a real evidence artifact; an unchecked item is a hard stop. Do not mark a gate complete based on a plan, local test, simulated response, or repository document.

## 1. Pre-activation gates

- [ ] Four independent validator operators enrolled under docs/OPERATIONS_MODEL.md.
- [ ] Four validator hosts pass separation-of-failure-domain review.
- [ ] Four unique HSM/KMS-backed validator keys and mTLS identities are enrolled and independently witnessed.
- [ ] HSM/KMS policy permits only the validator's signing gateway; direct-sign bypass tests are denied.
- [ ] 3-of-4 HCCGN root-custodian ceremony completed; trust-root manifest independently pinned on every validator.
- [ ] Two independent GAIA-JUSTICE authorities sign the same policy/evidence digest; negative tests prove one signature is insufficient.
- [ ] Worker anchor authorization verifies issuer, audience, exact expected sequence/hash, expiry, and nonce; stale/concurrent/arbitrary updates are rejected.
- [ ] Wrangler D1 migration history initialized by Wrangler and reconciled with the deployed schema.
- [ ] Restore, rollback, concurrency, partition, signer-outage, clock-skew, and hard power-loss drills pass with independent witnesses.
- [ ] Protocol conformance suite passes for Python and Worker implementations.
- [ ] Two independent release/security approvals recorded against the exact release commit and deployment artifact digests.

## 2. Activation sequence

1. Freeze the release commit and produce source, dependency, build, and Worker artifact digests.
2. Verify the trust-root manifest and validator-set digest independently on all four hosts.
3. Verify each host's signer policy and key/certificate binding; perform a denied direct-HSM signing attempt.
4. Verify all four nodes have recovered durable state and agree on network, epoch, height, parent hash, validator-set digest, and anchor sequence.
5. Run a read-only connectivity and message-authentication check. Do not issue votes.
6. Run a controlled test height in an isolated network with non-production keys and payloads. Preserve complete evidence.
7. Obtain two independent release approvals for the exact commit, configuration digest, and Worker deployment version.
8. Enable the approved Worker route and anchor authorization only after the above checks pass.
9. Enable validator signing one host at a time while continuously verifying the 3-of-4 quorum and signer audit stream.
10. Record activation time, operators, evidence digests, and initial height/anchor state in the append-only release ledger.

Any mismatch, missing evidence, unauthorized signing event, unexplained sequence jump, or failed health check aborts activation and keeps signing disabled.

## 3. Rollback and pause

- A node may stop its own signer immediately.
- The incident commander may coordinate network isolation and evidence preservation.
- Do not delete vote locks, signing intents, round-change records, finality certificates, or anchor history.
- Do not roll back consensus height by editing a database.
- A software rollback must use a previously verified artifact and preserve forward-compatible durable state. If schema compatibility is uncertain, remain paused and restore from a verified backup into an isolated recovery environment.
- A trust-root or validator-key compromise requires a governance-approved new epoch; never silently replace a key under the same validator ID.

## 4. Evidence format

Each drill and activation record contains:
- unique event/incident ID;
- UTC start/end and monotonic duration;
- release commit, source/build/Worker digests;
- validator IDs and operator organization IDs (private registry references only);
- validator-set and trust-root digests;
- anchor sequence/hash before and after;
- test procedure/version, expected result, observed result;
- raw log and audit references plus SHA-256 digests;
- independent witness identity/signature;
- pass/fail and remediation references.

Do not place private keys, bearer tokens, personal contact details, or confidential HSM identifiers in the repository.

## 5. Current status

This file defines the target procedure. It does not attest that any production operator, validator host, HSM policy, trust-root ceremony, justice authority, migration history, or witnessed drill exists. The staging Worker remains dormant until every hard gate is independently evidenced.
