# CRYPTIC Pool Coordinator v1

## Scope

The pool coordinator composes the existing signed HCCGN job format, worker
execution envelope, independent HCCGN proof admission, and durable share
ledger. It is a pool service boundary, not a consensus replacement and not a
transferable reward or payout system.

The HCCGN miner implementation is not modified by this coordinator.

## Request path

1. An operator-side caller invokes `PoolCoordinator.issue_job()`.
2. The coordinator resolves the target using the configured active-policy
   resolver at the job's network, height, epoch, and issue-time boundary.
   Caller-supplied targets are not accepted.
3. The coordinator signs and persists the bounded job against one assigned worker before returning it. A different authenticated worker cannot fetch or submit against that job.
4. An authenticated worker retrieves the job through
   `GET /v1/pool/jobs/{job_id}`.
5. The worker submits its proof envelope through `POST /v1/pool/shares`.
6. The WSGI adapter obtains worker identity only from its injected trusted
   authenticator. A body field or HTTP identity header is not authoritative.
7. Admission checks the issuer signature, pool/network/job binding, worker
   identity, submission time, proof commitment, currently active target, and
   HCCGN proof independently.
8. The share ledger commits accepted work with replay protection and a
   SHA-256 hash-chained event record.

## Active policy and job lifecycle

- Jobs have a bounded lifetime of at most 300 seconds.
- Jobs are persisted before being returned to their assigned worker.
- The coordinator durably reserves each nonce interval per network, epoch, height, parent hash, and payload hash in the same SQLite transaction as job issuance. Overlapping intervals are rejected across workers, including after revocation; revoked ranges are not recycled.
- Nonce interval endpoints are stored as fixed-width decimal text so the complete unsigned 64-bit nonce space, including an exclusive endpoint of `2^64`, is represented without SQLite signed-integer truncation.
- Worker binding and nonce-range reservation are independent controls: the first limits who may use a job, and the second prevents two issued jobs from assigning the same work window.
- Revoked jobs are rejected.
- Shares are checked against the currently active target policy at submission
  time, not merely the target that was active when the job was issued. A policy
  update therefore invalidates outstanding jobs whose target is superseded.
- A job is not a consensus proposal and an accepted share is not a finalized
  block.

## Worker transport contract

Mount `PoolWSGI` only behind a TLS gateway with client authentication (mTLS
or an equivalently strong authenticated transport). The supplied
`worker_authenticator(environ)` must map verified transport credentials to a
registered worker identity. The gateway must strip externally supplied
identity headers before constructing trusted WSGI environment fields.

The adapter deliberately has no default authenticator and no public-server
launcher. If authentication cannot be established, the request fails closed.
The repository includes `MTLSWorkerAuthenticator`, which requires
`SSL_CLIENT_VERIFY=SUCCESS`, hashes the supplied client certificate, and maps
its SHA-256 fingerprint through an explicit worker allowlist. The TLS gateway
must validate the chain and overwrite/strip all client-supplied `SSL_*` identity
variables before invoking WSGI. Certificate issuance, allowlist distribution,
revocation/rotation, gateway configuration, and multi-host identity custody
remain operator responsibilities.

## Persistence and process model

- The job registry and share ledger are separate durable SQLite databases.
- SQLite WAL mode, full synchronous commits, and restrictive database file
  permissions are configured by the service components.
- Run one coordinator writer per database unless an external serialization
  and transaction boundary is provided across coordinator instances.
- Protect database files, WAL/SHM files, backups, and host storage as
  operational trust material.
- `PoolCoordinator.status()` reports job counts, accepted-share count, and
  share-ledger chain verification. It does not prove host integrity or
  external backup recoverability.

## Reward boundary

The share ledger records accepted work only. It does not mint a token, create a
redeemable balance, transfer assets, or issue payouts. Settlement remains
disabled until the network reward schedule, finalized reward certificate,
accounting rules, and independent settlement authority are specified and
reviewed. A share alone must never trigger a network reward.

## Verification

The pool test suite covers signed-job verification, bounded worker execution,
worker identity binding, current target-policy binding, independent proof
admission, job registration and revocation, durable share recording, replay
rejection, and authenticated HTTP retrieval/submission behavior.

Passing unit tests and CI are software evidence only. Production activation
still requires deployed mTLS identity controls, independent policy/issuer key
custody, durable backup and recovery drills, abuse/rate controls, monitoring,
and independent operator review.


## Finalized-block settlement ledger v1

The pool now has a separate `PoolSettlementLedger` in `src/consensus/pool_settlement.py`. It does not change share admission or the HCCGN miner.

### Settlement prerequisites

1. Verify the complete GCF finality certificate with an independent verifier configured with the active validator set and the required HCCGN, governance, and justice evidence gates. The ledger requires the verifier to return `valid: true`; an unconfigured verifier denies settlement.
2. Supply a signed `CRYPTIC-POOL-REWARD-POLICY/1` policy. The policy fields are exactly: `schema`, `policy_id`, `network_id`, `pool_id`, `epoch`, `effective_height_start`, `effective_height_end`, `reward_units`, `max_total_credits`, `asset`, `issuer_id`, `issued_at`, `expires_at`, and `signature`. The signature uses the `CRYPTIC-POOL-REWARD-POLICY/1\\0` Ed25519 domain and a public key pinned by the settlement service.
3. Verify the share ledger hash chain and resolve the share's historical job through `PoolCoordinator.resolve_issued_job`. This re-verifies the original issuer signature at the job's issue time without making an expired or revoked job eligible for new submissions.
4. Require exactly one accepted share whose proof hash matches the finalized proposal proof hash, and require its signed job to match the finalized network, pool, epoch, height, parent hash, and payload hash.
5. Atomically append a settlement event and one internal credit record. A network/epoch/height can be settled only once. Exact retries are idempotent; a different certificate or policy at the same height is a conflict. A signed policy-wide credit cap is enforced.

### Accounting boundary

The current HCCGN pool admission profile accepts proofs against the active network target; it does not implement a separate pool partial-share target or difficulty-weighted shares. Therefore v1 credits only the unique pool worker whose accepted proof is the exact proof finalized by consensus. It does not distribute a block reward across unrelated accepted work. Any future partial-share allocation must be a separately versioned and authorized policy/protocol.

The ledger asset is fixed to `INTERNAL_NONREDEEMABLE_CREDIT`. It has no transfer, withdrawal, redemption, token-minting, or payout API. The policy's `reward_units` are accounting units only and do not imply a transferable asset or external liability.

### Composition

Construct the settlement ledger with the persistent share ledger, `PoolCoordinator.resolve_issued_job`, an independently configured finality-verifier callback, and the pinned reward-policy public key. Call `settle_finalized_block(finality=..., reward_policy=..., pool_id=...)` only after the certificate and policy are available. Monitor `verify_chain()`, `list_settlements()`, and `worker_balances()`. Protect the settlement database and its backups with the same operational controls as the share ledger.

Unit tests and CI do not prove independent policy-key custody, HSM deployment, host integrity, backup recovery, or production reward governance. Settlement is not a public payout service.
