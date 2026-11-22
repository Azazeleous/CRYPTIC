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
- The operator must allocate non-overlapping nonce windows when issuing jobs to different workers; worker binding alone does not partition the nonce space.
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
