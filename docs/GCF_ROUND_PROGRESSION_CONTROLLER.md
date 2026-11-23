# GCF Round Progression Controller v1

## Purpose

`RoundProgressionController` closes the gap between the existing bounded
pacemaker timeout calculation and durable round-state coordination. It is
composed into `ConsensusRuntime.round_progression`.

It is a deterministic controller invoked by a host scheduler. It does not
create background threads, sign validator messages, select proposals, alter
vote locks, or establish finality.

## Scheduler contract

For a newly active height/round:

1. Call `arm(height=H)`. The controller reads its durable current round and
   records a process-local monotonic start time.
2. Periodically call `poll_timeout(height=H)`.
3. Before the deadline, the result is `None`.
4. At or after the deadline, the controller writes a durable timeout intent
   and returns `REQUEST_SIGNED_ROUND_CHANGE`, including source and target
   rounds. The response explicitly states that signing is not authorized and
   no lock has been released.
5. The configured validator signer must independently enforce its own
   persistent signing-intent and POLC policy before signing a round-change
   message. The scheduler forwards the signed message through authenticated
   peer transport.
6. After the node receives a complete certificate, call
   `activate_certificate(certificate, height=H)`. The controller independently
   verifies every message, the active validator set, strict weighted quorum,
   and the exact next-round/source-round relationship before persisting the
   certificate and advancing its local round record.
7. Arm the new round. Proposal admission and vote signing still pass through
   the GCF engine and signer safety checks.

A timeout event is a request to initiate the protocol, not proof of a round
change. The scheduler must not fabricate a validator message or use the local
timeout as a substitute for signed round-change quorum evidence.

## Persistence and restart

The controller stores:

- current round by network, epoch, and height;
- verified round-change certificate bytes and digest;
- durable pending/acknowledged timeout intents.

Monotonic timestamps are process-local and are deliberately not persisted as
wall-clock substitutes. After restart, the runtime must re-arm the current
round using a fresh monotonic origin. A previously emitted pending timeout
intent is returned immediately and remains actionable. The controller never
assumes that a process restart itself advances time or releases a lock.

## Safety boundaries

- A certificate must advance exactly one local round.
- Every signed message in that certificate must report the controller's
  current source round.
- A conflicting certificate for an already recorded target round is rejected.
- A persisted certificate is independently reverified when retrieved.
- Timeout intent creation does not mutate GCF vote locks.
- Certificate activation does not authorize any vote signature.
- The GCF engine independently checks proposal round-change evidence and
  local vote-lock transition rules. The persistent signer/HSM boundary must
  independently enforce the same policy.

## Operational limitations

This controller is not a distributed leader-election service, peer discovery
system, or production scheduler. It supplies the durable local state and
explicit call contract that an operator-managed scheduler can drive. The
scheduler must use authenticated peer transport, a signer that enforces
persistent policy, bounded retries, and monitoring. Independent validator
hosts must agree on the same verified certificate; a local controller record
is not itself network finality.

Production activation remains gated on external HSM/KMS enforcement,
independent validator custody, multi-host partition/restart drills, and
review of the full cross-component protocol.
