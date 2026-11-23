# GCF Round Progression Controller v1

## Purpose

`RoundProgressionController` closes the gap between the existing bounded
pacemaker timeout calculation and durable round-state coordination. It is
composed into `ConsensusRuntime.round_progression`.

It is a deterministic controller invoked by a host scheduler. The optional
`RoundChangeOrchestrator` composes it with an injected persistent signer and
peer broadcaster. Neither component creates background threads, selects
proposals, alters vote locks, or establishes finality.

## Runtime wiring

`build_consensus_runtime()` can receive the optional
`local_validator_id`, `round_change_signer`, and
`round_change_broadcaster` arguments as one required group. If any
one is supplied without the others, runtime construction fails closed.
`ConsensusRuntime.round_orchestrator` is otherwise `None`.
The signer callback must enforce the validator's durable lock and HSM/KMS
policy and return a complete signed `GCF-ROUND-CHANGE/1` message.
The broadcaster must return literal `True` only after its configured
peer-delivery contract succeeds. A false result leaves the durable timeout
intent pending so the same persisted signed message can be retried.

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
5. When configured, call `RoundChangeOrchestrator.tick(height=H)`. It
   invokes the signer only after the timeout intent exists, verifies the
   returned signed message, persists it, and broadcasts it through the
   injected authenticated peer transport.
6. If broadcast is ambiguous or unsuccessful, the orchestrator retries the
   exact persisted message; it does not create a second signing intent.
   Remote peer messages continue to enter through authenticated GCF-P2P/1
   dispatch and `GCFEngine.submit_round_change()`.
7. When a complete certificate exists, the orchestrator independently checks
   it and calls `activate_certificate(certificate, height=H)`. The controller
   verifies the active validator set, strict weighted quorum, and exact
   next-round/source-round relationship before persisting the certificate
   and advancing its local round record.
8. Arm the new round. Proposal admission and vote signing still pass through
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
