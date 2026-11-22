# GCF/1 Round-Change Protocol — Safety Specification

Status: **PROOF-BOUND ROUND ADMISSION, LOCAL LOCK TRANSITIONS, PERSISTENT SIGNER GUARDS, AND WORKER VERIFICATION IMPLEMENTED — OPERATIONAL ACTIVATION DISABLED**

This document specifies the GCF round-change transition rules. The branch accepts authenticated GCF-P2P/1 ROUND_CHANGE envelopes, durably collects signed messages, and verifies strict weighted-quorum certificates. Every proposal above round zero now carries its round-change certificate in the signed proposal body. The engine binds that certificate to the exact height and target round, checks the highest POLC against a stable value digest, and permits a conflicting local vote-lock transition only when a higher-round POLC proves the new value. The persistent vote signer independently verifies and records proposal authorization, retains immutable signing-intent history, and enforces the same higher-POLC rule locally. It also signs one immutable ROUND_CHANGE message per height/target round through the HSM adapter, persisting an exact-message intent before the HSM call and allowing only identical retries after ambiguous results. The Cloudflare Worker independently verifies round-change certificates and nested POLCs before accepting finality certificates. These changes implement the software proof path; they do not establish HSM-side enforcement or independent multi-host operational evidence. Historical signed-vote and signing-intent records remain authoritative and are retained across transitions.

## 1.1 Implemented proof-verification and transition path

The branch now contains `src/consensus/round_change.py` and
`tests/test_round_change.py`. The module provides pure, fail-closed
verification for:

- Signed `GCF-ROUND-CHANGE/1` messages with network/epoch/height/round,
  validator identity, nonce, validity window, and Ed25519 domain separation.
- Complete externally supplied POLCs: proposal signature, every affirmative
  PREVOTE signature, unique validators, active validator-set hash, and
  strict weighted quorum are independently recomputed.
- Round-change certificates: unique validator messages, strict weighted
  quorum, canonical digest, highest-POLC selection, rejection of same-round
  conflicting candidate POLCs, and deterministic digest tie-breaking when
  multiple proofs establish the same candidate and round.
- Live POLC checks use the verifier's supplied current clock for proposal
  expiry and vote freshness. Signed timestamps are never used to reset the
  verifier clock. POLC vote count and round-change message count are bounded
  by the active validator-set size; time-window configuration and consensus
  integers are range-checked.

The production-gate workflow invokes `tests/test_round_change.py` on Ubuntu
and Windows. `GCFEngine.submit_round_change()` persists one message per validator
and target round, rejects duplicate/equivocating submissions, constructs a
canonical certificate, and caches only a certificate that independently
passes the proof verifier. `get_round_change_certificate()` re-verifies cached
evidence after restart. Each canonical signed message is capped at 1 MiB
before persistence. GCF-P2P/1 accepts the `ROUND_CHANGE` message type and
dispatches it through the authenticated peer identity boundary. The suite covers strict weighted quorum (including exact
two-thirds rejection), duplicate signers, invalid signatures, conflicting
POLCs, deterministic same-candidate tie-breaking, expired proposals, stale
votes, bounded proof lists, and invalid verifier limits. CI evidence for the
latest implementation head is recorded in the PR and capability ledger only
after the corresponding workflow runs complete successfully.

The implemented software path does not automatically schedule timeouts or round advancement. A later-round proposal must be explicitly constructed with a verified certificate; local engine and signer guards independently reject a conflicting value without a higher POLC. The Worker verifies the same certificate chain as part of finality. The remote HSM service itself is not modified by this repository: direct callers that can bypass `PersistentGCFVoteSigner` must be blocked by HSM/KMS policy before production activation. The local adapter now provides durable HSM-backed signing for both votes and round-change messages, but cannot enforce policy against callers that invoke the HSM endpoint directly.
The module's verifier result is evidence about a supplied proof only; it is
not authorization to sign or unlock.

## 1. Current implementation boundary

The GCF engine persists its conservative vote-admission lock keyed by:

`(network_id, epoch, height, vote_type, validator_id)`

The round is retained as lock metadata, but is deliberately not part of the lock key. The engine and persistent signer check both PREVOTE and PRECOMMIT state for the same validator/height: a different value requires a verified POLC strictly above every conflicting prior round, and a same-round proposal-digest substitution is rejected across phases. The same value may continue into a later round. Timeout, process restart, peer loss, or proposal expiry does not release a lock.

The remote `PersistentGCFVoteSigner` independently records proposal authorization, a durable round-state row, and immutable pre-sign history keyed by network, epoch, height, phase, validator, and message digest. It binds the candidate digest and full signed-message digest. An ambiguous signer result permits only an identical-message retry. Legacy lock rows without round-state metadata cannot transition.

The engine now distinguishes stable value identity from round-specific proposal identity. A later proposal may retain the same value across rounds; changing to a different value requires a verified POLC at a round strictly higher than the local recorded vote-lock round and below the new proposal round. The persistent signer applies the same rule using its own durable round-state table. Historical signed intents remain in the signing-history table and are never erased by a transition. Legacy signer lock rows without corresponding round-state metadata are fail-closed for transitions.

This remains deliberately conservative rather than a full Tendermint-compatible state machine. The current GCF vote model still uses `approve: bool` and does not define explicit nil-vote semantics or a complete timeout/round-scheduling controller. Engine vote-admission locks are not claimed to be a formally acquired consensus lock under a separate lock-acquisition protocol. No timeout, missing peer, process restart, or higher round number releases a lock.

## 2. Protocol objective and invariants

A later-round proposal may be admitted only with an authenticated round-change certificate whose signer weight is strictly greater than two-thirds of the active validator-set weight and whose target round exactly matches the proposal round.

The protocol must preserve all of these invariants:

1. **Height isolation:** every message and proof binds the exact network, epoch, and height.
2. **Round monotonicity:** a round-change certificate targets a round strictly greater than every included message's source round.
3. **Validator uniqueness:** at most one round-change message per validator is counted in one certificate.
4. **Signature authenticity:** every round-change message and every embedded vote is verified against the active validator-set key.
5. **Weighted quorum:** the certificate uses integer arithmetic and requires `floor(2*total_weight/3)+1`; equality to two-thirds is insufficient.
6. **Highest-lock preservation:** a proposal for a later round must carry the highest valid POLC reported by the certified round-change set. If that certificate contains a POLC, the proposal must use the value selected by the highest POLC.
7. **Local lock preservation:** a validator must not sign a conflicting PREVOTE merely because a timeout elapsed or a round-change certificate exists. It may change its local consensus lock only after validating a POLC at a strictly higher round than its recorded lock round.
8. **Separate signing history:** changing a consensus lock must never erase historical signed messages, signing intents, or equivocation evidence.
9. **Deterministic proof selection:** when multiple valid POLCs prove the same candidate at the same round, every verifier must select the same proof independent of message arrival order (the implementation selects the lexicographically smallest canonical POLC digest).
10. **Restart equivalence:** after restart, the validator must recover the same lock, highest valid POLC, and signed-message history before it can sign another vote.
11. **Finality unchanged:** a height finalizes only with the existing strict weighted PREVOTE/PRECOMMIT requirements and a certificate that independently verifies all proposal, vote, POLC, validator-set, and transition bindings.

## 3. Implemented message model

The following is the accepted GCF/1 round-change wire model implemented by this branch.

### 3.1 Signed round-change message

A `GCF-ROUND-CHANGE/1` message binds:

- schema;
- network_id and epoch;
- height;
- source_round and target_round;
- validator_id;
- issued_at and a bounded validity window;
- a unique nonce/message identifier;
- highest_polc, either null or a complete independently verifiable POLC object;
- signature over the canonical unsigned message under a dedicated domain separator.

The message must be rejected if its validator is not in the active set, the public key does not match, the network/epoch/height differs, the target round is not greater than the source round, the time window is invalid, the nonce is replayed, or the embedded POLC fails independent verification.

A signer must not be allowed to report a lower POLC than its durable local consensus lock. If local lock state says a valid POLC at round (q) exists, a signed round-change message for target round (R>q) must include that lock or a later valid POLC. This check belongs at the local signer boundary as well as in the consensus engine.

### 3.2 POLC proof

A POLC is a set of unique, valid, affirmative PREVOTE signatures for one exact candidate at one exact height and round, with total signer weight strictly greater than two-thirds.

The proof must bind:
- the exact candidate/proposal digest;
- network, epoch, height, and round;
- validator-set hash;
- canonical, validator-ID-sorted vote list;
- computed voting weight and required quorum weight.

Every embedded vote must be revalidated. A caller-supplied weight, a claimed boolean, or a digest without the underlying signed votes is not proof.

The engine's `_polc()` helper derives a POLC from locally stored votes. The independent `verify_polc()` function validates externally supplied signed vote sets without trusting a remote node's database or claimed weight.

### 3.3 Round-change certificate

A round-change certificate contains the exact target round and a canonical sorted list of unique signed round-change messages. The verifier must:

1. validate every message independently;
2. reject duplicate validator IDs and conflicting messages;
3. verify every embedded POLC;
4. compute weight from the active validator set, never from message fields;
5. require strict greater-than-two-thirds weight;
6. select the highest valid POLC round among the messages;
7. reject same-round conflicting POLCs rather than choosing one arbitrarily;
8. compute a domain-separated certificate digest over the canonical certificate.

The certificate must be bound to the new proposal. A proposal cannot cite a certificate for another network, epoch, height, or target round.

## 4. Proposal and lock-transition rules

A proposal in target round (R) must carry the verified round-change certificate and, when present, the highest POLC selected from it.

- If the certificate contains no POLC, the proposal may nominate a candidate, but each validator must still enforce its own persisted lock. A validator with a local lock must not vote for a different candidate.
- If the certificate contains a highest POLC for candidate (B) at round (q), where (q<R), the proposal must carry that exact proof and propose (B).
- A validator locked on candidate (A) at round (l) may change its lock to (B) only after verifying a POLC for (B) at (q>l), with (q<R), and verifying that the new proposal is bound to that proof.
- A validator that cannot prove the required transition must retain its existing lock and must not sign a conflicting affirmative PREVOTE.
- A timeout, missing peer, process restart, or higher round number is never a lock-transition proof.

The design must distinguish three records that the current implementation currently conflates or treats conservatively:

1. **Vote-signing history:** immutable record of every signed vote intent and signature, retained for equivocation/accountability.
2. **Consensus lock:** candidate and POLC round established by a verified lock-acquisition rule.
3. **Round-change state:** authenticated messages and certificates observed for the current height and target round.

Do not implement unlocking by deleting or overwriting the existing vote-lock rows.

## 5. Schema and compatibility status

The branch now persists round-change messages/certificate digests, signer proposal authorization, per-phase round state, and immutable signing-intent history. The remaining schema work before activation is:

- durable consensus-lock records including candidate digest, lock round, POLC digest, and validator-set hash;
- immutable signing-history records that retain every signed message digest and its exact round;
- persisted round-change messages and verified certificate digests;
- replay protection for round-change message identifiers;
- proposal fields that bind the round-change certificate and highest POLC;
- vote fields that unambiguously distinguish a candidate vote from a nil vote, if nil-vote progression is adopted.

The current `approve: bool` field is not a complete representation of Tendermint-style candidate-versus-nil voting. Do not overload `approve=false` as a nil vote without changing and reviewing the canonical schema, vote aggregation, POLC verification, finality certificate, Worker verifier, and signer policy together.

Migration must be atomic and fail closed. Existing rows do not contain sufficient information to infer a verified POLC-based lock. Preserve them as historical signing/vote locks; do not synthesize a consensus lock or infer an unlock permission from them. If the migration cannot prove a safe mapping, require an explicit operator-controlled recovery or validator identity/key rotation procedure.

## 6. Integration status and remaining authority boundaries

The software path now binds the transition rules across these repository components:

- **Implemented:** GCF proposal schema extension, canonical signing bytes, and proposal validation;
- **Partially implemented:** existing GCF vote schema/aggregation plus independent POLC verification; explicit nil-vote semantics remain undefined;
- **Implemented:** engine vote-admission lock transition and persistent recovery;
- **Implemented locally:** `PersistentGCFVoteSigner` proposal authorization, durable transition guard, and signing history;
- **External requirement:** remote HSM/KMS signer authorization, so direct callers cannot bypass local lock policy;
- **Implemented:** peer message schema, authenticated dispatch, replay persistence, and bounded resource handling;
- **Implemented:** finality certificate proposal binding and independent `verify_finality_certificate()`;
- **Implemented:** Cloudflare sequence-anchor Worker round-change/POLC verifier and contract tests;
- **Integrated:** HCCGN policy-update coordinator can pass a round-change certificate into a signed proposal;
- **Updated:** capability ledger and protocol runbook; external deployment gate evidence remains outstanding.

The Worker now rejects invalid transition evidence at finality. Production activation remains blocked until the HSM/KMS enforces equivalent policy against direct signing requests.

## 7. Adversarial verification matrix

The implementation must add tests for, at minimum:

- no round change with less than strict greater-than-two-thirds weight;
- exact two-thirds weight rejected;
- duplicate validator IDs rejected;
- unknown validator and wrong key rejected;
- wrong network, epoch, height, or target round rejected;
- target round equal to or below source round rejected;
- stale, future, expired, malformed, or replayed round-change messages rejected;
- malformed POLC, wrong candidate, wrong round, wrong validator-set hash, duplicate votes, invalid signatures, and insufficient POLC weight rejected;
- same-round conflicting POLCs fail closed;
- proposal that omits a required highest POLC rejected;
- proposal that cites a lower POLC when a higher one is certified rejected;
- proposal that changes candidate despite a certified highest POLC rejected;
- local signer refuses a conflicting vote without a valid higher-round POLC;
- local signer accepts only the exact safe lock transition and persists it before signing;
- direct HSM signing cannot bypass the transition policy;
- timeout alone never unlocks;
- crash between certificate verification, durable lock update, and signature request cannot produce an unsafe signature;
- restart restores lock and signing history exactly;
- concurrent round-change certificates cannot race the local lock state;
- old schema migration preserves all historical signed intents and fails closed on ambiguous state;
- no PREVOTE or PRECOMMIT quorum means no finality certificate;
- independent Worker verification rejects every malformed or insufficient round-change/POLC case;
- four independently operated nodes agree on the same lock transition under partition, delay, restart, and recovery drills.

Tests must include weighted validator sets, not only equal-weight fixtures, and Byzantine schedules that attempt to omit, equivocate about, or downgrade a previously reported POLC.

## 8. Rollout gates

1. Review the protocol and proof obligations independently before implementation.
2. **Completed in this branch:** implement the canonical wire schema and pure verification functions.
3. **Partially complete:** add adversarial tests before enabling lock transitions; the remaining matrix in Section 7 is still required.
4. **Implemented with remaining drill work:** integrate engine persistence and local signer enforcement; extend crash/restart and concurrent-transition tests.
5. **Worker verification implemented; HSM-side enforcement remains external.**
6. **Outstanding:** run multi-process and multi-host partition/recovery drills with independent operators.
7. Keep the feature disabled until the complete integration and review evidence is recorded.

No step may mark the protocol production-ready based only on unit tests, loopback TLS, or CI.

## 9. Reference model

This design follows the safety-relevant structure of the Tendermint round-based model: later-round proposals carry the latest known proof-of-lock round; a validator changes a lock only when it has a valid proof from a later round; and a timeout advances the state machine but is not itself a lock-change proof.

References:
- Tendermint consensus state machine and POLC/lock rules: https://github.com/tendermint/tendermint/blob/main/spec/consensus/consensus.md
- Tendermint signing constraints and the distinction between signed-message history and consensus locking: https://docs.tendermint.com/master/spec/consensus/signing.html
- Safety/liveness discussion and lock-change rationale: https://docs.tendermint.com/master/spec/consensus/consensus.html

This is a reference model, not a claim that GCF is Tendermint-compatible or that importing these rules alone proves GCF safety. GCF must have its own complete, reviewed proof and cross-component implementation.

---

**Current operational rule:** proof-bound round changes are implemented in the Python engine, persistent local signer guard, peer ingress, and Cloudflare Worker verifier. Automated timeout scheduling remains disabled; direct HSM-side policy, independent four-host drills, external trust ceremonies, and hardware durability evidence remain mandatory before production activation.
