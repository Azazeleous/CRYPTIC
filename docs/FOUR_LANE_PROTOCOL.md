# CRYPTIC Four-Lane Protocol

## Lane assignments

| Lane | Traversal | Primary responsibility |
|---|---|---|
| 1 | Forward | Candidate scheduling and forward frame path |
| 2 | Reverse | Independent reverse-order candidate traversal |
| 3 | Reverse | Reverse frame reconstruction and candidate traversal |
| 4 | Forward | Independent forward reconstruction and candidate traversal |

All lanes use one protocol version, canonical field encoding, fixed-width integer rules, and explicit sequence numbers. Lane identity is an assigned identifier, not a secret or proof of identity.

## Reversible frame pipeline

The reversible diagnostic pipeline is:

1. Rotate each byte by a fixed-width 8-bit ROTL.
2. Circularly rotate the byte sequence.
3. Distribute bytes round-robin across four lanes.
4. Rotate lane order.
5. Reconstruct by reversing these operations.

The round-trip invariant is:

    unroll_frame(roll_frame(payload, parameters), parameters) == payload

Parameters must be recorded with the frame. Unsupported or missing parameters cause rejection rather than guessed reconstruction.

## Mining candidate ownership

The scheduler partitions global ordinals by lane number modulo four. Each candidate belongs to exactly one lane. Lanes 2 and 3 process their assigned ordinals in reverse order; this changes traversal order, not candidate identity. A complete finite job must cover every ordinal exactly once.

## Midpoint and checkpoints

The 0.5 midpoint is a synchronization checkpoint only. It is not a cryptographic primitive, secret, parity proof, or consensus parameter. Checkpoints include protocol version, job ID, lane ID, ordinal interval, sequence number, transform parameters, and digest of the canonical payload.

## Failure handling

A lane mismatch, duplicate ordinal, missing ordinal, invalid inverse transform, or checkpoint digest mismatch marks the job incomplete. Do not silently repair or discard evidence. Preserve original bytes, record the failure, rerun an independently assigned verification, and commit only after verification succeeds.

## Consensus boundary

Lane scheduling and frame transforms never change the canonical mining header or consensus hash. The verifier recomputes each candidate using the chain adapter's specified rules.
