# Multiplexed Accessibility Terminal — Integration Contract v1

## Purpose

The Multiplexed Accessibility Terminal is the presentation, accessibility, and command-routing surface for CRYPTIC and the S.O.S. virtual computer. It is not a second consensus engine and it is not a browser permission bypass.

The integration follows the invariant: **Execute → Measure → Verify → Commit → Reverify**.

Boundary — Nothing executes beyond its time.  
Capacity — Nothing claims capacity without measurement.  
Correctness — Nothing claims correctness without verification.

## Verified repository components

The current CRYPTIC main branch contains HCCGN-WORK/1 canonical work headers, bounded nonce search, proof construction and verification; signed, short-lived pool jobs; assigned-worker binding; bounded submissions; active-target checks; authenticated worker transport; durable accepted-share ledger; and pool settlement requiring an injected independent finality verifier, exact accepted-share proof match, signed reward policy, replay protection, and a separate settlement ledger.

It also contains GCF consensus, HCCGN verification adapters, validator-set admission, weighted PREVOTE/PRECOMMIT finality, sequence-anchor integration, peer transport, production-gate adapters, S.O.S. virtual-computer extension grants, process supervision, and typed command boundaries.

The branch introduced with this document adds a portable CRYPTIC sparsebundle container and a capability-gated S.O.S. partition mount adapter. It is a custom format, not an Apple sparsebundle image and not a host operating-system block-device mount.

## System composition

Multiplexed Accessibility UI
- Screen-reader, keyboard, and voice interaction
- Nested workspace and graph panels
- Joiner Command Bus
- Typed command envelope and capability check
  - Browser compute provider (foreground Web Worker)
  - S.O.S. virtual filesystem and partition mounts
  - CRYPTIC HCCGN pool worker and pool HTTP service
  - GCF consensus and finality verifier
  - Telemetry, audit, and evidence registry

The browser UI is a client of these providers. It must never treat UI state, worker-reported metrics, peer messages, or iframe messages as consensus evidence.

## Command envelope

Every command dispatched across the Joiner Command Bus uses a versioned envelope with:
- schema: GAIA-MULTIPLEXED-COMMAND/1
- command_id: unique random identifier
- correlation_id: shared by a related command chain
- principal: authenticated user or enrolled device identity
- capability: exact required capability
- operation: allowlisted operation name
- issued_at: trusted server time
- deadline_ms: finite execution deadline
- payload: operation-specific, schema-validated data

The receiver validates the complete envelope, principal, capability, deadline, payload size, and replay identity before dispatch. Unknown operations fail closed. A command bus does not gain shell, filesystem, network, or device privileges merely because it is the bus.

Responses distinguish accepted, completed, verified, and committed. A response must not report committed until durable commit and integrity verification succeed.

## Mining profile separation

The repository contains different proof-of-work formats. They are not interchangeable:

| Profile | Preimage / nonce convention | Intended use |
|---|---|---|
| HCCGN-WORK/1 | Domain-separated canonical work header and 64-bit big-endian nonce | Current signed pool-job and proof-admission path |
| Four-lane SHA-256 reference | header concatenated with uint64 big-endian nonce | Finite-window reference miner and benchmark |
| SHA-256d 80-byte profile | 80-byte header, 32-bit little-endian nonce, double SHA-256, little-endian target comparison | Separate CPU scanner / compatibility profile |
| FGR-ICE regtest | Its own finite-window SHA-256d test contract | Conformance and regression testing |

Only the HCCGN-WORK/1 worker is accepted by the current CRYPTIC pool admission path. The other profiles must not be silently translated into HCCGN proofs. A future browser implementation must port HCCGN-WORK/1 exactly and pass the same known-answer and negative vectors before it can submit shares.

The browser compute provider must:
1. Require a visible, explicit user action to start.
2. Display the selected work profile, pool/network scope, attempt limit, and resource budget before starting.
3. Use a fixed, bounded number of Web Workers and bounded nonce windows.
4. Expose pause and stop controls that remain keyboard and screen-reader accessible.
5. Stop or pause on pagehide, loss of authorization, job expiry, or an exceeded time/resource budget.
6. Recompute candidate proofs independently before submission, then rely on pool-side independent verification.
7. Report measured attempts and elapsed time separately from accepted shares. A local candidate is not an accepted share; an accepted share is not a finalized block; finality is not a payout.

Do not run hidden or involuntary mining, do not use a service worker as a persistent mining process, and do not infer permission from a page being open. navigator.hardwareConcurrency is advisory, not a capacity measurement. Measure actual throughput and enforce an operator-configured budget.

## Sparsebundle and S.O.S. partition set

storage/sparsebundle.py defines CRYPTIC-SPARSEBUNDLE/1:
- A manifest declares a unique bundle ID, chunk size, generation, and partition set.
- Partition roles are boot, system, data, ledger, recovery, or scratch.
- Logical partitions are sparse; unallocated chunks read as zeroes.
- Nonzero chunks are immutable and content-addressed by SHA-256.
- The manifest is canonical JSON with a separate SHA-256 integrity file.
- Writes stage content-addressed chunks and atomically replace manifest files.
- Reads and verification recompute chunk hashes.
- The manifest checksum detects integrity errors; it is not a publisher signature or proof of authenticity.

src/sos/sparsebundle_mount.py exposes partitions as virtual mounts with explicit read or read/write capability authorization, principal binding, unique mount IDs, mountpoint validation, bounded I/O, finite leases, expiry, and mandatory audit acknowledgements.

This is a virtual partition I/O adapter. It does not mount a host device, format a disk, boot firmware, or provide a custom OS kernel. A VFS integration must map virtual paths to this adapter and retain the same capability checks.

## Accessibility and graph synchronization

The screen-reader panel is the semantic view of the application, not a second source of truth.

- All controls have names, roles, states, and keyboard operation.
- Announcements use a polite live region for state changes and an assertive region only for actionable errors.
- Graph animation frames are not announced. Provide a stable textual summary and an accessible data table for graph values.
- Users can pause animation, reduce motion, hide decorative layers, and choose update frequency.
- Focus is managed when nested or floating panels open, close, or change workspace.
- Voice commands are parsed into the same typed command envelope as keyboard commands; voice input does not bypass authorization.
- Visualization reads measured worker counts, accepted-share receipts, finality certificates, mount status, and storage verification reports. Missing or stale data is labelled unavailable or stale, never filled with synthetic values.

## Browser federation and networking

### WebRTC

Use HTTPS/WSS signaling to exchange short-lived offers, answers, and ICE candidates. Use ICE with STUN for connectivity discovery and TURN when a direct path is unavailable. STUN is not authentication. TURN credentials must be short-lived and scoped. Peer identity and authorization must be established separately using enrolled-device keys and signed, nonce-bound challenges.

WebRTC data channels are encrypted with DTLS. Application messages still require schema validation, replay protection, capability checks, and authenticated peer identity.

References:
- https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API/Protocols
- https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API/Using_data_channels
- https://www.rfc-editor.org/rfc/rfc8827.html

### IRC

A normal browser page cannot open arbitrary raw TCP IRC sockets. If IRC interoperability is required, connect through an explicitly operated IRC-over-WebSocket gateway or a server-side relay. Apply TLS, channel allowlists, authenticated identity, rate limits, message-size limits, and audit policy. Do not describe the relay as peer-to-peer.

### Iframes and browser permissions

- Treat every embedded origin as a separate trust boundary.
- Use a restrictive iframe sandbox, a narrow allow policy, and a restrictive Content Security Policy.
- Validate event.origin, event.source, schema, correlation ID, and a fresh nonce for every postMessage exchange.
- Never expose arbitrary shell execution or unrestricted filesystem access to an iframe.
- Camera, microphone, display capture, clipboard, and device access require normal browser permission and user-gesture flows. Do not obscure, spoof, or circumvent browser permission UI.
- Browser adapters and native S.O.S. services are separate execution providers with separate lifecycle and permission reporting.

## ChromeOS and ChromeOS Flex boundary

The Chrome wallpaper extension API requires the wallpaper permission and is documented as ChromeOS-only. Its existence does not prove every ChromeOS Flex device or management configuration supports it. Test each target and fail gracefully when unavailable:
https://developer.chrome.com/docs/extensions/reference/api/wallpaper

ChromeOS Flex is not a route to replacing ChromeOS or creating a bootable OS through a wallpaper extension. Google documents differences including the lack of a Google security chip and ChromeOS Verified Boot, lack of general Google Play/Android app support, and model-dependent Linux environment support:
https://support.google.com/chrome/a/answer/11542901

A wallpaper can be an optional presentation surface. It cannot host the S.O.S. kernel, grant background execution, replace firmware, or create an operating-system boot path. A marketable OS product requires a separately engineered and validated boot chain, installer, recovery system, hardware support matrix, update mechanism, and security model.

## Consensus and pool settlement

The pool service creates signed HCCGN jobs, assigns them to authenticated workers, independently verifies submitted proofs against the current active target, and records accepted shares in a durable hash-chained ledger.

Pool settlement is a separate stage. PoolSettlementLedger accepts a finality verifier callback and fails closed unless it returns both valid=true and finalized=true. The pool runtime composition requires two distinct proofs: independent GCF certificate verification and an ADAM commit-store check that revalidates the contiguous height/parent chain and matches the exact candidate digest, parent hash, payload/state hash, and certificate digest. If the proposal carries an external anchor sequence, that exact sequence must also be confirmed. A quorum certificate alone cannot manufacture canonical-commit evidence. Production composition must use the real GCF verifier configured with the active validator set, HCCGN proof trust root, GAIA-JUSTICE providers, and required sequence anchor. Test callbacks are not production authority.

Accepted shares are evidence of work only. Current settlement records internal, nonredeemable credits and does not implement wallet transfers or payouts.

## Acceptance gates

The integration is not complete until all of the following have evidence:

1. Sparsebundle: create, reopen, sparse zero reads, cross-chunk writes, chunk corruption detection, manifest tampering detection, and crash/recovery tests.
2. S.O.S.: mount authorization, read-only enforcement, principal binding, lease expiry, audit failure, and VFS path integration.
3. Mining: identical HCCGN known-answer vectors in Python and browser worker; job expiry; pause/stop; bounded worker count; target-change invalidation; independent server verification.
4. Pool: mTLS worker authentication; job assignment; replay rejection; nonce-range non-overlap; durable share-ledger verification.
5. Consensus: real validator signatures, strict weighted PREVOTE and PRECOMMIT quorums, proof-of-lock verification, certificate replay rejection, and exact anchor tuple compare-and-swap.
6. Settlement: independently verified finality certificate, exact proof-to-share match, signed policy, cap enforcement, and settlement-ledger verification.
7. Browser federation: signaling authorization, peer identity, DTLS data channel, TURN fallback, reconnect, replay rejection, and consent revocation.
8. Accessibility: keyboard-only, screen-reader, reduced-motion, nested focus, and accessible graph-table tests.
9. Recovery: restart, expired leases, interrupted writes, corrupted chunks, stale UI state, offline/reconnect, and backup restore.
10. Platform: actual ChromeOS and ChromeOS Flex hardware tests before making support claims.

The repository CI suite must run on the pull request. A green component test suite is not a substitute for the integrated runtime smoke test. Record exact commit SHA, workflow run IDs, test counts, skipped tests, and remaining external production gates.

## Current delivery status

This branch adds the sparsebundle container, S.O.S. capability-gated mount adapter, and focused tests. The browser-side HCCGN worker, AI Studio UI wiring, live WebRTC/IRC infrastructure, real production validator and justice authorities, native platform services, and hardware/ChromeOS Flex validation remain separate implementation and deployment gates. Do not mark those as complete based on this document.
