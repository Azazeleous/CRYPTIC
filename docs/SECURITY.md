# Security Model

- Default-deny network, filesystem, process, and device access.
- Enroll devices using cryptographic identities; use short-lived, scoped credentials and revocation.
- Keep secrets outside source control and model context.
- Sandbox untrusted extensions with resource limits and restricted syscalls/network/filesystem.
- Require explicit grants for BLE, home automation, shell, mounts, and remote device actions.
- Sign and hash artifacts; verify signatures and provenance before loading.
- Audit administrative changes and sensitive actions.
- Apply dependency scanning, SBOM generation, secret scanning, and vulnerability response.
- Treat model-generated code, extension metadata, source responses, and retrieved documents as untrusted input.
- Provide backup, restore, incident response, and credential rotation procedures.

## Post-quantum cryptography

- Use vetted implementations of ML-KEM-768 and ML-DSA-65; never implement standardized PQ primitives from scratch.
- Authenticate KEM public-key distribution and bind session identities into the handshake transcript.
- Use per-lane signing identities, purpose-separated derived keys, and strict AEAD nonce uniqueness.
- Track key expiry, rotation, revocation, algorithm identifiers, and downgrade attempts.
- Keep private keys and shared secrets out of source control, logs, test fixtures, and model context.
- Treat SLH-DSA as an optional hash-based signature profile, not a lattice-based algorithm.

## Mining security

- Use the exact chain-specific canonical header, consensus hash, nonce encoding, and target.
- Keep lane scheduling and barrel-roll framing outside the consensus hash preimage.
- Assign disjoint candidate ranges and reject duplicate or out-of-range submissions.
- Independently recompute every accepted candidate.
- Do not embed pool credentials or wallet secrets in source code.
- Mining authorization and pool connectivity require explicit configuration.

Owner identity is established by enrollment and cryptographic proof, not by a username string or model prompt.
