# CRYPTIC Cryptographic Key Lifecycle

## Key classes

| Key material | Purpose | Handling |
|---|---|---|
| ML-KEM-768 private key | Decapsulate session secrets | Protected key store; never export to logs |
| ML-DSA-65 private key | Sign lane identities and checkpoints | Per-lane identity; protected key store |
| SLH-DSA private key | Optional alternative signatures | Separate identity/profile |
| Derived traffic keys | Encrypt/authenticate session traffic | Short-lived, purpose- and direction-separated |
| Public keys and certificates | Identity and verification | Versioned registry with provenance |

## Required metadata

Every key registry record contains key ID, owner/lane ID, algorithm, public-key digest, purpose, creation time, activation time, expiration time, status, provider reference, and revocation reason where applicable. Secret key bytes and shared secrets are excluded.

## Rotation and revocation

Rotation creates a new key record and authenticated transition statement. The old key remains available for historical signature verification according to retention policy, but is no longer accepted for new sessions after revocation or expiry. Revocation is checked during session establishment and checkpoint verification.

## Session derivation

Derive separate keys for each lane, direction, and use. Bind the KDF context to the transcript hash, protocol version, session ID, peer identities, algorithm suite, lane ID, and purpose. Reject missing or mismatched context.

## Operational controls

- No secrets in Git, issue comments, test fixtures, logs, or model prompts.
- Use a vetted cryptographic library and OS-backed or hardware-backed key storage where available.
- Apply least privilege and explicit key-use permissions.
- Require auditable approval for identity replacement and emergency revocation.
- Test rotation, revocation, replay rejection, and recovery.
