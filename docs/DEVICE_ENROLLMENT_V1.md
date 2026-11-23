# CRYPTIC Device Enrollment and Mutual Authentication v1

## Scope

This phase defines the identity and policy boundary for enrolled devices. It includes signed enrollment requests, operator approval, host/device challenge-response, scoped sessions, revocation, and an audit chain. It does not connect to radios, network endpoints, or home-automation controllers.

## Enrollment

A device creates a self-signed CRYPTIC-DEVICE-ENROLLMENT-REQUEST/1 document. The signature proves possession of the proposed Ed25519 private key. The request includes an explicit consent boolean, requested read-only capabilities, exact resource scopes, a nonce, and a short validity window.

An operator reviews the request and signs a CRYPTIC-DEVICE-ENROLLMENT-CERT/1 certificate. The certificate binds the exact signed request digest and may grant only a subset of requested capabilities and scopes. The operator signer must resolve to a separately provisioned trust key.

Supported capabilities are intentionally read-only:

- device.status
- network.read
- ble.observe
- home.read

No network write, BLE write, lock/actuator, or home-control capability is defined in this profile.

## Mutual authentication

The host issues a signed, short-lived challenge bound to device ID, session ID, and a random challenge value. The device verifies the host signature against its pinned host public key before signing a response. The host verifies the response with the enrolled device key, checks the pending challenge and expiry, then consumes the challenge exactly once.

Authentication produces a server-side session with a bounded lifetime. Authorization checks the session, device enrollment, revocation state, capability, and exact resource scope on every request. Device revocation invalidates all active sessions.

## Persistence and audit

Device records, pending challenges, active sessions, and audit events are stored in SQLite with WAL and synchronous=FULL. Audit events form a domain-separated SHA-256 chain. Enrollment, challenge issuance, authentication, authorization decisions, and revocation are recorded. Appends verify the existing chain before mutation; audit tampering blocks further audited state changes.

This is application-level tamper evidence and transactional persistence, not WORM storage or physical power-loss proof.

## Integration boundaries

The protocol does not itself provide a network transport, BLE GATT client, Android/iOS key-store integration, home-automation adapter, secure hardware attestation, or live device discovery. Those adapters must consume the verified session and exact scope; they must not bypass this registry. Private keys and operator trust roots must be provisioned by an external OS credential store or operator-controlled key service.

## Verification

tests/test_device_enrollment.py covers explicit consent, device proof-of-possession, operator certificate binding, capability/scope subset enforcement, host challenge verification, response replay rejection, scoped authorization, expiry, device revocation, duplicate enrollment, and audit tampering.

CI evidence is recorded after the current branch head passes. No live device, network, BLE, or home-automation action is claimed.
