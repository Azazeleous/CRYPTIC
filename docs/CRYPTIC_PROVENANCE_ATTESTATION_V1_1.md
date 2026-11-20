# CRYPTIC Provenance Attestation v1.1

## Scope

This layer adds issuer-authenticated attestations for existing local
provenance checkpoints. It does not change receipt, trophy-manifest, index,
or federation schemas. It does not create or submit proofs, issue assets,
establish network acceptance, or assign value.

Install the optional dependency:

```sh
python -m pip install -r requirements-attestation.txt
```

The implementation uses the Ed25519 primitive from the maintained
`cryptography` package. It does not implement elliptic-curve arithmetic
itself.

## Trust model

Three separate questions must remain distinct:

1. **Integrity:** does the SHA-256 digest match the canonical document?
2. **Signature:** does the Ed25519 signature verify against the public key?
3. **Trust:** does the configured trust store recognize that issuer/key as
   active?

A passing signature check alone does not make an issuer trusted. A trusted
issuer entry is a governance decision made by whoever controls distribution
of the trust store.

## Key material

`generate_ed25519_keypair()` returns raw 32-byte private and public keys as
hex strings plus the SHA-256 fingerprint of the public key.

The private key is returned unencrypted for caller-managed custody. Do not
commit it, place it in a public configuration, send it to another device, or
write it to logs. Store it in an operating-system credential store or other
protected secret provider. The repository does not retain or escrow keys.

A trust-store entry has this form:

```json
{
  "issuer_id": "archive-owner-a",
  "key_fingerprint": "SHA-256 of the 32-byte raw public key",
  "public_key_hex": "64 hexadecimal characters",
  "status": "active"
}
```

The containing document uses schema
`cryptic.provenance-trust-store.v1` and an `issuers` array. A revoked or
otherwise inactive entry is rejected. Replacing a key requires publishing a
new fingerprint and an explicit trust-store update; old keys should be
revoked according to the operator's policy.

## Attestation envelope

Schema: `cryptic.provenance-attestation.v1`

The signed payload binds:

- issuer ID and public-key fingerprint;
- subject schema, subject ID, SHA-256 digest algorithm, and digest;
- Unix timestamp of issuance;
- purpose string.

The signature input is domain-separated with
`CRYPTIC|PROVENANCE-ATTESTATION|ED25519|V1`. The attestation ID is a SHA-256
checksum over the canonical envelope fields, including the signature.

`create_federation_attestation()` computes a SHA-256 digest over the complete
canonical federation document and signs that digest reference. The subject
ID is the federation checkpoint root. This helper signs the supplied
document; it does not rebuild the underlying wallet archives. Consumers
must still run the federation source-rebuild audit separately.

## Verification

`verify_attestation(attestation, trust_store)` checks:

- supported schemas and exact envelope/payload fields;
- attestation ID consistency;
- issuer/key fingerprint lookup with exactly one matching trust entry;
- active (not revoked) key status;
- raw public-key length and fingerprint consistency;
- base64 signature encoding and Ed25519 verification.

The verifier reports a structured reason on failure. A valid result means
the signature matches a key currently marked active in the supplied trust
store. It does not prove that the subject's claims are true or that the
trust store itself is authentic or current.

## Revocation and time

Revocation is represented by changing the trust-store entry status away from
`active`. Verification uses the trust store supplied at verification time.
There is no online revocation service or automatic trust-store distribution
in v1.1.

`issued_at` is signed metadata. The verifier does not infer trusted time,
check clock accuracy, or enforce expiration. Operators must define and
document time synchronization, trust-store update cadence, and historical
verification policy. Historical verification should preserve the exact
trust-store snapshot used for the decision.

## Security boundaries

- Private keys never belong in source control or test fixtures committed as
  real secrets. Tests generate ephemeral keys.
- A fingerprint identifies public-key bytes; it is not a person identity.
- A signature authenticates possession of a private key, not the truth of
  the signed statement.
- A trust store is a policy input and must be distributed through an
  independently trusted channel.
- SHA-256 integrity, Ed25519 signature validity, issuer trust, and source
  archive correctness are separate verification results.
- Network acceptance, monetary value, transferability, and payments remain
  outside this subsystem.
