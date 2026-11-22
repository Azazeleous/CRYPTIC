# CRYPTIC independent sequence anchor Worker

This Worker implements the `HTTPSSequenceAnchor` contract in
`src/governance/remote_providers.py`. Anchor writes are authorized by a
cryptographically verified GCF/1 finality certificate, not by a GOD
transition-signing service.

## Security properties

- Ed25519 read/write attestations use the
  `CRYPTIC-SEQUENCE-ANCHOR/1\0` domain and canonical JSON.
- GET requests require a 128-bit hexadecimal nonce and return signed state.
- PUT requests require a bearer credential of at least 32 non-whitespace
  characters for transport authentication **and** a valid GCF/1 finality
  certificate.
- The Worker checks the certificate's proposal signature, candidate digest,
  active network/epoch, proposer membership and key, validator-set hash,
  unique sorted PREVOTE/PRECOMMIT signers, each vote signature, POLC digest,
  and strict greater-than-two-thirds voting weight in both phases.
- The validator set is independently pinned through Worker configuration.
  The Worker recomputes its canonical SHA-256 set hash and fails closed when
  the configured network, epoch, or hash does not match.
- The certificate binds the anchor transition: proposal anchor_sequence equals the
  new anchor sequence, proposal parent hash equals the expected prior anchor
  hash, and proposal payload hash equals the new anchor policy hash.
- A D1 receipt keyed by the full certificate digest rejects replay. The conditional D1 UPSERT remains the atomic
  compare-and-swap point.
- Responses are non-cacheable. No permissive CORS policy is installed.
- No signing key or bearer credential is stored in source or D1.

**Scope boundary:** a GCF finality certificate proves that the configured
validator quorum finalized the exact proposal. It does not independently
validate the underlying HCCGN proof or prove GAIA-JUSTICE policy/evidence
approval. Those remain separate admission/production gates. The anchor does
not become a GOD authority.

## Required Worker configuration

Secrets:
- `ANCHOR_SIGNING_KEY_PKCS8_B64`: base64 Ed25519 private key in PKCS#8 DER.
- `ANCHOR_WRITE_TOKEN`: random secret of at least 32 non-whitespace characters.

Non-secret, independently approved configuration:
- `ANCHOR_SIGNER_ID`: anchor response signer identity.
- `ANCHOR_VALIDATOR_SET_JSON`: canonical JSON object with exactly
  `network_id`, `epoch`, and `validators`. The validators array must be
  sorted by `validator_id`; each item has exactly `validator_id`,
  `public_key_hex` (64 lowercase hex), and positive integer `weight`.
- `ANCHOR_VALIDATOR_SET_SHA256`: independently provisioned expected SHA-256
  of canonical JSON for
  `{network_id, epoch, validators}` (same sorted validator array).
- `ANCHOR_VALIDATOR_NETWORK_ID`: exact network ID permitted to advance.
- `ANCHOR_VALIDATOR_EPOCH`: active pinned validator epoch as a positive
  decimal integer string.

The validator-set JSON and its expected fingerprint must be approved and
distributed through independent authenticated channels. Do not derive both
from one untrusted artifact. Validator public keys/weights must come from the
network's authenticated genesis/epoch governance process.

The account and D1 identifiers in `wrangler.toml` refer to the staged
Cloudflare account/database; they do not prove independent administration.
The Worker currently uses `workers_dev = false` and has no route.

## Endpoint contract

- `GET /v1/anchors/{network_id}` with
  `X-Anchor-Nonce: <32 lowercase hex>` returns 404 if uninitialized, else a
  signed anchor state record.
- `PUT /v1/anchors/{network_id}` uses
  `Authorization: Bearer <token>`, `If-None-Match: *` for initialization,
  or `If-Match: "<expected_sequence>:<expected_policy_hash>"` for advancement.
- PUT body fields are exactly `schema`, `network_id`, `sequence`,
  `policy_hash`, `expected_sequence`, `expected_policy_hash`, `issued_at`,
  `nonce`, and `certificate`.
- The certificate is the exact object returned by GCF/1
  `GCFEngine.finalize(candidate_digest)["certificate"]`. The Worker verifies
  its signed proposal, signed votes, validator-set hash, POLC, and both
  weighted quorums before attempting the D1 write.
- Successful writes return a signed record with `accepted: true`.
- Stale or competing writes return 412; missing/invalid bearer credentials
  return 401; missing or inconsistent validator-set trust configuration
  returns 503; invalid certificates return 403.
- `GET /health` reports configuration presence only; it is not a readiness
  or trust assertion.

## Client use

The Python client now submits the certificate explicitly:

```python
anchor.advance_sequence(
    network_id,
    sequence=proposal["anchor_sequence"],
    policy_hash=proposal["payload_hash"],
    certificate=finalized["certificate"],
)
```

The proposal must use the previous anchor hash as `parent_hash`, and the new
policy hash as `payload_hash`. For HCCGN policy updates, compute the digest
with `HCCGNActiveTargetPolicy.digest_snapshot(snapshot)`, finalize a GCF
proposal with `anchor_sequence=snapshot["sequence"]` bound to that digest and previous anchor hash, then pass the exact certificate
to `HCCGNActiveTargetPolicy.install(snapshot, finality_certificate=certificate)`.
An externally anchored policy install now fails closed without that certificate.
The client performs signed anchor reads and CAS writes; the Worker independently
performs certificate verification.

## Local deployment sequence

1. Review Worker source, tests, Wrangler configuration, and migrations.
2. Obtain the active validator set through the authenticated governance
   process; verify the canonical hash and epoch through an independent channel.
3. Configure the five validator-set variables listed above.
4. Create the anchor response-signing key in an approved operator-controlled
   environment or HSM. Provision its private key and the write token directly
   to Cloudflare using the approved secret-management procedure.
5. Apply migrations (including `0003_gcf_finality_certificate_receipts.sql`) with
   `wrangler d1 migrations apply cryptic-production-sequence-anchor --remote`.
6. Deploy with `wrangler deploy`. Keep `workers_dev = false` and do not add
   a route until independent ownership, access controls, validator-set
   provisioning, signing-key custody, and security review are approved.
7. Test certificate success/failure cases, initialization, advancement,
   stale writers, replay, concurrent CAS, key rotation, backup/restore, and
   outage. Record independent evidence before updating the capability ledger.

## Staged Cloudflare deployment record

The corrected Worker source from PR #33 commit
`aa83c24e9527ff918d0d16baa4aa0555f7a153db` was uploaded to the connected
Cloudflare account as `cryptic-production-sequence-anchor`.

- Deployment ID: `b539142b233842d9b71bc8da1c6b27ea`
- Worker version tag: `f4b9f90848404d10ac3efdb1f701d762`
- D1 database: `1d6199f8-8a49-45c4-abd6-ac816a91a487`
- Remote D1 tables created: `anchors`, `used_authorization_nonces`,
  `used_finality_certificates`.
- Remote D1 SQL for migrations 0001–0003 was applied idempotently. The
  Wrangler `d1_migrations` history table has not been initialized; a later
  Wrangler migration run must record these migrations and may safely replay
  their `CREATE TABLE/INDEX IF NOT EXISTS` statements.
- `wrangler.toml` specifies `workers_dev = false`; the deployed route list is
  empty, and the script's workers.dev subdomain is explicitly disabled.
- The Worker secrets list is empty. No signing key, validator-set trust
  configuration, signer identity, or bearer write token has been provisioned.

This is a real code upload and D1 schema initialization, not an activated
anchor service. The Worker remains intentionally dormant and cannot accept
authenticated writes or verify a production validator set until independent
trust configuration and secrets are provisioned.


## Activation boundary

Do not expose the Worker until the corrected source and migrations are
deployed, the validator-set hash/epoch are independently approved, signing and
write secrets are provisioned, the anchor is independently administered, and
runtime verification is complete. CI and local Worker tests do not establish
multi-region concurrency, rollback resistance, independent validator
governance, HCCGN proof validity, GAIA-JUSTICE approval, or physical durability.
