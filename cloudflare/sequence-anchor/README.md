# CRYPTIC independent sequence anchor Worker

This Worker implements the `HTTPSSequenceAnchor` contract in
`src/governance/remote_providers.py`.

## Security properties

- Signed Ed25519 read and write attestations use the exact
  `CRYPTIC-SEQUENCE-ANCHOR/1\0` domain and canonical JSON contract.
- GET requests require a 128-bit hexadecimal nonce and return signed state.
- PUT requests require a bearer credential of at least 32 non-whitespace
  characters, a valid request nonce, a fresh timestamp, an HTTP conditional
  header, and a valid GOD Ed25519 authorization for the exact update tuple.
- The bearer credential authenticates the caller only. It does not authorize
  a governance transition. The Worker verifies the GOD signature before D1.
- GOD authorization uses the domain CRYPTIC-GOD-ANCHOR-AUTH/1 followed by a
  NUL byte and canonical UTF-8 JSON of the authorization fields excluding
  signature. The signed tuple includes network, new sequence/hash, expected
  prior sequence/hash, timestamp, and nonce; all fields must match the PUT body.
- The D1 conditional UPSERT is the single atomic compare-and-swap point.
  Initial creation requires sequence 0 plus the all-zero expected hash;
  updates require the exact prior sequence/hash and a strictly greater
  sequence. A stale writer receives HTTP 412.
- Responses are non-cacheable. No permissive CORS policy is installed.
- No signing key or bearer credential is stored in source or D1.

## Provisioning prerequisites

The account and D1 database identifiers in `wrangler.toml` refer to the
staged Cloudflare account/database. They are not proof of independent
administration. The Worker is configured with `workers_dev = false` and
has no route: deploying it does not publish a public endpoint.

A responsible operator must create the production signing key on a trusted
operator-controlled machine or HSM, verify the public key/fingerprint through
an independent channel, and provision secrets directly to Cloudflare. Never
paste private key material or the write token into GitHub, chat, source code,
D1, or shell history.

The Worker requires these Cloudflare secrets:
- `ANCHOR_SIGNING_KEY_PKCS8_B64`: base64 of the Ed25519 private key in PKCS#8 DER.
- `ANCHOR_SIGNER_ID`: signer identity authorized by the independent trust ceremony.
- `ANCHOR_WRITE_TOKEN`: random secret of at least 32 non-whitespace characters.
- `GOD_ANCHOR_AUTH_SIGNER_ID`: the exact GOD authorization signer identity.
- `GOD_ANCHOR_AUTH_PUBLIC_KEY_HEX`: the 32-byte Ed25519 GOD public key as 64 lowercase hex characters.
- `GOD_ANCHOR_AUTH_KEY_FINGERPRINT`: SHA-256 of that raw public key as 64 lowercase hex characters, obtained through an independent authenticated channel.

The CRYPTIC validator host must receive the same write token through its
protected secret manager as `CRYPTIC_SEQUENCE_ANCHOR_TOKEN`, and receive the
public key plus SHA-256 fingerprint through independently authenticated
channels. Do not use the same channel to distribute both key and fingerprint.

## Local deployment sequence

1. Review this source and the D1 migration.
2. Complete the signing-key and write-token ceremony outside this repository.
3. From this directory, provision each Cloudflare secret with Wrangler's
   interactive `wrangler secret put` command, including all three GOD trust-pin
   values. Obtain the public key and fingerprint through separate authenticated
   channels; do not derive the expected fingerprint from the same deployment
   bundle that supplies the key.
4. Apply migrations with `wrangler d1 migrations apply cryptic-production-sequence-anchor --remote`.
5. Deploy with `wrangler deploy`. Keep `workers_dev = false` and do not add
   a route until the trust-root fingerprint, client token, signer identity,
   external ownership, and security review are approved.
6. From an authenticated operator-controlled environment, attach a route or
   enable a protected service endpoint only after approval. Require Access
   service-token or mTLS controls at the edge in addition to the Worker bearer
   credential when the deployment topology supports it.
7. Test initialization, advancement, stale-write rejection, concurrent CAS,
   nonce binding, signature verification, key rotation, backup/restore, and
   service outage. Record independent evidence before changing the CRYPTIC
   capability ledger.

## Endpoint contract

- `GET /v1/anchors/{network_id}` with `X-Anchor-Nonce: <32 lowercase hex>`
  returns 404 for an uninitialized network or a signed state record.
- `PUT /v1/anchors/{network_id}` uses `Authorization: Bearer <token>`,
  `If-None-Match: *` for initialization or
  `If-Match: "<expected_sequence>:<expected_policy_hash>"` for advancement.
  Its canonical JSON body must also include an `authorization` object with
  exactly `schema`, `signer_id`, `network_id`, `sequence`, `policy_hash`,
  `expected_sequence`, `expected_policy_hash`, `issued_at`, `nonce`, and
  `signature`. The Worker independently verifies the Ed25519 signature and exact tuple.
- Successful writes return a signed record with `accepted: true`.
- Stale or competing writes return 412. Missing bearer credentials return
  401; missing/invalid GOD authorization returns 403; missing or inconsistent
  GOD trust configuration returns 503.
- `GET /health` reports configuration presence only; it is not a readiness
  or trust assertion.

The Worker is an implementation component. It is not an independent operator,
a GOD authorization authority, or proof of production finality by itself.

## Staged Cloudflare deployment record

On 2026-11-22, the Worker script was uploaded to the connected Cloudflare account
`bc67ed84864df46b05d196cff28126bb` as
`cryptic-production-sequence-anchor`.

- Deployment ID: `697e0e25b28a4e109eda04dd98769e1b`
- Script tag: `f4b9f90848404d10ac3efdb1f701d762`
- Bound D1 database: `1d6199f8-8a49-45c4-abd6-ac816a91a487`
- Workers.dev: verified disabled (`enabled=false`, `previews_enabled=false`)
- Zone routes: verified no route points to this Worker
- D1 schema: verified `anchors` table exists; row count is zero
- Signing and write secrets: not provisioned
- External endpoint: not published

This is a real but dormant code deployment. It is not a live anchor service,
does not establish an independently administered trust root, and cannot
accept writes while secrets and a protected route remain absent.

### D1 compare-and-swap integration check

A direct integration check was run against the staged Cloudflare D1 database on
2026-11-22 using a temporary reserved network ID. The exact conditional UPSERT
statement was exercised against D1:

- Initial sequence insert: 1 row changed.
- Stale initialization attempt: 0 rows changed.
- Valid advancement from sequence 1 to 2: 1 row changed.
- Competing stale writer using the old expected tuple: 0 rows changed.
- Readback: sequence 2 with the expected digest.
- Cleanup: 1 row deleted; follow-up count was 0.

This verifies the D1 SQL behavior and cleanup for a single sequential test.
It does not establish concurrent multi-region behavior, signed Worker request
execution, rollback resistance, or independent service administration.
