# CRYPTIC independent sequence anchor Worker

This Worker implements the `HTTPSSequenceAnchor` contract in
`src/governance/remote_providers.py`.

## Security properties

- Signed Ed25519 read and write attestations use the exact
  `CRYPTIC-SEQUENCE-ANCHOR/1\0` domain and canonical JSON contract.
- GET requests require a 128-bit hexadecimal nonce and return signed state.
- PUT requests require a bearer credential of at least 32 non-whitespace
  characters **and** a separately verifiable GOD policy-transition signature.
  The signed envelope binds signer, capability, policy ID, network, prior and
  proposed sequence/hash, validity window, and a one-time nonce.
- The Worker verifies the GOD Ed25519 signature against the independently
  provisioned `ANCHOR_GOD_POLICY_PUBLIC_KEY_HEX`; the signer ID and policy ID
  must match `ANCHOR_GOD_POLICY_SIGNER_ID` and `ANCHOR_POLICY_ID`.
- A D1 nonce-receipt table rejects replayed `(signer_id, nonce)` pairs. The
  nonce is consumed only when the expected anchor state matches. A failed CAS
  can consume a valid authorization; obtain a fresh GOD authorization to retry.
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

The Worker requires these Cloudflare secrets/configuration:
- `ANCHOR_GOD_POLICY_PUBLIC_KEY_HEX`: GOD Ed25519 public key (32-byte raw key as 64 lowercase hex characters).
- `ANCHOR_GOD_POLICY_PUBLIC_KEY_SHA256`: its SHA-256 fingerprint obtained independently from the key-distribution channel; the Worker recomputes and checks this pin before signature verification.
- `ANCHOR_GOD_POLICY_SIGNER_ID`: exact authorized GOD policy signer identity.
- `ANCHOR_POLICY_ID`: exact policy namespace permitted to advance this anchor.
- `ANCHOR_SIGNING_KEY_PKCS8_B64`: base64 of the Ed25519 private key in PKCS#8 DER.
- `ANCHOR_SIGNER_ID`: signer identity authorized by the independent trust ceremony.
- `ANCHOR_WRITE_TOKEN`: random secret of at least 32 non-whitespace characters.

The validator host may receive the transport write token through its protected
secret manager as `CRYPTIC_SEQUENCE_ANCHOR_TOKEN`, but possession of that token
is not policy authority. Every PUT must also carry a fresh GOD-signed transition
envelope. The GOD public key/fingerprint and policy signer identity must be
provisioned independently; the GOD private key never enters the validator or
anchor Worker. Keep the anchor response-signing key separate from the GOD key.

## Local deployment sequence

1. Review this source and the D1 migration.
2. Complete the GOD policy-key pin ceremony separately from the anchor response-key ceremony.
3. Provision `ANCHOR_GOD_POLICY_PUBLIC_KEY_HEX`,
   `ANCHOR_GOD_POLICY_PUBLIC_KEY_SHA256`, `ANCHOR_GOD_POLICY_SIGNER_ID`, and
   `ANCHOR_POLICY_ID` as protected Worker configuration. Obtain the SHA-256
   fingerprint through an independent authenticated channel; do not derive it
   from the same artifact that supplies the public key. Provision private
   secrets with Wrangler's interactive `wrangler secret put` command.
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
- Every PUT body includes an `authorization` object with exactly `schema`,
  `signer_id`, `capability`, `policy_id`, `network_id`, `expected_sequence`,
  `expected_policy_hash`, `sequence`, `policy_hash`, `issued_at`, `expires_at`,
  `nonce`, and `signature`. Its Ed25519 signature covers canonical UTF-8 JSON
  of every field except `signature`, prefixed by
  `CRYPTIC-GOD-POLICY-TRANSITION/1` and one NUL byte. The capability must be
  `cryptic.sequence_anchor.advance`; the Worker checks signer, policy, tuple,
  validity window, fingerprint, and one-time nonce before D1 mutation.
- Successful writes return a signed record with `accepted: true`.
- Stale or competing writes return 412. Missing credentials return 401.
- `GET /health` reports configuration presence only; it is not a readiness
  or trust assertion.

The Worker verifies GOD authorization; it does not create GOD authorization
or become the GOD authority. It is not an independent operator or proof of
production finality by itself.

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

## GOD policy-transition issuer API

```text
POST <GOD_ANCHOR_TRANSITION_URL>
Content-Type: application/json
Accept: application/json

Request schema: CRYPTIC-GOD-POLICY-TRANSITION-REQUEST/1
Response schema: CRYPTIC-GOD-POLICY-TRANSITION/1
```

The request contains exactly: `schema`, `capability`, `policy_id`,
`network_id`, `expected_sequence`, `expected_policy_hash`, `sequence`,
`policy_hash`, `issued_at`, and `nonce`. The capability is
`cryptic.sequence_anchor.advance`; the nonce is 32 lowercase hexadecimal
characters. The GOD service evaluates the actual policy and authorization
state before responding. It MUST NOT act as a blind signing oracle.

A successful response contains exactly: `schema`, `signer_id`, `capability`,
`policy_id`, `network_id`, `expected_sequence`, `expected_policy_hash`,
`sequence`, `policy_hash`, `issued_at`, `expires_at`, `nonce`, and
`signature`. The response repeats the request's tuple, issued_at, and nonce.
Its Ed25519 signature covers canonical UTF-8 JSON of all response fields
except `signature`, prefixed by `CRYPTIC-GOD-POLICY-TRANSITION/1` and one NUL
byte. The client checks the signer, policy, capability, exact tuple, nonce,
validity window, and signature. The Worker independently checks the same
signature, policy pin, tuple, validity window, and one-time nonce receipt.

Return HTTP 200 only for an authorized transition; return 403 for a policy
denial. Do not sign caller-supplied tuples merely because the caller is
authenticated. The service must enforce policy version, caller identity,
network scope, signer revocation/rotation, and an auditable governance decision.
The private GOD policy key remains inside the independently administered GOD
signing boundary. The validator and anchor Worker receive only the public key
and independently sourced fingerprint.

```bash
# Example environment names only; supply values from the approved operator
# secret manager. Never put credentials or private keys on the command line.
GOD_ANCHOR_TRANSITION_URL=https://<approved-god-authority>/v1/anchor-transitions
GOD_POLICY_SIGNER_ID=<approved-signer-id>
CRYPTIC_ANCHOR_POLICY_ID=<approved-policy-id>
```
