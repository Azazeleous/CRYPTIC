import test from "node:test";
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
globalThis.crypto ||= webcrypto;

import worker from "../cloudflare/sequence-anchor/src/index.js";

const ZERO = "0".repeat(64);
const TOKEN = "anchor-test-token-".padEnd(40, "x");
const ANCHOR_DOMAIN = new TextEncoder().encode("CRYPTIC-SEQUENCE-ANCHOR/1\0");
const PROPOSAL_DOMAIN = new TextEncoder().encode("GCF/1|PROPOSAL|ED25519\0");
const VOTE_DOMAIN = new TextEncoder().encode("GCF/1|VOTE|ED25519\0");
const CERT_DOMAIN = new TextEncoder().encode("GCF/1|FINALITY-CERTIFICATE\0");
const ROUND_CHANGE_DOMAIN = new TextEncoder().encode("GCF/1|ROUND-CHANGE|ED25519\0");
const ROUND_CHANGE_CERT_DOMAIN = new TextEncoder().encode("GCF/1|ROUND-CHANGE-CERTIFICATE\0");

function canonical(value) {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value && typeof value === "object") return "{" +
    Object.keys(value).sort().map(k => JSON.stringify(k) + ":" + canonical(value[k])).join(",") + "}";
  return JSON.stringify(value);
}
function b64(bytes) {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary);
}
async function sha256(bytes) {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
    b => b.toString(16).padStart(2, "0")).join("");
}
async function sign(privateKey, domain, body) {
  const payload = new TextEncoder().encode(canonical(body));
  const message = new Uint8Array(domain.length + payload.length);
  message.set(domain); message.set(payload, domain.length);
  return b64(await crypto.subtle.sign("Ed25519", privateKey, message));
}
class MemoryD1 {
  constructor() { this.rows = new Map(); this.nonces = new Set(); }
  prepare(sql) {
    const db = this;
    return {
      values: [],
      bind(...values) { this.values = values; return this; },
      async first() {
        const row = db.rows.get(this.values[0]);
        return row ? { sequence: row.sequence, policy_hash: row.policy_hash } : null;
      },
      async run() {
        if (sql.includes("INSERT INTO used_finality_certificates")) {
          const [certificateDigest, network, sequence, acceptedAt, expectedSequence,
            expectedHash, zeroHash, initNetwork, guardNetwork, guardSequence, guardHash] = this.values;
          const row = db.rows.get(network);
          const matches = expectedSequence === 0
            ? expectedHash === zeroHash && !row && initNetwork === network
            : Boolean(row && row.sequence === guardSequence &&
              row.policy_hash === guardHash && guardNetwork === network);
          if (!matches || db.nonces.has(certificateDigest)) {
            return { success: true, meta: { changes: 0 } };
          }
          db.nonces.add(certificateDigest);
          return { success: true, meta: { changes: 1, sequence, acceptedAt } };
        }
        const [network, sequence, hash, updated, expectedSequence, expectedHash,
          zeroHash, guardNetwork, guardSequence, guardHash, whereSequence, whereHash] = this.values;
        const row = db.rows.get(network);
        if (!row) {
          if (expectedSequence === 0 && expectedHash === zeroHash) {
            db.rows.set(network, { sequence, policy_hash: hash, updated_at: updated });
            return { success: true, meta: { changes: 1 } };
          }
          return { success: true, meta: { changes: 0 } };
        }
        if (guardNetwork === network && row.sequence === guardSequence &&
            row.policy_hash === guardHash && row.sequence === whereSequence &&
            row.policy_hash === whereHash && sequence > row.sequence) {
          db.rows.set(network, { sequence, policy_hash: hash, updated_at: updated });
          return { success: true, meta: { changes: 1 } };
        }
        return { success: true, meta: { changes: 0 } };
      },
    };
  }
}
async function setup() {
  const anchorPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const anchorPkcs8 = await crypto.subtle.exportKey("pkcs8", anchorPair.privateKey);
  const anchorPublic = await crypto.subtle.exportKey("raw", anchorPair.publicKey);
  const validatorPairs = [];
  const validators = [];
  for (let i = 1; i <= 4; i++) {
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    const publicHex = Array.from(raw, b => b.toString(16).padStart(2, "0")).join("");
    validators.push({ validator_id: "v" + i, public_key_hex: publicHex, weight: 1 });
    validatorPairs.push(pair);
  }
  const setBody = { network_id: "test-net", epoch: 1, validators };
  const setHash = await sha256(new TextEncoder().encode(canonical(setBody)));
  const env = {
    ANCHOR_DB: new MemoryD1(),
    ANCHOR_SIGNER_ID: "anchor-test-root",
    ANCHOR_SIGNING_KEY_PKCS8_B64: b64(anchorPkcs8),
    ANCHOR_WRITE_TOKEN: TOKEN,
    ANCHOR_VALIDATOR_SET_JSON: JSON.stringify(setBody),
    ANCHOR_VALIDATOR_SET_SHA256: setHash,
    ANCHOR_VALIDATOR_NETWORK_ID: "test-net",
    ANCHOR_VALIDATOR_EPOCH: "1",
  };
  return {
    env, validatorPairs, validators,
    anchorPublicKey: await crypto.subtle.importKey("raw", anchorPublic,
      { name: "Ed25519" }, false, ["verify"]),
  };
}
async function request(env, method, path, { headers = {}, body } = {}) {
  return worker.fetch(new Request("https://anchor.test" + path, {
    method, headers, body: body === undefined ? undefined : canonical(body),
  }), env);
}
async function makeCertificate(ctx, { sequence, height = sequence, oldHash, newHash, signers = [0, 1, 2],
  network = "test-net", epoch = 1, round = 0, roundChangeCertificate = null } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const proposalBody = {
    schema: "GCF/1", network_id: network, epoch, height, anchor_sequence: sequence, round,
    parent_hash: oldHash, payload_hash: newHash, proof_hash: "a".repeat(64),
    justice_commitment: { justice_profile: "GAIA-JUSTICE/1", commitment: "b".repeat(64) },
    issued_at: now, expires_at: now + 300, proposer_id: "v1",
    proposer_public_key: ctx.validators[0].public_key_hex, nonce: "proposal-nonce-0001",
  };
  if (roundChangeCertificate !== null) proposalBody.round_change_certificate = roundChangeCertificate;
  const proposal = { ...proposalBody,
    signature: await sign(ctx.validatorPairs[0].privateKey, PROPOSAL_DOMAIN, proposalBody) };
  const candidateDigest = await sha256(new TextEncoder().encode(canonical(proposal)));
  async function votes(kind, polcDigest = null) {
    const output = [];
    for (const index of signers) {
      const body = {
        schema: "GCF/1", network_id: network, epoch, height, round,
        candidate_digest: candidateDigest, validator_id: "v" + (index + 1),
        vote_type: kind, approve: true, polc_digest: polcDigest, issued_at: now + 1,
      };
      output.push({ ...body,
        signature: await sign(ctx.validatorPairs[index].privateKey, VOTE_DOMAIN, body) });
    }
    return output.sort((a, b) => a.validator_id.localeCompare(b.validator_id));
  }
  const prevotes = await votes("PREVOTE");
  const polcBody = { schema: "GCF/1", candidate_digest: candidateDigest,
    validator_set_hash: ctx.env.ANCHOR_VALIDATOR_SET_SHA256, prevotes };
  const polcDigest = await sha256(new Uint8Array([
    ...CERT_DOMAIN, ...new TextEncoder().encode(canonical(polcBody))
  ]));
  const precommits = await votes("PRECOMMIT", polcDigest);
  return {
    schema: "GCF/1", network_id: network, epoch, height, round,
    candidate_digest: candidateDigest, proposal,
    validator_set: { network_id: "test-net", epoch: 1,
      validators: ctx.validators, validator_set_hash: ctx.env.ANCHOR_VALIDATOR_SET_SHA256 },
    polc: { digest: polcDigest, prevotes }, precommits,
    total_voting_weight: 4, precommit_weight: signers.length,
  };
}

async function makeGcf2AnchorEnvelope(ctx, {
  sequence, height = sequence, oldHash, newHash, signers = [0, 1, 2],
}) {
  const now = Math.floor(Date.now() / 1000);
  const base = await makeCertificate(ctx, {
    sequence, height, oldHash, newHash, signers: [0, 1, 2],
  });
  const proposal = base.proposal;
  const candidateDigest = await sha256(new TextEncoder().encode(canonical(proposal)));
  async function votes(phase, polcDigest = null) {
    const output = [];
    for (const index of signers) {
      const body = {
        schema: "GCF/2", network_id: proposal.network_id,
        epoch: proposal.epoch, height: proposal.height, round: proposal.round,
        parent_hash: proposal.parent_hash, vote_type: phase,
        vote_kind: "CANDIDATE", candidate_digest: candidateDigest,
        validator_id: "v" + (index + 1), approve: true,
        polc_digest: polcDigest, issued_at: now + 1, expires_at: now + 200,
      };
      const domain = new TextEncoder().encode("GCF/2|VOTE|ED25519\0");
      output.push({ ...body, signature: await sign(ctx.validatorPairs[index].privateKey, domain, body) });
    }
    return output.sort((a, b) => a.validator_id.localeCompare(b.validator_id));
  }
  const prevotes = await votes("PREVOTE");
  const polcBody = {
    schema: "GCF/2", network_id: proposal.network_id, epoch: proposal.epoch,
    height: proposal.height, round: proposal.round, parent_hash: proposal.parent_hash,
    candidate_digest: candidateDigest,
    validator_set_hash: ctx.env.ANCHOR_VALIDATOR_SET_SHA256, prevotes,
  };
  const polcDomain = new TextEncoder().encode("GCF/2|POLC\0");
  const polcDigest = await sha256(new Uint8Array([
    ...polcDomain, ...new TextEncoder().encode(canonical(polcBody)),
  ]));
  const precommits = await votes("PRECOMMIT", polcDigest);
  const certificateBody = {
    schema: "GCF/2", network_id: proposal.network_id, epoch: proposal.epoch,
    height: proposal.height, round: proposal.round, parent_hash: proposal.parent_hash,
    candidate_digest: candidateDigest,
    validator_set_hash: ctx.env.ANCHOR_VALIDATOR_SET_SHA256,
    proposal,
    finalized_at: now + 2,
    polc: { ...polcBody, polc_digest: polcDigest },
    precommits,
  };
  const certDomain = new TextEncoder().encode("GCF/2|FINALITY-CERTIFICATE\0");
  const certificateDigest = await sha256(new Uint8Array([
    ...certDomain, ...new TextEncoder().encode(canonical(certificateBody)),
  ]));
  return {
    schema: "GCF/2-ANCHOR-ENVELOPE/1", proposal,
    certificate: { ...certificateBody, certificate_digest: certificateDigest },
  };
}

async function makeRoundChangeMessage(ctx, index, {
  height, sourceRound, targetRound, highestPolc = null, issuedAt = Math.floor(Date.now() / 1000),
}) {
  const body = {
    schema: "GCF-ROUND-CHANGE/1", network_id: "test-net", epoch: 1, height,
    source_round: sourceRound, target_round: targetRound,
    validator_id: "v" + (index + 1), issued_at: issuedAt, expires_at: issuedAt + 300,
    nonce: (index + 1).toString(16).padStart(2, "0").repeat(16),
    highest_polc: highestPolc,
  };
  return { ...body, signature: await sign(
    ctx.validatorPairs[index].privateKey, ROUND_CHANGE_DOMAIN, body
  ) };
}
async function makeRoundChangeCertificate(messages, { height, targetRound }) {
  const ordered = messages.slice().sort((a, b) => a.validator_id.localeCompare(b.validator_id));
  const body = {
    schema: "GCF-ROUND-CHANGE/1-CERT", network_id: "test-net", epoch: 1,
    height, target_round: targetRound, messages: ordered,
  };
  return { ...body, digest: await sha256(new Uint8Array([
    ...ROUND_CHANGE_CERT_DOMAIN, ...new TextEncoder().encode(canonical(body))
  ])) };
}

function writeBody(sequence, hash, expectedSequence, expectedHash, certificate) {
  return {
    schema: "CRYPTIC-SEQUENCE-ANCHOR/1", network_id: "test-net",
    sequence, policy_hash: hash, expected_sequence: expectedSequence,
    expected_policy_hash: expectedHash, issued_at: Math.floor(Date.now() / 1000),
    nonce: crypto.randomUUID().replaceAll("-", "").slice(0, 32), certificate,
  };
}
async function put(ctx, body, initial = false) {
  return request(ctx.env, "PUT", "/v1/anchors/test-net", {
    headers: { authorization: "Bearer " + TOKEN,
      ...(initial ? { "if-none-match": "*" } :
        { "if-match": '"' + body.expected_sequence + ":" + body.expected_policy_hash + '"' }),
      "content-type": "application/json" }, body,
  });
}
async function verifyAnchorRecord(record, publicKey) {
  const { signature, ...unsigned } = record;
  const signatureBytes = Uint8Array.from(atob(signature), ch => ch.charCodeAt(0));
  const payload = new TextEncoder().encode(canonical(unsigned));
  const message = new Uint8Array(ANCHOR_DOMAIN.length + payload.length);
  message.set(ANCHOR_DOMAIN); message.set(payload, ANCHOR_DOMAIN.length);
  assert.equal(await crypto.subtle.verify("Ed25519", publicKey, signatureBytes, message), true);
}

test("unauthenticated write is rejected before D1 mutation", async () => {
  const ctx = await setup();
  const cert = await makeCertificate(ctx, { sequence: 1, oldHash: ZERO, newHash: "1".repeat(64) });
  const body = writeBody(1, "1".repeat(64), 0, ZERO, cert);
  const response = await request(ctx.env, "PUT", "/v1/anchors/test-net", {
    headers: { "if-none-match": "*", "content-type": "application/json" }, body,
  });
  assert.equal(response.status, 401);
  assert.equal(ctx.env.ANCHOR_DB.rows.size, 0);
});

test("Python GCF/2 known-answer certificate verifies identically in the Worker", async () => {
  const vectorBytes = gunzipSync(Buffer.from(
    readFileSync(new URL("./vectors/gcf2_finality_known_answer.json.gz.b64", import.meta.url), "utf8"),
    "base64",
  ));
  const vector = JSON.parse(vectorBytes.toString("utf8"));
  const ctx = await setup();
  const pinnedSet = {
    network_id: vector.network_id, epoch: vector.epoch,
    validators: vector.validators,
  };
  ctx.env.ANCHOR_VALIDATOR_SET_JSON = JSON.stringify(pinnedSet);
  ctx.env.ANCHOR_VALIDATOR_SET_SHA256 = vector.validator_set_hash;
  ctx.env.ANCHOR_VALIDATOR_NETWORK_ID = vector.network_id;
  ctx.env.ANCHOR_VALIDATOR_EPOCH = String(vector.epoch);
  const proposal = vector.proposal;
  const body = {
    schema: "CRYPTIC-SEQUENCE-ANCHOR/1",
    network_id: vector.network_id, sequence: proposal.anchor_sequence,
    policy_hash: proposal.payload_hash,
    expected_sequence: proposal.anchor_sequence - 1,
    expected_policy_hash: proposal.parent_hash,
    issued_at: Math.floor(Date.now() / 1000),
    nonce: "a".repeat(32),
    certificate: {
      schema: "GCF/2-ANCHOR-ENVELOPE/1",
      proposal, certificate: vector.certificate,
    },
  };
  const response = await request(
    ctx.env, "PUT", "/v1/anchors/" + vector.network_id,
    { headers: {
      authorization: "Bearer " + TOKEN,
      "if-match": '"' + body.expected_sequence + ":" + body.expected_policy_hash + '"',
      "content-type": "application/json",
    }, body },
  );
  assert.equal(response.status, 200, JSON.stringify(await response.clone().json()));
  assert.equal(ctx.env.ANCHOR_DB.rows.get(vector.network_id).policy_hash, proposal.payload_hash);
});

test("pinned GCF/2 finality certificate authorizes sequence-anchor initialization", async () => {
  const ctx = await setup();
  const hash = "c".repeat(64);
  const certificate = await makeGcf2AnchorEnvelope(ctx, {
    sequence: 1, height: 44, oldHash: ZERO, newHash: hash,
  });
  const response = await put(ctx, writeBody(1, hash, 0, ZERO, certificate), true);
  assert.equal(response.status, 200, JSON.stringify(await response.clone().json()));
  assert.equal(ctx.env.ANCHOR_DB.rows.get("test-net").policy_hash, hash);
});

test("GCF/2 anchor verifier rejects a tampered finality digest", async () => {
  const ctx = await setup();
  const hash = "d".repeat(64);
  const certificate = await makeGcf2AnchorEnvelope(ctx, {
    sequence: 1, height: 45, oldHash: ZERO, newHash: hash,
  });
  certificate.certificate.certificate_digest = "0".repeat(64);
  const response = await put(ctx, writeBody(1, hash, 0, ZERO, certificate), true);
  assert.equal(response.status, 403);
  assert.equal(ctx.env.ANCHOR_DB.rows.size, 0);
});

test("pinned GCF finality certificate authorizes initialization and advancement", async () => {
  const ctx = await setup();
  const firstHash = "1".repeat(64);
  const firstCert = await makeCertificate(ctx, { sequence: 1, height: 17, oldHash: ZERO, newHash: firstHash });
  const first = writeBody(1, firstHash, 0, ZERO, firstCert);
  const initialized = await put(ctx, first, true);
  assert.equal(initialized.status, 200, JSON.stringify(await initialized.clone().json()));
  const record = await initialized.json();
  assert.equal(record.accepted, true);
  await verifyAnchorRecord(record, ctx.anchorPublicKey);

  const secondHash = "2".repeat(64);
  const secondCert = await makeCertificate(ctx, { sequence: 2, height: 18, oldHash: firstHash, newHash: secondHash });
  const second = writeBody(2, secondHash, 1, firstHash, secondCert);
  const advanced = await put(ctx, second);
  assert.equal(advanced.status, 200, JSON.stringify(await advanced.clone().json()));
  assert.equal((await advanced.json()).sequence, 2);

  const staleCert = await makeCertificate(ctx, { sequence: 2, oldHash: firstHash, newHash: "3".repeat(64) });
  const stale = writeBody(2, "3".repeat(64), 1, firstHash, staleCert);
  assert.equal((await put(ctx, stale)).status, 412);
  assert.equal(ctx.env.ANCHOR_DB.rows.get("test-net").sequence, 2);
});

test("rejects insufficient quorum, forged signatures, wrong epoch, and transition substitution", async () => {
  const ctx = await setup();
  const hash = "4".repeat(64);
  let cert = await makeCertificate(ctx, { sequence: 1, oldHash: ZERO, newHash: hash, signers: [0, 1] });
  let response = await put(ctx, writeBody(1, hash, 0, ZERO, cert), true);
  assert.equal(response.status, 403);

  cert = await makeCertificate(ctx, { sequence: 1, oldHash: ZERO, newHash: hash });
  cert.precommits[0].signature = b64(new Uint8Array(64));
  response = await put(ctx, writeBody(1, hash, 0, ZERO, cert), true);
  assert.equal(response.status, 403);

  cert = await makeCertificate(ctx, { sequence: 1, oldHash: ZERO, newHash: hash, epoch: 2 });
  response = await put(ctx, writeBody(1, hash, 0, ZERO, cert), true);
  assert.equal(response.status, 403);

  cert = await makeCertificate(ctx, { sequence: 1, oldHash: "f".repeat(64), newHash: hash });
  response = await put(ctx, writeBody(1, hash, 0, ZERO, cert), true);
  assert.equal(response.status, 403);
  assert.equal(ctx.env.ANCHOR_DB.rows.size, 0);
});


test("pinned Worker verifies nested round-change certificates and POLC-bound proposal values", async () => {
  const ctx = await setup();
  const now = Math.floor(Date.now() / 1000);
  const height = 31, policyHash = "9".repeat(64);
  const firstRoundMessages = await Promise.all([0, 1, 2].map(index =>
    makeRoundChangeMessage(ctx, index, {
      height, sourceRound: 0, targetRound: 1, issuedAt: now,
    })
  ));
  const firstRoundCertificate = await makeRoundChangeCertificate(
    firstRoundMessages, { height, targetRound: 1 },
  );
  const roundOneFinality = await makeCertificate(ctx, {
    sequence: 1, height, oldHash: ZERO, newHash: policyHash,
    round: 1, roundChangeCertificate: firstRoundCertificate,
  });
  const polc = {
    schema: "GCF-POLC/1", proposal: roundOneFinality.proposal,
    candidate_digest: roundOneFinality.candidate_digest,
    validator_set_hash: ctx.env.ANCHOR_VALIDATOR_SET_SHA256,
    prevotes: roundOneFinality.polc.prevotes,
    digest: roundOneFinality.polc.digest,
  };
  const secondRoundMessages = await Promise.all([0, 1, 2].map(index =>
    makeRoundChangeMessage(ctx, index, {
      height, sourceRound: 1, targetRound: 2, highestPolc: polc, issuedAt: now,
    })
  ));
  const secondRoundCertificate = await makeRoundChangeCertificate(
    secondRoundMessages, { height, targetRound: 2 },
  );
  const finality = await makeCertificate(ctx, {
    sequence: 1, height, oldHash: ZERO, newHash: policyHash,
    round: 2, roundChangeCertificate: secondRoundCertificate,
  });
  const accepted = await put(ctx, writeBody(1, policyHash, 0, ZERO, finality), true);
  assert.equal(accepted.status, 200, JSON.stringify(await accepted.clone().json()));

  const corrupted = structuredClone(finality);
  corrupted.proposal.round_change_certificate.messages[0].highest_polc.proposal.payload_hash = "a".repeat(64);
  const rejected = await put(ctx, writeBody(1, policyHash, 0, ZERO, corrupted), true);
  assert.equal(rejected.status, 403);
  assert.equal(ctx.env.ANCHOR_DB.rows.get("test-net").policy_hash, policyHash);
});

test("certificate digest replay is rejected even when request nonce changes", async () => {
  const ctx = await setup();
  const hash = "5".repeat(64);
  const cert = await makeCertificate(ctx, { sequence: 1, oldHash: ZERO, newHash: hash });
  const first = writeBody(1, hash, 0, ZERO, cert);
  assert.equal((await put(ctx, first, true)).status, 200);
  // Model restoration of only the anchor row while retaining the independent
  // certificate receipt ledger. The exact certificate must remain unusable.
  ctx.env.ANCHOR_DB.rows.delete("test-net");
  const replay = { ...first, nonce: "f".repeat(32) };
  assert.equal((await put(ctx, replay, true)).status, 412);
  assert.equal(ctx.env.ANCHOR_DB.rows.has("test-net"), false);
});

test("missing pinned validator-set configuration fails closed as unavailable", async () => {
  const ctx = await setup();
  const cert = await makeCertificate(ctx, { sequence: 1, oldHash: ZERO, newHash: "6".repeat(64) });
  delete ctx.env.ANCHOR_VALIDATOR_SET_SHA256;
  const response = await put(ctx, writeBody(1, "6".repeat(64), 0, ZERO, cert), true);
  assert.equal(response.status, 503);
  assert.equal(ctx.env.ANCHOR_DB.rows.size, 0);
});

test("validator-set hash pin mismatch fails closed", async () => {
  const ctx = await setup();
  const hash = "8".repeat(64);
  const cert = await makeCertificate(ctx, { sequence: 1, oldHash: ZERO, newHash: hash });
  ctx.env.ANCHOR_VALIDATOR_SET_SHA256 = "0".repeat(64);
  const response = await put(ctx, writeBody(1, hash, 0, ZERO, cert), true);
  assert.equal(response.status, 503);
  assert.equal((await response.json()).error, "validator_set_hash_pin_mismatch");
  assert.equal(ctx.env.ANCHOR_DB.rows.size, 0);
});

test("rejects malformed nonce, request schema, and bearer token", async () => {
  const ctx = await setup();
  const badNonce = await request(ctx.env, "GET", "/v1/anchors/test-net", {
    headers: { "x-anchor-nonce": "bad" },
  });
  assert.equal(badNonce.status, 400);
  const cert = await makeCertificate(ctx, { sequence: 1, oldHash: ZERO, newHash: "7".repeat(64) });
  const body = writeBody(1, "7".repeat(64), 0, ZERO, cert);
  const badAuth = await request(ctx.env, "PUT", "/v1/anchors/test-net", {
    headers: { authorization: "Bearer invalid", "if-none-match": "*",
      "content-type": "application/json" }, body,
  });
  assert.equal(badAuth.status, 401);
  const badSchema = await request(ctx.env, "PUT", "/v1/anchors/test-net", {
    headers: { authorization: "Bearer " + TOKEN, "if-none-match": "*",
      "content-type": "application/json" }, body: { ...body, extra: true },
  });
  assert.equal(badSchema.status, 400);
});
