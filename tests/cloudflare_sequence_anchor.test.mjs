import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
globalThis.crypto ||= webcrypto;

import worker from "../cloudflare/sequence-anchor/src/index.js";

const ZERO = "0".repeat(64);
const ANCHOR_DOMAIN = new TextEncoder().encode("CRYPTIC-SEQUENCE-ANCHOR/1\0");
const POLICY_DOMAIN = new TextEncoder().encode("CRYPTIC-GOD-POLICY-TRANSITION/1\0");
const TOKEN = "anchor-test-token-".padEnd(40, "x");

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
        if (sql.includes("DELETE FROM used_authorization_nonces")) {
          const cutoff = this.values[0];
          return { success: true, meta: { changes: 0, cutoff } };
        }
        if (sql.includes("INSERT INTO used_authorization_nonces")) {
          const [signer, nonce, network, expiry, expectedSequence, expectedHash,
            zeroHash, initNetwork, guardNetwork, guardSequence, guardHash] = this.values;
          const row = db.rows.get(network);
          const stateMatches = expectedSequence === 0
            ? expectedHash === zeroHash && !row
            : Boolean(row && row.sequence === guardSequence &&
              row.policy_hash === guardHash && guardNetwork === network);
          const key = signer + ":" + nonce;
          if (!stateMatches || db.nonces.has(key)) {
            return { success: true, meta: { changes: 0 } };
          }
          db.nonces.add(key);
          return { success: true, meta: { changes: 1, expiry, initNetwork } };
        }
        const [network, sequence, hash, updated, expectedSequence,
          expectedHash, zeroHash, guardNetwork, guardSequence, guardHash,
          whereSequence, whereHash] = this.values;
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
  const godPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", anchorPair.privateKey);
  const anchorPublicRaw = await crypto.subtle.exportKey("raw", anchorPair.publicKey);
  const godPublicRaw = await crypto.subtle.exportKey("raw", godPair.publicKey);
  const godPublicHex = Array.from(new Uint8Array(godPublicRaw), b => b.toString(16).padStart(2, "0")).join("");
  const godFingerprint = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", godPublicRaw)), b => b.toString(16).padStart(2, "0")).join("");
  const env = {
    ANCHOR_DB: new MemoryD1(),
    ANCHOR_SIGNER_ID: "anchor-test-root",
    ANCHOR_SIGNING_KEY_PKCS8_B64: b64(pkcs8),
    ANCHOR_WRITE_TOKEN: TOKEN,
    ANCHOR_GOD_POLICY_PUBLIC_KEY_HEX: godPublicHex,
    ANCHOR_GOD_POLICY_PUBLIC_KEY_SHA256: godFingerprint,
    ANCHOR_GOD_POLICY_SIGNER_ID: "god-policy-root",
    ANCHOR_POLICY_ID: "cryptic-main-policy-v1",
  };
  return {
    env, godPrivateKey: godPair.privateKey,
    publicKey: await crypto.subtle.importKey(
      "raw", anchorPublicRaw, { name: "Ed25519" }, false, ["verify"]
    ),
  };
}
async function request(env, method, path, { headers = {}, body } = {}) {
  return worker.fetch(new Request("https://anchor.test" + path, {
    method, headers, body: body === undefined ? undefined : canonical(body),
  }), env);
}
function writeBody(network, sequence, hash, expectedSequence, expectedHash, nonce) {
  return {
    schema: "CRYPTIC-SEQUENCE-ANCHOR/1", network_id: network,
    sequence, policy_hash: hash, expected_sequence: expectedSequence,
    expected_policy_hash: expectedHash, issued_at: Math.floor(Date.now() / 1000),
    nonce: nonce || "ab".repeat(16),
  };
}
async function authorize(godPrivateKey, transition, nonce) {
  const body = {
    schema: "CRYPTIC-GOD-POLICY-TRANSITION/1",
    signer_id: "god-policy-root",
    capability: "cryptic.sequence_anchor.advance",
    policy_id: "cryptic-main-policy-v1",
    network_id: transition.network_id,
    expected_sequence: transition.expected_sequence,
    expected_policy_hash: transition.expected_policy_hash,
    sequence: transition.sequence,
    policy_hash: transition.policy_hash,
    issued_at: Math.floor(Date.now() / 1000),
    expires_at: Math.floor(Date.now() / 1000) + 120,
    nonce: nonce || crypto.randomUUID().replaceAll("-", "").slice(0, 32),
  };
  const payload = new TextEncoder().encode(canonical(body));
  const message = new Uint8Array(POLICY_DOMAIN.length + payload.length);
  message.set(POLICY_DOMAIN); message.set(payload, POLICY_DOMAIN.length);
  return { ...body, signature: b64(await crypto.subtle.sign("Ed25519", godPrivateKey, message)) };
}
async function verifyRecord(record, publicKey) {
  const { signature, ...unsigned } = record;
  const binary = atob(signature);
  const bytes = Uint8Array.from(binary, ch => ch.charCodeAt(0));
  const payload = new TextEncoder().encode(canonical(unsigned));
  const message = new Uint8Array(ANCHOR_DOMAIN.length + payload.length);
  message.set(ANCHOR_DOMAIN); message.set(payload, ANCHOR_DOMAIN.length);
  assert.equal(await crypto.subtle.verify("Ed25519", publicKey, bytes, message), true);
}

test("unauthenticated write is rejected before D1 mutation", async () => {
  const { env } = await setup();
  const body = writeBody("test-net", 1, "1".repeat(64), 0, ZERO);
  const response = await request(env, "PUT", "/v1/anchors/test-net", {
    headers: { "if-none-match": "*", "content-type": "application/json" }, body,
  });
  assert.equal(response.status, 401);
  assert.equal(env.ANCHOR_DB.rows.size, 0);
});

test("signed GOD transition authorizes initialization and advancement; stale CAS is rejected", async () => {
  const { env, publicKey, godPrivateKey } = await setup();
  const network = "test-net";
  const absent = await request(env, "GET", "/v1/anchors/test-net", {
    headers: { "x-anchor-nonce": "cd".repeat(16) },
  });
  assert.equal(absent.status, 404);

  const first = writeBody(network, 1, "1".repeat(64), 0, ZERO);
  first.authorization = await authorize(godPrivateKey, first, "01".repeat(16));
  const initialized = await request(env, "PUT", "/v1/anchors/test-net", {
    headers: { authorization: "Bearer " + TOKEN, "if-none-match": "*",
      "content-type": "application/json" }, body: first,
  });
  assert.equal(initialized.status, 200, JSON.stringify(await initialized.clone().json()));
  const initRecord = await initialized.json();
  assert.equal(initRecord.accepted, true);
  assert.equal(initRecord.nonce, first.nonce);
  await verifyRecord(initRecord, publicKey);

  const readNonce = "ef".repeat(16);
  const read = await request(env, "GET", "/v1/anchors/test-net", {
    headers: { "x-anchor-nonce": readNonce },
  });
  assert.equal(read.status, 200);
  const readRecord = await read.json();
  assert.equal(readRecord.nonce, readNonce);
  assert.equal(readRecord.sequence, 1);
  await verifyRecord(readRecord, publicKey);

  const stale = writeBody(network, 2, "2".repeat(64), 0, ZERO, "02".repeat(16));
  stale.authorization = await authorize(godPrivateKey, stale, "12".repeat(16));
  const rejected = await request(env, "PUT", "/v1/anchors/test-net", {
    headers: { authorization: "Bearer " + TOKEN, "if-none-match": "*",
      "content-type": "application/json" }, body: stale,
  });
  assert.equal(rejected.status, 412);
  assert.equal(env.ANCHOR_DB.rows.get(network).sequence, 1);

  const next = writeBody(network, 2, "2".repeat(64), 1, "1".repeat(64), "03".repeat(16));
  next.authorization = await authorize(godPrivateKey, next, "13".repeat(16));
  const advanced = await request(env, "PUT", "/v1/anchors/test-net", {
    headers: { authorization: "Bearer " + TOKEN,
      "if-match": '"1:' + "1".repeat(64) + '"',
      "content-type": "application/json" }, body: next,
  });
  assert.equal(advanced.status, 200);
  const nextRecord = await advanced.json();
  assert.equal(nextRecord.sequence, 2);
  await verifyRecord(nextRecord, publicKey);
});

test("rejects missing, forged, mismatched, wrong-policy and replayed GOD authorizations", async () => {
  const { env, godPrivateKey } = await setup();
  const headers = { authorization: "Bearer " + TOKEN, "if-none-match": "*",
    "content-type": "application/json" };
  const base = writeBody("test-net", 1, "1".repeat(64), 0, ZERO, "21".repeat(16));
  let response = await request(env, "PUT", "/v1/anchors/test-net", { headers, body: { ...base, authorization: null } });
  assert.equal(response.status, 403);

  const forged = { ...base, authorization: { ...(await authorize(godPrivateKey, base, "22".repeat(16))), signature: b64(new Uint8Array(64)) } };
  response = await request(env, "PUT", "/v1/anchors/test-net", { headers, body: forged });
  assert.equal(response.status, 403);

  const mismatched = { ...base, authorization: await authorize(godPrivateKey, { ...base, policy_hash: "2".repeat(64) }, "23".repeat(16)) };
  response = await request(env, "PUT", "/v1/anchors/test-net", { headers, body: mismatched });
  assert.equal(response.status, 403);

  const wrongPolicy = await authorize(godPrivateKey, base, "24".repeat(16));
  wrongPolicy.policy_id = "other-policy";
  const payload = new TextEncoder().encode(canonical(Object.fromEntries(Object.entries(wrongPolicy).filter(([k]) => k !== "signature"))));
  const message = new Uint8Array(POLICY_DOMAIN.length + payload.length);
  message.set(POLICY_DOMAIN); message.set(payload, POLICY_DOMAIN.length);
  wrongPolicy.signature = b64(await crypto.subtle.sign("Ed25519", godPrivateKey, message));
  response = await request(env, "PUT", "/v1/anchors/test-net", { headers, body: { ...base, authorization: wrongPolicy } });
  assert.equal(response.status, 403);

  const replayProof = await authorize(godPrivateKey, base, "24".repeat(16));
  env.ANCHOR_DB.nonces.add("god-policy-root:" + replayProof.nonce);
  response = await request(env, "PUT", "/v1/anchors/test-net", {
    headers, body: { ...base, authorization: replayProof },
  });
  assert.equal(response.status, 412);
  assert.equal(env.ANCHOR_DB.rows.size, 0);

  const valid = { ...base, authorization: await authorize(godPrivateKey, base, "25".repeat(16)) };
  response = await request(env, "PUT", "/v1/anchors/test-net", { headers, body: valid });
  assert.equal(response.status, 200, JSON.stringify(await response.clone().json()));
  const replay = { ...base, nonce: "26".repeat(16), authorization: valid.authorization };
  response = await request(env, "PUT", "/v1/anchors/test-net", { headers, body: replay });
  assert.equal(response.status, 412);
  assert.equal(env.ANCHOR_DB.rows.get("test-net").sequence, 1);
});

test("rejects malformed nonce, malformed request and wrong bearer token", async () => {
  const { env } = await setup();
  const badNonce = await request(env, "GET", "/v1/anchors/test-net", {
    headers: { "x-anchor-nonce": "not-a-nonce" },
  });
  assert.equal(badNonce.status, 400);
  const body = writeBody("test-net", 1, "1".repeat(64), 0, ZERO);
  const badAuth = await request(env, "PUT", "/v1/anchors/test-net", {
    headers: { authorization: "Bearer wrong-token", "if-none-match": "*",
      "content-type": "application/json" }, body,
  });
  assert.equal(badAuth.status, 401);
  const badSchema = await request(env, "PUT", "/v1/anchors/test-net", {
    headers: { authorization: "Bearer " + TOKEN, "if-none-match": "*",
      "content-type": "application/json" }, body: { ...body, extra: true },
  });
  assert.equal(badSchema.status, 400);
});
