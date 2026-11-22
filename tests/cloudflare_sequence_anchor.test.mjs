import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
globalThis.crypto ||= webcrypto;

import worker from "../cloudflare/sequence-anchor/src/index.js";

const ZERO = "0".repeat(64);
const DOMAIN = new TextEncoder().encode("CRYPTIC-SEQUENCE-ANCHOR/1\0");
const GOD_DOMAIN = new TextEncoder().encode("CRYPTIC-GOD-ANCHOR-AUTH/1\0");
const GOD_SCHEMA = "CRYPTIC-GOD-ANCHOR-AUTH/1";
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
  constructor() { this.rows = new Map(); }
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
        const [network, sequence, hash, updated, expectedSequence,
          expectedHash, zeroHash, guardNetwork, guardSequence, guardHash,
          whereSequence, whereHash] = this.values;
        let row = db.rows.get(network);
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
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
  const publicRaw = await crypto.subtle.exportKey("raw", pair.publicKey);
  const godPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const godPublicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", godPair.publicKey));
  const godFingerprint = new Uint8Array(await crypto.subtle.digest("SHA-256", godPublicRaw));
  const godFingerprintHex = Array.from(godFingerprint, b => b.toString(16).padStart(2, "0")).join("");
  const godPublicHex = Array.from(godPublicRaw, b => b.toString(16).padStart(2, "0")).join("");
  const env = {
    ANCHOR_DB: new MemoryD1(),
    ANCHOR_SIGNER_ID: "anchor-test-root",
    ANCHOR_SIGNING_KEY_PKCS8_B64: b64(pkcs8),
    ANCHOR_WRITE_TOKEN: TOKEN,
    GOD_ANCHOR_AUTH_SIGNER_ID: "god-policy-test-root",
    GOD_ANCHOR_AUTH_PUBLIC_KEY_HEX: godPublicHex,
    GOD_ANCHOR_AUTH_KEY_FINGERPRINT: godFingerprintHex,
    __TEST_GOD_PRIVATE_KEY: godPair.privateKey,
  };
  return { env, publicKey: await crypto.subtle.importKey(
    "raw", publicRaw, { name: "Ed25519" }, false, ["verify"]
  ) };
}
async function request(env, method, path, { headers = {}, body, signGod = true } = {}) {
  let wireBody = body;
  if (method === "PUT" && signGod && body && !Object.prototype.hasOwnProperty.call(body, "authorization")) {
    const unsigned = {
      schema: GOD_SCHEMA, signer_id: env.GOD_ANCHOR_AUTH_SIGNER_ID,
      network_id: body.network_id, sequence: body.sequence, policy_hash: body.policy_hash,
      expected_sequence: body.expected_sequence,
      expected_policy_hash: body.expected_policy_hash, issued_at: body.issued_at,
      nonce: body.nonce,
    };
    const payload = new TextEncoder().encode(canonical(unsigned));
    const message = new Uint8Array(GOD_DOMAIN.length + payload.length);
    message.set(GOD_DOMAIN); message.set(payload, GOD_DOMAIN.length);
    const signature = await crypto.subtle.sign("Ed25519", env.__TEST_GOD_PRIVATE_KEY, message);
    wireBody = { ...body, authorization: { ...unsigned, signature: b64(signature) } };
  }
  return worker.fetch(new Request("https://anchor.test" + path, {
    method, headers, body: wireBody === undefined ? undefined : canonical(wireBody),
  }), env);
}
function writeBody(network, sequence, hash, expectedSequence, expectedHash) {
  return {
    schema: "CRYPTIC-SEQUENCE-ANCHOR/1", network_id: network,
    sequence, policy_hash: hash, expected_sequence: expectedSequence,
    expected_policy_hash: expectedHash, issued_at: Math.floor(Date.now() / 1000),
    nonce: "ab".repeat(16),
  };
}
async function verifyRecord(record, publicKey) {
  const { signature, ...unsigned } = record;
  const binary = atob(signature);
  const bytes = Uint8Array.from(binary, ch => ch.charCodeAt(0));
  const payload = new TextEncoder().encode(canonical(unsigned));
  const message = new Uint8Array(DOMAIN.length + payload.length);
  message.set(DOMAIN); message.set(payload, DOMAIN.length);
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

test("valid bearer without GOD authorization is rejected", async () => {
  const { env } = await setup();
  const body = writeBody("test-net", 1, "1".repeat(64), 0, ZERO);
  const response = await request(env, "PUT", "/v1/anchors/test-net", {
    headers: { authorization: "Bearer " + TOKEN, "if-none-match": "*",
      "content-type": "application/json" }, body, signGod: false,
  });
  assert.equal(response.status, 403);
  assert.equal(env.ANCHOR_DB.rows.size, 0);
});

test("GOD authorization trust-root configuration is mandatory", async () => {
  const { env } = await setup();
  delete env.GOD_ANCHOR_AUTH_KEY_FINGERPRINT;
  const body = writeBody("test-net", 1, "1".repeat(64), 0, ZERO);
  const response = await request(env, "PUT", "/v1/anchors/test-net", {
    headers: { authorization: "Bearer " + TOKEN, "if-none-match": "*",
      "content-type": "application/json" }, body,
  });
  assert.equal(response.status, 503);
  assert.equal(env.ANCHOR_DB.rows.size, 0);
});

test("signed read, initialization, monotonic update and stale CAS rejection", async () => {
  const { env, publicKey } = await setup();
  const network = "test-net";
  const absent = await request(env, "GET", "/v1/anchors/test-net", {
    headers: { "x-anchor-nonce": "cd".repeat(16) },
  });
  assert.equal(absent.status, 404);

  const first = writeBody(network, 1, "1".repeat(64), 0, ZERO);
  const initialized = await request(env, "PUT", "/v1/anchors/test-net", {
    headers: { authorization: "Bearer " + TOKEN, "if-none-match": "*",
      "content-type": "application/json" }, body: first,
  });
  assert.equal(initialized.status, 200);
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

  const stale = writeBody(network, 2, "2".repeat(64), 0, ZERO);
  const rejected = await request(env, "PUT", "/v1/anchors/test-net", {
    headers: { authorization: "Bearer " + TOKEN, "if-none-match": "*",
      "content-type": "application/json" }, body: stale,
  });
  assert.equal(rejected.status, 412);
  assert.equal(env.ANCHOR_DB.rows.get(network).sequence, 1);

  const next = writeBody(network, 2, "2".repeat(64), 1, "1".repeat(64));
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
