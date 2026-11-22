const ANCHOR_SCHEMA = "CRYPTIC-SEQUENCE-ANCHOR/1";
const ANCHOR_DOMAIN = new TextEncoder().encode("CRYPTIC-SEQUENCE-ANCHOR/1\0");
const ZERO_HASH = "0".repeat(64);
const MAX_BODY_BYTES = 8192;
const HEX_256 = /^[0-9a-f]{64}$/;
const NONCE = /^[0-9a-f]{32}$/;
const POLICY_SCHEMA = "CRYPTIC-GOD-POLICY-TRANSITION/1";
const POLICY_DOMAIN = new TextEncoder().encode(POLICY_SCHEMA + "\0");
const POLICY_CAPABILITY = "cryptic.sequence_anchor.advance";
const MAX_POLICY_TTL_SECONDS = 300;

function decodeHex(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error("god_policy_public_key_invalid");
  }
  return Uint8Array.from(value.match(/../g), byte => parseInt(byte, 16));
}

async function verifyPolicyAuthorization(authorization, transition, networkId, env, now) {
  const required = ["schema", "signer_id", "capability", "policy_id", "network_id",
    "expected_sequence", "expected_policy_hash", "sequence", "policy_hash",
    "issued_at", "expires_at", "nonce", "signature"];
  if (!authorization || typeof authorization !== "object" || Array.isArray(authorization) ||
      Object.keys(authorization).sort().join("|") !== required.slice().sort().join("|")) {
    return { ok: false, reason: "policy_authorization_schema_invalid" };
  }
  if (!env.ANCHOR_GOD_POLICY_PUBLIC_KEY_HEX || !env.ANCHOR_GOD_POLICY_PUBLIC_KEY_SHA256 ||
      !env.ANCHOR_GOD_POLICY_SIGNER_ID || !env.ANCHOR_POLICY_ID) {
    return { ok: false, reason: "god_policy_trust_not_configured" };
  }
  if (!HEX_256.test(env.ANCHOR_GOD_POLICY_PUBLIC_KEY_HEX) ||
      !HEX_256.test(env.ANCHOR_GOD_POLICY_PUBLIC_KEY_SHA256)) {
    return { ok: false, reason: "god_policy_trust_configuration_invalid" };
  }
  const a = authorization;
  if (a.schema !== POLICY_SCHEMA || a.signer_id !== env.ANCHOR_GOD_POLICY_SIGNER_ID ||
      a.capability !== POLICY_CAPABILITY || a.policy_id !== env.ANCHOR_POLICY_ID ||
      a.network_id !== networkId || a.expected_sequence !== transition.expected_sequence ||
      a.expected_policy_hash !== transition.expected_policy_hash ||
      a.sequence !== transition.sequence || a.policy_hash !== transition.policy_hash ||
      !NONCE.test(a.nonce) || !Number.isSafeInteger(a.issued_at) ||
      !Number.isSafeInteger(a.expires_at) || a.expires_at <= a.issued_at ||
      a.expires_at - a.issued_at > MAX_POLICY_TTL_SECONDS ||
      a.issued_at > now + 30 || a.expires_at < now - 30) {
    return { ok: false, reason: "policy_authorization_binding_or_expiry_invalid" };
  }
  try {
    if (typeof a.signature !== "string" ||
        !/^[A-Za-z0-9+/]{86}==$/.test(a.signature)) {
      return { ok: false, reason: "policy_authorization_signature_invalid" };
    }
    const publicRaw = decodeHex(env.ANCHOR_GOD_POLICY_PUBLIC_KEY_HEX);
    const fingerprintBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", publicRaw));
    const fingerprint = Array.from(fingerprintBytes, byte => byte.toString(16).padStart(2, "0")).join("");
    if (!/^[0-9a-f]{64}$/.test(env.ANCHOR_GOD_POLICY_PUBLIC_KEY_SHA256) ||
        fingerprint !== env.ANCHOR_GOD_POLICY_PUBLIC_KEY_SHA256) {
      return { ok: false, reason: "god_policy_trust_fingerprint_pin_mismatch" };
    }
    let publicKey;
    try {
      publicKey = await crypto.subtle.importKey(
        "raw", publicRaw, { name: "Ed25519" }, false, ["verify"]
      );
    } catch {
      return { ok: false, reason: "god_policy_trust_configuration_invalid" };
    }
    const signature = decodeBase64(a.signature);
    if (signature.length !== 64) throw new Error("signature_length_invalid");
    const unsigned = Object.fromEntries(Object.entries(a).filter(([key]) => key !== "signature"));
    const payload = new TextEncoder().encode(canonical(unsigned));
    const message = new Uint8Array(POLICY_DOMAIN.length + payload.length);
    message.set(POLICY_DOMAIN);
    message.set(payload, POLICY_DOMAIN.length);
    const valid = await crypto.subtle.verify("Ed25519", publicKey, signature, message);
    return valid
      ? { ok: true, signerId: a.signer_id, nonce: a.nonce, expiresAt: a.expires_at }
      : { ok: false, reason: "policy_authorization_signature_invalid" };
  } catch {
    return { ok: false, reason: "policy_authorization_signature_invalid" };
  }
}


function canonical(value) {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value && typeof value === "object") {
    return "{" + Object.keys(value).sort().map(
      key => JSON.stringify(key) + ":" + canonical(value[key])
    ).join(",") + "}";
  }
  return JSON.stringify(value);
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store", "x-content-type-options": "nosniff", ...headers },
  });
}

function validNetworkId(value) {
  return typeof value === "string" && value.length > 0 &&
    new TextEncoder().encode(value).length <= 256 &&
    !/[\u0000-\u001f\u007f]/.test(value);
}

function validTimestamp(value, now) {
  return Number.isSafeInteger(value) && Math.abs(now - value) <= 30;
}

function decodeBase64(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error("key_encoding_invalid");
  }
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function signingKey(env) {
  if (!env.ANCHOR_SIGNING_KEY_PKCS8_B64 || !env.ANCHOR_SIGNER_ID) {
    throw new Error("anchor_signing_not_configured");
  }
  return crypto.subtle.importKey(
    "pkcs8", decodeBase64(env.ANCHOR_SIGNING_KEY_PKCS8_B64),
    { name: "Ed25519" }, false, ["sign"]
  );
}

async function signRecord(record, env) {
  const key = await signingKey(env);
  const payload = new TextEncoder().encode(canonical(record));
  const message = new Uint8Array(ANCHOR_DOMAIN.length + payload.length);
  message.set(ANCHOR_DOMAIN);
  message.set(payload, ANCHOR_DOMAIN.length);
  const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", key, message));
  let binary = "";
  for (const byte of signature) binary += String.fromCharCode(byte);
  return { ...record, signature: btoa(binary) };
}

async function authorized(request, env) {
  const supplied = request.headers.get("authorization") || "";
  const expected = env.ANCHOR_WRITE_TOKEN || "";
  if (expected.length < 32 || /\s/.test(expected) ||
      !supplied.startsWith("Bearer ")) return false;
  const candidate = supplied.slice(7);
  const encoder = new TextEncoder();
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(candidate)),
    crypto.subtle.digest("SHA-256", encoder.encode(expected)),
  ]);
  const left = new Uint8Array(a), right = new Uint8Array(b);
  let difference = 0;
  for (let i = 0; i < left.length; i++) difference |= left[i] ^ right[i];
  return difference === 0 && candidate.length === expected.length;
}

async function readAnchor(networkId, nonce, env) {
  const row = await env.ANCHOR_DB.prepare(
    "SELECT sequence, policy_hash FROM anchors WHERE network_id = ?"
  ).bind(networkId).first();
  if (!row) return new Response(null, { status: 404, headers: { "cache-control": "no-store" } });
  if (!Number.isSafeInteger(row.sequence) || row.sequence < 1 ||
      typeof row.policy_hash !== "string" || !HEX_256.test(row.policy_hash)) {
    throw new Error("anchor_storage_record_invalid");
  }
  const record = await signRecord({
    schema: ANCHOR_SCHEMA, signer_id: env.ANCHOR_SIGNER_ID,
    network_id: networkId, sequence: row.sequence,
    policy_hash: row.policy_hash, issued_at: Math.floor(Date.now() / 1000),
    nonce,
  }, env);
  return json(record);
}

async function readBoundedBody(request) {
  const length = request.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_BODY_BYTES)) {
    throw new Error("body_too_large");
  }
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) {
        await reader.cancel();
        throw new Error("body_too_large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.byteLength; }
  return output;
}

async function advanceAnchor(request, networkId, env) {
  if (!await authorized(request, env)) return json({ error: "unauthorized" }, 401);
  let raw;
  try { raw = await readBoundedBody(request); }
  catch { return json({ error: "body_too_large" }, 413); }
  let body, decoded;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    body = JSON.parse(decoded);
  } catch { return json({ error: "invalid_json" }, 400); }
  if (canonical(body) !== decoded) return json({ error: "noncanonical_json" }, 400);
  const fields = ["schema", "network_id", "sequence", "policy_hash",
    "expected_sequence", "expected_policy_hash", "issued_at", "nonce", "authorization"];
  if (!body || typeof body !== "object" || Array.isArray(body) ||
      Object.keys(body).sort().join("|") !== fields.slice().sort().join("|")) {
    return json({ error: "request_schema_invalid" }, 400);
  }
  const now = Math.floor(Date.now() / 1000);
  if (body.schema !== ANCHOR_SCHEMA || body.network_id !== networkId ||
      !Number.isSafeInteger(body.sequence) || body.sequence < 1 ||
      !Number.isSafeInteger(body.expected_sequence) || body.expected_sequence < 0 ||
      !HEX_256.test(body.policy_hash) || !HEX_256.test(body.expected_policy_hash) ||
      !validTimestamp(body.issued_at, now) || !NONCE.test(body.nonce)) {
    return json({ error: "request_fields_invalid" }, 400);
  }
  const authorization = await verifyPolicyAuthorization(body.authorization, body,
    networkId, env, now);
  if (!authorization.ok) {
    const trustUnavailable = authorization.reason.startsWith("god_policy_trust_");
    return json({ error: authorization.reason }, trustUnavailable ? 503 : 403);
  }

  const ifNoneMatch = request.headers.get("if-none-match");
  const ifMatch = request.headers.get("if-match");
  const condition = ifNoneMatch === "*" && ifMatch === null &&
    body.expected_sequence === 0 && body.expected_policy_hash === ZERO_HASH;
  const match = ifNoneMatch === null && ifMatch ===
    `"${body.expected_sequence}:${body.expected_policy_hash}"` &&
    body.expected_sequence > 0;
  if (!condition && !match) return json({ error: "precondition_required" }, 428);
  if (body.sequence <= body.expected_sequence) {
    return json({ error: "sequence_not_increasing" }, 409);
  }
  try {
    // Expired authorization receipts are safe to prune. A nonce is inserted
    // only when the exact expected anchor state still exists (or is absent for
    // initialization); duplicate signer/nonce pairs cannot be reused.
    await env.ANCHOR_DB.prepare(
      "DELETE FROM used_authorization_nonces WHERE expires_at < ?"
    ).bind(now - 30).run();
    const nonceResult = await env.ANCHOR_DB.prepare(`
      INSERT INTO used_authorization_nonces(signer_id, nonce, network_id, expires_at)
      SELECT ?, ?, ?, ?
      WHERE ((? = 0 AND ? = ? AND NOT EXISTS (
        SELECT 1 FROM anchors WHERE network_id = ?
      )) OR EXISTS (
        SELECT 1 FROM anchors
        WHERE network_id = ? AND sequence = ? AND policy_hash = ?
      ))
      ON CONFLICT(signer_id, nonce) DO NOTHING
    `).bind(
      authorization.signerId, authorization.nonce, networkId, authorization.expiresAt,
      body.expected_sequence, body.expected_policy_hash, ZERO_HASH, networkId,
      networkId, body.expected_sequence, body.expected_policy_hash
    ).run();
    if (!nonceResult?.success || nonceResult.meta?.changes !== 1) {
      return json({ error: "authorization_replayed_or_state_changed" }, 412);
    }

    // One conditional UPSERT remains the anchor linearization point. The
    // nonce receipt is consumed first in the same request; a failed CAS may
    // consume a proof, so clients must obtain a fresh GOD authorization.
    const result = await env.ANCHOR_DB.prepare(`
      INSERT INTO anchors(network_id, sequence, policy_hash, updated_at)
      SELECT ?, ?, ?, ?
      WHERE (? = 0 AND ? = ?) OR EXISTS (
        SELECT 1 FROM anchors
        WHERE network_id = ? AND sequence = ? AND policy_hash = ?
      )
      ON CONFLICT(network_id) DO UPDATE SET
        sequence = excluded.sequence,
        policy_hash = excluded.policy_hash,
        updated_at = excluded.updated_at
      WHERE anchors.sequence = ?
        AND anchors.policy_hash = ?
        AND excluded.sequence > anchors.sequence
    `).bind(
      networkId, body.sequence, body.policy_hash, now,
      body.expected_sequence, body.expected_policy_hash, ZERO_HASH,
      networkId, body.expected_sequence, body.expected_policy_hash,
      body.expected_sequence, body.expected_policy_hash
    ).run();
    if (!result?.success || result.meta?.changes !== 1) {
      return json({ error: "compare_and_swap_conflict" }, 412);
    }
    return json(await signRecord({
      schema: ANCHOR_SCHEMA, signer_id: env.ANCHOR_SIGNER_ID,
      network_id: networkId, sequence: body.sequence,
      policy_hash: body.policy_hash, accepted: true, issued_at: now,
      nonce: body.nonce,
    }, env));
  } catch {
    return json({ error: "anchor_storage_unavailable" }, 503);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return json({ service: "cryptic-sequence-anchor", schema: ANCHOR_SCHEMA,
        configured: Boolean(env.ANCHOR_DB && env.ANCHOR_SIGNER_ID &&
          env.ANCHOR_SIGNING_KEY_PKCS8_B64 && env.ANCHOR_WRITE_TOKEN &&
          env.ANCHOR_GOD_POLICY_PUBLIC_KEY_HEX && env.ANCHOR_GOD_POLICY_PUBLIC_KEY_SHA256 &&
          env.ANCHOR_GOD_POLICY_SIGNER_ID && env.ANCHOR_POLICY_ID) });
    }
    const match = url.pathname.match(/^\/v1\/anchors\/([^/]+)$/);
    if (!match) return json({ error: "not_found" }, 404);
    let networkId;
    try { networkId = decodeURIComponent(match[1]); }
    catch { return json({ error: "network_id_invalid" }, 400); }
    if (!validNetworkId(networkId)) return json({ error: "network_id_invalid" }, 400);
    if (!env.ANCHOR_DB) return json({ error: "anchor_storage_not_configured" }, 503);
    if (request.method === "GET" || request.method === "PUT") {
      try { await signingKey(env); }
      catch { return json({ error: "anchor_signing_not_configured" }, 503); }
      if (request.method === "GET") {
        const nonce = request.headers.get("x-anchor-nonce") || "";
        if (!NONCE.test(nonce)) return json({ error: "nonce_required" }, 400);
        try { return await readAnchor(networkId, nonce, env); }
        catch { return json({ error: "anchor_signing_or_storage_unavailable" }, 503); }
      }
      try { return await advanceAnchor(request, networkId, env); }
      catch { return json({ error: "anchor_service_unavailable" }, 503); }
    }
    return json({ error: "method_not_allowed" }, 405, { allow: "GET, PUT" });
  },
};
