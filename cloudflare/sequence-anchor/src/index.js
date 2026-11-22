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



const GCF_SCHEMA = "GCF/1";
const GCF_PROPOSAL_DOMAIN = new TextEncoder().encode("GCF/1|PROPOSAL|ED25519\0");
const GCF_VOTE_DOMAIN = new TextEncoder().encode("GCF/1|VOTE|ED25519\0");
const GCF_CERT_DOMAIN = new TextEncoder().encode("GCF/1|FINALITY-CERTIFICATE\0");

async function sha256Hex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, b => b.toString(16).padStart(2, "0")).join("");
}

function strictHex(value, length = 64) {
  return typeof value === "string" && value.length === length &&
    new RegExp("^[0-9a-f]{" + length + "}$").test(value);
}

function strictBase64(value) {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error("certificate_signature_encoding_invalid");
  }
  return decodeBase64(value);
}

async function verifyGcfSignature(publicHex, signatureText, domain, body) {
  if (!strictHex(publicHex)) return false;
  const publicKey = await crypto.subtle.importKey(
    "raw", Uint8Array.from(publicHex.match(/../g), x => parseInt(x, 16)),
    { name: "Ed25519" }, false, ["verify"]
  );
  const signature = strictBase64(signatureText);
  if (signature.length !== 64) return false;
  const payload = new TextEncoder().encode(canonical(body));
  const message = new Uint8Array(domain.length + payload.length);
  message.set(domain); message.set(payload, domain.length);
  return crypto.subtle.verify("Ed25519", publicKey, signature, message);
}

async function loadPinnedValidatorSet(env, networkId) {
  const required = ["ANCHOR_VALIDATOR_SET_JSON", "ANCHOR_VALIDATOR_SET_SHA256",
    "ANCHOR_VALIDATOR_NETWORK_ID", "ANCHOR_VALIDATOR_EPOCH"];
  if (required.some(key => !env[key])) {
    return { ok: false, unavailable: true, reason: "validator_set_trust_not_configured" };
  }
  if (!strictHex(env.ANCHOR_VALIDATOR_SET_SHA256) ||
      env.ANCHOR_VALIDATOR_NETWORK_ID !== networkId ||
      !/^[1-9][0-9]*$/.test(String(env.ANCHOR_VALIDATOR_EPOCH))) {
    return { ok: false, unavailable: true, reason: "validator_set_trust_configuration_invalid" };
  }
  let configured;
  try { configured = JSON.parse(env.ANCHOR_VALIDATOR_SET_JSON); }
  catch { return { ok: false, unavailable: true, reason: "validator_set_configuration_invalid" }; }
  if (!configured || typeof configured !== "object" || Array.isArray(configured) ||
      Object.keys(configured).sort().join("|") !== ["network_id", "epoch", "validators"].sort().join("|") ||
      configured.network_id !== networkId ||
      configured.epoch !== Number(env.ANCHOR_VALIDATOR_EPOCH) ||
      !Array.isArray(configured.validators) || configured.validators.length < 1 ||
      configured.validators.length > 256) {
    return { ok: false, unavailable: true, reason: "validator_set_configuration_invalid" };
  }
  const validators = new Map();
  let totalWeight = 0;
  let previousId = null;
  const normalized = [];
  for (const item of configured.validators) {
    if (!item || typeof item !== "object" || Array.isArray(item) ||
        Object.keys(item).sort().join("|") !== ["validator_id", "public_key_hex", "weight"].sort().join("|") ||
        typeof item.validator_id !== "string" || !item.validator_id ||
        !strictHex(item.public_key_hex) ||
        !Number.isSafeInteger(item.weight) || item.weight < 1 ||
        validators.has(item.validator_id)) {
      return { ok: false, unavailable: true, reason: "validator_set_configuration_invalid" };
    }
    if (previousId !== null && item.validator_id <= previousId) {
      return { ok: false, unavailable: true, reason: "validator_set_order_invalid" };
    }
    previousId = item.validator_id;
    validators.set(item.validator_id, item);
    totalWeight += item.weight;
    if (!Number.isSafeInteger(totalWeight)) {
      return { ok: false, unavailable: true, reason: "validator_set_weight_invalid" };
    }
    normalized.push(item);
  }
  const setBody = { network_id: networkId, epoch: configured.epoch, validators: normalized };
  const setHash = await sha256Hex(new TextEncoder().encode(canonical(setBody)));
  if (setHash !== env.ANCHOR_VALIDATOR_SET_SHA256) {
    return { ok: false, unavailable: true, reason: "validator_set_hash_pin_mismatch" };
  }
  return { ok: true, validators, totalWeight, quorumWeight: Math.floor((2 * totalWeight) / 3) + 1,
    setHash, epoch: configured.epoch };
}

async function verifyGcfProposal(proposal, certificate, vset) {
  const required = ["schema", "network_id", "epoch", "height", "round", "parent_hash",
    "payload_hash", "proof_hash", "justice_commitment", "issued_at", "expires_at",
    "proposer_id", "proposer_public_key", "nonce", "signature"];
  if (!proposal || typeof proposal !== "object" || Array.isArray(proposal) ||
      Object.keys(proposal).sort().join("|") !== required.slice().sort().join("|") ||
      proposal.schema !== GCF_SCHEMA || proposal.network_id !== certificate.network_id ||
      proposal.epoch !== certificate.epoch || !Number.isSafeInteger(proposal.height) || proposal.height < 1 ||
      !Number.isSafeInteger(proposal.round) || proposal.round < 0 ||
      !strictHex(proposal.parent_hash) || !strictHex(proposal.payload_hash) ||
      !strictHex(proposal.proof_hash) ||
      !Number.isSafeInteger(proposal.issued_at) || !Number.isSafeInteger(proposal.expires_at) ||
      proposal.expires_at <= proposal.issued_at ||
      proposal.expires_at - proposal.issued_at > 3600 ||
      typeof proposal.proposer_id !== "string" || !proposal.proposer_id ||
      typeof proposal.nonce !== "string" || proposal.nonce.length < 16 || proposal.nonce.length > 128 ||
      !proposal.justice_commitment || typeof proposal.justice_commitment !== "object" ||
      Array.isArray(proposal.justice_commitment)) {
    return { ok: false, reason: "gcf_proposal_invalid" };
  }
  const proposer = vset.validators.get(proposal.proposer_id);
  if (!proposer || proposer.public_key_hex !== proposal.proposer_public_key) {
    return { ok: false, reason: "gcf_proposer_not_in_pinned_validator_set" };
  }
  const unsigned = Object.fromEntries(Object.entries(proposal).filter(([key]) => key !== "signature"));
  if (!await verifyGcfSignature(proposer.public_key_hex, proposal.signature, GCF_PROPOSAL_DOMAIN, unsigned)) {
    return { ok: false, reason: "gcf_proposal_signature_invalid" };
  }
  const digest = await sha256Hex(new TextEncoder().encode(canonical(proposal)));
  if (digest !== certificate.candidate_digest) return { ok: false, reason: "gcf_candidate_digest_mismatch" };
  return { ok: true, digest };
}

async function verifyGcfVoteSet(votes, kind, proposal, digest, vset, polcDigest = null) {
  if (!Array.isArray(votes) || votes.length > vset.validators.size) {
    return { ok: false, reason: kind.toLowerCase() + "_vote_set_invalid" };
  }
  let weight = 0, previousId = null;
  const seen = new Set();
  const required = ["schema", "network_id", "epoch", "height", "round", "candidate_digest",
    "validator_id", "vote_type", "approve", "polc_digest", "issued_at", "signature"];
  for (const vote of votes) {
    if (!vote || typeof vote !== "object" || Array.isArray(vote) ||
        Object.keys(vote).sort().join("|") !== required.slice().sort().join("|") ||
        vote.schema !== GCF_SCHEMA || vote.network_id !== proposal.network_id ||
        vote.epoch !== proposal.epoch || vote.height !== proposal.height ||
        vote.round !== proposal.round || vote.candidate_digest !== digest ||
        vote.vote_type !== kind || vote.approve !== true ||
        !Number.isSafeInteger(vote.issued_at) ||
        vote.issued_at < proposal.issued_at || vote.issued_at > proposal.expires_at ||
        (kind === "PREVOTE" && vote.polc_digest !== null) ||
        (kind === "PRECOMMIT" && vote.polc_digest !== polcDigest)) {
      return { ok: false, reason: kind.toLowerCase() + "_vote_fields_invalid" };
    }
    if (typeof vote.validator_id !== "string" || seen.has(vote.validator_id) ||
        (previousId !== null && vote.validator_id <= previousId)) {
      return { ok: false, reason: kind.toLowerCase() + "_duplicate_or_unsorted_signer" };
    }
    const validator = vset.validators.get(vote.validator_id);
    if (!validator) return { ok: false, reason: "gcf_vote_unknown_validator" };
    const unsigned = Object.fromEntries(Object.entries(vote).filter(([key]) => key !== "signature"));
    if (!await verifyGcfSignature(validator.public_key_hex, vote.signature, GCF_VOTE_DOMAIN, unsigned)) {
      return { ok: false, reason: kind.toLowerCase() + "_vote_signature_invalid" };
    }
    seen.add(vote.validator_id);
    previousId = vote.validator_id;
    weight += validator.weight;
  }
  return { ok: true, weight, reached: weight >= vset.quorumWeight };
}

async function verifyFinalityCertificate(certificate, transition, networkId, env) {
  const vsetResult = await loadPinnedValidatorSet(env, networkId);
  if (!vsetResult.ok) return vsetResult;
  const vset = vsetResult;
  const required = ["schema", "network_id", "epoch", "height", "round", "candidate_digest",
    "proposal", "validator_set", "polc", "precommits", "total_voting_weight", "precommit_weight"];
  if (!certificate || typeof certificate !== "object" || Array.isArray(certificate) ||
      Object.keys(certificate).sort().join("|") !== required.slice().sort().join("|") ||
      certificate.schema !== GCF_SCHEMA || certificate.network_id !== networkId ||
      certificate.epoch !== vset.epoch || certificate.height !== transition.sequence ||
      certificate.proposal?.height !== transition.sequence ||
      certificate.round !== certificate.proposal?.round ||
      certificate.total_voting_weight !== vset.totalWeight ||
      certificate.validator_set?.network_id !== networkId ||
      certificate.validator_set?.epoch !== vset.epoch ||
      certificate.validator_set?.validator_set_hash !== vset.setHash ||
      !Array.isArray(certificate.validator_set?.validators) ||
      canonical(certificate.validator_set.validators) !== canonical(
        Array.from(vset.validators.values()).map(v => ({
          validator_id: v.validator_id, public_key_hex: v.public_key_hex, weight: v.weight
        }))
      )) {
    return { ok: false, reason: "gcf_certificate_or_validator_set_binding_invalid" };
  }
  const proposalResult = await verifyGcfProposal(certificate.proposal, certificate, vset);
  if (!proposalResult.ok) return proposalResult;
  if (certificate.proposal.parent_hash !== transition.expected_policy_hash ||
      certificate.proposal.payload_hash !== transition.policy_hash) {
    return { ok: false, reason: "gcf_anchor_transition_binding_invalid" };
  }
  const prevotes = certificate.polc?.prevotes;
  const prevoteResult = await verifyGcfVoteSet(prevotes, "PREVOTE",
    certificate.proposal, proposalResult.digest, vset);
  if (!prevoteResult.ok || !prevoteResult.reached) {
    return { ok: false, reason: prevoteResult.reason || "gcf_prevote_quorum_missing" };
  }
  const polcBody = { schema: GCF_SCHEMA, candidate_digest: proposalResult.digest,
    validator_set_hash: vset.setHash, prevotes };
  const polcDigest = await sha256Hex(new Uint8Array([
    ...GCF_CERT_DOMAIN, ...new TextEncoder().encode(canonical(polcBody))
  ]));
  if (certificate.polc?.digest !== polcDigest) return { ok: false, reason: "gcf_polc_digest_mismatch" };
  const precommitResult = await verifyGcfVoteSet(certificate.precommits, "PRECOMMIT",
    certificate.proposal, proposalResult.digest, vset, polcDigest);
  if (!precommitResult.ok || !precommitResult.reached) {
    return { ok: false, reason: precommitResult.reason || "gcf_precommit_quorum_missing" };
  }
  if (certificate.precommit_weight !== precommitResult.weight) {
    return { ok: false, reason: "gcf_precommit_weight_mismatch" };
  }
  const certificateDigest = await sha256Hex(new Uint8Array([
    ...GCF_CERT_DOMAIN, ...new TextEncoder().encode(canonical(certificate))
  ]));
  return { ok: true, certificateDigest, signerId: "validator-set:" + vset.setHash,
    nonce: certificateDigest.slice(0, 32), expiresAt: Math.floor(Date.now() / 1000) + 31536000 };
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
    "expected_sequence", "expected_policy_hash", "issued_at", "nonce", "certificate"];
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
  const authorization = await verifyFinalityCertificate(body.certificate, body,
    networkId, env);
  if (!authorization.ok) {
    return json({ error: authorization.reason }, authorization.unavailable ? 503 : 403);
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
          env.ANCHOR_VALIDATOR_SET_JSON && env.ANCHOR_VALIDATOR_SET_SHA256 &&
          env.ANCHOR_VALIDATOR_NETWORK_ID && env.ANCHOR_VALIDATOR_EPOCH) });
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
