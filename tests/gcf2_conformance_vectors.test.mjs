import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash, webcrypto } from "node:crypto";

const vector = JSON.parse(readFileSync(
  new URL("./vectors/gcf2_known_answers.json", import.meta.url), "utf8"
));
const canonical = value => {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value && typeof value === "object") {
    return "{" + Object.keys(value).sort().map(
      key => JSON.stringify(key) + ":" + canonical(value[key])
    ).join(",") + "}";
  }
  return JSON.stringify(value);
};
const sha256 = value => createHash("sha256").update(value).digest("hex");
const bytes = value => new TextEncoder().encode(value);
const concat = (...parts) => {
  const length = parts.reduce((sum, item) => sum + item.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
};
const hexBytes = value => Uint8Array.from(value.match(/../g), part => parseInt(part, 16));
const privatePrefix = hexBytes("302e020100300506032b657004220420");
async function privateKey(seedByte) {
  const seed = new Uint8Array(32).fill(parseInt(seedByte, 16));
  return webcrypto.subtle.importKey(
    "pkcs8", concat(privatePrefix, seed), { name: "Ed25519" }, false, ["sign"]
  );
}
async function sign(seedByte, domain, body) {
  const key = await privateKey(seedByte);
  return Buffer.from(await webcrypto.subtle.sign(
    "Ed25519", key, concat(bytes(domain), bytes(canonical(body)))
  )).toString("base64");
}
async function verify(publicHex, signature, domain, body) {
  const key = await webcrypto.subtle.importKey(
    "raw", hexBytes(publicHex), { name: "Ed25519" }, false, ["verify"]
  );
  return webcrypto.subtle.verify(
    "Ed25519", key, Buffer.from(signature, "base64"),
    concat(bytes(domain), bytes(canonical(body)))
  );
}

test("JavaScript matches Python GCF/2 known-answer vector", async () => {
  const validators = Object.keys(vector.validator_public_keys).sort().map(id => ({
    validator_id: id, public_key_hex: vector.validator_public_keys[id], weight: 1,
  }));
  const validatorSetHash = sha256(canonical({
    network_id: vector.network_id, epoch: vector.epoch, validators,
  }));
  const proposalBody = {
    schema: "GCF/1", network_id: vector.network_id, epoch: vector.epoch,
    height: vector.height, round: vector.round,
    parent_hash: vector.parent_hash, payload_hash: vector.payload_hash,
    proof_hash: vector.proof_hash,
    justice_commitment: {
      justice_profile: "GAIA-JUSTICE/1",
      policy_hash: vector.justice_policy_hash,
    },
    issued_at: vector.issued_at, expires_at: vector.expires_at,
    proposer_id: "v0", proposer_public_key: vector.validator_public_keys.v0,
    nonce: vector.nonce, anchor_sequence: vector.anchor_sequence,
  };
  const proposal = {
    ...proposalBody,
    signature: await sign("01", "GCF/1|PROPOSAL|ED25519\0", proposalBody),
  };
  const candidateDigest = sha256(canonical(proposal));
  async function makeVotes(phase, polcDigest = null) {
    const votes = [];
    for (const id of ["v0", "v1", "v2"]) {
      const body = {
        schema: "GCF/2", network_id: vector.network_id, epoch: vector.epoch,
        height: vector.height, round: vector.round,
        parent_hash: vector.parent_hash, vote_type: phase,
        vote_kind: "CANDIDATE", candidate_digest: candidateDigest,
        validator_id: id, approve: true, polc_digest: polcDigest,
        issued_at: vector.vote_issued_at, expires_at: vector.vote_expires_at,
      };
      votes.push({
        ...body,
        signature: await sign(
          vector.validator_seed_bytes[Number(id.slice(1))],
          "GCF/2|VOTE|ED25519\0", body
        ),
      });
    }
    return votes;
  }
  const prevotes = await makeVotes("PREVOTE");
  const polcBody = {
    schema: "GCF/2", network_id: vector.network_id, epoch: vector.epoch,
    height: vector.height, round: vector.round, parent_hash: vector.parent_hash,
    candidate_digest: candidateDigest, validator_set_hash: validatorSetHash,
    prevotes,
  };
  const polcDigest = sha256(concat(
    bytes("GCF/2|POLC\0"), bytes(canonical(polcBody))
  ));
  const polc = { ...polcBody, polc_digest: polcDigest };
  const precommits = await makeVotes("PRECOMMIT", polcDigest);
  const certificateBody = {
    schema: "GCF/2", network_id: vector.network_id, epoch: vector.epoch,
    height: vector.height, round: vector.round, parent_hash: vector.parent_hash,
    candidate_digest: candidateDigest, validator_set_hash: validatorSetHash,
    proposal, finalized_at: vector.finalized_at, polc, precommits,
  };
  const certificateDigest = sha256(concat(
    bytes("GCF/2|FINALITY-CERTIFICATE\0"), bytes(canonical(certificateBody))
  ));

  assert.equal(validatorSetHash, vector.expected.validator_set_hash);
  assert.equal(candidateDigest, vector.expected.candidate_digest);
  assert.equal(polcDigest, vector.expected.polc_digest);
  assert.equal(certificateDigest, vector.expected.certificate_digest);
  assert.equal(await verify(
    vector.validator_public_keys.v0, proposal.signature,
    "GCF/1|PROPOSAL|ED25519\0", proposalBody
  ), true);
  assert.equal(await verify(
    vector.validator_public_keys.v2, prevotes[2].signature,
    "GCF/2|VOTE|ED25519\0",
    Object.fromEntries(Object.entries(prevotes[2]).filter(([key]) => key !== "signature"))
  ), true);
});
