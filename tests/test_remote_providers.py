import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import unquote

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.governance.remote_providers import (
    ANCHOR_DOMAIN, ANCHOR_SCHEMA, DECISION_SCHEMA, RESPONSE_DOMAIN,
    HTTPSSequenceAnchor, HTTPSJusticeProviders, RemoteProviderError,
    SignedHTTPSDecisionClient, load_independently_pinned_root,
    HTTPSHSMEd25519Signer, GODHTTPSGate, make_proposal_with_signer,
    make_vote_with_signer, _canonical,
)


def keypair():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private, public


class RemoteProviderTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_800_000_000
        self.private, self.public = keypair()

    def signed(self, private, domain, body):
        return base64.b64encode(private.sign(domain + _canonical(body))).decode("ascii")

    def test_decision_client_binds_signed_response_to_exact_request(self):
        def transport(method, url, headers, raw, timeout):
            request = json.loads(raw)
            request_hash = hashlib.sha256(
                b"CRYPTIC-REMOTE-REQUEST/1\x00" + _canonical(request)
            ).hexdigest()
            body = {
                "schema": DECISION_SCHEMA, "signer_id": "policy-root",
                "request_hash": request_hash, "decision": True,
                "issued_at": self.now - 1, "expires_at": self.now + 30,
                "nonce": request["request_id"],
            }
            return 200, {}, _canonical({
                **body, "signature": self.signed(
                    self.private, RESPONSE_DOMAIN, body
                )
            })

        client = SignedHTTPSDecisionClient(
            "https://policy.example/v1/check", signer_id="policy-root",
            trusted_public_key=self.public, clock=lambda: self.now,
            transport=transport,
        )
        self.assertTrue(client.verify_decision("test", {"height": 7}))

    def test_decision_client_rejects_unbound_or_unsigned_response(self):
        def transport(method, url, headers, raw, timeout):
            body = {
                "schema": DECISION_SCHEMA, "signer_id": "policy-root",
                "request_hash": "0" * 64, "decision": True,
                "issued_at": self.now, "expires_at": self.now + 30,
                "nonce": "0" * 32,
            }
            return 200, {}, _canonical({
                **body, "signature": self.signed(
                    self.private, RESPONSE_DOMAIN, body
                )
            })
        client = SignedHTTPSDecisionClient(
            "https://policy.example/check", signer_id="policy-root",
            trusted_public_key=self.public, clock=lambda: self.now,
            transport=transport,
        )
        with self.assertRaisesRegex(RemoteProviderError, "request_binding"):
            client.verify_decision("test", {})

    def test_non_https_endpoints_are_rejected(self):
        with self.assertRaisesRegex(RemoteProviderError, "https_endpoint_required"):
            SignedHTTPSDecisionClient(
                "http://policy.example/check", signer_id="policy-root",
                trusted_public_key=self.public,
            )

    def test_justice_requires_independent_policy_and_evidence_signers(self):
        other_private, other_public = keypair()
        policy = SignedHTTPSDecisionClient(
            "https://policy.example/check", signer_id="policy",
            trusted_public_key=self.public, clock=lambda: self.now,
            transport=lambda *_: (500, {}, b""),
        )
        evidence = SignedHTTPSDecisionClient(
            "https://evidence.example/check", signer_id="evidence",
            trusted_public_key=other_public, clock=lambda: self.now,
            transport=lambda *_: (500, {}, b""),
        )
        providers = HTTPSJusticeProviders(policy=policy, evidence=evidence)
        self.assertIsNotNone(providers.verify_policy)
        self.assertIsNotNone(providers.verify_evidence)
        with self.assertRaisesRegex(RemoteProviderError, "must_be_independent"):
            HTTPSJusticeProviders(policy=policy, evidence=policy)

    def test_anchor_initialization_and_monotonic_cas(self):
        state = {}
        def transport(method, url, headers, raw, timeout):
            network = unquote(url.rsplit("/", 1)[1])
            current = state.get(network)
            if method == "GET":
                if current is None:
                    return 404, {}, b""
                seq, digest = current
                body = {
                    "schema": ANCHOR_SCHEMA, "signer_id": "anchor-root",
                    "network_id": network, "sequence": seq,
                    "policy_hash": digest, "issued_at": self.now,
                    "nonce": headers["X-Anchor-Nonce"],
                }
                return 200, {}, _canonical({
                    **body, "signature": self.signed(
                        self.private, ANCHOR_DOMAIN, body
                    )
                })
            self.assertEqual(headers.get("Authorization"), "Bearer " + "T" * 40)
            request = json.loads(raw)
            if current is None:
                if headers.get("If-None-Match") != "*":
                    return 412, {}, b""
                expected = (0, "0" * 64)
            else:
                expected = current
                if headers.get("If-Match") != f'"{current[0]}:{current[1]}"':
                    return 412, {}, b""
            if (request["expected_sequence"], request["expected_policy_hash"]) != expected:
                return 412, {}, b""
            state[network] = (request["sequence"], request["policy_hash"])
            body = {
                "schema": ANCHOR_SCHEMA, "signer_id": "anchor-root",
                "network_id": network, "sequence": request["sequence"],
                "policy_hash": request["policy_hash"], "issued_at": self.now,
                "nonce": request["nonce"], "accepted": True,
            }
            return 200, {}, _canonical({
                **body, "signature": self.signed(
                    self.private, ANCHOR_DOMAIN, body
                )
            })

        anchor = HTTPSSequenceAnchor(
            "https://anchor.example", signer_id="anchor-root",
            trusted_public_key=self.public, write_token="T" * 40,
            clock=lambda: self.now, transport=transport,
        )
        self.assertIsNone(anchor.read_sequence("test-net"))
        digest1 = "1" * 64
        digest2 = "2" * 64
        self.assertTrue(anchor.advance_sequence("test-net", 1, digest1))
        self.assertEqual(anchor.read_sequence("test-net"), (1, digest1))
        self.assertFalse(anchor.advance_sequence("test-net", 1, digest1))
        self.assertTrue(anchor.advance_sequence("test-net", 2, digest2))
        self.assertEqual(anchor.read_sequence("test-net"), (2, digest2))

    def test_anchor_write_requires_authentication(self):
        anchor = HTTPSSequenceAnchor(
            "https://anchor.example", signer_id="anchor-root",
            trusted_public_key=self.public, clock=lambda: self.now,
            transport=lambda *_: self.fail("transport must not be called"),
        )
        with self.assertRaisesRegex(RemoteProviderError, "write_authentication_required"):
            anchor.advance_sequence("test", 1, "1" * 64)

    def test_anchor_rejects_cas_conflict(self):
        def transport(method, url, headers, raw, timeout):
            if method == "GET":
                body = {
                    "schema": ANCHOR_SCHEMA, "signer_id": "anchor-root",
                    "network_id": "test", "sequence": 5,
                    "policy_hash": "5" * 64, "issued_at": self.now,
                    "nonce": headers["X-Anchor-Nonce"],
                }
                return 200, {}, _canonical({
                    **body, "signature": self.signed(
                        self.private, ANCHOR_DOMAIN, body
                    )
                })
            return 412, {}, b""
        anchor = HTTPSSequenceAnchor(
            "https://anchor.example", signer_id="anchor-root",
            trusted_public_key=self.public, write_token="T" * 40,
            clock=lambda: self.now, transport=transport,
        )
        self.assertFalse(anchor.advance_sequence("test", 6, "6" * 64))

    def test_god_gate_uses_signed_remote_decision(self):
        def transport(method, url, headers, raw, timeout):
            request = json.loads(raw)
            request_hash = hashlib.sha256(
                b"CRYPTIC-REMOTE-REQUEST/1\x00" + _canonical(request)
            ).hexdigest()
            body = {
                "schema": DECISION_SCHEMA, "signer_id": "god-root",
                "request_hash": request_hash, "decision": True,
                "issued_at": self.now, "expires_at": self.now + 30,
                "nonce": request["request_id"],
            }
            return 200, {}, _canonical({
                **body, "signature": self.signed(self.private, RESPONSE_DOMAIN, body)
            })
        client = SignedHTTPSDecisionClient(
            "https://god.example/authorize", signer_id="god-root",
            trusted_public_key=self.public, clock=lambda: self.now,
            transport=transport,
        )
        decision = GODHTTPSGate(client).runnable(
            "gcf.consensus.propose", "https://validator.example"
        )
        self.assertTrue(decision["allowed"])

    def test_remote_signer_produces_locally_verified_gcf_signatures(self):
        def transport(method, url, headers, raw, timeout):
            request = json.loads(raw)
            message = base64.b64decode(request["message_b64"], validate=True)
            signature = self.private.sign(message)
            return 200, {}, _canonical({
                "schema": "CRYPTIC-ED25519-SIGN/1",
                "key_id": "validator-key-1",
                "request_id": request["request_id"],
                "signature": base64.b64encode(signature).decode("ascii"),
            })
        signer = HTTPSHSMEd25519Signer(
            "https://hsm.example/sign", key_id="validator-key-1",
            public_key=self.public, client_certificate="/provisioned/client.crt",
            client_private_key="/provisioned/client.key", transport=transport,
        )
        fields = {
            "network_id": "test-net", "epoch": 1, "height": 1, "round": 0,
            "parent_hash": "0" * 64, "payload_hash": "1" * 64,
            "proof_hash": "2" * 64, "justice_commitment": {"justice_profile": "GAIA-JUSTICE/1"},
            "proposer_id": "validator-1", "nonce": "a" * 32,
            "issued_at": self.now, "expires_at": self.now + 60,
        }
        proposal = make_proposal_with_signer(signer=signer, **fields)
        from src.consensus.gcf import PROPOSAL_DOMAIN, verify_object
        unsigned = {k: v for k, v in proposal.items() if k != "signature"}
        self.assertTrue(verify_object(
            signer.public_key_hex, proposal["signature"],
            PROPOSAL_DOMAIN, unsigned,
        ))
        vote = make_vote_with_signer(
            signer=signer, validator_id="validator-1", proposal=proposal,
            vote_type="PREVOTE", issued_at=self.now,
        )
        from src.consensus.gcf import VOTE_DOMAIN
        unsigned_vote = {k: v for k, v in vote.items() if k != "signature"}
        self.assertTrue(verify_object(
            signer.public_key_hex, vote["signature"], VOTE_DOMAIN, unsigned_vote
        ))

    def test_root_pin_requires_independent_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "root.json"
            path.write_text(json.dumps({
                "schema": "CRYPTIC-GOD-ROOT-PIN/1",
                "signer_id": "GOD-ROOT-1",
                "public_key_hex": self.public.hex(),
            }))
            import os
            os.chmod(path, 0o600)
            fingerprint = hashlib.sha256(self.public).hexdigest()
            self.assertEqual(
                load_independently_pinned_root(
                    str(path), expected_fingerprint=fingerprint,
                    expected_signer_id="GOD-ROOT-1",
                ),
                self.public,
            )
            with self.assertRaisesRegex(RemoteProviderError, "fingerprint_pin_mismatch"):
                load_independently_pinned_root(
                    str(path), expected_fingerprint="0" * 64,
                    expected_signer_id="GOD-ROOT-1",
                )


    def test_justice_rejects_shared_signing_key_even_with_distinct_signer_ids(self):
        policy = SignedHTTPSDecisionClient(
            "https://policy.example/check", signer_id="policy-root",
            trusted_public_key=self.public, clock=lambda: self.now,
            transport=lambda *_: (500, {}, b""),
        )
        evidence = SignedHTTPSDecisionClient(
            "https://evidence.example/check", signer_id="evidence-root",
            trusted_public_key=self.public, clock=lambda: self.now,
            transport=lambda *_: (500, {}, b""),
        )
        with self.assertRaisesRegex(RemoteProviderError, "must_be_independent"):
            HTTPSJusticeProviders(policy=policy, evidence=evidence)

    def test_justice_rejects_shared_endpoint_even_with_distinct_keys(self):
        _other_private, other_public = keypair()
        policy = SignedHTTPSDecisionClient(
            "https://justice.example/check", signer_id="policy-root",
            trusted_public_key=self.public, clock=lambda: self.now,
            transport=lambda *_: (500, {}, b""),
        )
        evidence = SignedHTTPSDecisionClient(
            "https://justice.example/check", signer_id="evidence-root",
            trusted_public_key=other_public, clock=lambda: self.now,
            transport=lambda *_: (500, {}, b""),
        )
        with self.assertRaisesRegex(RemoteProviderError, "must_be_independent"):
            HTTPSJusticeProviders(policy=policy, evidence=evidence)


if __name__ == "__main__":
    unittest.main()
