import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import unquote

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.governance.remote_providers import (
    ANCHOR_DOMAIN, ANCHOR_SCHEMA, DECISION_SCHEMA, RESPONSE_DOMAIN,
    POLICY_TRANSITION_DOMAIN, POLICY_TRANSITION_SCHEMA,
    HTTPSSequenceAnchor, HTTPSJusticeProviders, RemoteProviderError,
    SignedHTTPSDecisionClient, SignedHTTPSPolicyTransitionClient,
    load_independently_pinned_root, HTTPSHSMEd25519Signer, GODHTTPSGate,
    make_proposal_with_signer,
    make_vote_with_signer, PersistentGCFVoteSigner, _canonical,
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
        self.god_private, self.god_public = keypair()

    def signed(self, private, domain, body):
        return base64.b64encode(private.sign(domain + _canonical(body))).decode("ascii")

    def policy_authorization(self, network, sequence, digest, expected_sequence,
                             expected_hash, nonce):
        body = {
            "schema": POLICY_TRANSITION_SCHEMA,
            "signer_id": "god-policy-root",
            "capability": "cryptic.sequence_anchor.advance",
            "policy_id": "cryptic-main-policy-v1",
            "network_id": network,
            "expected_sequence": expected_sequence,
            "expected_policy_hash": expected_hash,
            "sequence": sequence,
            "policy_hash": digest,
            "issued_at": self.now - 1,
            "expires_at": self.now + 120,
            "nonce": nonce,
        }
        return {**body, "signature": self.signed(
            self.god_private, POLICY_TRANSITION_DOMAIN, body
        )}

    def anchor_authorization_provider(self):
        owner = self

        class Provider:
            def __init__(self):
                self.counter = 0

            def authorize_transition(self, transition):
                self.counter += 1
                nonce = f"{self.counter:032x}"
                return owner.policy_authorization(
                    transition["network_id"], transition["sequence"],
                    transition["policy_hash"], transition["expected_sequence"],
                    transition["expected_policy_hash"], nonce,
                )

        return Provider()

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
        certificate = {"schema": "GCF/1", "candidate_digest": "c" * 64}
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
            self.assertEqual(request["certificate"], certificate)
            self.assertNotIn("authorization", request)
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
        self.assertTrue(anchor.advance_sequence("test-net", 1, digest1, certificate=certificate))
        self.assertEqual(anchor.read_sequence("test-net"), (1, digest1))
        self.assertFalse(anchor.advance_sequence("test-net", 1, digest1, certificate=certificate))
        self.assertTrue(anchor.advance_sequence("test-net", 2, digest2, certificate=certificate))
        self.assertEqual(anchor.read_sequence("test-net"), (2, digest2))

    def test_policy_transition_client_requires_caller_authentication(self):
        with self.assertRaisesRegex(RemoteProviderError, "request_authentication_required"):
            SignedHTTPSPolicyTransitionClient(
                "https://god.example/v1/anchor-transitions",
                signer_id="god-policy-root", policy_id="cryptic-main-policy-v1",
                trusted_public_key=self.god_public, clock=lambda: self.now,
                transport=lambda *_: self.fail("transport must not be called"),
            )

    def test_policy_transition_client_verifies_exact_signed_god_response(self):
        def transport(method, url, headers, raw, timeout):
            self.assertEqual(headers.get("Authorization"), "Bearer " + "G" * 40)
            request = json.loads(raw)
            body = {
                "schema": POLICY_TRANSITION_SCHEMA,
                "signer_id": "god-policy-root",
                "capability": request["capability"],
                "policy_id": request["policy_id"],
                "network_id": request["network_id"],
                "expected_sequence": request["expected_sequence"],
                "expected_policy_hash": request["expected_policy_hash"],
                "sequence": request["sequence"],
                "policy_hash": request["policy_hash"],
                "issued_at": request["issued_at"],
                "expires_at": self.now + 120,
                "nonce": request["nonce"],
            }
            return 200, {}, _canonical({
                **body, "signature": self.signed(
                    self.god_private, POLICY_TRANSITION_DOMAIN, body
                )
            })

        client = SignedHTTPSPolicyTransitionClient(
            "https://god.example/v1/anchor-transitions",
            signer_id="god-policy-root", policy_id="cryptic-main-policy-v1",
            trusted_public_key=self.god_public, request_token="G" * 40,
            clock=lambda: self.now,
            transport=transport,
        )
        authorization = client.authorize_transition({
            "network_id": "test-net", "sequence": 8, "policy_hash": "8" * 64,
            "expected_sequence": 7, "expected_policy_hash": "7" * 64,
        })
        self.assertEqual(authorization["schema"], POLICY_TRANSITION_SCHEMA)
        self.assertEqual(authorization["sequence"], 8)
        self.assertEqual(authorization["expected_sequence"], 7)

    def test_policy_transition_client_rejects_tuple_substitution(self):
        def transport(method, url, headers, raw, timeout):
            request = json.loads(raw)
            body = {
                "schema": POLICY_TRANSITION_SCHEMA,
                "signer_id": "god-policy-root",
                "capability": request["capability"],
                "policy_id": request["policy_id"],
                "network_id": request["network_id"],
                "expected_sequence": request["expected_sequence"],
                "expected_policy_hash": request["expected_policy_hash"],
                "sequence": request["sequence"] + 1,
                "policy_hash": request["policy_hash"],
                "issued_at": request["issued_at"],
                "expires_at": self.now + 120,
                "nonce": request["nonce"],
            }
            return 200, {}, _canonical({
                **body, "signature": self.signed(
                    self.god_private, POLICY_TRANSITION_DOMAIN, body
                )
            })

        client = SignedHTTPSPolicyTransitionClient(
            "https://god.example/v1/anchor-transitions",
            signer_id="god-policy-root", policy_id="cryptic-main-policy-v1",
            trusted_public_key=self.god_public, request_token="G" * 40,
            clock=lambda: self.now,
            transport=transport,
        )
        with self.assertRaisesRegex(RemoteProviderError, "binding_mismatch"):
            client.authorize_transition({
                "network_id": "test-net", "sequence": 8, "policy_hash": "8" * 64,
                "expected_sequence": 7, "expected_policy_hash": "7" * 64,
            })

    def test_anchor_write_requires_gcf_finality_certificate(self):
        anchor = HTTPSSequenceAnchor(
            "https://anchor.example", signer_id="anchor-root",
            trusted_public_key=self.public, write_token="T" * 40,
            clock=lambda: self.now,
            transport=lambda *_: self.fail("transport must not be called"),
        )
        with self.assertRaisesRegex(RemoteProviderError, "gcf_finality_certificate_required"):
            anchor.advance_sequence("test-net", 1, "1" * 64)

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
        self.assertFalse(anchor.advance_sequence(
            "test", 6, "6" * 64, certificate={"schema": "GCF/1"}
        ))

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
        from src.consensus.gcf import VOTE_DOMAIN, ValidatorSet
        validator_set = ValidatorSet("test-net", 1, {
            "validator-1": {"public_key_hex": signer.public_key_hex, "weight": 1},
        })
        with tempfile.TemporaryDirectory() as directory:
            vote_signer = PersistentGCFVoteSigner(
                signer, validator_id="validator-1", validator_set=validator_set,
                db_path=Path(directory) / "vote-locks.sqlite3", initialize=True, clock=lambda: self.now,
            )
            vote = make_vote_with_signer(
                signer=vote_signer, validator_id="validator-1", proposal=proposal,
                vote_type="PREVOTE", issued_at=self.now,
            )
            unsigned_vote = {k: v for k, v in vote.items() if k != "signature"}
            self.assertTrue(verify_object(
                signer.public_key_hex, vote["signature"], VOTE_DOMAIN, unsigned_vote
            ))

    def test_persistent_vote_signer_blocks_cross_round_signature_and_survives_restart(self):
        signer_calls = []

        def transport(method, url, headers, raw, timeout):
            request = json.loads(raw)
            message = base64.b64decode(request["message_b64"], validate=True)
            signer_calls.append(message)
            return 200, {}, _canonical({
                "schema": "CRYPTIC-ED25519-SIGN/1",
                "key_id": "validator-key-1",
                "request_id": request["request_id"],
                "signature": base64.b64encode(self.private.sign(message)).decode("ascii"),
            })

        signer = HTTPSHSMEd25519Signer(
            "https://hsm.example/sign", key_id="validator-key-1",
            public_key=self.public, client_certificate="/provisioned/client.crt",
            client_private_key="/provisioned/client.key", transport=transport,
        )
        from src.consensus.gcf import ValidatorSet
        validator_set = ValidatorSet("test-net", 1, {
            "validator-1": {"public_key_hex": signer.public_key_hex, "weight": 1},
        })
        common = {
            "network_id": "test-net", "epoch": 1, "height": 8, "round": 0,
            "parent_hash": "0" * 64, "payload_hash": "1" * 64,
            "proof_hash": "2" * 64,
            "justice_commitment": {"justice_profile": "GAIA-JUSTICE/1"},
            "proposer_id": "validator-1", "issued_at": self.now,
            "expires_at": self.now + 60,
        }
        proposal_0 = make_proposal_with_signer(
            signer=signer, **common, nonce="a" * 32,
        )
        proposal_1 = make_proposal_with_signer(
            signer=signer, **{**common, "round": 1}, nonce="b" * 32,
        )
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "vote-locks.sqlite3"
            guarded = PersistentGCFVoteSigner(
                signer, validator_id="validator-1",
                validator_set=validator_set, db_path=db_path, initialize=True, clock=lambda: self.now,
            )
            make_vote_with_signer(
                signer=guarded, validator_id="validator-1",
                proposal=proposal_0, vote_type="PREVOTE", issued_at=self.now,
            )
            signed_count = len(signer_calls)
            with self.assertRaisesRegex(RemoteProviderError, "vote_signing_proposal_not_authorized"):
                make_vote_with_signer(
                    signer=guarded, validator_id="validator-1",
                    proposal=proposal_1, vote_type="PREVOTE", issued_at=self.now,
                )
            self.assertEqual(len(signer_calls), signed_count)

            restarted = PersistentGCFVoteSigner(
                signer, validator_id="validator-1",
                validator_set=validator_set, db_path=db_path, clock=lambda: self.now,
            )
            with self.assertRaisesRegex(RemoteProviderError, "vote_signing_proposal_not_authorized"):
                make_vote_with_signer(
                    signer=restarted, validator_id="validator-1",
                    proposal=proposal_1, vote_type="PREVOTE", issued_at=self.now,
                )
            self.assertEqual(len(signer_calls), signed_count)



    def test_round_change_hsm_signing_is_durable_idempotent_and_non_equivocating(self):
        from src.consensus.gcf import ValidatorSet
        from src.consensus.round_change import verify_round_change_message
        from src.governance.remote_providers import make_round_change_message_with_signer

        validator_set = ValidatorSet("test-net", 1, {
            "validator-1": {"public_key_hex": self.public.hex(), "weight": 1},
        })
        signer_calls = []

        def transport(method, url, headers, raw, timeout):
            request = json.loads(raw)
            message = base64.b64decode(request["message_b64"], validate=True)
            signer_calls.append(message)
            return 200, {}, _canonical({
                "schema": "CRYPTIC-ED25519-SIGN/1", "key_id": "validator-key-1",
                "request_id": request["request_id"],
                "signature": base64.b64encode(self.private.sign(message)).decode("ascii"),
            })

        remote = HTTPSHSMEd25519Signer(
            "https://hsm.example/sign", key_id="validator-key-1",
            public_key=self.public, client_certificate="/provisioned/client.crt",
            client_private_key="/provisioned/client.key", transport=transport,
        )
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "round-change-signing.sqlite3"
            signer = PersistentGCFVoteSigner(
                remote, validator_id="validator-1", validator_set=validator_set,
                db_path=db_path, initialize=True, clock=lambda: self.now,
            )
            kwargs = {
                "signer": signer, "height": 7, "source_round": 0, "target_round": 1,
                "issued_at": self.now, "expires_at": self.now + 300,
                "nonce": "a" * 32, "highest_polc": None,
            }
            signed = make_round_change_message_with_signer(**kwargs)
            retry = make_round_change_message_with_signer(**kwargs)
            self.assertEqual(signed, retry)
            self.assertEqual(len(signer_calls), 1)
            from src.consensus.round_change import make_round_change_message
            private_hex = self.private.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            ).hex()
            expected = make_round_change_message(
                validator_id="validator-1", private_key_hex=private_hex,
                network_id="test-net", epoch=1, height=7,
                source_round=0, target_round=1, issued_at=self.now,
                expires_at=self.now + 300, nonce="a" * 32,
                highest_polc=None,
            )
            self.assertEqual(signed["signature"], expected["signature"])
            verified = verify_round_change_message(
                signed, validator_set=validator_set, height=7,
                target_round=1, clock=lambda: self.now,
            )
            self.assertTrue(verified["valid"], verified)

            with self.assertRaisesRegex(
                RemoteProviderError, "round_change_signing_equivocation",
            ):
                make_round_change_message_with_signer(**{**kwargs, "nonce": "b" * 32})

            restarted = PersistentGCFVoteSigner(
                remote, validator_id="validator-1", validator_set=validator_set,
                db_path=db_path, initialize=False, clock=lambda: self.now,
            )
            recovered = make_round_change_message_with_signer(
                **{**kwargs, "signer": restarted},
            )
            self.assertEqual(recovered, signed)
            self.assertEqual(len(signer_calls), 1)
            db = sqlite3.connect(db_path)
            try:
                count = db.execute(
                    "SELECT COUNT(*) FROM gcf_round_change_signing_locks "
                    "WHERE height=7 AND target_round=1 AND validator_id='validator-1'"
                ).fetchone()[0]
            finally:
                db.close()
            self.assertEqual(count, 1)

    def test_persistent_signer_transitions_only_with_higher_verified_polc_and_keeps_history(self):
        from src.consensus.gcf import (
            ValidatorSet, make_proposal, make_vote, public_key_hex, canonical_bytes, sha256_hex,
        )
        from src.consensus.round_change import (
            POLC_SCHEMA, make_round_change_message, make_round_change_certificate, polc_digest,
        )

        other = {f"v{i}": keypair() for i in range(2, 5)}
        validator_set = ValidatorSet("test-net", 1, {
            "v1": {"public_key_hex": self.public.hex(), "weight": 1},
            **{name: {"public_key_hex": pair[1].hex(), "weight": 1}
               for name, pair in other.items()},
        })
        signer_calls = []

        def transport(method, url, headers, raw, timeout):
            request = json.loads(raw)
            message = base64.b64decode(request["message_b64"], validate=True)
            signer_calls.append(message)
            return 200, {}, _canonical({
                "schema": "CRYPTIC-ED25519-SIGN/1", "key_id": "validator-key-1",
                "request_id": request["request_id"],
                "signature": base64.b64encode(self.private.sign(message)).decode("ascii"),
            })

        remote = HTTPSHSMEd25519Signer(
            "https://hsm.example/sign", key_id="validator-key-1",
            public_key=self.public, client_certificate="/provisioned/client.crt",
            client_private_key="/provisioned/client.key", transport=transport,
        )

        def proposal(payload, round_number, certificate, nonce):
            return make_proposal(
                network_id="test-net", epoch=1, height=22, round=round_number,
                parent_hash="0" * 64, payload_hash=payload * 64,
                proof_hash="2" * 64, justice_commitment={"justice_profile": "GAIA-JUSTICE/1"},
                proposer_id="v1", proposer_private_key_hex=self.private.private_bytes(
                    serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                ).hex(),
                nonce=nonce, issued_at=self.now, expires_at=self.now + 300,
                round_change_certificate=certificate,
            )

        def message(validator_id, private_key, source, target, polc, nonce):
            return make_round_change_message(
                validator_id=validator_id,
                private_key_hex=private_key.private_bytes(
                    serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                ).hex(),
                network_id="test-net", epoch=1, height=22,
                source_round=source, target_round=target,
                issued_at=self.now + 2, expires_at=self.now + 300,
                nonce=nonce, highest_polc=polc,
            )

        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "signer.sqlite3"
            guarded = PersistentGCFVoteSigner(
                remote, validator_id="v1", validator_set=validator_set,
                db_path=db_path, initialize=True, clock=lambda: self.now,
            )
            proposal_a = proposal("a", 0, None, "a" * 32)
            make_vote_with_signer(
                signer=guarded, validator_id="v1", proposal=proposal_a,
                vote_type="PREVOTE", issued_at=self.now + 1,
            )

            first_messages = [
                message(name, pair[0], 0, 1, None, (str(i + 1) * 32))
                for i, (name, pair) in enumerate(other.items())
            ]
            first_certificate = make_round_change_certificate(
                first_messages, network_id="test-net", epoch=1,
                height=22, target_round=1,
            )
            proposal_b1 = proposal("b", 1, first_certificate, "b" * 32)
            with self.assertRaisesRegex(
                RemoteProviderError, "vote_signing_round_change_not_authorized",
            ):
                make_vote_with_signer(
                    signer=guarded, validator_id="v1", proposal=proposal_b1,
                    vote_type="PREVOTE", issued_at=self.now + 3,
                )
            with self.assertRaisesRegex(
                RemoteProviderError, "vote_signing_round_change_not_authorized",
            ):
                make_vote_with_signer(
                    signer=guarded, validator_id="v1", proposal=proposal_b1,
                    vote_type="PRECOMMIT", polc_digest="0" * 64,
                    issued_at=self.now + 3,
                )

            round_one_votes = [
                make_vote(
                    validator_id=name, validator_private_key_hex=pair[0].private_bytes(
                        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                        serialization.NoEncryption(),
                    ).hex(),
                    proposal=proposal_b1, vote_type="PREVOTE", issued_at=self.now + 1,
                )
                for name, pair in other.items()
            ]
            polc = {
                "schema": POLC_SCHEMA, "proposal": proposal_b1,
                "candidate_digest": sha256_hex(canonical_bytes(proposal_b1)),
                "validator_set_hash": validator_set.digest,
                "prevotes": round_one_votes,
            }
            polc["digest"] = polc_digest(polc)
            second_messages = [
                message(name, pair[0], 1, 2, polc, (str(i + 5) * 32))
                for i, (name, pair) in enumerate(other.items())
            ]
            second_certificate = make_round_change_certificate(
                second_messages, network_id="test-net", epoch=1,
                height=22, target_round=2,
            )
            proposal_b2 = proposal("b", 2, second_certificate, "c" * 32)
            signed = make_vote_with_signer(
                signer=guarded, validator_id="v1", proposal=proposal_b2,
                vote_type="PREVOTE", issued_at=self.now + 4,
            )
            self.assertEqual(signed["round"], 2)
            self.assertEqual(len(signer_calls), 2)

            third_messages = [
                message(name, pair[0], 2, 3, None, (f"{i + 8:02x}" * 16))
                for i, (name, pair) in enumerate(other.items())
            ]
            third_certificate = make_round_change_certificate(
                third_messages, network_id="test-net", epoch=1,
                height=22, target_round=3,
            )
            proposal_b3 = proposal("b", 3, third_certificate, "d" * 32)
            restarted = PersistentGCFVoteSigner(
                remote, validator_id="v1", validator_set=validator_set,
                db_path=db_path, initialize=False, clock=lambda: self.now,
            )
            restarted_vote = make_vote_with_signer(
                signer=restarted, validator_id="v1", proposal=proposal_b3,
                vote_type="PREVOTE", issued_at=self.now + 5,
            )
            self.assertEqual(restarted_vote["round"], 3)
            self.assertEqual(len(signer_calls), 3)
            db = sqlite3.connect(db_path)
            try:
                state = db.execute(
                    "SELECT round,value_digest FROM gcf_vote_signing_round_state "
                    "WHERE height=22 AND vote_type='PREVOTE' AND validator_id='v1'"
                ).fetchone()
                history = db.execute(
                    "SELECT COUNT(*) FROM gcf_vote_signing_history "
                    "WHERE height=22 AND vote_type='PREVOTE' AND validator_id='v1'"
                ).fetchone()[0]
            finally:
                db.close()
            self.assertEqual(state[0], 3)
            self.assertEqual(history, 3)

    def test_pre_sign_lock_is_atomic_across_signer_instances(self):
        from src.consensus.gcf import VOTE_DOMAIN
        calls = []
        calls_lock = threading.Lock()

        def transport(method, url, headers, raw, timeout):
            request = json.loads(raw)
            message = base64.b64decode(request["message_b64"], validate=True)
            if message.startswith(VOTE_DOMAIN):
                with calls_lock:
                    calls.append(message)
            return 200, {}, _canonical({
                "schema": "CRYPTIC-ED25519-SIGN/1",
                "key_id": "validator-key-1",
                "request_id": request["request_id"],
                "signature": base64.b64encode(self.private.sign(message)).decode("ascii"),
            })

        signer = HTTPSHSMEd25519Signer(
            "https://hsm.example/sign", key_id="validator-key-1",
            public_key=self.public, client_certificate="/provisioned/client.crt",
            client_private_key="/provisioned/client.key", transport=transport,
        )
        from src.consensus.gcf import ValidatorSet
        validator_set = ValidatorSet("test-net", 1, {
            "validator-1": {"public_key_hex": signer.public_key_hex, "weight": 1},
        })
        fields = {
            "network_id": "test-net", "epoch": 1, "height": 11, "round": 0,
            "parent_hash": "0" * 64, "payload_hash": "1" * 64,
            "proof_hash": "2" * 64,
            "justice_commitment": {"justice_profile": "GAIA-JUSTICE/1"},
            "proposer_id": "validator-1", "issued_at": self.now,
            "expires_at": self.now + 60,
        }
        proposal_0 = make_proposal_with_signer(signer=signer, **fields, nonce="c" * 32)
        proposal_1 = make_proposal_with_signer(
            signer=signer, **{**fields, "round": 1}, nonce="d" * 32,
        )
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "vote-locks.sqlite3"
            guards = [
                PersistentGCFVoteSigner(
                    signer, validator_id="validator-1",
                    validator_set=validator_set, db_path=db_path, clock=lambda: self.now,
                    initialize=(_ == 0),
                )
                for _ in range(2)
            ]

            def attempt(args):
                guard, proposal = args
                try:
                    make_vote_with_signer(
                        signer=guard, validator_id="validator-1",
                        proposal=proposal, vote_type="PREVOTE", issued_at=self.now,
                    )
                    return "signed"
                except RemoteProviderError as exc:
                    return str(exc)

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(attempt, [
                    (guards[0], proposal_0), (guards[1], proposal_1),
                ]))
        self.assertCountEqual(results, ["signed", "vote_signing_proposal_not_authorized"])
        self.assertEqual(len(calls), 1)

    def test_ambiguous_hsm_failure_keeps_lock_and_allows_exact_retry(self):
        from src.consensus.gcf import VOTE_DOMAIN
        attempts = []

        def transport(method, url, headers, raw, timeout):
            request = json.loads(raw)
            message = base64.b64decode(request["message_b64"], validate=True)
            if message.startswith(VOTE_DOMAIN):
                attempts.append(message)
                if len(attempts) == 1:
                    return 503, {}, b""
            return 200, {}, _canonical({
                "schema": "CRYPTIC-ED25519-SIGN/1",
                "key_id": "validator-key-1",
                "request_id": request["request_id"],
                "signature": base64.b64encode(self.private.sign(message)).decode("ascii"),
            })

        signer = HTTPSHSMEd25519Signer(
            "https://hsm.example/sign", key_id="validator-key-1",
            public_key=self.public, client_certificate="/provisioned/client.crt",
            client_private_key="/provisioned/client.key", transport=transport,
        )
        from src.consensus.gcf import ValidatorSet
        validator_set = ValidatorSet("test-net", 1, {
            "validator-1": {"public_key_hex": signer.public_key_hex, "weight": 1},
        })
        fields = {
            "network_id": "test-net", "epoch": 1, "height": 12, "round": 0,
            "parent_hash": "0" * 64, "payload_hash": "1" * 64,
            "proof_hash": "2" * 64,
            "justice_commitment": {"justice_profile": "GAIA-JUSTICE/1"},
            "proposer_id": "validator-1", "issued_at": self.now,
            "expires_at": self.now + 60,
        }
        proposal_0 = make_proposal_with_signer(signer=signer, **fields, nonce="e" * 32)
        proposal_1 = make_proposal_with_signer(
            signer=signer, **{**fields, "round": 1}, nonce="f" * 32,
        )
        with tempfile.TemporaryDirectory() as directory:
            guard = PersistentGCFVoteSigner(
                signer, validator_id="validator-1", validator_set=validator_set,
                db_path=Path(directory) / "vote-locks.sqlite3", initialize=True, clock=lambda: self.now,
            )
            with self.assertRaisesRegex(RemoteProviderError, "hsm_http_status_503"):
                make_vote_with_signer(
                    signer=guard, validator_id="validator-1",
                    proposal=proposal_0, vote_type="PREVOTE", issued_at=self.now,
                )
            with self.assertRaisesRegex(RemoteProviderError, "vote_signing_proposal_not_authorized"):
                make_vote_with_signer(
                    signer=guard, validator_id="validator-1",
                    proposal=proposal_1, vote_type="PREVOTE", issued_at=self.now,
                )
            retry = make_vote_with_signer(
                signer=guard, validator_id="validator-1",
                proposal=proposal_0, vote_type="PREVOTE", issued_at=self.now,
            )
            self.assertEqual(retry["vote_type"], "PREVOTE")
        self.assertEqual(len(attempts), 2)
        self.assertEqual(attempts[0], attempts[1])

    def test_vote_lock_store_does_not_silently_reinitialize_missing_state(self):
        signer = HTTPSHSMEd25519Signer(
            "https://hsm.example/sign", key_id="validator-key-1",
            public_key=self.public, client_certificate="/provisioned/client.crt",
            client_private_key="/provisioned/client.key",
            transport=lambda *_: (500, {}, b""),
        )
        from src.consensus.gcf import ValidatorSet
        validator_set = ValidatorSet("test-net", 1, {
            "validator-1": {"public_key_hex": signer.public_key_hex, "weight": 1},
        })
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing-vote-locks.sqlite3"
            with self.assertRaisesRegex(RemoteProviderError, "vote_lock_database_missing"):
                PersistentGCFVoteSigner(
                    signer, validator_id="validator-1",
                    validator_set=validator_set, db_path=missing, clock=lambda: self.now,
                )
            self.assertFalse(missing.exists())

    def test_vote_builder_rejects_unlocked_remote_signer(self):
        signer = HTTPSHSMEd25519Signer(
            "https://hsm.example/sign", key_id="validator-key-1",
            public_key=self.public, client_certificate="/provisioned/client.crt",
            client_private_key="/provisioned/client.key",
            transport=lambda *_: (500, {}, b""),
        )
        from src.consensus.gcf import VOTE_DOMAIN
        with self.assertRaisesRegex(RemoteProviderError, "durable_vote_signing_lock_required"):
            signer.sign(VOTE_DOMAIN + b"{}")
        with self.assertRaisesRegex(RemoteProviderError, "durable_vote_signing_lock_required"):
            make_vote_with_signer(
                signer=signer, validator_id="validator-1",
                proposal={"network_id": "test-net", "epoch": 1, "height": 1, "round": 0},
                vote_type="PREVOTE", issued_at=self.now,
            )

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
