import asyncio
import base64
import hashlib
import io
import ipaddress
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from src.consensus.gcf import (
    CERT_DOMAIN, GateResult, GCFEngine, ValidatorSet,
    canonical_bytes, make_proposal, make_vote, sha256_hex,
)
from src.consensus.hccgn_adapter import HCCGNVerifierAdapter
from src.consensus.independent_verifier import verify_certificate
from src.consensus.peer_transport import (
    GCFPeerNode, PeerTransportError, build_client_ssl_context,
    build_server_ssl_context,
)
from src.consensus.http_api import GCFWSGI


def keypair():
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    ).hex()
    return private, public


class IndependentVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.now = 1_800_000_000
        self.proposer_private, _ = keypair()
        self.keys = {f"v{i}": keypair() for i in range(4)}
        self.validators = {
            name: {"public_key_hex": pair[1], "weight": 1}
            for name, pair in self.keys.items()
        }
        self.vset = ValidatorSet("gaia-testnet", 1, self.validators)
        self.allow = lambda *_: GateResult(True, "verified")
        self.engine = GCFEngine(
            Path(self.temp.name) / "engine.sqlite3", self.vset,
            hccgn_verifier=self.allow, god_authorizer=self.allow,
            justice_verifier=self.allow, clock=lambda: self.now,
        )
        self.state = b'{"account":"alpha","balance_units":1250}'
        self.proposal = make_proposal(
            network_id="gaia-testnet", epoch=1, height=1, round=0,
            parent_hash="0" * 64, payload_hash=sha256_hex(self.state),
            proof_hash=hashlib.sha256(b"proof-commitment").hexdigest(),
            justice_commitment={
                "justice_profile": "GAIA-JUSTICE/1",
                "policy_hash": "1" * 64,
                "policy_audit_hash": "2" * 64,
                "evidence_root": "3" * 64,
                "transition_hash": "4" * 64,
                "value_accounting_hash": "5" * 64,
                "challenge_state_hash": "6" * 64,
            },
            proposer_id="proposer-1", proposer_private_key_hex=self.proposer_private,
            nonce="0123456789abcdef0123456789abcdef",
            issued_at=self.now, expires_at=self.now + 300,
        )

    def tearDown(self):
        self.temp.cleanup()

    def build_certificate(self):
        digest = self.engine.submit_proposal(self.proposal)["candidate_digest"]
        prevotes = []
        for name in ("v0", "v1", "v2"):
            vote = make_vote(
                validator_id=name, validator_private_key_hex=self.keys[name][0],
                proposal=self.proposal, vote_type="PREVOTE", issued_at=self.now,
            )
            self.engine.submit_vote(vote)
            prevotes.append(vote)
        polc = sha256_hex(CERT_DOMAIN + canonical_bytes({
            "schema": "GCF/1", "candidate_digest": digest,
            "validator_set_hash": self.vset.digest,
            "prevotes": sorted(prevotes, key=lambda x: x["validator_id"]),
        }))
        for name in ("v0", "v1", "v2"):
            self.engine.submit_vote(make_vote(
                validator_id=name, validator_private_key_hex=self.keys[name][0],
                proposal=self.proposal, vote_type="PRECOMMIT",
                polc_digest=polc, issued_at=self.now,
            ))
        return self.engine.finalize(digest)["certificate"]

    def test_proposal_can_bind_anchor_sequence_independently_of_block_height(self):
        base = self.proposal
        proposal = make_proposal(
            network_id=base["network_id"], epoch=base["epoch"], height=17, round=base["round"],
            parent_hash=base["parent_hash"], payload_hash=base["payload_hash"],
            proof_hash=base["proof_hash"], justice_commitment=base["justice_commitment"],
            proposer_id=base["proposer_id"], proposer_private_key_hex=self.proposer_private,
            nonce=base["nonce"], issued_at=base["issued_at"], expires_at=base["expires_at"],
            anchor_sequence=3,
        )
        _digest, normalized = self.engine._validate_proposal(proposal)
        self.assertEqual(normalized["height"], 17)
        self.assertEqual(normalized["anchor_sequence"], 3)

    def test_independent_verifier_accepts_engine_certificate(self):
        cert = self.build_certificate()
        result = verify_certificate(
            cert, hccgn_verifier=self.allow,
            god_authorizer=self.allow, justice_verifier=self.allow,
        )
        self.assertTrue(result["valid"], result)
        self.assertEqual(result["precommit_weight"], 3)

    def test_independent_verifier_fails_closed_without_external_proof(self):
        cert = self.build_certificate()
        result = verify_certificate(cert)
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "HCCGN_PROOF_NOT_INDEPENDENTLY_VERIFIED")

    def test_independent_verifier_rejects_certificate_tampering(self):
        cert = self.build_certificate()
        cert["precommit_weight"] = 999
        result = verify_certificate(
            cert, hccgn_verifier=self.allow,
            god_authorizer=self.allow, justice_verifier=self.allow,
        )
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "PRECOMMIT_WEIGHT_MISMATCH")

    def test_independent_verifier_rejects_duplicate_validator_entries(self):
        cert = self.build_certificate()
        cert["validator_set"]["validators"].append(
            dict(cert["validator_set"]["validators"][0])
        )
        result = verify_certificate(
            cert, hccgn_verifier=self.allow,
            god_authorizer=self.allow, justice_verifier=self.allow,
        )
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "VALIDATOR_ID_DUPLICATE_OR_INVALID")

    def test_adam_validator_uses_independent_verifier(self):
        from src.adam.commit_store import AdamCommitStore, APEXValidator
        cert = self.build_certificate()
        store = AdamCommitStore(Path(self.temp.name) / "adam.sqlite3")
        apex = APEXValidator(
            store, hccgn_verifier=self.allow,
            god_authorizer=self.allow, justice_verifier=self.allow,
        )
        result = apex.validate_and_commit(cert, self.state)
        self.assertTrue(result["committed"])
        self.assertEqual(store.head()["height"], 1)


    def test_adam_commit_http_endpoint_and_head_recovery(self):
        from src.adam.commit_store import AdamCommitStore, APEXValidator
        cert = self.build_certificate()
        store = AdamCommitStore(Path(self.temp.name) / "adam-http.sqlite3")
        apex = APEXValidator(
            store, hccgn_verifier=self.allow,
            god_authorizer=self.allow, justice_verifier=self.allow,
        )
        app = GCFWSGI(self.engine, apex_validator=apex)
        request = json.dumps({
            "certificate": cert,
            "state_b64": base64.b64encode(self.state).decode("ascii"),
        }).encode()
        environ = {
            "REQUEST_METHOD": "POST", "PATH_INFO": "/v1/adam/commit",
            "CONTENT_TYPE": "application/json", "CONTENT_LENGTH": str(len(request)),
            "wsgi.input": io.BytesIO(request),
        }
        response = {}
        def start(status, headers): response["status"] = status
        payload = json.loads(b"".join(app(environ, start)).decode())
        self.assertEqual(response["status"], "201 Created")
        self.assertTrue(payload["committed"])
        head_env = {
            "REQUEST_METHOD": "GET", "PATH_INFO": "/v1/adam/head",
            "CONTENT_TYPE": "", "CONTENT_LENGTH": "0",
            "wsgi.input": io.BytesIO(b""),
        }
        head_response = {}
        def head_start(status, headers): head_response["status"] = status
        head = json.loads(b"".join(app(head_env, head_start)).decode())
        self.assertEqual(head_response["status"], "200 OK")
        self.assertEqual(head["height"], 1)
        self.assertEqual(head["state_hash"], sha256_hex(self.state))


class HCCGNAdapterTests(unittest.TestCase):
    def test_hccgn_adapter_denies_without_provider(self):
        result = HCCGNVerifierAdapter()({"proof_hash": "a" * 64})
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "HCCGN_PROOF_PROVIDER_NOT_CONNECTED")

    def test_hccgn_adapter_requires_exact_profile_and_proof_hash(self):
        class Provider:
            def verify_proof_hash(self, proof_hash, proposal):
                return {"valid": True, "profile_id": "HCCGN/UNSPECIFIED",
                        "proof_hash": proof_hash}
        adapter = HCCGNVerifierAdapter(Provider(), profile_id="HCCGN/UNSPECIFIED")
        self.assertTrue(adapter({"proof_hash": "b" * 64}).allowed)
        wrong = HCCGNVerifierAdapter(Provider(), profile_id="HCCGN/1")
        self.assertFalse(wrong({"proof_hash": "b" * 64}).allowed)


def write_tls_identity(directory, name, serial, ca_key, ca_cert, usage, ip=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - timedelta(minutes=2))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=None, decipher_only=None,
            ),
            critical=True,
        )
    )
    if ip is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip))]),
            critical=False,
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    cert_path = Path(directory) / f"{name}.crt.pem"
    key_path = Path(directory) / f"{name}.key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    return cert, cert_path, key_path


class PeerTransportTests(unittest.TestCase):
    def test_signed_peer_envelope_dispatches_and_replay_is_rejected(self):
        temp = tempfile.TemporaryDirectory()
        try:
            private, public = keypair()
            vset = ValidatorSet("gaia-testnet", 1, {
                "peer-a": {"public_key_hex": public, "weight": 1},
                "peer-b": {"public_key_hex": public, "weight": 1},
            })
            class Engine:
                def __init__(self): self.seen = []
                def submit_proposal(self, payload):
                    self.seen.append(("PROPOSAL", payload))
                    return {"accepted": True}
                def submit_vote(self, payload):
                    self.seen.append(("VOTE", payload))
                    return {"accepted": True}
            engine = Engine()
            node = GCFPeerNode(
                engine=engine, validator_set=vset, node_id="peer-b",
                private_key_hex=private,
                peer_certificate_fingerprints={},
                replay_db_path=Path(temp.name) / "replay.sqlite3",
                clock=lambda: 1_800_000_000,
            )
            envelope = {
                "schema": "GCF-P2P/1", "message_id": "a" * 32,
                "sender_id": "peer-a", "issued_at": 1_800_000_000,
                "message_type": "PROPOSAL", "payload": {"candidate": "x"},
            }
            from src.consensus.gcf import sign_object
            from src.consensus.peer_transport import P2P_DOMAIN
            envelope["signature"] = sign_object(
                private, P2P_DOMAIN, {k:v for k,v in envelope.items()}
            )
            result = node.handle_envelope("peer-a", envelope)
            self.assertTrue(result["accepted"])
            self.assertEqual(len(engine.seen), 1)
            with self.assertRaisesRegex(PeerTransportError, "MESSAGE_REPLAY"):
                node.handle_envelope("peer-a", envelope)
        finally:
            temp.cleanup()

    def test_mutual_tls_peer_send_and_receive_loopback(self):
        temp = tempfile.TemporaryDirectory()
        try:
            now = datetime.now(timezone.utc)
            ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "GCF test CA")])
            ca_cert = (
                x509.CertificateBuilder()
                .subject_name(ca_name).issuer_name(ca_name)
                .public_key(ca_key.public_key()).serial_number(1)
                .not_valid_before(now - timedelta(minutes=2))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True, content_commitment=False,
                        key_encipherment=False, data_encipherment=False,
                        key_agreement=False, key_cert_sign=True, crl_sign=True,
                        encipher_only=None, decipher_only=None,
                    ), critical=True,
                )
                .sign(ca_key, hashes.SHA256())
            )
            ca_path = Path(temp.name) / "ca.pem"
            ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
            server_cert, server_cert_path, server_key_path = write_tls_identity(
                temp.name, "gcf-server", 2, ca_key, ca_cert,
                ExtendedKeyUsageOID.SERVER_AUTH, "127.0.0.1",
            )
            client_cert, client_cert_path, client_key_path = write_tls_identity(
                temp.name, "gcf-client", 3, ca_key, ca_cert,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            )
            server_private, server_public = keypair()
            client_private, client_public = keypair()
            vset = ValidatorSet("gaia-testnet", 1, {
                "peer-a": {"public_key_hex": client_public, "weight": 1},
                "peer-b": {"public_key_hex": server_public, "weight": 1},
            })
            class Engine:
                def __init__(self): self.seen = []
                def submit_proposal(self, payload):
                    self.seen.append(payload)
                    return {"candidate_received": True}
                def submit_vote(self, payload):
                    return {"vote_received": True}
            engine = Engine()
            fingerprint = hashlib.sha256(
                client_cert.public_bytes(serialization.Encoding.DER)
            ).hexdigest()
            server_node = GCFPeerNode(
                engine=engine, validator_set=vset, node_id="peer-b",
                private_key_hex=server_private,
                peer_certificate_fingerprints={fingerprint: "peer-a"},
                replay_db_path=Path(temp.name) / "server-replay.sqlite3",
            )
            client_node = GCFPeerNode(
                engine=Engine(), validator_set=vset, node_id="peer-a",
                private_key_hex=client_private,
                peer_certificate_fingerprints={},
                replay_db_path=Path(temp.name) / "client-replay.sqlite3",
            )
            server_tls = build_server_ssl_context(
                str(server_cert_path), str(server_key_path), str(ca_path)
            )
            client_tls = build_client_ssl_context(
                str(client_cert_path), str(client_key_path), str(ca_path)
            )
            server_fingerprint = hashlib.sha256(
                server_cert.public_bytes(serialization.Encoding.DER)
            ).hexdigest()

            async def exchange():
                server = await server_node.serve("127.0.0.1", 0, server_tls)
                try:
                    port = server.sockets[0].getsockname()[1]
                    return await client_node.send(
                        "127.0.0.1", port, client_tls, server_fingerprint,
                        "PROPOSAL", {"candidate": "loopback"},
                        "d" * 32,
                    )
                finally:
                    server.close()
                    await server.wait_closed()

            response = asyncio.run(exchange())
            self.assertEqual(response["status"], "accepted")
            self.assertTrue(response["accepted"])
            self.assertEqual(engine.seen, [{"candidate": "loopback"}])
        finally:
            temp.cleanup()

    def test_peer_identity_must_match_authenticated_certificate_identity(self):
        temp = tempfile.TemporaryDirectory()
        try:
            private, public = keypair()
            vset = ValidatorSet("gaia-testnet", 1, {
                "peer-a": {"public_key_hex": public, "weight": 1},
            })
            node = GCFPeerNode(
                engine=object(), validator_set=vset, node_id="peer-a",
                private_key_hex=private, peer_certificate_fingerprints={},
                replay_db_path=Path(temp.name) / "replay.sqlite3",
            )
            from src.consensus.gcf import sign_object
            from src.consensus.peer_transport import P2P_DOMAIN
            envelope = {
                "schema": "GCF-P2P/1", "message_id": "c" * 32,
                "sender_id": "peer-a", "issued_at": int(__import__("time").time()),
                "message_type": "PROPOSAL", "payload": {"candidate": "x"},
            }
            envelope["signature"] = sign_object(private, P2P_DOMAIN, envelope)
            with self.assertRaisesRegex(PeerTransportError, "PEER_IDENTITY_MISMATCH"):
                node.handle_envelope("peer-other", envelope)
        finally:
            temp.cleanup()


class StrictHTTPJSONTests(unittest.TestCase):
    def test_duplicate_json_keys_are_rejected(self):
        class Engine:
            def submit_proposal(self, proposal):
                raise AssertionError("must not dispatch ambiguous JSON")
        app = GCFWSGI(Engine())
        raw = b'{"candidate":1,"candidate":2}'
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/v1/consensus/proposals",
            "CONTENT_TYPE": "application/json",
            "CONTENT_LENGTH": str(len(raw)),
            "wsgi.input": io.BytesIO(raw),
        }
        response = {}
        def start(status, headers): response["status"] = status
        body = b"".join(app(environ, start)).decode()
        self.assertEqual(response["status"], "400 Bad Request")
        self.assertIn("REQUEST_JSON_DUPLICATE_KEY", body)

    def test_adam_endpoint_requires_validator(self):
        class Engine: pass
        app = GCFWSGI(Engine())
        raw = json.dumps({
            "certificate": {}, "state_b64": base64.b64encode(b"x").decode()
        }).encode()
        environ = {
            "REQUEST_METHOD": "POST", "PATH_INFO": "/v1/adam/commit",
            "CONTENT_TYPE": "application/json", "CONTENT_LENGTH": str(len(raw)),
            "wsgi.input": io.BytesIO(raw),
        }
        response = {}
        def start(status, headers): response["status"] = status
        body = b"".join(app(environ, start)).decode()
        self.assertEqual(response["status"], "400 Bad Request")
        self.assertIn("ADAM_APEX_NOT_CONFIGURED", body)


if __name__ == "__main__":
    unittest.main()
