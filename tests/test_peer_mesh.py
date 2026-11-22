import asyncio
import datetime as dt
import hashlib
import ipaddress
import json
import ssl
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from src.consensus.gcf import ValidatorSet
from src.consensus.peer_transport import (
    GCFPeerMesh, GCFPeerNode, PeerTransportError,
    build_client_ssl_context, build_server_ssl_context,
)


class RecordingPeerNode(GCFPeerNode):
    async def send(self, host, port, tls_context, expected_server_fingerprint,
                   message_type, payload, message_id):
        await asyncio.sleep(0)
        if host == "reject.example":
            return {"status": "rejected", "error": "peer_policy_denied"}
        return {"status": "accepted", "message_id": message_id}


def issue_certificate(subject_key, issuer_name, issuer_key, *, common_name,
                     is_ca=False, dns_name=None, extended_key_usage=None):
    now = dt.datetime.now(dt.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=1 if is_ca else None), critical=True)
    )
    if extended_key_usage:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([extended_key_usage]),
            critical=False,
        )
    if dns_name:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(dns_name),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
    return builder.sign(issuer_key, algorithm=None)


class GCFPeerMeshTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.keys = {f"v{i}": Ed25519PrivateKey.generate() for i in range(3)}
        self.private_hex = {
            name: key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            ).hex()
            for name, key in self.keys.items()
        }
        self.public_hex = {
            name: key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ).hex()
            for name, key in self.keys.items()
        }
        self.validator_set = ValidatorSet("mesh-test", 2, {
            name: {"public_key_hex": self.public_hex[name], "weight": 1}
            for name in self.keys
        })
        self.node = RecordingPeerNode(
            engine=object(),
            validator_set=self.validator_set,
            node_id="v0",
            private_key_hex=self.private_hex["v0"],
            peer_certificate_fingerprints={},
            replay_db_path=Path(self.temp.name) / "replay.sqlite3",
            clock=lambda: 1_800_000_000,
        )
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.tls.check_hostname = True
        self.tls.verify_mode = ssl.CERT_REQUIRED
        self.fingerprint = "ab" * 32

    def tearDown(self):
        self.temp.cleanup()

    async def test_broadcast_reports_per_peer_acceptance_without_claiming_quorum(self):
        mesh = GCFPeerMesh(
            node=self.node,
            tls_context=self.tls,
            peers={
                "v1": {"host": "accept.example", "port": 9443,
                       "server_fingerprint": self.fingerprint},
                "v2": {"host": "reject.example", "port": 9444,
                       "server_fingerprint": self.fingerprint},
            },
            timeout_seconds=2,
            max_parallel=2,
        )
        result = await mesh.broadcast("PROPOSAL", {
            "schema": "GCF/1", "network_id": "mesh-test",
        })
        self.assertEqual(result["accepted_peers"], ["v1"])
        self.assertEqual(result["failed_peers"], ["v2"])
        self.assertEqual(len(result["message_id"]), 32)
        self.assertEqual(result["message_type"], "PROPOSAL")

    async def test_real_mutual_tls_peer_roundtrip_and_replay_rejection(self):
        ca_key = Ed25519PrivateKey.generate()
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CRYPTIC test CA")])
        ca_cert = issue_certificate(ca_key, ca_name, ca_key, common_name="CRYPTIC test CA", is_ca=True)
        sender_cert = issue_certificate(
            self.keys["v0"], ca_name, ca_key, common_name="validator-v0",
            extended_key_usage=ExtendedKeyUsageOID.CLIENT_AUTH,
        )
        receiver_cert = issue_certificate(
            self.keys["v1"], ca_name, ca_key, common_name="localhost",
            dns_name="localhost",
            extended_key_usage=ExtendedKeyUsageOID.SERVER_AUTH,
        )
        ca_path = Path(self.temp.name) / "ca.pem"
        sender_cert_path = Path(self.temp.name) / "sender.pem"
        sender_key_path = Path(self.temp.name) / "sender-key.pem"
        receiver_cert_path = Path(self.temp.name) / "receiver.pem"
        receiver_key_path = Path(self.temp.name) / "receiver-key.pem"
        for path, value in (
            (ca_path, ca_cert.public_bytes(serialization.Encoding.PEM)),
            (sender_cert_path, sender_cert.public_bytes(serialization.Encoding.PEM)),
            (receiver_cert_path, receiver_cert.public_bytes(serialization.Encoding.PEM)),
            (sender_key_path, self.keys["v0"].private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )),
            (receiver_key_path, self.keys["v1"].private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )),
        ):
            path.write_bytes(value)

        class ReceiverEngine:
            def __init__(self):
                self.proposals = []

            def submit_proposal(self, proposal):
                self.proposals.append(dict(proposal))
                return {"accepted": True, "candidate_digest": "a" * 64}

            def submit_vote(self, vote):
                raise AssertionError("unexpected vote dispatch")

        receiver_engine = ReceiverEngine()
        receiver_node = GCFPeerNode(
            engine=receiver_engine,
            validator_set=self.validator_set,
            node_id="v1",
            private_key_hex=self.private_hex["v1"],
            peer_certificate_fingerprints={
                hashlib.sha256(sender_cert.public_bytes(serialization.Encoding.DER)).hexdigest(): "v0",
            },
            replay_db_path=Path(self.temp.name) / "receiver-replay.sqlite3",
            clock=lambda: 1_800_000_000,
            io_timeout_seconds=0.2,
            max_connections=4,
        )
        sender_node = GCFPeerNode(
            engine=object(),
            validator_set=self.validator_set,
            node_id="v0",
            private_key_hex=self.private_hex["v0"],
            peer_certificate_fingerprints={},
            replay_db_path=Path(self.temp.name) / "sender-replay.sqlite3",
            clock=lambda: 1_800_000_000,
        )
        server_tls = build_server_ssl_context(
            str(receiver_cert_path), str(receiver_key_path), str(ca_path),
        )
        client_tls = build_client_ssl_context(
            str(sender_cert_path), str(sender_key_path), str(ca_path),
        )
        server = await receiver_node.serve("127.0.0.1", 0, server_tls)
        port = server.sockets[0].getsockname()[1]
        fingerprint = hashlib.sha256(
            receiver_cert.public_bytes(serialization.Encoding.DER)
        ).hexdigest()
        try:
            payload = {"schema": "GCF/1", "network_id": "mesh-test", "height": 1}
            first = await sender_node.send(
                "localhost", port, client_tls, fingerprint,
                "PROPOSAL", payload, "01" * 16,
            )
            self.assertEqual(first["status"], "accepted")
            self.assertEqual(len(receiver_engine.proposals), 1)
            replay = await sender_node.send(
                "localhost", port, client_tls, fingerprint,
                "PROPOSAL", payload, "01" * 16,
            )
            self.assertEqual(replay["status"], "rejected")
            self.assertEqual(replay["error"], "MESSAGE_REPLAY")
            self.assertEqual(len(receiver_engine.proposals), 1)

            slow_reader, slow_writer = await asyncio.open_connection(
                "localhost", port, ssl=client_tls, server_hostname="localhost",
            )
            try:
                slow_writer.write(b"\x00\x00")
                await slow_writer.drain()
                prefix = await asyncio.wait_for(slow_reader.readexactly(4), timeout=2)
                response = await asyncio.wait_for(
                    slow_reader.readexactly(int.from_bytes(prefix, "big")), timeout=2,
                )
                self.assertEqual(json.loads(response)["error"], "PEER_IO_TIMEOUT")
            finally:
                slow_writer.close()
                await slow_writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()


    def test_round_change_message_uses_authenticated_peer_dispatch(self):
        class RoundChangeEngine:
            def __init__(self):
                self.messages = []

            def submit_round_change(self, message):
                self.messages.append(dict(message))
                return {"accepted": True, "quorum_reached": False}

        engine = RoundChangeEngine()
        self.node.engine = engine
        payload = {
            "schema": "GCF-ROUND-CHANGE/1",
            "network_id": "mesh-test",
            "epoch": 2,
            "height": 9,
            "source_round": 0,
            "target_round": 1,
        }
        envelope = self.node.make_envelope(
            "ROUND_CHANGE", payload, message_id="ab" * 16,
        )
        response = self.node.handle_envelope("v0", envelope)
        self.assertTrue(response["accepted"])
        self.assertEqual(response["result"]["quorum_reached"], False)
        self.assertEqual(engine.messages, [payload])

    def test_node_rejects_unbounded_inbound_resource_settings(self):
        with self.assertRaisesRegex(PeerTransportError, "MAX_CONNECTIONS_INVALID"):
            GCFPeerNode(
                engine=object(), validator_set=self.validator_set,
                node_id="v0", private_key_hex=self.private_hex["v0"],
                peer_certificate_fingerprints={},
                replay_db_path=Path(self.temp.name) / "bad-limit.sqlite3",
                max_connections=0,
            )
        with self.assertRaisesRegex(PeerTransportError, "PEER_IO_TIMEOUT_INVALID"):
            GCFPeerNode(
                engine=object(), validator_set=self.validator_set,
                node_id="v0", private_key_hex=self.private_hex["v0"],
                peer_certificate_fingerprints={},
                replay_db_path=Path(self.temp.name) / "bad-timeout.sqlite3",
                io_timeout_seconds=120,
            )

    def test_mesh_rejects_unknown_peer_and_invalid_endpoint(self):
        with self.assertRaisesRegex(PeerTransportError, "PEER_ID_INVALID"):
            GCFPeerMesh(
                node=self.node, tls_context=self.tls,
                peers={"unknown": {"host": "peer.example", "port": 9000,
                                   "server_fingerprint": self.fingerprint}},
            )
        with self.assertRaisesRegex(PeerTransportError, "PEER_ENDPOINT_CONFIG_INVALID"):
            GCFPeerMesh(
                node=self.node, tls_context=self.tls,
                peers={"v1": {"host": "peer.example", "port": 9000}},
            )


if __name__ == "__main__":
    unittest.main()
