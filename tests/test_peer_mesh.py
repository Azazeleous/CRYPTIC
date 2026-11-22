import asyncio
import ssl
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.consensus.gcf import ValidatorSet
from src.consensus.peer_transport import GCFPeerMesh, GCFPeerNode, PeerTransportError


class RecordingPeerNode(GCFPeerNode):
    async def send(self, host, port, tls_context, expected_server_fingerprint,
                   message_type, payload, message_id):
        await asyncio.sleep(0)
        if host == "reject.example":
            return {"status": "rejected", "error": "peer_policy_denied"}
        return {"status": "accepted", "message_id": message_id}


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
