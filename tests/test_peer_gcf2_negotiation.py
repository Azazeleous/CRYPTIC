import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from src.consensus.gcf import ValidatorSet
from src.consensus.peer_transport import GCFPeerNode, PeerTransportError


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


class PeerGCF2NegotiationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        keys = {name: keypair() for name in ("v0", "v1")}
        self.vset = ValidatorSet("mesh-test", 2, {
            name: {"public_key_hex": pair[1], "weight": 1}
            for name, pair in keys.items()
        })
        self.private = keys
        self.node = GCFPeerNode(
            engine=object(), validator_set=self.vset, node_id="v0",
            private_key_hex=keys["v0"][0], peer_certificate_fingerprints={},
            replay_db_path=Path(self.temp.name) / "receiver.sqlite3",
            clock=lambda: 1_800_000_000,
        )
        self.sender = GCFPeerNode(
            engine=object(), validator_set=self.vset, node_id="v1",
            private_key_hex=keys["v1"][0], peer_certificate_fingerprints={},
            replay_db_path=Path(self.temp.name) / "sender.sqlite3",
            clock=lambda: 1_800_000_000,
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_peer_advertises_supported_protocol_versions(self):
        hello = self.sender.make_envelope(
            "HELLO",
            {"schema": "GCF-CAPABILITIES/1", "network_id": "mesh-test",
             "epoch": 2, "supported_versions": ["GCF/1", "GCF/2"]},
            message_id="01" * 16,
        )
        result = self.node.handle_envelope("v1", hello)
        self.assertEqual(result["result"]["selected_version"], "GCF/1")

    def test_gcf2_message_requires_negotiated_peer_version_and_enabled_store(self):
        class Store:
            def __init__(self):
                self.votes = []

            def submit_vote(self, vote):
                self.votes.append(dict(vote))
                return {"accepted": True}

        self.node.gcf2_vote_store = Store()
        vote = {"schema": "GCF/2", "network_id": "mesh-test"}
        envelope = self.sender.make_envelope(
            "GCF2_VOTE", vote, message_id="02" * 16,
        )
        with self.assertRaisesRegex(PeerTransportError, "GCF2_PROTOCOL_NOT_NEGOTIATED"):
            self.node.handle_envelope("v1", envelope)
        hello = self.sender.make_envelope(
            "HELLO",
            {"schema": "GCF-CAPABILITIES/1", "network_id": "mesh-test",
             "epoch": 2, "supported_versions": ["GCF/1", "GCF/2"]},
            message_id="03" * 16,
        )
        self.node.handle_envelope("v1", hello)
        accepted = self.node.handle_envelope(
            "v1", self.sender.make_envelope(
                "GCF2_VOTE", vote, message_id="04" * 16,
            ),
        )
        self.assertTrue(accepted["accepted"])
        self.assertEqual(self.node.gcf2_vote_store.votes, [vote])


if __name__ == "__main__":
    unittest.main()
