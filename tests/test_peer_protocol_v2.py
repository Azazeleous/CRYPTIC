import tempfile
import unittest
from pathlib import Path

from src.consensus.gcf import ValidatorSet, public_key_hex
from src.consensus.peer_transport import GCFPeerNode, PeerTransportError


class _VoteStore:
    def __init__(self):
        self.votes = []

    def submit_vote(self, vote):
        self.votes.append(dict(vote))
        return {"stored": True}


class _Engine:
    def submit_proposal(self, payload):
        return {"stored": True}

    def submit_vote(self, payload):
        return {"stored": True}

    def submit_round_change(self, payload):
        return {"stored": True}


class GCFPeerProtocolNegotiationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.keys = {"v0": "01" * 32, "v1": "02" * 32, "v2": "03" * 32}
        validators = {
            name: {"public_key_hex": public_key_hex(private), "weight": 1}
            for name, private in self.keys.items()
        }
        self.vset = ValidatorSet("gaia-testnet", 1, validators)
        self.stores = {"v0": _VoteStore(), "v1": _VoteStore()}
        self.nodes = {}
        for name in ("v0", "v1"):
            self.nodes[name] = GCFPeerNode(
                engine=_Engine(), validator_set=self.vset, node_id=name,
                private_key_hex=self.keys[name], peer_certificate_fingerprints={},
                replay_db_path=Path(self.tmp.name) / (name + ".sqlite3"),
                clock=lambda: 1000, gcf2_vote_store=self.stores[name],
            )

    def tearDown(self):
        self.tmp.cleanup()

    def hello(self):
        return {
            "schema": "GCF-CAPABILITIES/1", "network_id": "gaia-testnet",
            "epoch": 1, "supported_versions": ["GCF/1", "GCF/2"],
        }

    def test_signed_hello_negotiates_gcf2(self):
        envelope = self.nodes["v0"].make_envelope(
            "HELLO", self.hello(), message_id="11" * 16,
        )
        result = self.nodes["v1"].handle_envelope("v0", envelope)
        self.assertEqual(result["result"]["selected_version"], "GCF/2")

    def test_gcf2_vote_is_rejected_before_negotiation(self):
        vote = {"schema": "GCF/2", "validator_id": "v0"}
        envelope = self.nodes["v0"].make_envelope(
            "GCF2_VOTE", vote, message_id="22" * 16,
        )
        with self.assertRaisesRegex(PeerTransportError, "GCF2_PROTOCOL_NOT_NEGOTIATED"):
            self.nodes["v1"].handle_envelope("v0", envelope)

    def test_negotiated_gcf2_vote_dispatches_to_gcf2_store(self):
        hello = self.nodes["v0"].make_envelope(
            "HELLO", self.hello(), message_id="33" * 16,
        )
        self.nodes["v1"].handle_envelope("v0", hello)
        vote = {"schema": "GCF/2", "validator_id": "v0", "candidate_digest": "aa" * 32}
        envelope = self.nodes["v0"].make_envelope(
            "GCF2_VOTE", vote, message_id="44" * 16,
        )
        accepted = self.nodes["v1"].handle_envelope("v0", envelope)
        self.assertTrue(accepted["accepted"])
        self.assertEqual(self.stores["v1"].votes, [vote])

    def test_peer_message_replay_is_rejected(self):
        envelope = self.nodes["v0"].make_envelope(
            "HELLO", self.hello(), message_id="55" * 16,
        )
        self.nodes["v1"].handle_envelope("v0", envelope)
        with self.assertRaisesRegex(PeerTransportError, "MESSAGE_REPLAY"):
            self.nodes["v1"].handle_envelope("v0", envelope)


if __name__ == "__main__":
    unittest.main()
