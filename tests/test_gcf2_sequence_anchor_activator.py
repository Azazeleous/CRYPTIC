import unittest

from src.consensus.runtime import (
    RuntimeConfigurationError, build_gcf2_sequence_anchor_activator,
)


class MemoryAnchor:
    def __init__(self):
        self.state = None
        self.received = []

    def read_sequence(self, network_id):
        return self.state

    def advance_sequence(self, network_id, sequence, policy_hash, *, certificate=None):
        self.received.append(certificate)
        if certificate["schema"] != "GCF/2-ANCHOR-ENVELOPE/1":
            return False
        proposal = certificate["proposal"]
        expected = (self.state[0] if self.state else 0)
        expected_hash = self.state[1] if self.state else "00" * 32
        if sequence != expected + 1 or proposal["parent_hash"] != expected_hash:
            return False
        self.state = (sequence, policy_hash)
        return True


class GCF2SequenceAnchorActivatorTests(unittest.TestCase):
    def setUp(self):
        self.anchor = MemoryAnchor()
        self.activate = build_gcf2_sequence_anchor_activator(
            sequence_anchor=self.anchor, network_id="gaia-testnet",
        )
        self.certificate = {
            "schema": "GCF/2", "certificate_digest": "ab" * 32,
            "proposal": {
                "network_id": "gaia-testnet", "anchor_sequence": 1,
                "parent_hash": "00" * 32, "payload_hash": "cd" * 32,
            },
        }

    def test_activation_confirms_anchor_state_and_exact_retry(self):
        first = self.activate(self.certificate)
        self.assertTrue(first["accepted"])
        self.assertTrue(first["finalized"])
        self.assertFalse(first["replayed"])
        self.assertEqual(self.anchor.state, (1, "cd" * 32))
        replay = self.activate(self.certificate)
        self.assertTrue(replay["replayed"])
        self.assertEqual(len(self.anchor.received), 1)

    def test_wrong_parent_or_skipped_sequence_fails_closed(self):
        wrong_parent = {
            **self.certificate,
            "proposal": {**self.certificate["proposal"], "parent_hash": "ff" * 32},
        }
        with self.assertRaisesRegex(RuntimeConfigurationError, "gcf2_anchor_parent_mismatch"):
            self.activate(wrong_parent)
        skipped = {
            **self.certificate,
            "proposal": {**self.certificate["proposal"], "anchor_sequence": 2},
        }
        with self.assertRaisesRegex(RuntimeConfigurationError, "gcf2_anchor_sequence_not_next"):
            self.activate(skipped)


if __name__ == "__main__":
    unittest.main()
