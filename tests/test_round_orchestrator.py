import tempfile
import unittest
from pathlib import Path

from src.consensus.gcf import GCFEngine, ValidatorSet, public_key_hex
from src.consensus.round_change import make_round_change_message
from src.consensus.round_progression import RoundProgressionController
from src.consensus.round_orchestrator import (
    RoundChangeOrchestrator, RoundOrchestrationError,
)


class RoundChangeOrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_800_000_000
        self.monotonic_now = 100.0
        self.private = {f"v{i}": (bytes([i]) * 32).hex() for i in range(1, 5)}
        self.vset = ValidatorSet("test-net", 7, {
            name: {"public_key_hex": public_key_hex(key), "weight": 1}
            for name, key in self.private.items()
        })
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.engine = GCFEngine(
            root / "gcf.sqlite3", self.vset, clock=lambda: self.now,
        )
        self.controller = RoundProgressionController(
            engine=self.engine, database=root / "progression.sqlite3",
            monotonic=lambda: self.monotonic_now,
        )
        self.controller.arm(height=12)

    def tearDown(self):
        self.temp.cleanup()

    def signed_message(self, request, validator="v1"):
        return make_round_change_message(
            validator_id=validator, private_key_hex=self.private[validator],
            network_id=request["network_id"], epoch=request["epoch"],
            height=request["height"], source_round=request["source_round"],
            target_round=request["target_round"], issued_at=request["issued_at"],
            expires_at=request["expires_at"], nonce="a" * 32,
        )

    def remote_message(self, validator, nonce):
        return make_round_change_message(
            validator_id=validator, private_key_hex=self.private[validator],
            network_id="test-net", epoch=7, height=12,
            source_round=0, target_round=1,
            issued_at=self.now, expires_at=self.now + 120,
            nonce=nonce * 32,
        )

    def test_timeout_signs_persists_broadcasts_then_advances_on_quorum(self):
        broadcasts = []
        signer_calls = []
        def signer(request):
            signer_calls.append(dict(request))
            return self.signed_message(request)
        orchestrator = RoundChangeOrchestrator(
            engine=self.engine, controller=self.controller,
            validator_id="v1", sign_round_change=signer,
            broadcast_round_change=lambda message: broadcasts.append(dict(message)) or True,
            clock=lambda: self.now,
        )
        self.assertEqual(orchestrator.tick(height=12)["status"], "waiting")
        self.monotonic_now = 105.0
        first = orchestrator.tick(height=12)
        self.assertEqual(first["status"], "awaiting_quorum")
        self.assertEqual(len(signer_calls), 1)
        self.assertEqual(len(broadcasts), 1)
        self.assertIsNotNone(self.engine.get_round_change_message(
            height=12, target_round=1, validator_id="v1",
        ))

        self.engine.submit_round_change(self.remote_message("v2", "2"))
        self.engine.submit_round_change(self.remote_message("v3", "3"))
        final = orchestrator.tick(height=12)
        self.assertEqual(final["status"], "round_advanced")
        self.assertEqual(self.controller.current_round(12), 1)
        self.assertEqual(len(signer_calls), 1)

    def test_ambiguous_broadcast_retries_persisted_message_without_resigning(self):
        attempts = []
        signer_calls = []
        def signer(request):
            signer_calls.append(1)
            return self.signed_message(request)
        def broadcast(message):
            attempts.append(dict(message))
            return len(attempts) > 1
        orchestrator = RoundChangeOrchestrator(
            engine=self.engine, controller=self.controller,
            validator_id="v1", sign_round_change=signer,
            broadcast_round_change=broadcast, clock=lambda: self.now,
        )
        self.monotonic_now = 105.0
        self.assertEqual(orchestrator.tick(height=12)["status"], "broadcast_pending")
        self.assertEqual(orchestrator.tick(height=12)["status"], "awaiting_quorum")
        self.assertEqual(len(signer_calls), 1)
        self.assertEqual(attempts[0], attempts[1])

    def test_signer_cannot_submit_another_validators_identity(self):
        orchestrator = RoundChangeOrchestrator(
            engine=self.engine, controller=self.controller,
            validator_id="v1",
            sign_round_change=lambda request: self.signed_message(request, "v2"),
            broadcast_round_change=lambda _message: True,
            clock=lambda: self.now,
        )
        self.monotonic_now = 105.0
        with self.assertRaisesRegex(RoundOrchestrationError, "message_rejected"):
            orchestrator.tick(height=12)
        self.assertIsNone(self.engine.get_round_change_message(
            height=12, target_round=1, validator_id="v1",
        ))

    def test_orchestrator_requires_signer_and_peer_transport(self):
        with self.assertRaisesRegex(RoundOrchestrationError, "signer_and_peer"):
            RoundChangeOrchestrator(
                engine=self.engine, controller=self.controller,
                validator_id="v1", sign_round_change=None,
                broadcast_round_change=lambda _message: True,
            )


if __name__ == "__main__":
    unittest.main()
