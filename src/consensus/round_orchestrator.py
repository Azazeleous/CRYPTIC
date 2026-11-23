"""Scheduler-driven GCF round-change orchestration.

Signing and peer delivery are injected trust boundaries. The orchestrator
verifies every locally signed message, persists it through GCFEngine, retries
broadcast from persisted evidence after ambiguous delivery, and activates a
round only after a complete verified certificate exists.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Mapping

from src.consensus.gcf import GCFError
from src.consensus.round_change import verify_round_change_message
from src.consensus.round_progression import (
    RoundProgressionController, RoundProgressionError,
)


class RoundOrchestrationError(ValueError):
    pass


class RoundChangeOrchestrator:
    def __init__(self, *, engine: Any, controller: RoundProgressionController,
                 validator_id: str,
                 sign_round_change: Callable[[dict], Mapping[str, Any]],
                 broadcast_round_change: Callable[[Mapping[str, Any]], bool],
                 clock: Callable[[], float] = time.time,
                 message_ttl_seconds: int = 120):
        if engine is None or controller is None:
            raise RoundOrchestrationError("engine_and_controller_required")
        if validator_id not in engine.validator_set.validators:
            raise RoundOrchestrationError("local_validator_not_in_active_set")
        if not callable(sign_round_change) or not callable(broadcast_round_change):
            raise RoundOrchestrationError("signer_and_peer_broadcast_required")
        if (isinstance(message_ttl_seconds, bool)
                or not isinstance(message_ttl_seconds, int)
                or not 1 <= message_ttl_seconds <= 300):
            raise RoundOrchestrationError("message_ttl_invalid")
        self.engine = engine
        self.controller = controller
        self.validator_id = validator_id
        self.sign_round_change = sign_round_change
        self.broadcast_round_change = broadcast_round_change
        self.clock = clock
        self.message_ttl_seconds = message_ttl_seconds

    def tick(self, *, height: int) -> dict:
        current = self.controller.current_round(height)
        target = current + 1

        certificate = self.engine.get_round_change_certificate(
            height=height, target_round=target,
        )
        if certificate is not None:
            advanced = self.controller.activate_certificate(
                certificate, height=height,
            )
            return {"status": "round_advanced", **advanced}

        intent = self.controller.poll_timeout(height=height)
        if intent is None:
            return {
                "status": "waiting", "height": height,
                "round": current, "target_round": target,
            }

        message = self.engine.get_round_change_message(
            height=height, target_round=target,
            validator_id=self.validator_id,
        )
        if message is None:
            issued_at = int(self.clock())
            request = {
                "schema": "GCF-ROUND-CHANGE/1",
                "network_id": self.engine.validator_set.network_id,
                "epoch": self.engine.validator_set.epoch,
                "height": height,
                "source_round": current,
                "target_round": target,
                "validator_id": self.validator_id,
                "issued_at": issued_at,
                "expires_at": issued_at + self.message_ttl_seconds,
            }
            try:
                message = self.sign_round_change(request)
            except Exception as exc:
                raise RoundOrchestrationError("round_change_signer_failed") from exc
            if not isinstance(message, Mapping):
                raise RoundOrchestrationError("round_change_signer_response_invalid")
            checked = verify_round_change_message(
                message, validator_set=self.engine.validator_set,
                height=height, target_round=target, clock=self.clock,
            )
            if (not checked.get("valid")
                    or checked.get("validator_id") != self.validator_id
                    or message.get("source_round") != current):
                raise RoundOrchestrationError(
                    "round_change_signer_message_rejected:" + str(checked.get("reason"))
                )
            try:
                self.engine.submit_round_change(message)
            except GCFError as exc:
                # A concurrent/retried tick may have persisted the exact same
                # message. Read back the stored proof and verify it before use.
                if "ROUND_CHANGE_DUPLICATE" not in str(exc):
                    raise RoundOrchestrationError("round_change_persistence_failed") from exc
                message = self.engine.get_round_change_message(
                    height=height, target_round=target,
                    validator_id=self.validator_id,
                )
                if message is None:
                    raise RoundOrchestrationError("persisted_round_change_missing") from exc

        try:
            delivered = self.broadcast_round_change(message)
        except Exception as exc:
            raise RoundOrchestrationError("round_change_broadcast_failed") from exc
        if delivered is not True:
            return {
                "status": "broadcast_pending", "height": height,
                "source_round": current, "target_round": target,
                "message_persisted": True, "timeout_acknowledged": False,
            }

        self.controller.acknowledge_timeout(
            height=height, source_round=current,
        )
        certificate = self.engine.get_round_change_certificate(
            height=height, target_round=target,
        )
        if certificate is not None:
            advanced = self.controller.activate_certificate(
                certificate, height=height,
            )
            return {"status": "round_advanced", **advanced}
        return {
            "status": "awaiting_quorum", "height": height,
            "source_round": current, "target_round": target,
            "message_persisted": True, "broadcast_confirmed": True,
        }
