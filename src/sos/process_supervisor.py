"""Hard-deadline, allowlisted OS worker for SOS built-in operations.

The worker receives bounded bytes and a fixed operation name. It never imports
extension artifacts, opens files, accesses the network, or evaluates code.
It runs with the same OS identity as the parent; this is process isolation and
deadline enforcement, not a privilege-separated OS sandbox.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import multiprocessing
import time
from dataclasses import dataclass
from multiprocessing.connection import Connection
from typing import Any

MAX_INPUT_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
MAX_TIMEOUT_SECONDS = 10.0
MIN_TIMEOUT_SECONDS = 0.05
MAX_DIAGNOSTIC_PAUSE_SECONDS = 5.0


class ProcessSupervisorError(ValueError):
    """A worker request, response, or operation failed validation."""


class ProcessDeadlineExceeded(TimeoutError):
    """The worker was terminated because its absolute deadline elapsed."""


@dataclass(frozen=True)
class ProcessResult:
    operation: str
    output: bytes
    process_id: int
    elapsed_ms: int


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ProcessSupervisorError("worker_json_encoding_failed") from exc


def _json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _reject_number(_value):
    raise ValueError("non_integer_json_number_forbidden")


def _worker_operation(operation: str, payload: bytes) -> bytes:
    if operation == "sha256":
        return hashlib.sha256(payload).hexdigest().encode("ascii")
    if operation == "text.stats":
        try:
            text = payload.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise ProcessSupervisorError("text_utf8_invalid") from exc
        return _canonical({
            "bytes": len(payload),
            "characters": len(text),
            "lines": 0 if not text else text.count("\n") + (0 if text.endswith("\n") else 1),
            "words": len(text.split()),
        })
    if operation == "json.canonicalize":
        try:
            value = json.loads(
                payload.decode("utf-8", "strict"),
                object_pairs_hook=_json_pairs,
                parse_float=_reject_number,
                parse_constant=_reject_number,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ProcessSupervisorError("worker_json_input_invalid") from exc
        return _canonical(value)
    if operation == "diagnostic.pause":
        try:
            request = json.loads(payload.decode("ascii"), object_pairs_hook=_json_pairs)
            seconds = request["seconds"]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ProcessSupervisorError("diagnostic_pause_input_invalid") from exc
        if (not isinstance(seconds, (int, float)) or isinstance(seconds, bool)
                or not math.isfinite(seconds)
                or not 0 <= seconds <= MAX_DIAGNOSTIC_PAUSE_SECONDS):
            raise ProcessSupervisorError("diagnostic_pause_duration_invalid")
        time.sleep(float(seconds))
        return b"paused"
    raise ProcessSupervisorError("worker_operation_not_allowed")


def _worker(send_connection: Connection, operation: str, payload: bytes) -> None:
    """Spawn-safe allowlisted worker; sends one bounded result and exits."""
    try:
        output = _worker_operation(operation, payload)
        if len(output) > MAX_OUTPUT_BYTES:
            response = {"ok": False, "error": "worker_output_too_large"}
        else:
            response = {"ok": True, "output_b64": base64.b64encode(output).decode("ascii")}
    except ProcessSupervisorError as exc:
        response = {"ok": False, "error": str(exc)}
    except Exception:
        response = {"ok": False, "error": "worker_operation_failed"}
    try:
        send_connection.send_bytes(_canonical(response))
    except (OSError, EOFError):
        pass
    finally:
        send_connection.close()


class ProcessSupervisor:
    """Run a single allowlisted operation in a killable spawn worker."""

    def __init__(self, *, terminate_grace_seconds: float = 0.2):
        if (isinstance(terminate_grace_seconds, bool)
                or not isinstance(terminate_grace_seconds, (int, float))
                or not math.isfinite(terminate_grace_seconds)
                or not 0 <= terminate_grace_seconds <= 2):
            raise ProcessSupervisorError("terminate_grace_invalid")
        self._ctx = multiprocessing.get_context("spawn")
        self.terminate_grace_seconds = float(terminate_grace_seconds)

    def _stop(self, process) -> None:
        if process.is_alive():
            process.terminate()
            process.join(timeout=self.terminate_grace_seconds)
        if process.is_alive():
            process.kill()
            process.join(timeout=self.terminate_grace_seconds)
        if process.is_alive():
            raise ProcessSupervisorError("worker_termination_failed")

    def execute(
        self,
        operation: str,
        payload: bytes,
        *,
        timeout_seconds: float = 1.0,
        deadline_monotonic: float | None = None,
    ) -> ProcessResult:
        if not isinstance(operation, str) or operation not in {
            "sha256", "text.stats", "json.canonicalize", "diagnostic.pause",
        }:
            raise ProcessSupervisorError("worker_operation_not_allowed")
        if not isinstance(payload, bytes) or len(payload) > MAX_INPUT_BYTES:
            raise ProcessSupervisorError("worker_input_size_invalid")
        if (isinstance(timeout_seconds, bool)
                or not isinstance(timeout_seconds, (int, float))
                or not math.isfinite(timeout_seconds)
                or not MIN_TIMEOUT_SECONDS <= timeout_seconds <= MAX_TIMEOUT_SECONDS):
            raise ProcessSupervisorError("worker_timeout_invalid")
        started = time.monotonic()
        deadline = started + float(timeout_seconds)
        if deadline_monotonic is not None:
            if (isinstance(deadline_monotonic, bool)
                    or not isinstance(deadline_monotonic, (int, float))
                    or not math.isfinite(deadline_monotonic)):
                raise ProcessSupervisorError("worker_deadline_invalid")
            deadline = min(deadline, float(deadline_monotonic))
        if deadline <= started:
            raise ProcessDeadlineExceeded("worker_deadline_exceeded")

        receive_connection, send_connection = self._ctx.Pipe(duplex=False)
        process = self._ctx.Process(
            target=_worker, args=(send_connection, operation, payload),
            name="cryptic-sos-operation", daemon=True,
        )
        started_process = False
        try:
            process.start()
            started_process = True
            send_connection.close()
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not receive_connection.poll(remaining):
                self._stop(process)
                raise ProcessDeadlineExceeded("worker_deadline_exceeded")
            try:
                raw = receive_connection.recv_bytes(MAX_OUTPUT_BYTES + 4096)
            except (OSError, EOFError) as exc:
                self._stop(process)
                raise ProcessSupervisorError("worker_response_invalid") from exc
            self._stop(process)
            try:
                response = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ProcessSupervisorError("worker_response_invalid") from exc
            if not isinstance(response, dict) or set(response) not in (
                {"ok", "output_b64"}, {"ok", "error"},
            ):
                raise ProcessSupervisorError("worker_response_schema_invalid")
            if response["ok"] is not True:
                raise ProcessSupervisorError(str(response.get("error", "worker_failed")))
            try:
                output = base64.b64decode(response["output_b64"], validate=True)
            except (ValueError, TypeError) as exc:
                raise ProcessSupervisorError("worker_output_encoding_invalid") from exc
            if len(output) > MAX_OUTPUT_BYTES:
                raise ProcessSupervisorError("worker_output_too_large")
            if time.monotonic() >= deadline:
                raise ProcessDeadlineExceeded("worker_deadline_exceeded")
            return ProcessResult(
                operation=operation,
                output=output,
                process_id=process.pid or 0,
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )
        finally:
            receive_connection.close()
            try:
                send_connection.close()
            except OSError:
                pass
            if started_process and process.is_alive():
                self._stop(process)
            if started_process:
                process.close()
