"""Fail-closed WSGI transport for authenticated pool workers.

Mount only behind a TLS/mTLS gateway. The injected authenticator must derive
identity from verified transport credentials; this adapter never trusts a
worker_id field or an identity header supplied by the request.
"""
from __future__ import annotations

import json
from typing import Any, Callable

from src.mining.pool_service import PoolCoordinator, PoolServiceError

MAX_BODY_BYTES = 65_536


class PoolWSGI:
    def __init__(self, coordinator: PoolCoordinator, *,
                 worker_authenticator: Callable[[dict], str]):
        if not callable(worker_authenticator):
            raise ValueError("trusted_worker_authenticator_required")
        self.coordinator = coordinator
        self.worker_authenticator = worker_authenticator

    @staticmethod
    def _response(start_response: Callable, status: str, payload: dict):
        body = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        start_response(status, [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
        ])
        return [body]

    @staticmethod
    def _read_json(environ: dict) -> Any:
        if environ.get("CONTENT_TYPE", "").split(";")[0].strip().lower() != "application/json":
            raise PoolServiceError("content_type_must_be_application_json")
        try:
            length = int(environ.get("CONTENT_LENGTH") or "0")
        except ValueError as exc:
            raise PoolServiceError("content_length_invalid") from exc
        if length < 1 or length > MAX_BODY_BYTES:
            raise PoolServiceError("request_body_size_invalid")
        raw = environ["wsgi.input"].read(length)
        if len(raw) != length:
            raise PoolServiceError("request_body_truncated")

        def unique_object(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise PoolServiceError("request_json_duplicate_key")
                value[key] = item
            return value

        def reject_constant(_value):
            raise PoolServiceError("request_json_non_finite_number")

        try:
            value = json.loads(
                raw.decode("utf-8"), object_pairs_hook=unique_object,
                parse_constant=reject_constant,
            )
        except PoolServiceError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PoolServiceError("request_json_invalid") from exc
        if not isinstance(value, dict):
            raise PoolServiceError("request_body_must_be_object")
        return value

    def __call__(self, environ: dict, start_response: Callable):
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "")
        try:
            try:
                worker_id = self.worker_authenticator(environ)
            except Exception:
                return self._response(start_response, "401 Unauthorized",
                                      {"error": "WORKER_AUTHENTICATION_FAILED"})
            if not isinstance(worker_id, str) or not worker_id or len(worker_id.encode("utf-8")) > 256:
                return self._response(start_response, "401 Unauthorized",
                                      {"error": "WORKER_AUTHENTICATION_FAILED"})

            if method == "GET" and path.startswith("/v1/pool/jobs/"):
                job_id = path.rsplit("/", 1)[-1]
                return self._response(
                    start_response, "200 OK", self.coordinator.get_job(job_id, authenticated_worker_id=worker_id)
                )
            if method == "POST" and path == "/v1/pool/shares":
                submission = self._read_json(environ)
                result = self.coordinator.submit_share(
                    submission, authenticated_worker_id=worker_id
                )
                return self._response(start_response, "202 Accepted", result)
            return self._response(start_response, "404 Not Found", {"error": "NOT_FOUND"})
        except PoolServiceError as exc:
            message = str(exc)
            status = "404 Not Found" if message in ("job_not_found", "job_unknown") else (
                "403 Forbidden" if ("worker_identity" in message or "not_assigned_to_worker" in message) else "409 Conflict"
            )
            return self._response(start_response, status, {"error": message[:180]})
        except Exception:
            return self._response(start_response, "500 Internal Server Error",
                                  {"error": "INTERNAL_ERROR"})
