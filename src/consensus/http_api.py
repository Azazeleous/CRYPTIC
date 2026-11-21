"""Small WSGI adapter for the GCF/1 submission and finality endpoints.

Mount behind an authenticated TLS reverse proxy. This adapter intentionally
contains no authentication bypass, CORS policy, or public-server launcher.
"""
from __future__ import annotations

import json
from typing import Any, Callable

from src.consensus.gcf import GCFError, GCFEngine, canonical_bytes


MAX_BODY_BYTES = 1_048_576


class GCFWSGI:
    def __init__(self, engine: GCFEngine):
        self.engine = engine

    @staticmethod
    def _response(start_response: Callable, status: str, payload: dict):
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
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
            raise GCFError("CONTENT_TYPE_MUST_BE_APPLICATION_JSON")
        try:
            length = int(environ.get("CONTENT_LENGTH") or "0")
        except ValueError as exc:
            raise GCFError("CONTENT_LENGTH_INVALID") from exc
        if length < 1 or length > MAX_BODY_BYTES:
            raise GCFError("REQUEST_BODY_SIZE_INVALID")
        raw = environ["wsgi.input"].read(length)
        if len(raw) != length:
            raise GCFError("REQUEST_BODY_TRUNCATED")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GCFError("REQUEST_JSON_INVALID") from exc
        if not isinstance(value, dict):
            raise GCFError("REQUEST_BODY_MUST_BE_OBJECT")
        return value

    def __call__(self, environ: dict, start_response: Callable):
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "")
        try:
            if method == "POST" and path == "/v1/consensus/proposals":
                result = self.engine.submit_proposal(self._read_json(environ))
                return self._response(start_response, "202 Accepted", result)
            if method == "POST" and path == "/v1/consensus/votes":
                result = self.engine.submit_vote(self._read_json(environ))
                return self._response(start_response, "202 Accepted", result)
            if method == "POST" and path.startswith("/v1/consensus/finalize/"):
                digest = path.rsplit("/", 1)[-1]
                result = self.engine.finalize(digest)
                return self._response(start_response, "200 OK", result)
            if method == "GET" and path.startswith("/v1/consensus/candidates/"):
                digest = path.rsplit("/", 1)[-1]
                return self._response(start_response, "200 OK", self.engine.get_status(digest))
            return self._response(start_response, "404 Not Found", {"error": "NOT_FOUND"})
        except GCFError as exc:
            message = str(exc)
            status = "403 Forbidden" if message.startswith(
                ("GOD_POLICY_DENIED", "MINER_PROOF_INVALID", "JUSTICE_VALIDATION_FAILED")
            ) else "409 Conflict" if "REPLAY" in message or "DUPLICATE" in message else "400 Bad Request"
            return self._response(start_response, status, {"error": message})
        except Exception:
            # Do not disclose database paths, key material, or internal exceptions.
            return self._response(start_response, "500 Internal Server Error",
                                  {"error": "INTERNAL_ERROR"})
