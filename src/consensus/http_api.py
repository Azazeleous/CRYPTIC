"""Small WSGI adapter for the GCF/1 submission and finality endpoints.

Mount behind an authenticated TLS reverse proxy. This adapter intentionally
contains no authentication bypass, CORS policy, or public-server launcher.
"""
from __future__ import annotations

import base64
import json
from typing import Any, Callable

from src.consensus.gcf import GCFError, GCFEngine


MAX_BODY_BYTES = 1_048_576


class GCFWSGI:
    def __init__(self, engine: GCFEngine, apex_validator=None):
        self.engine = engine
        self.apex_validator = apex_validator

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
        def unique_object(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise GCFError("REQUEST_JSON_DUPLICATE_KEY")
                value[key] = item
            return value
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
        except GCFError:
            raise
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
            if method == "POST" and path == "/v1/adam/commit":
                if self.apex_validator is None:
                    raise GCFError("ADAM_APEX_NOT_CONFIGURED")
                request = self._read_json(environ)
                if set(request) != {"certificate", "state_b64"}:
                    raise GCFError("ADAM_COMMIT_FIELDS_INVALID")
                encoded = request["state_b64"]
                if not isinstance(encoded, str) or len(encoded) > ((MAX_BODY_BYTES * 4 // 3) + 8):
                    raise GCFError("ADAM_STATE_ENCODING_INVALID")
                try:
                    state_bytes = base64.b64decode(encoded, validate=True)
                except (ValueError, TypeError) as exc:
                    raise GCFError("ADAM_STATE_ENCODING_INVALID") from exc
                if len(state_bytes) > MAX_BODY_BYTES:
                    raise GCFError("ADAM_STATE_TOO_LARGE")
                result = self.apex_validator.validate_and_commit(
                    request["certificate"], state_bytes
                )
                return self._response(start_response, "201 Created", result)
            if method == "GET" and path == "/v1/adam/head":
                if self.apex_validator is None:
                    raise GCFError("ADAM_APEX_NOT_CONFIGURED")
                return self._response(
                    start_response, "200 OK", self.apex_validator.store.head()
                )
            if method == "GET" and path.startswith("/v1/adam/commits/"):
                if self.apex_validator is None:
                    raise GCFError("ADAM_APEX_NOT_CONFIGURED")
                raw_height = path.rsplit("/", 1)[-1]
                if not raw_height.isascii() or not raw_height.isdigit():
                    raise GCFError("ADAM_HEIGHT_INVALID")
                record = self.apex_validator.store.get_commit(int(raw_height))
                if record is None:
                    return self._response(start_response, "404 Not Found", {"error": "ADAM_COMMIT_NOT_FOUND"})
                record["state_b64"] = base64.b64encode(record.pop("state_bytes")).decode("ascii")
                return self._response(start_response, "200 OK", record)
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
