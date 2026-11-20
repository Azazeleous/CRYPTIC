"""Supervised whole-request HTTP transport for absolute-deadline callers.

The worker is spawned and handshaken during adapter preparation. DNS, connect,
TLS, request, headers, and body reads all happen inside that process. A parent
deadline timeout terminates and permanently poisons the worker.
"""
from __future__ import annotations

import math
import multiprocessing
import threading
import time
from multiprocessing.connection import Connection
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener


class SupervisedTransportError(OSError):
    """Sanitized worker lifecycle or transport failure."""


class SupervisedTransportDeadlineExceeded(TimeoutError):
    """The parent deadline elapsed before the whole HTTP request completed."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def _http_worker(connection: Connection) -> None:
    """Spawn-safe worker entry point. Never returns exception text or secrets."""
    try:
        connection.send(("ready",))
        while True:
            message = connection.recv()
            if message is None:
                return
            request_id, url, body, timeout_seconds, max_response_bytes = message
            try:
                request = Request(
                    url, data=body,
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    method="POST",
                )
                opener = build_opener(_NoRedirect())
                try:
                    with opener.open(request, timeout=timeout_seconds) as response:
                        payload = response.read(max_response_bytes + 1)
                        status = int(response.status)
                except HTTPError as exc:
                    status, payload = int(exc.code), b""
                connection.send((request_id, "ok", status, payload))
            except (URLError, TimeoutError, OSError, ValueError):
                connection.send((request_id, "transport", 0, b""))
    except (EOFError, OSError):
        return
    finally:
        connection.close()


class SupervisedHttpTransport:
    """One prestarted, serialized HTTP worker; timeout is fail-closed."""

    def __init__(self, *, startup_timeout_seconds: float = 5.0) -> None:
        if (isinstance(startup_timeout_seconds, bool)
                or not isinstance(startup_timeout_seconds, (int, float))
                or not 0.1 <= startup_timeout_seconds <= 30):
            raise SupervisedTransportError("worker_startup_timeout_invalid")
        self._ctx = multiprocessing.get_context("spawn")
        parent, child = self._ctx.Pipe(duplex=True)
        self._connection = parent
        self._process = self._ctx.Process(
            target=_http_worker, args=(child,),
            name="cryptic-http-transport", daemon=True,
        )
        self._lock = threading.Lock()
        self._closed = False
        self._poisoned = False
        self._next_id = 1
        self._process.start()
        child.close()
        if not parent.poll(float(startup_timeout_seconds)):
            self._poisoned = True
            self._terminate()
            raise SupervisedTransportError("worker_startup_timeout")
        try:
            ready = parent.recv()
        except (EOFError, OSError):
            self._poisoned = True
            self._terminate()
            raise SupervisedTransportError("worker_startup_failed") from None
        if ready != ("ready",) or not self._process.is_alive():
            self._poisoned = True
            self._terminate()
            raise SupervisedTransportError("worker_startup_failed")

    @property
    def healthy(self) -> bool:
        return not self._closed and not self._poisoned and self._process.is_alive()

    def _terminate(self) -> None:
        try:
            if self._process.is_alive():
                self._process.terminate()
            self._process.join(timeout=0.25)
            if self._process.is_alive():
                self._process.kill()
                self._process.join(timeout=0.25)
        finally:
            try:
                self._connection.close()
            except OSError:
                pass

    def request(
        self, url: str, body: bytes, *, timeout_seconds: float,
        max_response_bytes: int, deadline_monotonic: float,
    ) -> tuple[int, bytes]:
        if not isinstance(url, str) or not url or not isinstance(body, bytes):
            raise SupervisedTransportError("request_invalid")
        if len(body) > 1_048_576:
            raise SupervisedTransportError("request_size_invalid")
        if (isinstance(timeout_seconds, bool)
                or not isinstance(timeout_seconds, (int, float))
                or not math.isfinite(timeout_seconds) or timeout_seconds <= 0):
            raise SupervisedTransportError("timeout_invalid")
        if (isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int)
                or max_response_bytes < 1):
            raise SupervisedTransportError("response_limit_invalid")
        if isinstance(deadline_monotonic, bool) or not isinstance(deadline_monotonic, (int, float)):
            raise SupervisedTransportError("deadline_invalid")
        remaining = float(deadline_monotonic) - time.monotonic()
        if remaining <= 0:
            raise SupervisedTransportDeadlineExceeded("http_deadline_exceeded")
        if not self._lock.acquire(timeout=remaining):
            self._poisoned = True
            self._terminate()
            raise SupervisedTransportDeadlineExceeded("http_deadline_exceeded")
        try:
            if not self.healthy:
                raise SupervisedTransportError("worker_unavailable")
            remaining = float(deadline_monotonic) - time.monotonic()
            if remaining <= 0:
                self._poisoned = True
                self._terminate()
                raise SupervisedTransportDeadlineExceeded("http_deadline_exceeded")
            request_id = self._next_id
            self._next_id += 1
            bounded_timeout = min(float(timeout_seconds), remaining)
            try:
                self._connection.send((
                    request_id, url, body, bounded_timeout, max_response_bytes,
                ))
                if not self._connection.poll(remaining):
                    self._poisoned = True
                    self._terminate()
                    raise SupervisedTransportDeadlineExceeded("http_deadline_exceeded")
                response = self._connection.recv()
            except SupervisedTransportDeadlineExceeded:
                raise
            except (EOFError, OSError):
                self._poisoned = True
                self._terminate()
                raise SupervisedTransportError("worker_unavailable") from None
            if (not isinstance(response, tuple) or len(response) != 4
                    or response[0] != request_id):
                self._poisoned = True
                self._terminate()
                raise SupervisedTransportError("worker_protocol_mismatch")
            _response_id, status, http_status, payload = response
            if time.monotonic() >= float(deadline_monotonic):
                self._poisoned = True
                self._terminate()
                raise SupervisedTransportDeadlineExceeded("http_deadline_exceeded")
            if status != "ok":
                raise SupervisedTransportError("transport_unavailable")
            if not isinstance(payload, bytes) or len(payload) > max_response_bytes + 1:
                raise SupervisedTransportError("worker_response_invalid")
            return int(http_status), payload
        finally:
            self._lock.release()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._process.is_alive() and not self._poisoned:
            try:
                self._connection.send(None)
            except (EOFError, OSError):
                pass
            self._process.join(timeout=0.25)
        self._terminate()

    def __enter__(self) -> "SupervisedHttpTransport":
        if not self.healthy:
            raise SupervisedTransportError("worker_unavailable")
        return self

    def __exit__(self, exc_type: Any, exc, traceback) -> None:
        self.close()
