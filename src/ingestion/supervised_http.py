"""Supervised whole-request HTTP transport for absolute-deadline callers.

A prestarted spawn worker performs DNS, TCP, TLS, HTTP, and body reads.
The parent waits on a multiprocessing event, never on a potentially partial
large-payload pipe receive. Bounded response bytes travel through shared memory.
"""
from __future__ import annotations

import math
import multiprocessing
import struct
import threading
import time
from multiprocessing.connection import Connection
from multiprocessing.shared_memory import SharedMemory
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

_HEADER = struct.Struct("!QII")  # request id, HTTP status (0 = transport error), payload length
_MAX_RESPONSE_BYTES = 8_388_608
_SHARED_CAPACITY = _HEADER.size + _MAX_RESPONSE_BYTES + 1
_MAX_REQUEST_BYTES = 65_536


class SupervisedTransportError(OSError):
    """Sanitized worker lifecycle or transport failure."""


class SupervisedTransportDeadlineExceeded(TimeoutError):
    """The parent deadline elapsed before the whole HTTP request completed."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def _http_worker(connection: Connection, shared_name: str, completed) -> None:
    """Spawn-safe worker entry point. Never returns exception text or secrets."""
    shared = None
    try:
        shared = SharedMemory(name=shared_name)
        connection.send(("ready",))
        while True:
            message = connection.recv()
            if message is None:
                return
            request_id, url, body, timeout_seconds, max_response_bytes = message
            status_code = 0
            payload = b""
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
                        status_code = int(response.status)
                except HTTPError as exc:
                    status_code = int(exc.code)
                    payload = b""
                if len(payload) > max_response_bytes + 1:
                    status_code, payload = 0, b""
            except (URLError, TimeoutError, OSError, ValueError):
                status_code, payload = 0, b""

            if len(payload) > _MAX_RESPONSE_BYTES + 1:
                status_code, payload = 0, b""
            shared.buf[_HEADER.size:_HEADER.size + len(payload)] = payload
            _HEADER.pack_into(shared.buf, 0, request_id, status_code, len(payload))
            completed.set()
    except (EOFError, OSError):
        return
    finally:
        if shared is not None:
            shared.close()
        connection.close()


class SupervisedHttpTransport:
    """One prestarted, serialized HTTP worker; timeout is fail-closed."""

    def __init__(self, *, startup_timeout_seconds: float = 5.0) -> None:
        if (isinstance(startup_timeout_seconds, bool)
                or not isinstance(startup_timeout_seconds, (int, float))
                or not math.isfinite(startup_timeout_seconds)
                or not 0.1 <= startup_timeout_seconds <= 30):
            raise SupervisedTransportError("worker_startup_timeout_invalid")
        self._ctx = multiprocessing.get_context("spawn")
        self._shared = SharedMemory(create=True, size=_SHARED_CAPACITY)
        parent, child = self._ctx.Pipe(duplex=True)
        self._connection = parent
        self._completed = self._ctx.Event()
        self._process = self._ctx.Process(
            target=_http_worker, args=(child, self._shared.name, self._completed),
            name="cryptic-http-transport", daemon=True,
        )
        self._lock = threading.Lock()
        self._closed = False
        self._poisoned = False
        self._shared_closed = False
        self._next_id = 1
        try:
            self._process.start()
            child.close()
            if not parent.poll(float(startup_timeout_seconds)):
                self._poisoned = True
                self._terminate()
                raise SupervisedTransportError("worker_startup_timeout")
            ready = parent.recv()
            if ready != ("ready",) or not self._process.is_alive():
                self._poisoned = True
                self._terminate()
                raise SupervisedTransportError("worker_startup_failed")
        except Exception:
            self._poisoned = True
            self._terminate()
            raise

    @property
    def healthy(self) -> bool:
        return not self._closed and not self._poisoned and self._process.is_alive()

    def _close_shared(self) -> None:
        if self._shared_closed:
            return
        self._shared_closed = True
        try:
            self._shared.close()
        finally:
            try:
                self._shared.unlink()
            except FileNotFoundError:
                pass

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
            self._close_shared()

    def request(
        self, url: str, body: bytes, *, timeout_seconds: float,
        max_response_bytes: int, deadline_monotonic: float,
    ) -> tuple[int, bytes]:
        if not isinstance(url, str) or not url or not isinstance(body, bytes):
            raise SupervisedTransportError("request_invalid")
        if len(body) > _MAX_REQUEST_BYTES:
            raise SupervisedTransportError("request_size_invalid")
        if (isinstance(timeout_seconds, bool)
                or not isinstance(timeout_seconds, (int, float))
                or not math.isfinite(timeout_seconds) or timeout_seconds <= 0):
            raise SupervisedTransportError("timeout_invalid")
        if (isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int)
                or not 1 <= max_response_bytes <= _MAX_RESPONSE_BYTES):
            raise SupervisedTransportError("response_limit_invalid")
        if (isinstance(deadline_monotonic, bool)
                or not isinstance(deadline_monotonic, (int, float))
                or not math.isfinite(deadline_monotonic)):
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
            self._completed.clear()
            bounded_timeout = min(float(timeout_seconds), remaining)
            try:
                self._connection.send((
                    request_id, url, body, bounded_timeout, max_response_bytes,
                ))
            except (EOFError, OSError):
                self._poisoned = True
                self._terminate()
                raise SupervisedTransportError("worker_unavailable") from None

            remaining = float(deadline_monotonic) - time.monotonic()
            if remaining <= 0 or not self._completed.wait(remaining):
                self._poisoned = True
                self._terminate()
                raise SupervisedTransportDeadlineExceeded("http_deadline_exceeded")

            response_id, status_code, payload_length = _HEADER.unpack_from(self._shared.buf, 0)
            if response_id != request_id or payload_length > max_response_bytes + 1:
                self._poisoned = True
                self._terminate()
                raise SupervisedTransportError("worker_protocol_mismatch")
            if time.monotonic() >= float(deadline_monotonic):
                self._poisoned = True
                self._terminate()
                raise SupervisedTransportDeadlineExceeded("http_deadline_exceeded")
            if status_code == 0:
                raise SupervisedTransportError("transport_unavailable")
            payload = bytes(self._shared.buf[_HEADER.size:_HEADER.size + payload_length])
            if time.monotonic() >= float(deadline_monotonic):
                self._poisoned = True
                self._terminate()
                raise SupervisedTransportDeadlineExceeded("http_deadline_exceeded")
            return int(status_code), payload
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
