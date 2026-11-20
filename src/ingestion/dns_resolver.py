"""Prestarted, supervised DNS resolution for deadline-aware transports.

The resolver process is started during adapter preparation, before a source
collection deadline begins. A timed-out lookup poisons and terminates the
worker; it is never silently restarted inside the active deadline.
"""
from __future__ import annotations

import ipaddress
import multiprocessing
import socket
import threading
import time
from multiprocessing.connection import Connection
from typing import Any


class DnsResolverError(RuntimeError):
    """Sanitized resolver lifecycle or lookup failure."""


class DnsResolverDeadlineExceeded(TimeoutError):
    """DNS resolution did not complete before the supplied monotonic deadline."""


def _resolver_worker(connection: Connection) -> None:
    """Child-process entry point; keep it module-level for spawn platforms."""
    try:
        connection.send(("ready", None))
        while True:
            message = connection.recv()
            if message is None:
                return
            request_id, hostname, port = message
            try:
                rows = socket.getaddrinfo(
                    hostname, port, family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP,
                )
                addresses: set[tuple[int, str]] = set()
                for family, socktype, proto, _canonname, sockaddr in rows:
                    if family not in (socket.AF_INET, socket.AF_INET6):
                        continue
                    if socktype != socket.SOCK_STREAM:
                        continue
                    if family == socket.AF_INET6 and len(sockaddr) > 3 and sockaddr[3]:
                        # The transport tuple cannot preserve an interface scope.
                        continue
                    address = str(ipaddress.ip_address(sockaddr[0]))
                    addresses.add((family, address))
                connection.send((request_id, ("ok", tuple(sorted(addresses)))))
            except (OSError, ValueError, OverflowError):
                connection.send((request_id, ("error", "dns_lookup_failed")))
    except (EOFError, OSError):
        return
    finally:
        connection.close()


class IsolatedDnsResolver:
    """One prestarted DNS worker with bounded waits and fail-closed poisoning.

    Construct this object before starting the collection deadline. The
    constructor waits at most startup_timeout_seconds for the worker's ready
    handshake. A lookup timeout terminates the worker and makes this instance
    permanently unusable; callers must abort that collection session.
    """

    def __init__(self, *, startup_timeout_seconds: float = 5.0) -> None:
        if (isinstance(startup_timeout_seconds, bool)
                or not isinstance(startup_timeout_seconds, (int, float))
                or not 0.1 <= startup_timeout_seconds <= 30):
            raise DnsResolverError("startup_timeout_invalid")
        self._ctx = multiprocessing.get_context("spawn")
        parent, child = self._ctx.Pipe(duplex=True)
        self._connection = parent
        self._process = self._ctx.Process(
            target=_resolver_worker, args=(child,),
            name="cryptic-dns-resolver", daemon=True,
        )
        self._lock = threading.Lock()
        self._closed = False
        self._poisoned = False
        self._next_id = 1
        self._process.start()
        child.close()
        if not parent.poll(float(startup_timeout_seconds)):
            self._terminate()
            raise DnsResolverError("resolver_startup_timeout")
        try:
            status, _ = parent.recv()
        except (EOFError, OSError):
            self._terminate()
            raise DnsResolverError("resolver_startup_failed") from None
        if status != "ready" or not self._process.is_alive():
            self._terminate()
            raise DnsResolverError("resolver_startup_failed")

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

    def resolve(self, hostname: str, port: int, *, deadline_monotonic: float) -> tuple[tuple[int, str], ...]:
        if not isinstance(hostname, str) or not hostname or len(hostname) > 253:
            raise DnsResolverError("hostname_invalid")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise DnsResolverError("port_invalid")
        if isinstance(deadline_monotonic, bool) or not isinstance(deadline_monotonic, (int, float)):
            raise DnsResolverError("deadline_invalid")
        remaining = float(deadline_monotonic) - time.monotonic()
        if remaining <= 0:
            raise DnsResolverDeadlineExceeded("dns_deadline_exceeded")
        try:
            literal = ipaddress.ip_address(hostname)
            if isinstance(literal, ipaddress.IPv6Address) and literal.scope_id:
                raise DnsResolverError("scoped_ipv6_unsupported")
            return ((socket.AF_INET6 if literal.version == 6 else socket.AF_INET, str(literal)),)
        except ValueError:
            pass
        if not self._lock.acquire(timeout=remaining):
            raise DnsResolverDeadlineExceeded("dns_deadline_exceeded")
        try:
            if self._closed or self._poisoned or not self._process.is_alive():
                raise DnsResolverError("resolver_unavailable")
            remaining = float(deadline_monotonic) - time.monotonic()
            if remaining <= 0:
                raise DnsResolverDeadlineExceeded("dns_deadline_exceeded")
            request_id = self._next_id
            self._next_id += 1
            try:
                self._connection.send((request_id, hostname, port))
                if not self._connection.poll(remaining):
                    self._poisoned = True
                    self._terminate()
                    raise DnsResolverDeadlineExceeded("dns_deadline_exceeded")
                response_id, result = self._connection.recv()
            except DnsResolverDeadlineExceeded:
                raise
            except (EOFError, OSError):
                self._poisoned = True
                self._terminate()
                raise DnsResolverError("resolver_unavailable") from None
            if response_id != request_id:
                self._poisoned = True
                self._terminate()
                raise DnsResolverError("resolver_protocol_mismatch")
            if time.monotonic() >= float(deadline_monotonic):
                self._poisoned = True
                self._terminate()
                raise DnsResolverDeadlineExceeded("dns_deadline_exceeded")
            status, value = result
            if status != "ok":
                raise DnsResolverError("dns_lookup_failed")
            if not value:
                raise DnsResolverError("dns_no_addresses")
            return tuple(value)
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

    def __enter__(self) -> "IsolatedDnsResolver":
        if not self.healthy:
            raise DnsResolverError("resolver_unavailable")
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()
