"""Integration tests for the supervised whole-request HTTP boundary."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from multiprocessing.shared_memory import SharedMemory
import threading
import time
import unittest

from src.ingestion.supervised_http import (
    SupervisedHttpTransport,
    SupervisedTransportDeadlineExceeded,
    SupervisedTransportError,
)


class _Server:
    def __init__(self, handler):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/rpc"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=1)


class SupervisedHttpTests(unittest.TestCase):
    def test_close_reaps_worker_and_unlinks_shared_memory(self):
        transport = SupervisedHttpTransport()
        process = transport._process
        shared_name = transport._shared.name
        transport.close()
        self.assertFalse(process.is_alive())
        with self.assertRaises(FileNotFoundError):
            SharedMemory(name=shared_name, create=False)

    def test_request_completes_in_worker_and_preserves_response(self):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                payload = b'{"jsonrpc":"2.0","id":1,"result":"ok"}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            def log_message(self, *args):
                pass

        server = _Server(Handler)
        try:
            with SupervisedHttpTransport() as transport:
                status, payload = transport.request(
                    server.url, b"{}", timeout_seconds=2, max_response_bytes=1024,
                    deadline_monotonic=time.monotonic() + 3,
                )
                self.assertEqual(status, 200)
                self.assertEqual(payload, b'{"jsonrpc":"2.0","id":1,"result":"ok"}')
                self.assertTrue(transport.healthy)
        finally:
            server.close()

    def test_redirect_is_not_followed(self):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(302)
                self.send_header("Location", "/elsewhere")
                self.send_header("Content-Length", "0")
                self.end_headers()
            def log_message(self, *args):
                pass

        server = _Server(Handler)
        try:
            with SupervisedHttpTransport() as transport:
                status, payload = transport.request(
                    server.url, b"{}", timeout_seconds=2, max_response_bytes=1024,
                    deadline_monotonic=time.monotonic() + 3,
                )
                self.assertEqual(status, 302)
                self.assertEqual(payload, b"")
        finally:
            server.close()

    def test_response_read_is_capped(self):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                payload = b"x" * 100
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            def log_message(self, *args):
                pass

        server = _Server(Handler)
        try:
            with SupervisedHttpTransport() as transport:
                _status, payload = transport.request(
                    server.url, b"{}", timeout_seconds=2, max_response_bytes=8,
                    deadline_monotonic=time.monotonic() + 3,
                )
                self.assertEqual(len(payload), 9)
        finally:
            server.close()

    def test_oversized_url_is_rejected_before_ipc(self):
        transport = SupervisedHttpTransport()
        try:
            with self.assertRaisesRegex(SupervisedTransportError, "url_size_invalid"):
                transport.request(
                    "http://localhost/" + ("x" * 2048), b"{}",
                    timeout_seconds=1, max_response_bytes=128,
                    deadline_monotonic=time.monotonic() + 2,
                )
            self.assertTrue(transport.healthy)
        finally:
            transport.close()

    def test_waiter_deadline_does_not_abort_active_request(self):
        entered = threading.Event()
        release = threading.Event()

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                entered.set()
                release.wait(1.5)
                payload = b"ok"
                try:
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *args):
                pass

        server = _Server(Handler)
        transport = SupervisedHttpTransport()
        first_result = []
        def first_call():
            first_result.append(transport.request(
                server.url, b"{}", timeout_seconds=2, max_response_bytes=128,
                deadline_monotonic=time.monotonic() + 3,
            ))
        thread = threading.Thread(target=first_call)
        try:
            thread.start()
            self.assertTrue(entered.wait(1))
            with self.assertRaises(SupervisedTransportDeadlineExceeded):
                transport.request(
                    server.url, b"{}", timeout_seconds=1, max_response_bytes=128,
                    deadline_monotonic=time.monotonic() + 0.1,
                )
            self.assertTrue(transport.healthy)
            release.set()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(first_result, [(200, b"ok")])
            self.assertTrue(transport.healthy)
        finally:
            release.set()
            transport.close()
            server.close()

    def test_truncated_chunked_response_is_reported_without_worker_hang(self):
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.send_response(200)
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                self.wfile.write(b"5\r\nabc")
                self.wfile.flush()
                self.close_connection = True
            def log_message(self, *args):
                pass

        server = _Server(Handler)
        transport = SupervisedHttpTransport()
        try:
            with self.assertRaisesRegex(SupervisedTransportError, "transport_unavailable"):
                transport.request(
                    server.url, b"{}", timeout_seconds=2, max_response_bytes=128,
                    deadline_monotonic=time.monotonic() + 2,
                )
            self.assertTrue(transport.healthy)
        finally:
            transport.close()
            server.close()

    def test_slow_trickle_body_is_terminated_at_absolute_deadline(self):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.send_response(200)
                self.send_header("Content-Length", "20")
                self.end_headers()
                try:
                    for _ in range(20):
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.15)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *args):
                pass

        server = _Server(Handler)
        transport = SupervisedHttpTransport()
        try:
            deadline = time.monotonic() + 0.45
            started = time.monotonic()
            with self.assertRaises(SupervisedTransportDeadlineExceeded):
                transport.request(
                    server.url, b"{}", timeout_seconds=2, max_response_bytes=1024,
                    deadline_monotonic=deadline,
                )
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 1.2)
            self.assertFalse(transport.healthy)
            with self.assertRaises(Exception):
                transport.request(
                    server.url, b"{}", timeout_seconds=2, max_response_bytes=1024,
                    deadline_monotonic=time.monotonic() + 1,
                )
        finally:
            transport.close()
            server.close()


if __name__ == "__main__":
    unittest.main()
