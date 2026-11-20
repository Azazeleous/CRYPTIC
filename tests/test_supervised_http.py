"""Integration tests for the supervised whole-request HTTP boundary."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time
import unittest

from src.ingestion.supervised_http import (
    SupervisedHttpTransport,
    SupervisedTransportDeadlineExceeded,
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
