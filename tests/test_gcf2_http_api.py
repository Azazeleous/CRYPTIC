import io
import json
import unittest

from src.consensus.http_api import GCFWSGI


class FakeGCF2Store:
    def submit_vote(self, vote):
        return {"accepted": True, "vote_kind": vote["vote_kind"]}

    def get_finality_certificate(self, *, height):
        return {"schema": "GCF/2", "height": height}

    def activate_finality_certificate(self, *, height):
        return {"activated": True, "anchor_sequence": height}

    def get_finality_activation(self, *, height):
        return {"anchor_sequence": height, "certificate_digest": "ab" * 32}


class GCF2HTTPTests(unittest.TestCase):
    def request(self, app, method, path, payload=None):
        raw = b"" if payload is None else json.dumps(payload).encode()
        environ = {
            "REQUEST_METHOD": method, "PATH_INFO": path,
            "CONTENT_TYPE": "application/json" if payload is not None else "",
            "CONTENT_LENGTH": str(len(raw)), "wsgi.input": io.BytesIO(raw),
        }
        status = []
        headers = []
        def start_response(value, response_headers):
            status.append(value)
            headers.extend(response_headers)
        body = b"".join(app(environ, start_response))
        return status[0], json.loads(body), dict(headers)

    def test_gcf2_vote_finality_and_activation_routes(self):
        app = GCFWSGI(object(), gcf2_vote_store=FakeGCF2Store())
        status, body, headers = self.request(
            app, "POST", "/v2/consensus/votes",
            {"vote_kind": "NIL"},
        )
        self.assertEqual(status, "202 Accepted")
        self.assertTrue(body["accepted"])
        self.assertEqual(headers["Cache-Control"], "no-store")

        status, body, _ = self.request(app, "GET", "/v2/consensus/finality/5")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["height"], 5)

        status, body, _ = self.request(app, "POST", "/v2/consensus/activate/5")
        self.assertEqual(status, "200 OK")
        self.assertTrue(body["activated"])

        status, body, _ = self.request(app, "GET", "/v2/consensus/activation/5")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["anchor_sequence"], 5)

    def test_gcf2_routes_fail_closed_when_store_is_disabled(self):
        app = GCFWSGI(object())
        status, body, _ = self.request(app, "POST", "/v2/consensus/votes", {})
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "GCF2_NOT_ENABLED")


if __name__ == "__main__":
    unittest.main()
