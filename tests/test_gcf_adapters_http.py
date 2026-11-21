import io
import json
import unittest

from src.consensus.http_api import GCFWSGI
from src.consensus.gcf import GateResult
from src.governance.god_adapter import GODNetworkAuthorizer
from src.governance.justice_adapter import JusticeEvidenceVerifier


class FakeGodGate:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def runnable(self, capability, endpoint):
        self.calls.append((capability, endpoint))
        return self.response


class GovernanceAdapterTests(unittest.TestCase):
    def test_god_adapter_denies_without_gate(self):
        adapter = GODNetworkAuthorizer(endpoint="https://consensus.example/v1")
        result = adapter("gcf.propose", {})
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "GOD_GATE_NOT_CONNECTED")

    def test_god_adapter_requests_explicit_gcf_capability(self):
        gate = FakeGodGate({"allowed": True, "reason": "authorized"})
        adapter = GODNetworkAuthorizer(gate, endpoint="https://consensus.example/v1")
        result = adapter("gcf.propose", {})
        self.assertTrue(result.allowed)
        self.assertEqual(gate.calls, [("gcf.consensus.propose", "https://consensus.example/v1")])

    def test_god_adapter_propagates_gate_denial(self):
        gate = FakeGodGate({"allowed": False, "reason": "unknown capability"})
        result = GODNetworkAuthorizer(gate, endpoint="https://consensus.example/v1")("gcf.propose", {})
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "unknown capability")

    def test_justice_adapter_requires_all_commitments_and_verifiers(self):
        commitment = {
            "justice_profile": "GAIA-JUSTICE/1",
            "policy_hash": "1" * 64,
            "policy_audit_hash": "2" * 64,
            "evidence_root": "3" * 64,
            "transition_hash": "4" * 64,
            "value_accounting_hash": "5" * 64,
            "challenge_state_hash": "6" * 64,
        }
        proposal = {"justice_commitment": commitment}
        denied = JusticeEvidenceVerifier()(proposal)
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.reason, "JUSTICE_EVIDENCE_VERIFIERS_NOT_CONFIGURED")
        allowed = JusticeEvidenceVerifier(lambda *_: True, lambda *_: True)(proposal)
        self.assertTrue(allowed.allowed)

    def test_justice_adapter_rejects_missing_evidence_field(self):
        result = JusticeEvidenceVerifier(lambda *_: True, lambda *_: True)(
            {"justice_commitment": {"justice_profile": "GAIA-JUSTICE/1"}}
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "JUSTICE_COMMITMENT_SCHEMA_INVALID")


class StubEngine:
    def get_status(self, digest):
        return {"status": "RECEIVED", "candidate_digest": digest}


class GCFHTTPTests(unittest.TestCase):
    def invoke(self, app, method, path, body=b"", content_type="application/json"):
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_TYPE": content_type,
            "CONTENT_LENGTH": str(len(body)),
            "wsgi.input": io.BytesIO(body),
        }
        captured = {}
        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)
        response = b"".join(app(environ, start_response))
        return captured, json.loads(response.decode())

    def test_candidate_status_endpoint(self):
        app = GCFWSGI(StubEngine())
        meta, payload = self.invoke(app, "GET", "/v1/consensus/candidates/" + "a" * 64)
        self.assertEqual(meta["status"], "200 OK")
        self.assertEqual(payload["status"], "RECEIVED")

    def test_unknown_route_returns_404(self):
        meta, payload = self.invoke(GCFWSGI(StubEngine()), "GET", "/not-a-route")
        self.assertEqual(meta["status"], "404 Not Found")
        self.assertEqual(payload["error"], "NOT_FOUND")

    def test_post_requires_json_content_type(self):
        meta, payload = self.invoke(
            GCFWSGI(StubEngine()), "POST", "/v1/consensus/proposals",
            b"{}", content_type="text/plain",
        )
        self.assertEqual(meta["status"], "400 Bad Request")
        self.assertIn("CONTENT_TYPE", payload["error"])


if __name__ == "__main__":
    unittest.main()
