"""Production-facing, fail-closed HTTPS adapters for external trust services.

The remote services are authority boundaries, not locally simulated providers.
Every response is signed by a separately pinned Ed25519 key and bound to the
exact request, nonce, signer identity, and a short validity window. HTTPS uses
the platform CA store and hostname verification. No private key is stored here.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REQUEST_DOMAIN = b"CRYPTIC-REMOTE-REQUEST/1\x00"
RESPONSE_DOMAIN = b"CRYPTIC-REMOTE-RESPONSE/1\x00"
ANCHOR_DOMAIN = b"CRYPTIC-SEQUENCE-ANCHOR/1\x00"
DECISION_SCHEMA = "CRYPTIC-REMOTE-DECISION/1"
ANCHOR_SCHEMA = "CRYPTIC-SEQUENCE-ANCHOR/1"
MAX_RESPONSE_BYTES = 65_536
MAX_TTL_SECONDS = 300
MAX_CLOCK_SKEW_SECONDS = 30


class RemoteProviderError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _public_key(value: bytes) -> Ed25519PublicKey:
    if not isinstance(value, bytes) or len(value) != 32:
        raise RemoteProviderError("pinned_public_key_invalid")
    return Ed25519PublicKey.from_public_bytes(value)


def _verify_signature(key: Ed25519PublicKey, signature_text: Any,
                       domain: bytes, body: Mapping[str, Any]) -> None:
    if not isinstance(signature_text, str):
        raise RemoteProviderError("provider_signature_missing")
    try:
        signature = base64.b64decode(signature_text, validate=True)
        if len(signature) != 64:
            raise ValueError("signature_length")
        key.verify(signature, domain + _canonical(body))
    except (ValueError, InvalidSignature) as exc:
        raise RemoteProviderError("provider_signature_invalid") from exc


def _https_endpoint(value: str) -> str:
    if not isinstance(value, str):
        raise RemoteProviderError("endpoint_invalid")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise RemoteProviderError("https_endpoint_required")
    if parsed.query or parsed.fragment:
        raise RemoteProviderError("endpoint_query_or_fragment_forbidden")
    return value.rstrip("/")


def _default_transport(method: str, url: str, headers: Mapping[str, str],
                       body: bytes | None, timeout: float) -> tuple[int, Mapping[str, str], bytes]:
    request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read(MAX_RESPONSE_BYTES + 1)
            if len(data) > MAX_RESPONSE_BYTES:
                raise RemoteProviderError("provider_response_too_large")
            return response.status, dict(response.headers.items()), data
    except urllib.error.HTTPError as exc:
        data = exc.read(MAX_RESPONSE_BYTES + 1)
        if len(data) > MAX_RESPONSE_BYTES:
            raise RemoteProviderError("provider_response_too_large") from exc
        return exc.code, dict(exc.headers.items()), data
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RemoteProviderError("provider_unavailable") from exc


class SignedHTTPSDecisionClient:
    """POST decision client for GOD/GAIA-JUSTICE-compatible signed services.

    Service response fields are exactly:
      schema, signer_id, request_hash, decision, issued_at, expires_at,
      nonce, signature
    The signature covers every field except signature, under RESPONSE_DOMAIN.
    """

    def __init__(self, endpoint: str, *, signer_id: str, trusted_public_key: bytes,
                 timeout: float = 5.0, clock: Callable[[], float] = time.time,
                 transport: Callable | None = None):
        self.endpoint = _https_endpoint(endpoint)
        if not isinstance(signer_id, str) or not signer_id:
            raise RemoteProviderError("signer_id_invalid")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
            raise RemoteProviderError("timeout_invalid")
        self.signer_id = signer_id
        self.key = _public_key(trusted_public_key)
        self.timeout = float(timeout)
        self.clock = clock
        self.transport = transport or _default_transport

    def verify_decision(self, purpose: str, payload: Mapping[str, Any]) -> bool:
        if not isinstance(purpose, str) or not purpose or not isinstance(payload, Mapping):
            raise RemoteProviderError("decision_request_invalid")
        issued = int(self.clock())
        body = {
            "schema": DECISION_SCHEMA,
            "request_id": secrets.token_hex(16),
            "purpose": purpose,
            "payload": dict(payload),
            "issued_at": issued,
        }
        request_hash = hashlib.sha256(REQUEST_DOMAIN + _canonical(body)).hexdigest()
        status, _headers, raw = self.transport(
            "POST", self.endpoint,
            {"Content-Type": "application/json", "Accept": "application/json"},
            _canonical(body), self.timeout,
        )
        if status != 200:
            raise RemoteProviderError(f"provider_http_status_{status}")
        try:
            response = json.loads(raw)
        except (TypeError, json.JSONDecodeError) as exc:
            raise RemoteProviderError("provider_json_invalid") from exc
        required = {"schema", "signer_id", "request_hash", "decision",
                    "issued_at", "expires_at", "nonce", "signature"}
        if not isinstance(response, dict) or set(response) != required:
            raise RemoteProviderError("provider_response_schema_invalid")
        if response["schema"] != DECISION_SCHEMA or response["signer_id"] != self.signer_id:
            raise RemoteProviderError("provider_identity_mismatch")
        if response["request_hash"] != request_hash:
            raise RemoteProviderError("provider_request_binding_mismatch")
        if response["nonce"] != body["request_id"]:
            raise RemoteProviderError("provider_nonce_mismatch")
        now = int(self.clock())
        start, end = response["issued_at"], response["expires_at"]
        if (isinstance(start, bool) or not isinstance(start, int)
                or isinstance(end, bool) or not isinstance(end, int)
                or end < start or end - start > MAX_TTL_SECONDS
                or start > now + MAX_CLOCK_SKEW_SECONDS
                or end < now - MAX_CLOCK_SKEW_SECONDS):
            raise RemoteProviderError("provider_attestation_expired_or_invalid")
        unsigned = {k: v for k, v in response.items() if k != "signature"}
        _verify_signature(self.key, response["signature"], RESPONSE_DOMAIN, unsigned)
        if type(response["decision"]) is not bool:
            raise RemoteProviderError("provider_decision_invalid")
        return response["decision"]


class HTTPSJusticeProviders:
    """Builds the two independent callables required by JusticeEvidenceVerifier."""

    def __init__(self, *, policy: SignedHTTPSDecisionClient,
                 evidence: SignedHTTPSDecisionClient):
        if policy.signer_id == evidence.signer_id:
            raise RemoteProviderError("justice_providers_must_be_independent")
        self.policy = policy
        self.evidence = evidence

    @staticmethod
    def _payload(commitment: Mapping[str, Any], proposal: Mapping[str, Any]) -> dict:
        return {
            "commitment": dict(commitment),
            "proposal_hash": hashlib.sha256(_canonical(dict(proposal))).hexdigest(),
            "network_id": proposal.get("network_id"),
            "epoch": proposal.get("epoch"),
            "height": proposal.get("height"),
            "candidate_payload_hash": proposal.get("payload_hash"),
        }

    def verify_policy(self, commitment: Mapping[str, Any],
                      proposal: Mapping[str, Any]) -> bool:
        return self.policy.verify_decision(
            "GAIA-JUSTICE-POLICY/1", self._payload(commitment, proposal)
        )

    def verify_evidence(self, commitment: Mapping[str, Any],
                        proposal: Mapping[str, Any]) -> bool:
        return self.evidence.verify_decision(
            "GAIA-JUSTICE-EVIDENCE/1", self._payload(commitment, proposal)
        )


class HTTPSSequenceAnchor:
    """Atomic compare-and-swap client for an independent sequence-anchor service.

    Service contract:
      GET /v1/anchors/{quoted_network_id}
        -> signed {schema, signer_id, network_id, sequence, policy_hash,
                   issued_at, nonce, signature}; HTTP 404 means uninitialized.
      PUT same URL with If-None-Match:* for initialization or If-Match:"seq:hash"
        for advancement. Body contains schema, network_id, sequence, policy_hash,
        expected_sequence, expected_policy_hash, issued_at, nonce.
        -> signed {schema, signer_id, network_id, sequence, policy_hash,
                   accepted, issued_at, nonce, signature}.
      HTTP 409/412 is a compare-and-swap conflict. The server MUST commit the
      tuple atomically in storage protected independently from the node's DB.
    """

    def __init__(self, endpoint: str, *, signer_id: str, trusted_public_key: bytes,
                 timeout: float = 5.0, clock: Callable[[], float] = time.time,
                 transport: Callable | None = None):
        self.endpoint = _https_endpoint(endpoint)
        self.signer_id = signer_id
        if not isinstance(signer_id, str) or not signer_id:
            raise RemoteProviderError("signer_id_invalid")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
            raise RemoteProviderError("timeout_invalid")
        self.key = _public_key(trusted_public_key)
        self.timeout = float(timeout)
        self.clock = clock
        self.transport = transport or _default_transport

    def _url(self, network_id: str) -> str:
        if not isinstance(network_id, str) or not network_id or len(network_id) > 256:
            raise RemoteProviderError("anchor_network_id_invalid")
        return self.endpoint + "/v1/anchors/" + urllib.parse.quote(network_id, safe="")

    def _signed(self, raw: bytes, network_id: str, *, update: bool = False) -> dict:
        try:
            response = json.loads(raw)
        except (TypeError, json.JSONDecodeError) as exc:
            raise RemoteProviderError("anchor_json_invalid") from exc
        required = {"schema", "signer_id", "network_id", "sequence",
                    "policy_hash", "issued_at", "nonce", "signature"}
        if update:
            required.add("accepted")
        if not isinstance(response, dict) or set(response) != required:
            raise RemoteProviderError("anchor_response_schema_invalid")
        if response["schema"] != ANCHOR_SCHEMA or response["signer_id"] != self.signer_id:
            raise RemoteProviderError("anchor_identity_mismatch")
        if response["network_id"] != network_id:
            raise RemoteProviderError("anchor_network_mismatch")
        sequence, issued = response["sequence"], response["issued_at"]
        digest = response["policy_hash"]
        if (isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1
                or isinstance(issued, bool) or not isinstance(issued, int)
                or not isinstance(digest, str) or len(digest) != 64):
            raise RemoteProviderError("anchor_fields_invalid")
        try:
            if bytes.fromhex(digest).hex() != digest:
                raise ValueError("digest")
        except ValueError as exc:
            raise RemoteProviderError("anchor_hash_invalid") from exc
        now = int(self.clock())
        if abs(now - issued) > MAX_CLOCK_SKEW_SECONDS:
            raise RemoteProviderError("anchor_attestation_stale")
        unsigned = {k: v for k, v in response.items() if k != "signature"}
        _verify_signature(self.key, response["signature"], ANCHOR_DOMAIN, unsigned)
        return response

    def read_sequence(self, network_id: str) -> tuple[int, str] | None:
        status, _headers, raw = self.transport(
            "GET", self._url(network_id),
            {"Accept": "application/json"}, None, self.timeout,
        )
        if status == 404:
            return None
        if status != 200:
            raise RemoteProviderError(f"anchor_http_status_{status}")
        response = self._signed(raw, network_id)
        return response["sequence"], response["policy_hash"]

    def advance_sequence(self, network_id: str, sequence: int, policy_hash: str) -> bool:
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
            raise RemoteProviderError("anchor_sequence_invalid")
        if not isinstance(policy_hash, str) or len(policy_hash) != 64:
            raise RemoteProviderError("anchor_policy_hash_invalid")
        try:
            if bytes.fromhex(policy_hash).hex() != policy_hash:
                raise ValueError("hash")
        except ValueError as exc:
            raise RemoteProviderError("anchor_policy_hash_invalid") from exc
        current = self.read_sequence(network_id)
        if current is None:
            expected_sequence, expected_hash = 0, "0" * 64
            condition = {"If-None-Match": "*"}
        else:
            expected_sequence, expected_hash = current
            if sequence <= expected_sequence:
                return False
            condition = {"If-Match": f'"{expected_sequence}:{expected_hash}"'}
        body = {
            "schema": ANCHOR_SCHEMA, "network_id": network_id,
            "sequence": sequence, "policy_hash": policy_hash,
            "expected_sequence": expected_sequence,
            "expected_policy_hash": expected_hash,
            "issued_at": int(self.clock()), "nonce": secrets.token_hex(16),
        }
        status, _headers, raw = self.transport(
            "PUT", self._url(network_id),
            {"Content-Type": "application/json", "Accept": "application/json", **condition},
            _canonical(body), self.timeout,
        )
        if status in (409, 412):
            return False
        if status != 200:
            raise RemoteProviderError(f"anchor_http_status_{status}")
        response = self._signed(raw, network_id, update=True)
        if (response.get("accepted") is not True or response["sequence"] != sequence
                or response["policy_hash"] != policy_hash):
            raise RemoteProviderError("anchor_update_not_confirmed")
        return True


def load_independently_pinned_root(path: str, *, expected_fingerprint: str,
                                   expected_signer_id: str) -> bytes:
    """Load public root bytes while requiring a fingerprint supplied separately."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read(4097)
        if len(raw) > 4096:
            raise RemoteProviderError("root_pin_file_too_large")
        record = json.loads(raw)
    except RemoteProviderError:
        raise
    except (OSError, json.JSONDecodeError) as exc:
        raise RemoteProviderError("root_pin_file_unavailable_or_invalid") from exc
    if (not isinstance(record, dict)
            or set(record) != {"schema", "signer_id", "public_key_hex"}
            or record["schema"] != "CRYPTIC-GOD-ROOT-PIN/1"
            or record["signer_id"] != expected_signer_id):
        raise RemoteProviderError("root_pin_schema_or_identity_invalid")
    value = record["public_key_hex"]
    if not isinstance(value, str) or len(value) != 64:
        raise RemoteProviderError("root_public_key_invalid")
    try:
        key = bytes.fromhex(value)
    except ValueError as exc:
        raise RemoteProviderError("root_public_key_invalid") from exc
    fingerprint = hashlib.sha256(key).hexdigest()
    if fingerprint != expected_fingerprint:
        raise RemoteProviderError("root_fingerprint_pin_mismatch")
    _public_key(key)
    return key
