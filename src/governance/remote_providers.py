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
import os
import stat
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REQUEST_DOMAIN = b"CRYPTIC-REMOTE-REQUEST/1\x00"
RESPONSE_DOMAIN = b"CRYPTIC-REMOTE-RESPONSE/1\x00"
ANCHOR_DOMAIN = b"CRYPTIC-SEQUENCE-ANCHOR/1\x00"
DECISION_SCHEMA = "CRYPTIC-REMOTE-DECISION/1"
ANCHOR_SCHEMA = "CRYPTIC-SEQUENCE-ANCHOR/1"
POLICY_TRANSITION_SCHEMA = "CRYPTIC-GOD-POLICY-TRANSITION/1"
POLICY_TRANSITION_REQUEST_SCHEMA = "CRYPTIC-GOD-POLICY-TRANSITION-REQUEST/1"
POLICY_TRANSITION_DOMAIN = b"CRYPTIC-GOD-POLICY-TRANSITION/1\x00"
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
        policy_key = policy.key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        evidence_key = evidence.key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        if (policy.signer_id == evidence.signer_id
                or policy.endpoint == evidence.endpoint
                or policy_key == evidence_key):
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


class SignedHTTPSPolicyTransitionClient:
    """Obtain and verify GOD authorization for one exact anchor transition.

    The remote authority must evaluate its actual governance rules before
    signing. This client verifies the signed response; the anchor Worker
    independently verifies it again before accepting the transition.
    """

    def __init__(self, endpoint: str, *, signer_id: str, policy_id: str,
                 trusted_public_key: bytes, request_token: str | None = None,
                 timeout: float = 5.0, clock: Callable[[], float] = time.time,
                 transport: Callable | None = None):
        self.endpoint = _https_endpoint(endpoint)
        if not isinstance(signer_id, str) or not signer_id:
            raise RemoteProviderError("policy_transition_signer_id_invalid")
        if not isinstance(policy_id, str) or not policy_id:
            raise RemoteProviderError("policy_transition_policy_id_invalid")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
            raise RemoteProviderError("timeout_invalid")
        self.signer_id = signer_id
        self.policy_id = policy_id
        if request_token is None:
            request_token = os.environ.get("CRYPTIC_GOD_POLICY_TOKEN")
        if (not isinstance(request_token, str) or len(request_token) < 32
                or any(ch.isspace() for ch in request_token)):
            raise RemoteProviderError("god_policy_request_authentication_required")
        self.request_token = request_token
        self.key = _public_key(trusted_public_key)
        self.timeout = float(timeout)
        self.clock = clock
        self.transport = transport or _default_transport

    def authorize_transition(self, transition: Mapping[str, Any]) -> dict:
        if not isinstance(transition, Mapping):
            raise RemoteProviderError("policy_transition_request_invalid")
        required_transition = {
            "network_id", "sequence", "policy_hash",
            "expected_sequence", "expected_policy_hash",
        }
        if set(transition) != required_transition:
            raise RemoteProviderError("policy_transition_request_schema_invalid")
        network_id = transition["network_id"]
        sequence = transition["sequence"]
        expected_sequence = transition["expected_sequence"]
        policy_hash = transition["policy_hash"]
        expected_hash = transition["expected_policy_hash"]
        if (not isinstance(network_id, str) or not network_id or len(network_id.encode("utf-8")) > 256
                or isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1
                or isinstance(expected_sequence, bool) or not isinstance(expected_sequence, int)
                or expected_sequence < 0 or sequence <= expected_sequence):
            raise RemoteProviderError("policy_transition_fields_invalid")
        for digest in (policy_hash, expected_hash):
            if (not isinstance(digest, str) or len(digest) != 64
                    or any(ch not in "0123456789abcdef" for ch in digest)):
                raise RemoteProviderError("policy_transition_hash_invalid")
        issued_at = int(self.clock())
        nonce = secrets.token_hex(16)
        request_body = {
            "schema": POLICY_TRANSITION_REQUEST_SCHEMA,
            "capability": "cryptic.sequence_anchor.advance",
            "policy_id": self.policy_id,
            "network_id": network_id,
            "expected_sequence": expected_sequence,
            "expected_policy_hash": expected_hash,
            "sequence": sequence,
            "policy_hash": policy_hash,
            "issued_at": issued_at,
            "nonce": nonce,
        }
        status, _headers, raw = self.transport(
            "POST", self.endpoint,
            {"Content-Type": "application/json", "Accept": "application/json",
             "Authorization": "Bearer " + self.request_token},
            _canonical(request_body), self.timeout,
        )
        if status != 200:
            raise RemoteProviderError(f"god_policy_transition_http_status_{status}")
        try:
            authorization = json.loads(raw)
        except (TypeError, json.JSONDecodeError) as exc:
            raise RemoteProviderError("god_policy_transition_json_invalid") from exc
        if _canonical(authorization) != raw:
            raise RemoteProviderError("god_policy_transition_noncanonical_json")
        required = {
            "schema", "signer_id", "capability", "policy_id", "network_id",
            "expected_sequence", "expected_policy_hash", "sequence",
            "policy_hash", "issued_at", "expires_at", "nonce", "signature",
        }
        if not isinstance(authorization, dict) or set(authorization) != required:
            raise RemoteProviderError("god_policy_transition_response_schema_invalid")
        expected = {
            "schema": POLICY_TRANSITION_SCHEMA,
            "signer_id": self.signer_id,
            "capability": request_body["capability"],
            "policy_id": self.policy_id,
            "network_id": network_id,
            "expected_sequence": expected_sequence,
            "expected_policy_hash": expected_hash,
            "sequence": sequence,
            "policy_hash": policy_hash,
            "issued_at": issued_at,
            "nonce": nonce,
        }
        if any(authorization.get(key) != value for key, value in expected.items()):
            raise RemoteProviderError("god_policy_transition_binding_mismatch")
        expires_at = authorization["expires_at"]
        now = int(self.clock())
        if (isinstance(authorization["issued_at"], bool)
                or not isinstance(authorization["issued_at"], int)
                or isinstance(authorization["sequence"], bool)
                or not isinstance(authorization["sequence"], int)
                or isinstance(authorization["expected_sequence"], bool)
                or not isinstance(authorization["expected_sequence"], int)
                or isinstance(expires_at, bool) or not isinstance(expires_at, int)
                or expires_at <= issued_at
                or expires_at - issued_at > MAX_TTL_SECONDS
                or issued_at > now + MAX_CLOCK_SKEW_SECONDS
                or expires_at < now - MAX_CLOCK_SKEW_SECONDS):
            raise RemoteProviderError("god_policy_transition_expired_or_invalid")
        unsigned = {key: value for key, value in authorization.items()
                    if key != "signature"}
        _verify_signature(self.key, authorization["signature"],
                          POLICY_TRANSITION_DOMAIN, unsigned)
        return authorization


class HTTPSSequenceAnchor:
    """Atomic compare-and-swap client for an independent sequence-anchor service.

    Service contract:
      GET /v1/anchors/{quoted_network_id}
        -> signed {schema, signer_id, network_id, sequence, policy_hash,
                   issued_at, nonce, signature}; HTTP 404 means uninitialized.
      PUT same URL with If-None-Match:* for initialization or If-Match:"seq:hash"
        for advancement. Body contains schema, network_id, sequence, policy_hash,
        expected_sequence, expected_policy_hash, issued_at, nonce, and a
        GOD-signed authorization obtained from authorization_provider. The
        provider is called after the signed prior tuple is read.
        -> signed {schema, signer_id, network_id, sequence, policy_hash,
                   accepted, issued_at, nonce, signature}.
      HTTP 409/412 is a compare-and-swap conflict. The server MUST commit the
      tuple atomically in storage protected independently from the node's DB.
    Writes carry a GCF/1 finality certificate; the Worker verifies it against
    an independently pinned validator set. No GOD transition service is used.
    """

    def __init__(self, endpoint: str, *, signer_id: str, trusted_public_key: bytes,
                 write_token: str | None = None,
                 authorization_provider: SignedHTTPSPolicyTransitionClient | None = None,
                 timeout: float = 5.0, clock: Callable[[], float] = time.time,
                 transport: Callable | None = None):
        self.endpoint = _https_endpoint(endpoint)
        self.signer_id = signer_id
        if not isinstance(signer_id, str) or not signer_id:
            raise RemoteProviderError("signer_id_invalid")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
            raise RemoteProviderError("timeout_invalid")
        if write_token is None:
            write_token = os.environ.get("CRYPTIC_SEQUENCE_ANCHOR_TOKEN")
        if write_token is not None and (
                not isinstance(write_token, str) or len(write_token) < 32
                or any(ch.isspace() for ch in write_token)):
            raise RemoteProviderError("anchor_write_token_invalid")
        self.write_token = write_token
        self.authorization_provider = authorization_provider
        self.key = _public_key(trusted_public_key)
        self.timeout = float(timeout)
        self.clock = clock
        self.transport = transport or _default_transport

    def _url(self, network_id: str) -> str:
        if not isinstance(network_id, str) or not network_id or len(network_id) > 256:
            raise RemoteProviderError("anchor_network_id_invalid")
        return self.endpoint + "/v1/anchors/" + urllib.parse.quote(network_id, safe="")

    def _signed(self, raw: bytes, network_id: str, *, update: bool = False, expected_nonce: str | None = None) -> dict:
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
        if expected_nonce is not None and response["nonce"] != expected_nonce:
            raise RemoteProviderError("anchor_nonce_mismatch")
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
        nonce = secrets.token_hex(16)
        status, _headers, raw = self.transport(
            "GET", self._url(network_id),
            {"Accept": "application/json", "X-Anchor-Nonce": nonce}, None, self.timeout,
        )
        if status == 404:
            return None
        if status != 200:
            raise RemoteProviderError(f"anchor_http_status_{status}")
        response = self._signed(raw, network_id, expected_nonce=nonce)
        return response["sequence"], response["policy_hash"]

    def advance_sequence(self, network_id: str, sequence: int, policy_hash: str,
                         *, certificate: Mapping[str, Any] | None = None) -> bool:
        if self.write_token is None:
            raise RemoteProviderError("anchor_write_authentication_required")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
            raise RemoteProviderError("anchor_sequence_invalid")
        if not isinstance(policy_hash, str) or len(policy_hash) != 64:
            raise RemoteProviderError("anchor_policy_hash_invalid")
        try:
            if bytes.fromhex(policy_hash).hex() != policy_hash:
                raise ValueError("hash")
        except ValueError as exc:
            raise RemoteProviderError("anchor_policy_hash_invalid") from exc
        if not isinstance(certificate, Mapping):
            raise RemoteProviderError("anchor_gcf_finality_certificate_required")
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
            "certificate": dict(certificate),
        }
        status, _headers, raw = self.transport(
            "PUT", self._url(network_id),
            {"Content-Type": "application/json", "Accept": "application/json",
             "Authorization": "Bearer " + self.write_token, **condition},
            _canonical(body), self.timeout,
        )
        if status in (409, 412):
            return False
        if status != 200:
            raise RemoteProviderError(f"anchor_http_status_{status}")
        response = self._signed(raw, network_id, update=True, expected_nonce=body["nonce"])
        if (response.get("accepted") is not True or response["sequence"] != sequence
                or response["policy_hash"] != policy_hash):
            raise RemoteProviderError("anchor_update_not_confirmed")
        return True


def load_independently_pinned_root(path: str, *, expected_fingerprint: str,
                                   expected_signer_id: str) -> bytes:
    """Load public root bytes while requiring a fingerprint supplied separately."""
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise RemoteProviderError("root_pin_must_be_regular_file")
        if os.name == "posix" and info.st_mode & 0o022:
            raise RemoteProviderError("root_pin_group_or_world_writable")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise RemoteProviderError("root_pin_owner_mismatch")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(4097)
        if len(raw) > 4096:
            raise RemoteProviderError("root_pin_file_too_large")
        record = json.loads(raw)
    except RemoteProviderError:
        raise
    except (OSError, json.JSONDecodeError) as exc:
        raise RemoteProviderError("root_pin_file_unavailable_or_invalid") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
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


class GODHTTPSGate:
    """Host GOD gate facade backed by an independently pinned signed endpoint.

    This does not grant authority by itself: the endpoint must be the actual
    GOD policy service and its key fingerprint must be provisioned out of band.
    """
    def __init__(self, client: SignedHTTPSDecisionClient):
        self.client = client

    def runnable(self, capability: str, endpoint: str) -> dict:
        try:
            allowed = self.client.verify_decision(
                "GOD-CAPABILITY-AUTHORIZATION/1",
                {"capability": capability, "endpoint": endpoint},
            )
        except RemoteProviderError as exc:
            return {"allowed": False, "reason": str(exc)}
        return {
            "allowed": allowed,
            "reason": "GOD_SIGNED_CAPABILITY_ALLOW" if allowed else "GOD_SIGNED_CAPABILITY_DENY",
        }


class HTTPSHSMEd25519Signer:
    """Remote Ed25519 signing boundary; private key never enters this process.

    The signing service MUST be an approved HSM/KMS-backed signer. Mutual TLS
    client identity is mandatory. Every returned signature is locally verified
    against the independently pinned validator public key before it is returned.
    """
    def __init__(self, endpoint: str, *, key_id: str, public_key: bytes,
                 client_certificate: str, client_private_key: str,
                 timeout: float = 5.0, transport: Callable | None = None):
        self.endpoint = _https_endpoint(endpoint)
        if not isinstance(key_id, str) or not key_id:
            raise RemoteProviderError("hsm_key_id_invalid")
        if not client_certificate or not client_private_key:
            raise RemoteProviderError("hsm_mutual_tls_identity_required")
        self.key_id = key_id
        self.public_key = _public_key(public_key)
        self.public_key_hex = public_key.hex()
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
            raise RemoteProviderError("timeout_invalid")
        self.timeout = float(timeout)
        self.transport = transport
        self.client_certificate = client_certificate
        self.client_private_key = client_private_key

    def sign(self, message: bytes) -> bytes:
        if not isinstance(message, bytes) or not message or len(message) > 1_048_576:
            raise RemoteProviderError("hsm_message_invalid")
        request_id = secrets.token_hex(16)
        body = {
            "schema": "CRYPTIC-ED25519-SIGN/1",
            "key_id": self.key_id,
            "request_id": request_id,
            "message_b64": base64.b64encode(message).decode("ascii"),
        }
        encoded = _canonical(body)
        if self.transport is None:
            import ssl
            context = ssl.create_default_context()
            context.load_cert_chain(self.client_certificate, self.client_private_key)
            request = urllib.request.Request(
                self.endpoint, data=encoded,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout, context=context) as response:
                    raw = response.read(MAX_RESPONSE_BYTES + 1)
                    status = response.status
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                raise RemoteProviderError("hsm_signer_unavailable") from exc
        else:
            status, _headers, raw = self.transport(
                "POST", self.endpoint,
                {"Content-Type": "application/json", "Accept": "application/json",
                 "X-Client-Certificate": self.client_certificate},
                encoded, self.timeout,
            )
        if len(raw) > MAX_RESPONSE_BYTES:
            raise RemoteProviderError("hsm_response_too_large")
        if status != 200:
            raise RemoteProviderError(f"hsm_http_status_{status}")
        try:
            result = json.loads(raw)
        except (TypeError, json.JSONDecodeError) as exc:
            raise RemoteProviderError("hsm_response_invalid") from exc
        if (not isinstance(result, dict)
                or set(result) != {"schema", "key_id", "request_id", "signature"}
                or result["schema"] != "CRYPTIC-ED25519-SIGN/1"
                or result["key_id"] != self.key_id
                or result["request_id"] != request_id):
            raise RemoteProviderError("hsm_response_binding_invalid")
        try:
            signature = base64.b64decode(result["signature"], validate=True)
            self.public_key.verify(signature, message)
        except (ValueError, InvalidSignature) as exc:
            raise RemoteProviderError("hsm_signature_verification_failed") from exc
        return signature


def make_proposal_with_signer(*, signer: HTTPSHSMEd25519Signer, **fields) -> dict:
    """GCF/1 proposal builder using a remote signer instead of raw private bytes."""
    from src.consensus.gcf import PROPOSAL_DOMAIN, SCHEMA, canonical_bytes
    required = {
        "network_id", "epoch", "height", "round", "parent_hash",
        "payload_hash", "proof_hash", "justice_commitment", "proposer_id",
        "nonce", "issued_at", "expires_at",
    }
    if set(fields) != required:
        raise RemoteProviderError("proposal_fields_invalid")
    body = {
        "schema": SCHEMA,
        **fields,
        "proposer_public_key": signer.public_key_hex,
    }
    signature = signer.sign(PROPOSAL_DOMAIN + canonical_bytes(body))
    return {**body, "signature": base64.b64encode(signature).decode("ascii")}


def make_vote_with_signer(*, signer: HTTPSHSMEd25519Signer, validator_id: str,
                          proposal: Mapping[str, Any], vote_type: str,
                          approve: bool = True, polc_digest: str | None = None,
                          issued_at: int | None = None) -> dict:
    """GCF/1 vote builder using a remote signer instead of raw private bytes."""
    from src.consensus.gcf import VOTE_DOMAIN, SCHEMA, canonical_bytes, sha256_hex
    import time as _time
    body = {
        "schema": SCHEMA, "network_id": proposal["network_id"],
        "epoch": proposal["epoch"], "height": proposal["height"],
        "round": proposal["round"],
        "candidate_digest": sha256_hex(canonical_bytes(proposal)),
        "validator_id": validator_id, "vote_type": vote_type,
        "approve": approve, "polc_digest": polc_digest,
        "issued_at": int(_time.time()) if issued_at is None else issued_at,
    }
    signature = signer.sign(VOTE_DOMAIN + canonical_bytes(body))
    return {**body, "signature": base64.b64encode(signature).decode("ascii")}
