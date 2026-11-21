"""Mutually authenticated, bounded GCF peer transport.

This is a direct-peer transport, not peer discovery or a complete gossip mesh.
Use TLS client certificates plus an Ed25519 validator identity allowlist.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import ssl
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Mapping

from src.consensus.gcf import (
    GCFError, VOTE_DOMAIN, ValidatorSet, canonical_bytes,
    sign_object, verify_object,
)

P2P_SCHEMA = "GCF-P2P/1"
P2P_DOMAIN = b"GCF-P2P/1|MESSAGE|ED25519\x00"
MAX_FRAME_BYTES = 1_048_576
MAX_CLOCK_SKEW_SECONDS = 120


class PeerTransportError(ValueError):
    pass


def build_server_ssl_context(certfile: str, keyfile: str, cafile: str) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=cafile)
    context.load_cert_chain(certfile, keyfile)
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def build_client_ssl_context(certfile: str, keyfile: str, cafile: str) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)
    context.load_cert_chain(certfile, keyfile)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class GCFPeerNode:
    """Receives authenticated proposal/vote envelopes and dispatches to GCFEngine."""

    def __init__(self, *, engine: Any, validator_set: ValidatorSet,
                 node_id: str, private_key_hex: str,
                 peer_certificate_fingerprints: Mapping[str, str],
                 replay_db_path: str | Path, clock=time.time):
        if node_id not in validator_set.validators:
            raise PeerTransportError("LOCAL_NODE_NOT_IN_VALIDATOR_SET")
        self.engine = engine
        self.validator_set = validator_set
        self.node_id = node_id
        self.private_key_hex = private_key_hex
        self.peer_fingerprints = {
            key.lower().replace(":", ""): value
            for key, value in peer_certificate_fingerprints.items()
        }
        self.clock = clock
        self.replay_db_path = str(replay_db_path)
        Path(self.replay_db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS peer_messages(
                  sender_id TEXT NOT NULL,
                  message_id TEXT NOT NULL,
                  issued_at INTEGER NOT NULL,
                  PRIMARY KEY(sender_id,message_id)
                )
            """)

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.replay_db_path, timeout=10, isolation_level=None)
        try:
            yield db
        finally:
            db.close()

    @staticmethod
    def _fingerprint(certificate_der: bytes) -> str:
        return hashlib.sha256(certificate_der).hexdigest()

    def make_envelope(self, message_type: str, payload: Mapping[str, Any],
                      *, message_id: str, issued_at: int | None = None) -> dict:
        if message_type not in {"PROPOSAL", "VOTE"}:
            raise PeerTransportError("MESSAGE_TYPE_UNSUPPORTED")
        body = {
            "schema": P2P_SCHEMA,
            "message_id": message_id,
            "sender_id": self.node_id,
            "issued_at": int(self.clock()) if issued_at is None else issued_at,
            "message_type": message_type,
            "payload": dict(payload),
        }
        signature = sign_object(self.private_key_hex, P2P_DOMAIN, body)
        return {**body, "signature": signature}

    def handle_envelope(self, authenticated_peer_id: str, envelope: Any) -> dict:
        required = {
            "schema", "message_id", "sender_id", "issued_at",
            "message_type", "payload", "signature",
        }
        if not isinstance(envelope, Mapping) or set(envelope) != required:
            raise PeerTransportError("ENVELOPE_FIELDS_INVALID")
        if envelope["schema"] != P2P_SCHEMA:
            raise PeerTransportError("ENVELOPE_SCHEMA_INVALID")
        sender = envelope["sender_id"]
        if sender != authenticated_peer_id or sender not in self.validator_set.validators:
            raise PeerTransportError("PEER_IDENTITY_MISMATCH")
        issued = envelope["issued_at"]
        if isinstance(issued, bool) or not isinstance(issued, int):
            raise PeerTransportError("MESSAGE_TIMESTAMP_INVALID")
        if abs(int(self.clock()) - issued) > MAX_CLOCK_SKEW_SECONDS:
            raise PeerTransportError("MESSAGE_TIMESTAMP_OUT_OF_WINDOW")
        message_id = envelope["message_id"]
        if not isinstance(message_id, str) or len(message_id) != 32:
            raise PeerTransportError("MESSAGE_ID_INVALID")
        try:
            bytes.fromhex(message_id)
        except ValueError as exc:
            raise PeerTransportError("MESSAGE_ID_INVALID") from exc
        payload = envelope["payload"]
        if not isinstance(payload, Mapping):
            raise PeerTransportError("MESSAGE_PAYLOAD_INVALID")
        body = {k: v for k, v in envelope.items() if k != "signature"}
        public_key = self.validator_set.validators[sender].public_key_hex
        if not verify_object(public_key, envelope["signature"], P2P_DOMAIN, body):
            raise PeerTransportError("MESSAGE_SIGNATURE_INVALID")

        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute(
                    "DELETE FROM peer_messages WHERE issued_at < ?",
                    (int(self.clock()) - 86400,),
                )
                db.execute(
                    "INSERT INTO peer_messages VALUES(?,?,?)",
                    (sender, message_id, issued),
                )
                db.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                db.execute("ROLLBACK")
                raise PeerTransportError("MESSAGE_REPLAY") from exc
            except Exception:
                db.execute("ROLLBACK")
                raise

        if envelope["message_type"] == "PROPOSAL":
            result = self.engine.submit_proposal(payload)
        elif envelope["message_type"] == "VOTE":
            result = self.engine.submit_vote(payload)
        else:
            raise PeerTransportError("MESSAGE_TYPE_UNSUPPORTED")
        return {"accepted": True, "message_id": message_id, "result": result}

    async def _handle_connection(self, reader: asyncio.StreamReader,
                                 writer: asyncio.StreamWriter) -> None:
        try:
            tls = writer.get_extra_info("ssl_object")
            cert = tls.getpeercert(binary_form=True) if tls else None
            if not cert:
                raise PeerTransportError("TLS_CLIENT_CERTIFICATE_REQUIRED")
            fingerprint = self._fingerprint(cert)
            peer_id = self.peer_fingerprints.get(fingerprint)
            if peer_id is None:
                raise PeerTransportError("TLS_PEER_CERTIFICATE_NOT_ALLOWLISTED")
            prefix = await reader.readexactly(4)
            length = int.from_bytes(prefix, "big")
            if length < 1 or length > MAX_FRAME_BYTES:
                raise PeerTransportError("FRAME_LENGTH_INVALID")
            raw = await reader.readexactly(length)

            def unique_object(pairs):
                out = {}
                for key, value in pairs:
                    if key in out:
                        raise PeerTransportError("JSON_DUPLICATE_KEY")
                    out[key] = value
                return out

            envelope = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
            response = self.handle_envelope(peer_id, envelope)
            status = "accepted"
        except Exception as exc:
            response = {"accepted": False, "error": str(exc)[:180]}
            status = "rejected"
        try:
            body = json.dumps(
                {"status": status, **response}, sort_keys=True,
                separators=(",", ":"), ensure_ascii=False,
            ).encode("utf-8")
            writer.write(len(body).to_bytes(4, "big") + body)
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def serve(self, host: str, port: int, tls_context: ssl.SSLContext):
        if tls_context.verify_mode != ssl.CERT_REQUIRED:
            raise PeerTransportError("MUTUAL_TLS_REQUIRED")
        if not tls_context.get_ca_certs():
            raise PeerTransportError("TLS_TRUST_ANCHOR_REQUIRED")
        return await asyncio.start_server(
            self._handle_connection, host, port,
            ssl=tls_context, limit=MAX_FRAME_BYTES + 4,
        )

    async def send(self, host: str, port: int, tls_context: ssl.SSLContext,
                   expected_server_fingerprint: str, message_type: str,
                   payload: Mapping[str, Any], message_id: str) -> dict:
        if tls_context.verify_mode != ssl.CERT_REQUIRED or not tls_context.check_hostname:
            raise PeerTransportError("VERIFIED_TLS_CLIENT_CONTEXT_REQUIRED")
        reader, writer = await asyncio.open_connection(
            host, port, ssl=tls_context, server_hostname=host,
            limit=MAX_FRAME_BYTES + 4,
        )
        try:
            tls = writer.get_extra_info("ssl_object")
            cert = tls.getpeercert(binary_form=True) if tls else None
            if not cert or self._fingerprint(cert) != expected_server_fingerprint.lower().replace(":", ""):
                raise PeerTransportError("REMOTE_CERTIFICATE_FINGERPRINT_MISMATCH")
            envelope = self.make_envelope(message_type, payload, message_id=message_id)
            body = canonical_bytes(envelope)
            if len(body) > MAX_FRAME_BYTES:
                raise PeerTransportError("FRAME_TOO_LARGE")
            writer.write(len(body).to_bytes(4, "big") + body)
            await writer.drain()
            prefix = await reader.readexactly(4)
            length = int.from_bytes(prefix, "big")
            if length < 1 or length > MAX_FRAME_BYTES:
                raise PeerTransportError("RESPONSE_FRAME_LENGTH_INVALID")
            response = await reader.readexactly(length)
            return json.loads(response.decode("utf-8"))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
