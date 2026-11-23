"""Mutually authenticated, bounded GCF peer transport.

This is a direct-peer transport, not peer discovery or a complete gossip mesh.
Use TLS client certificates plus an Ed25519 validator identity allowlist.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import sqlite3
import ssl
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Mapping

from src.consensus.gcf import (
    GCFError, VOTE_DOMAIN, ValidatorSet, canonical_bytes,
    public_key_hex, sign_object, verify_object,
)

P2P_SCHEMA = "GCF-P2P/1"
P2P_DOMAIN = b"GCF-P2P/1|MESSAGE|ED25519\x00"
MAX_FRAME_BYTES = 1_048_576
MAX_CLOCK_SKEW_SECONDS = 120
DEFAULT_MAX_PEER_CONNECTIONS = 128
DEFAULT_PEER_IO_TIMEOUT_SECONDS = 10.0


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
    """Receives authenticated proposal, vote, and round-change envelopes and dispatches to GCFEngine."""

    def __init__(self, *, engine: Any, validator_set: ValidatorSet,
                 node_id: str, private_key_hex: str,
                 peer_certificate_fingerprints: Mapping[str, str],
                 replay_db_path: str | Path, clock=time.time,
                 max_connections: int = DEFAULT_MAX_PEER_CONNECTIONS,
                 io_timeout_seconds: float = DEFAULT_PEER_IO_TIMEOUT_SECONDS,
                 gcf2_vote_store: Any | None = None):
        if node_id not in validator_set.validators:
            raise PeerTransportError("LOCAL_NODE_NOT_IN_VALIDATOR_SET")
        if public_key_hex(private_key_hex) != validator_set.validators[node_id].public_key_hex:
            raise PeerTransportError("LOCAL_PRIVATE_KEY_DOES_NOT_MATCH_VALIDATOR_ID")
        self.engine = engine
        self.gcf2_vote_store = gcf2_vote_store
        self.validator_set = validator_set
        self.node_id = node_id
        self.private_key_hex = private_key_hex
        self.peer_fingerprints = {}
        for fingerprint, peer_id in peer_certificate_fingerprints.items():
            normalized = fingerprint.lower().replace(":", "")
            if len(normalized) != 64:
                raise PeerTransportError("PEER_CERTIFICATE_FINGERPRINT_INVALID")
            try:
                bytes.fromhex(normalized)
            except ValueError as exc:
                raise PeerTransportError("PEER_CERTIFICATE_FINGERPRINT_INVALID") from exc
            if peer_id not in validator_set.validators:
                raise PeerTransportError("PEER_ID_NOT_IN_VALIDATOR_SET")
            self.peer_fingerprints[normalized] = peer_id
        if (isinstance(max_connections, bool) or not isinstance(max_connections, int)
                or not 1 <= max_connections <= 1024):
            raise PeerTransportError("MAX_CONNECTIONS_INVALID")
        if (isinstance(io_timeout_seconds, bool)
                or not isinstance(io_timeout_seconds, (int, float))
                or not 0.1 <= io_timeout_seconds <= 60):
            raise PeerTransportError("PEER_IO_TIMEOUT_INVALID")
        self.clock = clock
        self.max_connections = max_connections
        self.io_timeout_seconds = float(io_timeout_seconds)
        self._connection_slots = asyncio.Semaphore(max_connections)
        self.replay_db_path = str(replay_db_path)
        Path(self.replay_db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS peer_messages(
                  sender_id TEXT NOT NULL,
                  message_id TEXT NOT NULL,
                  issued_at INTEGER NOT NULL,
                  PRIMARY KEY(sender_id,message_id)
                );
                CREATE TABLE IF NOT EXISTS peer_protocols(
                  peer_id TEXT PRIMARY KEY,
                  versions_json TEXT NOT NULL,
                  selected_version TEXT NOT NULL,
                  negotiated_at INTEGER NOT NULL
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
        if message_type not in {"PROPOSAL", "VOTE", "ROUND_CHANGE", "HELLO", "GCF2_VOTE"}:
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
        if envelope["message_type"] not in {"PROPOSAL", "VOTE", "ROUND_CHANGE", "HELLO", "GCF2_VOTE"}:
            raise PeerTransportError("MESSAGE_TYPE_UNSUPPORTED")
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

        try:
            if envelope["message_type"] == "HELLO":
                required_hello = {"schema", "network_id", "epoch", "supported_versions"}
                versions = payload.get("supported_versions")
                if (set(payload) != required_hello
                        or payload.get("schema") != "GCF-CAPABILITIES/1"
                        or payload.get("network_id") != self.validator_set.network_id
                        or payload.get("epoch") != self.validator_set.epoch
                        or not isinstance(versions, list)
                        or not versions
                        or versions != sorted(set(versions))
                        or any(item not in {"GCF/1", "GCF/2"} for item in versions)):
                    raise PeerTransportError("PROTOCOL_CAPABILITIES_INVALID")
                local = ["GCF/1"] + (["GCF/2"] if self.gcf2_vote_store is not None else [])
                common = sorted(set(local).intersection(versions))
                selected = common[-1] if common else None
                if selected is None:
                    raise PeerTransportError("NO_COMMON_CONSENSUS_PROTOCOL")
                with self._db() as db:
                    db.execute(
                        """INSERT INTO peer_protocols VALUES(?,?,?,?)
                           ON CONFLICT(peer_id) DO UPDATE SET
                           versions_json=excluded.versions_json,
                           selected_version=excluded.selected_version,
                           negotiated_at=excluded.negotiated_at""",
                        (sender, json.dumps(versions, separators=(",", ":")),
                         selected, int(self.clock())),
                    )
                result = {"selected_version": selected, "local_versions": local}
            elif envelope["message_type"] == "GCF2_VOTE":
                if self.gcf2_vote_store is None:
                    raise PeerTransportError("GCF2_NOT_ENABLED_ON_NODE")
                with self._db() as db:
                    negotiated = db.execute(
                        "SELECT selected_version FROM peer_protocols WHERE peer_id=?",
                        (sender,),
                    ).fetchone()
                if negotiated is None or negotiated[0] != "GCF/2":
                    raise PeerTransportError("GCF2_PROTOCOL_NOT_NEGOTIATED")
                result = self.gcf2_vote_store.submit_vote(payload)
            elif envelope["message_type"] == "PROPOSAL":
                result = self.engine.submit_proposal(payload)
            elif envelope["message_type"] == "VOTE":
                result = self.engine.submit_vote(payload)
            else:
                result = self.engine.submit_round_change(payload)
        except Exception:
            # A transient dispatch failure must not permanently consume the
            # sender's message ID. Successful GCF admission remains replay-safe.
            with self._db() as db:
                db.execute(
                    "DELETE FROM peer_messages WHERE sender_id=? AND message_id=?",
                    (sender, message_id),
                )
            raise
        return {"accepted": True, "message_id": message_id, "result": result}

    async def _handle_connection(self, reader: asyncio.StreamReader,
                                 writer: asyncio.StreamWriter) -> None:
        async with self._connection_slots:
            await self._process_connection(reader, writer)

    async def _process_connection(self, reader: asyncio.StreamReader,
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
            prefix = await asyncio.wait_for(
                reader.readexactly(4), timeout=self.io_timeout_seconds,
            )
            length = int.from_bytes(prefix, "big")
            if length < 1 or length > MAX_FRAME_BYTES:
                raise PeerTransportError("FRAME_LENGTH_INVALID")
            raw = await asyncio.wait_for(
                reader.readexactly(length), timeout=self.io_timeout_seconds,
            )

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
        except asyncio.TimeoutError:
            response = {"accepted": False, "error": "PEER_IO_TIMEOUT"}
            status = "rejected"
        except Exception as exc:
            response = {"accepted": False, "error": str(exc)[:180]}
            status = "rejected"
        try:
            body = json.dumps(
                {"status": status, **response}, sort_keys=True,
                separators=(",", ":"), ensure_ascii=False,
            ).encode("utf-8")
            writer.write(len(body).to_bytes(4, "big") + body)
            await asyncio.wait_for(
                writer.drain(), timeout=self.io_timeout_seconds,
            )
        except Exception:
            pass
        finally:
            writer.close()
            try:
                await asyncio.wait_for(
                    writer.wait_closed(), timeout=self.io_timeout_seconds,
                )
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
            backlog=self.max_connections,
            ssl_handshake_timeout=self.io_timeout_seconds,
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



class GCFPeerMesh:
    """Bounded direct-peer fan-out over preconfigured mutually authenticated links.

    This is not discovery or epidemic gossip. Every peer endpoint and server
    certificate fingerprint must be provisioned by the operator.
    """

    def __init__(self, *, node: GCFPeerNode, tls_context: ssl.SSLContext,
                 peers: Mapping[str, Mapping[str, Any]],
                 timeout_seconds: float = 8.0, max_parallel: int = 8):
        if not isinstance(node, GCFPeerNode):
            raise PeerTransportError("PEER_NODE_REQUIRED")
        if tls_context.verify_mode != ssl.CERT_REQUIRED or not tls_context.check_hostname:
            raise PeerTransportError("VERIFIED_MUTUAL_TLS_CLIENT_CONTEXT_REQUIRED")
        if not isinstance(peers, Mapping) or not peers:
            raise PeerTransportError("PEER_ENDPOINTS_REQUIRED")
        if not isinstance(timeout_seconds, (int, float)) or not 0 < timeout_seconds <= 60:
            raise PeerTransportError("PEER_TIMEOUT_INVALID")
        if isinstance(max_parallel, bool) or not isinstance(max_parallel, int) or not 1 <= max_parallel <= 32:
            raise PeerTransportError("PEER_PARALLELISM_INVALID")
        normalized = {}
        for peer_id, config in peers.items():
            if peer_id == node.node_id or peer_id not in node.validator_set.validators:
                raise PeerTransportError("PEER_ID_INVALID")
            if not isinstance(config, Mapping) or set(config) != {"host", "port", "server_fingerprint"}:
                raise PeerTransportError("PEER_ENDPOINT_CONFIG_INVALID")
            host, port, fingerprint = config["host"], config["port"], config["server_fingerprint"]
            if not isinstance(host, str) or not host or len(host) > 253:
                raise PeerTransportError("PEER_HOST_INVALID")
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise PeerTransportError("PEER_PORT_INVALID")
            if not isinstance(fingerprint, str):
                raise PeerTransportError("PEER_SERVER_FINGERPRINT_INVALID")
            fingerprint = fingerprint.lower().replace(":", "")
            if len(fingerprint) != 64:
                raise PeerTransportError("PEER_SERVER_FINGERPRINT_INVALID")
            try:
                bytes.fromhex(fingerprint)
            except ValueError as exc:
                raise PeerTransportError("PEER_SERVER_FINGERPRINT_INVALID") from exc
            normalized[peer_id] = {
                "host": host, "port": port, "server_fingerprint": fingerprint,
            }
        self.node = node
        self.tls_context = tls_context
        self.peers = normalized
        self.timeout_seconds = float(timeout_seconds)
        self.max_parallel = max_parallel

    async def broadcast(self, message_type: str, payload: Mapping[str, Any]) -> dict:
        """Fan out one signed proposal, validator vote, or round-change message."""
        if message_type not in {"PROPOSAL", "VOTE", "ROUND_CHANGE", "GCF2_VOTE"} or not isinstance(payload, Mapping):
            raise PeerTransportError("BROADCAST_MESSAGE_INVALID")
        message_id = secrets.token_hex(16)
        semaphore = asyncio.Semaphore(self.max_parallel)

        async def deliver(peer_id, config):
            async with semaphore:
                try:
                    if message_type == "GCF2_VOTE":
                        hello = await asyncio.wait_for(
                            self.node.send(
                                config["host"], config["port"], self.tls_context,
                                config["server_fingerprint"], "HELLO",
                                {"schema": "GCF-CAPABILITIES/1",
                                 "network_id": self.node.validator_set.network_id,
                                 "epoch": self.node.validator_set.epoch,
                                 "supported_versions": ["GCF/1", "GCF/2"]},
                                secrets.token_hex(16),
                            ),
                            timeout=self.timeout_seconds,
                        )
                        selected = hello.get("result", {}).get("selected_version") if isinstance(hello, Mapping) else None
                        if hello.get("status") != "accepted" or selected != "GCF/2":
                            return {"accepted": False, "error": "GCF2_PROTOCOL_NOT_NEGOTIATED"}
                    response = await asyncio.wait_for(
                        self.node.send(
                            config["host"], config["port"], self.tls_context,
                            config["server_fingerprint"], message_type, payload,
                            message_id,
                        ),
                        timeout=self.timeout_seconds,
                    )
                    if not isinstance(response, Mapping) or response.get("status") != "accepted":
                        return {"accepted": False, "response": response}
                    return {"accepted": True, "response": dict(response)}
                except Exception as exc:
                    return {"accepted": False, "error": type(exc).__name__}

        pairs = await asyncio.gather(*(
            deliver(peer_id, config) for peer_id, config in self.peers.items()
        ))
        results = {peer_id: result for peer_id, result in zip(self.peers, pairs)}
        accepted = [peer_id for peer_id, result in results.items() if result["accepted"]]
        failed = [peer_id for peer_id, result in results.items() if not result["accepted"]]
        return {
            "message_id": message_id,
            "message_type": message_type,
            "accepted_peers": accepted,
            "failed_peers": failed,
            "results": results,
        }
