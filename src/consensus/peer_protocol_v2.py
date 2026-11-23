"""Opt-in GCF-P2P/2 negotiation and GCF/2 vote transport.

GCF-P2P/1 remains unchanged. Nodes exchange a signed HELLO over the existing
mutually authenticated TLS transport before GCF/2 vote delivery is permitted.
"""
from __future__ import annotations

import asyncio
import json
import secrets
import ssl
import time
from typing import Any, Mapping

from src.consensus.gcf import sign_object, verify_object, canonical_bytes
from src.consensus.peer_transport import (
    GCFPeerNode, GCFPeerMesh, PeerTransportError, MAX_FRAME_BYTES,
)

P2P_V2_SCHEMA = "GCF-P2P/2"
P2P_V2_DOMAIN = b"GCF-P2P/2|MESSAGE|ED25519\x00"
GCF2_CAPABILITY = "gcf2-vote-nil"


class GCF2PeerNode(GCFPeerNode):
    def __init__(self, *, gcf2_vote_store: Any, **kwargs):
        if gcf2_vote_store is None or not callable(getattr(gcf2_vote_store, "submit_vote", None)):
            raise PeerTransportError("GCF2_VOTE_STORE_REQUIRED")
        super().__init__(**kwargs)
        self.gcf2_vote_store = gcf2_vote_store
        with self._db() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS peer_protocol_sessions(
                  peer_id TEXT PRIMARY KEY,
                  protocol_version INTEGER NOT NULL,
                  capabilities_json TEXT NOT NULL,
                  negotiated_at INTEGER NOT NULL
                )
            """)

    def local_capabilities(self) -> list[str]:
        return ["gcf1", GCF2_CAPABILITY]

    def make_v2_envelope(
        self, message_type: str, payload: Mapping[str, Any],
        *, message_id: str | None = None,
    ) -> dict:
        if message_type not in {"HELLO", "GCF2_VOTE"} or not isinstance(payload, Mapping):
            raise PeerTransportError("V2_MESSAGE_TYPE_UNSUPPORTED")
        body = {
            "schema": P2P_V2_SCHEMA, "protocol_version": 2,
            "message_id": message_id or secrets.token_hex(16),
            "sender_id": self.node_id, "issued_at": int(self.clock()),
            "message_type": message_type, "capabilities": self.local_capabilities(),
            "payload": dict(payload),
        }
        return {**body, "signature": sign_object(
            self.private_key_hex, P2P_V2_DOMAIN, body,
        )}

    def handle_envelope(self, authenticated_peer_id: str, envelope: Any) -> dict:
        if not isinstance(envelope, Mapping) or envelope.get("schema") != P2P_V2_SCHEMA:
            return super().handle_envelope(authenticated_peer_id, envelope)
        required = {
            "schema", "protocol_version", "message_id", "sender_id",
            "issued_at", "message_type", "capabilities", "payload", "signature",
        }
        if set(envelope) != required or envelope["protocol_version"] != 2:
            raise PeerTransportError("V2_ENVELOPE_FIELDS_OR_VERSION_INVALID")
        sender = envelope["sender_id"]
        if sender != authenticated_peer_id or sender not in self.validator_set.validators:
            raise PeerTransportError("PEER_IDENTITY_MISMATCH")
        issued = envelope["issued_at"]
        if isinstance(issued, bool) or not isinstance(issued, int) or abs(int(self.clock()) - issued) > 120:
            raise PeerTransportError("MESSAGE_TIMESTAMP_OUT_OF_WINDOW")
        message_id = envelope["message_id"]
        if not isinstance(message_id, str) or len(message_id) != 32:
            raise PeerTransportError("MESSAGE_ID_INVALID")
        try:
            bytes.fromhex(message_id)
        except ValueError as exc:
            raise PeerTransportError("MESSAGE_ID_INVALID") from exc
        caps = envelope["capabilities"]
        if (not isinstance(caps, list) or len(caps) > 16
                or any(not isinstance(x, str) or not x for x in caps)
                or len(set(caps)) != len(caps)):
            raise PeerTransportError("V2_CAPABILITIES_INVALID")
        if not isinstance(envelope["payload"], Mapping):
            raise PeerTransportError("MESSAGE_PAYLOAD_INVALID")
        body = {k: v for k, v in envelope.items() if k != "signature"}
        if not verify_object(
            self.validator_set.validators[sender].public_key_hex,
            envelope["signature"], P2P_V2_DOMAIN, body,
        ):
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
            except Exception as exc:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise PeerTransportError("MESSAGE_REPLAY_OR_STORAGE_FAILURE") from exc
        try:
            if envelope["message_type"] == "HELLO":
                negotiated = sorted(set(caps) & set(self.local_capabilities()))
                with self._db() as db:
                    db.execute(
                        """INSERT INTO peer_protocol_sessions VALUES(?,?,?,?)
                           ON CONFLICT(peer_id) DO UPDATE SET
                             protocol_version=excluded.protocol_version,
                             capabilities_json=excluded.capabilities_json,
                             negotiated_at=excluded.negotiated_at""",
                        (sender, 2, json.dumps(negotiated, separators=(",", ":")),
                         int(self.clock())),
                    )
                return {
                    "accepted": True, "protocol_version": 2,
                    "negotiated_capabilities": negotiated,
                    "local_capabilities": self.local_capabilities(),
                }
            if envelope["message_type"] != "GCF2_VOTE":
                raise PeerTransportError("V2_MESSAGE_TYPE_UNSUPPORTED")
            with self._db() as db:
                session = db.execute(
                    "SELECT protocol_version,capabilities_json FROM peer_protocol_sessions WHERE peer_id=?",
                    (sender,),
                ).fetchone()
            if (session is None or session[0] != 2
                    or GCF2_CAPABILITY not in json.loads(session[1])):
                raise PeerTransportError("GCF2_CAPABILITY_NOT_NEGOTIATED")
            result = self.gcf2_vote_store.submit_vote(envelope["payload"])
            return {"accepted": True, "result": result}
        except Exception:
            with self._db() as db:
                db.execute(
                    "DELETE FROM peer_messages WHERE sender_id=? AND message_id=?",
                    (sender, message_id),
                )
            raise

    def record_remote_hello(self, peer_id: str, response: Mapping[str, Any]) -> None:
        if (not isinstance(response, Mapping) or response.get("accepted") is not True
                or response.get("protocol_version") != 2):
            raise PeerTransportError("PEER_V2_NEGOTIATION_REJECTED")
        caps = response.get("negotiated_capabilities")
        if not isinstance(caps, list) or any(not isinstance(x, str) for x in caps):
            raise PeerTransportError("PEER_V2_NEGOTIATION_RESPONSE_INVALID")
        with self._db() as db:
            db.execute(
                """INSERT INTO peer_protocol_sessions VALUES(?,?,?,?)
                   ON CONFLICT(peer_id) DO UPDATE SET
                     protocol_version=excluded.protocol_version,
                     capabilities_json=excluded.capabilities_json,
                     negotiated_at=excluded.negotiated_at""",
                (peer_id, 2, json.dumps(caps, separators=(",", ":")),
                 int(self.clock())),
            )

    async def send_v2(
        self, host: str, port: int, tls_context: ssl.SSLContext,
        expected_server_fingerprint: str, message_type: str,
        payload: Mapping[str, Any],
    ) -> dict:
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
            body = canonical_bytes(self.make_v2_envelope(message_type, payload))
            if len(body) > MAX_FRAME_BYTES:
                raise PeerTransportError("FRAME_TOO_LARGE")
            writer.write(len(body).to_bytes(4, "big") + body)
            await writer.drain()
            prefix = await reader.readexactly(4)
            length = int.from_bytes(prefix, "big")
            if length < 1 or length > MAX_FRAME_BYTES:
                raise PeerTransportError("RESPONSE_FRAME_LENGTH_INVALID")
            return json.loads((await reader.readexactly(length)).decode("utf-8"))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


class GCF2PeerMesh(GCFPeerMesh):
    def __init__(self, *, node: GCF2PeerNode, **kwargs):
        if not isinstance(node, GCF2PeerNode):
            raise PeerTransportError("GCF2_PEER_NODE_REQUIRED")
        super().__init__(node=node, **kwargs)
        self.node: GCF2PeerNode = node

    async def negotiate(self) -> dict:
        async def one(peer_id: str, config: Mapping[str, Any]):
            try:
                response = await asyncio.wait_for(
                    self.node.send_v2(
                        config["host"], config["port"], self.tls_context,
                        config["server_fingerprint"], "HELLO", {},
                    ), timeout=self.timeout_seconds,
                )
                if not isinstance(response, Mapping) or response.get("status") != "accepted":
                    return {"accepted": False, "response": response}
                self.node.record_remote_hello(peer_id, response)
                return {"accepted": True, "capabilities": response.get("negotiated_capabilities", [])}
            except Exception as exc:
                return {"accepted": False, "error": type(exc).__name__}
        results = dict(zip(
            self.peers,
            await asyncio.gather(*(one(peer, cfg) for peer, cfg in self.peers.items())),
        ))
        return {"negotiated": [peer for peer, result in results.items() if result["accepted"]],
                "rejected": [peer for peer, result in results.items() if not result["accepted"]],
                "results": results}

    async def broadcast_gcf2_vote(self, vote: Mapping[str, Any]) -> dict:
        with self.node._db() as db:
            sessions = {
                row[0]: (row[1], json.loads(row[2]))
                for row in db.execute(
                    "SELECT peer_id,protocol_version,capabilities_json FROM peer_protocol_sessions"
                ).fetchall()
            }
        missing = [
            peer for peer in self.peers
            if peer not in sessions or sessions[peer][0] != 2
            or GCF2_CAPABILITY not in sessions[peer][1]
        ]
        if missing:
            raise PeerTransportError("GCF2_PEERS_NOT_NEGOTIATED:" + ",".join(sorted(missing)))
        semaphore = asyncio.Semaphore(self.max_parallel)
        async def one(peer_id: str, config: Mapping[str, Any]):
            async with semaphore:
                try:
                    response = await asyncio.wait_for(
                        self.node.send_v2(
                            config["host"], config["port"], self.tls_context,
                            config["server_fingerprint"], "GCF2_VOTE", vote,
                        ), timeout=self.timeout_seconds,
                    )
                    return {"accepted": isinstance(response, Mapping) and response.get("status") == "accepted",
                            "response": response}
                except Exception as exc:
                    return {"accepted": False, "error": type(exc).__name__}
        results = dict(zip(
            self.peers,
            await asyncio.gather(*(one(peer, cfg) for peer, cfg in self.peers.items())),
        ))
        return {
            "accepted_peers": [peer for peer, result in results.items() if result["accepted"]],
            "failed_peers": [peer for peer, result in results.items() if not result["accepted"]],
            "results": results,
        }
