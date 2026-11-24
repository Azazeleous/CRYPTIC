"""Compatibility exports for the negotiated GCF peer protocol.

The deployed envelope remains GCF-P2P/1. Consensus version negotiation occurs
inside its signed HELLO capability payload; no incompatible transport framing
is introduced.
"""
from src.consensus.peer_transport import GCFPeerNode, GCFPeerMesh, PeerTransportError

GCF2_CAPABILITY = "GCF/2"
