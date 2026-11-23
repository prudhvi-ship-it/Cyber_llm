"""Verify a documented Erlang distribution *default* cookie from handshake bytes.

No wordlist, brute-force, arbitrary secret guessing, or label/filename lookup.
Matches one publicly documented historic CouchDB default value only.  All
claims are derived from packet bytes, directions, and a same-flow RPC pair.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Sequence

from erlang_rpc_evidence import ErlangRpcPair, find_erlang_id_rpc_pairs

# Public vendor advisory: https://docs.couchdb.org/en/stable/cve/2022-24706.html
_DOCUMENTED_COOKIE = "monster"


@dataclass(frozen=True)
class DefaultCookieHandshake:
    challenge_frame: int
    client_reply_frame: int
    server_ack_frame: int
    client: str
    server: str
    server_node: str
    client_digest_matched: bool
    server_digest_matched: bool


@dataclass(frozen=True)
class VerifiedCookieRpcSequence:
    stream_id: int
    handshake: DefaultCookieHandshake
    rpc: ErlangRpcPair


def _raw(packet) -> bytes:
    hex_text = getattr(packet, "payload_hex", "")
    if not isinstance(hex_text, str) or not hex_text:
        return b""
    try:
        return bytes.fromhex(hex_text.replace(":", ""))
    except ValueError:
        return b""


def _message(packet, tag: int, size: int | None = None) -> bytes | None:
    raw = _raw(packet)
    if len(raw) < 3 or raw[2] != tag:
        return None
    if int.from_bytes(raw[:2], "big") != len(raw) - 2:
        return None
    message = raw[3:]
    if size is not None and len(message) != size:
        return None
    return message


def _digest(challenge: int) -> bytes:
    # The actual Erlang handshake packets use cookie + decimal challenge.
    return hashlib.md5((_DOCUMENTED_COOKIE + str(challenge)).encode("ascii")).digest()


def find_default_cookie_handshakes(packets: Sequence, max_seconds: float = 30.0) -> list[DefaultCookieHandshake]:
    """Recognize legacy 'n' / 'r' / 'a' exchange, never standalone digests."""
    ordered = sorted(packets, key=lambda p: (p.timestamp_epoch, p.frame_number))
    results = []
    for idx, challenge_packet in enumerate(ordered):
        if challenge_packet.direction != "server->client" or challenge_packet.frame_number <= 0:
            continue
        body = _message(challenge_packet, ord('n'))
        if body is None or len(body) < 10:
            continue
        # Legacy challenge: two-byte version, four-byte flags, four-byte challenge, node name.
        server_challenge = int.from_bytes(body[6:10], "big")
        node = body[10:].decode("ascii", errors="ignore")
        if not (node.startswith("couchdb@") and len(node) <= 120):
            continue
        client_endpoint, server_endpoint = challenge_packet.destination, challenge_packet.source
        for j in range(idx + 1, len(ordered)):
            reply = ordered[j]
            if reply.timestamp_epoch - challenge_packet.timestamp_epoch > max_seconds:
                break
            if (reply.direction != "client->server" or reply.source != client_endpoint
                    or reply.destination != server_endpoint):
                continue
            reply_body = _message(reply, ord('r'), 20)
            if reply_body is None or reply.frame_number <= challenge_packet.frame_number:
                continue
            client_challenge = int.from_bytes(reply_body[:4], "big")
            if reply_body[4:] != _digest(server_challenge):
                continue
            for ack in ordered[j + 1:]:
                if ack.timestamp_epoch - reply.timestamp_epoch > max_seconds:
                    break
                if (ack.direction != "server->client" or ack.source != server_endpoint
                        or ack.destination != client_endpoint
                        or ack.frame_number <= reply.frame_number):
                    continue
                ack_body = _message(ack, ord('a'), 16)
                if ack_body != _digest(client_challenge):
                    continue
                results.append(DefaultCookieHandshake(
                    challenge_frame=challenge_packet.frame_number,
                    client_reply_frame=reply.frame_number,
                    server_ack_frame=ack.frame_number,
                    client=client_endpoint, server=server_endpoint,
                    server_node=node,
                    client_digest_matched=True, server_digest_matched=True,
                ))
                break
            break
    # One authenticated exchange is sufficient; ignore duplicates/retransmits.
    return list({(x.challenge_frame, x.client_reply_frame, x.server_ack_frame): x for x in results}.values())


def find_verified_cookie_rpc_sequences(packets: Sequence, stream_id: int) -> list[VerifiedCookieRpcSequence]:
    """Require cookie exchange then server-side RPC command output in one stream."""
    pairs = find_erlang_id_rpc_pairs(packets)
    results = []
    for handshake in find_default_cookie_handshakes(packets):
        for pair in pairs:
            if (pair.client == handshake.client and pair.server == handshake.server
                    and pair.request_frame > handshake.server_ack_frame):
                results.append(VerifiedCookieRpcSequence(stream_id, handshake, pair))
    return results
