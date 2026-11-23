"""Narrow packet-level correlation of Erlang distribution os:cmd('id') requests.

Only observed, directionally matched request/response pairs are reported.
This proves observed command execution, not whether the caller was authorized
and not a specific CVE. This is intentionally a narrow protocol recognizer,
not a generic arbitrary-command decoder.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

# Erlang External Term Format fragments: atom_utf8_ext(call), atom_utf8_ext(os),
# atom_utf8_ext(cmd), list_ext(1), string_ext('id'). Require binary tags, not
# merely finding words in an unrelated HTTP or log message.
_ID_REQUEST = re.compile(
    r"\x77\x04call\x77\x02os\x77\x03cmd\x6c\x00\x00\x00\x01\x6b\x00\x02id"
)
# Erlang 'rex' RPC reply: atom_utf8_ext(rex), string_ext(length), text.
_REX_REPLY = re.compile(r"\x77\x03rex\x6b([\s\S]{2})")
_UID = re.compile(r"\buid\s*=\s*\d+\s*\([^\r\n()]{1,32}\)", re.IGNORECASE)
_GID = re.compile(r"\bgid\s*=\s*\d+\s*\([^\r\n()]{1,32}\)", re.IGNORECASE)


@dataclass(frozen=True)
class ErlangRpcPair:
    request_frame: int
    reply_frame: int
    request_timestamp: float
    reply_timestamp: float
    client: str
    server: str
    command: str
    observed_output: str


def _extract_rex_id_output(payload: str) -> str | None:
    """Read the length-delimited, printable rex reply without guessing text."""
    tag = _REX_REPLY.search(payload)
    if not tag:
        return None
    n = int.from_bytes(tag.group(1).encode('latin-1'), 'big')
    if not 1 <= n <= 500:
        return None
    start = tag.end()
    raw = payload[start:start + n]
    if len(raw) != n:
        return None
    if not _UID.search(raw) or not _GID.search(raw):
        return None
    # Do not propagate arbitrary shell output into prompts. Only the
    # expected identity fields are necessary for this correlation.
    return f"{_UID.search(raw).group(0)} {_GID.search(raw).group(0)}"


def find_erlang_id_rpc_pairs(packets: Sequence, max_delay_seconds: float = 30.0) -> list[ErlangRpcPair]:
    """Correlate request to reply within one provided TCP stream.

    Caller must pass the packet records for ONE TCP stream; matching source
    and destination pairs prevent cross-flow joining.
    """
    requests = []
    matches: list[ErlangRpcPair] = []
    used_requests: set[int] = set()
    for packet in sorted(packets, key=lambda p: (p.timestamp_epoch, p.frame_number)):
        payload = packet.payload
        if (packet.frame_number > 0 and packet.direction == 'client->server'
                and _ID_REQUEST.search(payload)):
            requests.append(packet)
            continue
        if packet.direction != 'server->client' or packet.frame_number <= 0:
            continue
        # utf-8 decoding with replacement characters destroys binary bytes
        # in a few fields, but ASCII ETF markers and ID output survive. The
        # rex/string tags used here are ASCII and are byte-identical.
        reply_output = _extract_rex_id_output(payload)
        if reply_output is None:
            continue
        for req in reversed(requests):
            if req.frame_number in used_requests:
                continue
            if (req.source != packet.destination or req.destination != packet.source):
                continue
            delta = packet.timestamp_epoch - req.timestamp_epoch
            if not (0 <= delta <= max_delay_seconds):
                continue
            used_requests.add(req.frame_number)
            matches.append(ErlangRpcPair(
                request_frame=req.frame_number, reply_frame=packet.frame_number,
                request_timestamp=req.timestamp_epoch, reply_timestamp=packet.timestamp_epoch,
                client=req.source, server=req.destination, command='id',
                observed_output=reply_output,
            ))
            break
    return matches
