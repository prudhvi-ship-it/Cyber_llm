"""Protocol-agnostic HTTP request triage over packet records.

This module *does not* predict a CVE, attacker intent, or attack success.
Findings are bounded hints from observed wire data to help an analyst choose
which streams deserve investigation instead of choosing by traffic volume.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote


# These patterns apply to any HTTP service; no application or CVE labels.
_REQUEST = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S{1,350})\s+HTTP/1\.[01]\r?\n", re.I)
_RESPONSE = re.compile(r"^HTTP/1\.[01]\s+(\d{3})\b", re.I)
_RULES = (
    ("shell command expression", re.compile(r"\bqx\s*[({][^\r\n})]{1,120}[})]", re.I), 10),
    ("JNDI lookup expression", re.compile(r"\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop)\s*:", re.I), 10),
    ("explicit command invocation", re.compile(r"\b(?:system|shell_exec|passthru|proc_open|popen)\s*\([^\r\n]{0,110}", re.I), 9),
    ("path traversal", re.compile(r"(?:\.\./|\.\.\\|%2e%2e(?:%2f|/|%5c))", re.I), 7),
    ("SQL injection syntax", re.compile(r"(?:\bunion\s+(?:all\s+)?select\b|\b(?:or|and)\s+1\s*=\s*1\b|\bwaitfor\s+delay\b)", re.I), 7),
    ("script or template evaluation", re.compile(r"(?:\beval\s*\(|\bbase64_decode\s*\(|<\?php\b)", re.I), 6),
)
_MAX_SCAN = 256 * 1024
_MAX_PREVIEW = 115
_MAX_FINDINGS = 4


@dataclass(frozen=True)
class HTTPRequestLead:
    stream_id: int
    request_frame: int
    method: str
    path: str
    client: str
    server: str
    indicators: tuple[str, ...]
    indicator_frame: int | None
    score: int
    response_code: int | None = None
    response_frame: int | None = None
    indicator_excerpt: str = ""

    def observation(self) -> str:
        tags = ", ".join(self.indicators) if self.indicators else "no exploit-specific indicator"
        linked = f"; indicator frame={self.indicator_frame}" if self.indicator_frame else ""
        response = (
            f"; response HTTP {self.response_code} frame={self.response_frame} "
            "(status alone does not prove exploit outcome)"
            if self.response_code is not None else
            "; no correlated HTTP response observed"
        )
        detail = f"; bounded indicator excerpt={self.indicator_excerpt}" if self.indicator_excerpt else ""
        observation = (
            f"HTTP request candidate {self.method} {self.path} to {self.server}; "
            f"request frame={self.request_frame}{linked}; indicators={tags}{detail}{response}; "
            "heuristic triage ONLY, not proof of exploit or CVE"
        )
        # EvidenceItem has a 500-character safety cap. Preserve bounded proof
        # labels and make truncation explicit if a pathological URI is supplied.
        return observation if len(observation) <= 495 else observation[:475] + "...[TRUNCATED]"


def _safe_path(path: str) -> str:
    # Avoid copying bearer tokens, secrets, or large user-supplied paths to prompts.
    from evidence_extractor import EvidenceExtractor  # deferred to avoid import cycle
    decoded = unquote(path)
    decoded = EvidenceExtractor().redact_text(decoded)
    # The path is a locator, not a source of full raw payload.
    return decoded[:110] + ("...[TRUNCATED]" if len(decoded) > 110 else "")


def _markers(text: str) -> list[tuple[str, int, str]]:
    findings = []
    for name, pattern, weight in _RULES:
        match = pattern.search(text)
        if match:
            # Keep only a tiny evidence excerpt; do not pass the whole body to
            # the LLM. Replace CR/LF and mask common query/form secrets.
            excerpt = match.group(0).replace("\r", " ").replace("\n", " ")
            from evidence_extractor import EvidenceExtractor
            excerpt = EvidenceExtractor().redact_text(excerpt)[:65]
            findings.append((name, weight, excerpt))
    # Multipart and file uploads are context, not an exploit by themselves.
    if re.search(r"\bmultipart/form-data\b", text, re.I):
        findings.append(("multipart upload", 2, "multipart/form-data"))
    # Generic magic/extension mismatch; not dependent on any named application.
    filename = re.search(r"filename\s*=\s*['\"]?[^'\"\r\n;]{0,140}", text, re.I)
    if filename and re.search(r"filename\s*=\s*['\"]?[^'\"\r\n;]+\.(?:jpe?g|png|gif)\b", filename.group(0), re.I):
        if re.search(r"(?:AT&TFORM.{0,80}DJVU|\bDJVU(?:INFO|ANTa))", text, re.S):
            findings.append(("uploaded file signature differs from image filename", 9, "image filename / DjVu content"))
    return findings


def find_http_request_leads(packets: list[object], stream_id: int = 0) -> list[HTTPRequestLead]:
    """Read HTTP requests (including late body chunks), keeping original frame IDs.

    No claim is made about TCP reassembly in captures with dropped/out-of-order
    segments: evidence labels are request/body *observations*, not definitive
    transactions. It is conservative about joining only same-direction chunks.
    """
    records: list[dict] = []
    active: dict | None = None
    for packet in sorted(packets, key=lambda p: p.frame_number):
        if not packet.payload or not packet.payload_bytes:
            continue
        text = packet.payload[:32768]
        start = _REQUEST.match(text)
        if start and packet.direction == "client->server":
            if active is not None:
                records.append(active)
            active = {
                "frame": packet.frame_number, "method": start.group(1).upper(),
                "path": _safe_path(start.group(2)),
                "client": packet.source, "server": packet.destination,
                "findings": {}, "marker_frame": None, "response_code": None,
                "response_frame": None, "bytes": 0, "excerpt": "",
            }
        if active is None:
            continue
        if packet.direction == "server->client":
            resp = _RESPONSE.match(text)
            if resp and active["response_code"] is None:
                active["response_code"] = int(resp.group(1))
                active["response_frame"] = packet.frame_number
                records.append(active)
                active = None
            continue
        if packet.direction != "client->server" or packet.source != active["client"]:
            continue
        remaining = _MAX_SCAN - active["bytes"]
        if remaining <= 0:
            continue
        segment = text[:remaining]
        active["bytes"] += len(segment)
        # Inspect percent-encoded HTTP request targets as well as raw bodies.
        # The result remains an observation; decoded text is untrusted.
        for indicator, weight, excerpt in _markers(unquote(segment)):
            if indicator not in active["findings"]:
                active["findings"][indicator] = weight
                if weight >= 6 and not active["excerpt"]:
                    active["excerpt"] = excerpt
                active["marker_frame"] = active["marker_frame"] or packet.frame_number
    if active is not None:
        records.append(active)
    results: list[HTTPRequestLead] = []
    for item in records:
        findings = item["findings"]
        if not findings:
            continue
        # Strong payload evidence outweighs protocol/traffic-volume heuristics.
        score = min(12, max(findings.values()) + (1 if len(findings) > 1 else 0))
        results.append(HTTPRequestLead(
            stream_id=stream_id, request_frame=item["frame"], method=item["method"],
            path=item["path"], client=item["client"], server=item["server"],
            indicators=tuple(findings.keys())[:_MAX_FINDINGS],
            indicator_frame=item["marker_frame"], score=score,
            response_code=item["response_code"], response_frame=item["response_frame"],
            indicator_excerpt=item["excerpt"],
        ))
    return results


def format_ranked_flow_leads(leads: list[HTTPRequestLead], limit: int = 8) -> str:
    lines = [
        "=== HEURISTIC ATTACK-FLOW PRIORITY (packet-derived, NOT ground truth) ===",
        "These are investigation leads. Ordinary traffic may coexist with attacks; "
        "HTTP response errors alone neither prove nor disprove exploitation.",
    ]
    for rank, lead in enumerate(sorted(leads, key=lambda x: (-x.score, x.request_frame))[:limit], 1):
        lines.append(
            f"Rank {rank}: TCP stream {lead.stream_id}; score={lead.score}/12; "
            f"frame={lead.request_frame}; {lead.observation()}"
        )
    if not leads:
        lines.append("No prioritized HTTP requests. Do not infer absence of attack; "
                     "non-HTTP protocols require independent inspection.")
    return "\n".join(lines)
