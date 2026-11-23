"""Deterministic, provenance-aware evidence extraction from TCP payloads."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote

from contracts import EvidenceCategory, EvidenceItem
from erlang_rpc_evidence import find_erlang_id_rpc_pairs
from erlang_cookie_evidence import find_default_cookie_handshakes
from attack_flow_ranker import find_http_request_leads


@dataclass(frozen=True)
class PacketRecord:
    frame_number: int
    timestamp_epoch: float
    source: str
    destination: str
    direction: str
    protocol: str
    payload: str
    payload_bytes: int
    payload_hex: str = ""  # unmodified bytes for binary-protocol authentication checks


class EvidenceExtractor:
    """Extract redacted evidence while preserving packet chronology."""

    CATEGORY_ORDER = (
        EvidenceCategory.NETWORK,
        EvidenceCategory.HTTP,
        EvidenceCategory.AUTHENTICATION,
        EvidenceCategory.SQL,
        EvidenceCategory.COMMAND,
        EvidenceCategory.INDICATOR,
    )

    HEADER_SECRET_PATTERN = re.compile(
        r"(?im)^([ \t]*(?:authorization|proxy-authorization|cookie|set-cookie|"
        r"x-api-key|x-auth-token)\s*:\s*)[^\r\n]*"
    )
    PARAM_SECRET_PATTERN = re.compile(
        r"(?i)\b(username|user|login|pma_username|password|passwd|pass|pwd|"
        r"pma_password|token|access_token|refresh_token|api[_-]?key|secret|"
        r"session(?:id)?|csrf(?:token)?)=([^&\s\r\n]*)"
    )
    BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
    JWT_PATTERN = re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
    )

    def redact_text(self, text: str) -> str:
        """Remove common credentials before evidence or text reaches an LLM."""
        text = self.HEADER_SECRET_PATTERN.sub(r"\1[REDACTED]", text)
        text = self.PARAM_SECRET_PATTERN.sub(
            lambda match: f"{match.group(1)}=[REDACTED]",
            text,
        )
        text = self.BEARER_PATTERN.sub("Bearer [REDACTED]", text)
        return self.JWT_PATTERN.sub("[REDACTED_JWT]", text)

    def extract(
        self,
        flow_content: str = "",
        *,
        stream_id: int = 0,
        packets: list[PacketRecord] | None = None,
    ) -> dict[str, list[EvidenceItem]]:
        """Extract evidence from packet payloads, or one legacy flow string."""
        if packets is None:
            packets = [
                PacketRecord(
                    frame_number=0,
                    timestamp_epoch=0.0,
                    source="Unknown",
                    destination="Unknown",
                    direction="Unknown",
                    protocol="TCP",
                    payload=flow_content,
                    payload_bytes=len(flow_content.encode("utf-8", errors="replace")),
                )
            ]

        evidence: dict[str, list[EvidenceItem]] = {
            category.value: [] for category in self.CATEGORY_ORDER
        }
        seen: set[tuple[str, str]] = set()
        sequence = 0

        for packet in packets:
            redacted_payload = self.redact_text(packet.payload)
            findings = {
                EvidenceCategory.NETWORK: self.extract_network(packet),
                EvidenceCategory.HTTP: self.extract_http(
                    redacted_payload, direction=packet.direction
                ),
                EvidenceCategory.AUTHENTICATION: self.extract_authentication(
                    redacted_payload
                ),
                EvidenceCategory.SQL: self.extract_sql(redacted_payload),
                EvidenceCategory.COMMAND: (
                    self.extract_commands(redacted_payload)
                    + (self.extract_response_effects(redacted_payload)
                       if packet.direction == "server->client" else [])
                ),
                EvidenceCategory.INDICATOR: self.extract_indicators(redacted_payload),
            }

            for category in self.CATEGORY_ORDER:
                for observation in findings[category]:
                    dedupe_key = (category.value, observation.casefold())
                    if dedupe_key in seen:
                        continue
                    seen.add(dedupe_key)
                    sequence += 1
                    frame_label = (
                        f"{packet.frame_number:06d}"
                        if packet.frame_number > 0
                        else "UNKNOWN"
                    )
                    evidence_id = (
                        f"E-S{stream_id:04d}-F{frame_label}-{sequence:03d}"
                    )
                    evidence[category.value].append(
                        EvidenceItem(
                            evidence_id=evidence_id,
                            category=category,
                            observation=observation,
                            stream_id=stream_id,
                            frame_number=(
                                packet.frame_number if packet.frame_number > 0 else None
                            ),
                            timestamp_epoch=(
                                packet.timestamp_epoch
                                if packet.timestamp_epoch > 0
                                else None
                            ),
                            direction=packet.direction,
                            redacted=True,
                        )
                    )

        # A frame-by-frame keyword extractor cannot identify Erlang RPC
        # calls reliably: their arguments are binary ETF terms. Add paired
        # request and reply observations only after checking direction,
        # endpoints, chronology, and a length-delimited rex reply.
        for pair in find_erlang_id_rpc_pairs(packets):
            for packet_frame, direction, description in (
                (
                    pair.request_frame,
                    "client->server",
                    f"Erlang RPC request: os:cmd('id') from {pair.client} "
                    f"to {pair.server}, paired with server response frame "
                    f"{pair.reply_frame} in the same TCP stream",
                ),
                (
                    pair.reply_frame,
                    "server->client",
                    f"Server response contains Erlang rex command output "
                    f"'{pair.observed_output}', paired with client "
                    f"os:cmd('id') request frame {pair.request_frame} in the "
                    f"same TCP stream",
                ),
            ):
                frame_packet = next(
                    (p for p in packets if p.frame_number == packet_frame), None
                )
                if frame_packet is None:
                    continue
                sequence += 1
                evidence[EvidenceCategory.COMMAND.value].append(
                    EvidenceItem(
                        evidence_id=(
                            f"E-S{stream_id:04d}-F{packet_frame:06d}-{sequence:03d}"
                        ),
                        category=EvidenceCategory.COMMAND,
                        observation=description,
                        stream_id=stream_id,
                        frame_number=packet_frame,
                        timestamp_epoch=frame_packet.timestamp_epoch,
                        direction=direction,
                        redacted=True,
                    )
                )
        # Public default-cookie evidence is derived from both challenge digests.
        # Do not pass raw handshake hashes, arbitrary cookies or guessed secrets
        # to LLM prompts. An isolated digest or unpaired response is not proof.
        for handshake in find_default_cookie_handshakes(packets):
            for frame, direction, description in (
                (handshake.challenge_frame, "server->client",
                 f"CouchDB Erlang distribution challenge from {handshake.server} "
                 f"with node {handshake.server_node}"),
                (handshake.client_reply_frame, "client->server",
                 "Erlang client authentication digest matches the publicly "
                 "documented CouchDB default cookie (legacy challenge-response)"),
                (handshake.server_ack_frame, "server->client",
                 "Erlang server authentication acknowledgement digest matches "
                 "the same publicly documented CouchDB default cookie"),
            ):
                frame_packet = next((p for p in packets if p.frame_number == frame), None)
                if frame_packet is None:
                    continue
                sequence += 1
                evidence[EvidenceCategory.AUTHENTICATION.value].append(EvidenceItem(
                    evidence_id=f"E-S{stream_id:04d}-F{frame:06d}-{sequence:03d}",
                    category=EvidenceCategory.AUTHENTICATION,
                    observation=description, stream_id=stream_id, frame_number=frame,
                    timestamp_epoch=frame_packet.timestamp_epoch,
                    direction=direction, redacted=True,
                ))
        # Generic HTTP body triage is evidence only, not a service/CVE
        # classification. Keep packet provenance even for late uploads.
        for lead in find_http_request_leads(packets, stream_id):
            frame_packet = next((p for p in packets if p.frame_number == lead.request_frame), None)
            if frame_packet is None:
                continue
            sequence += 1
            evidence[EvidenceCategory.INDICATOR.value].append(EvidenceItem(
                evidence_id=f"E-S{stream_id:04d}-F{lead.request_frame:06d}-{sequence:03d}",
                category=EvidenceCategory.INDICATOR, observation=lead.observation(),
                stream_id=stream_id, frame_number=lead.request_frame,
                timestamp_epoch=frame_packet.timestamp_epoch,
                direction="client->server", redacted=True,
            ))
        return evidence

    def extract_network(self, packet: PacketRecord) -> list[str]:
        if packet.source == "Unknown" and packet.destination == "Unknown":
            return []
        return [
            f"{packet.source} -> {packet.destination} ({packet.protocol or 'TCP'})"
        ]

    def extract_http(self, text: str, *, direction: str | None = None) -> list[str]:
        findings: list[str] = []
        methods = re.findall(
            r"\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+([^\s]+)",
            text,
            re.IGNORECASE,
        )
        for method, uri in methods:
            findings.append(f"{method.upper()} {unquote(uri)}")

        for code in re.findall(r"HTTP/\d(?:\.\d)?\s+(\d{3})", text):
            findings.append(f"HTTP Status {code}")

        for host in re.findall(r"(?im)^[ \t]*Host:\s*([^\r\n]+)", text):
            findings.append(f"Host: {host.strip()}")

        for agent in re.findall(r"(?im)^[ \t]*User-Agent:\s*([^\r\n]+)", text):
            findings.append(f"User-Agent: {agent.strip()}")

        # Preserve selected protocol fields that distinguish otherwise similar
        # requests and responses. Values have already passed through redact_text.
        # Do NOT enumerate arbitrary custom headers, which may carry secrets.
        for header in ("X-Middleware-Subrequest", "Location", "Content-Type"):
            pattern = rf"(?im)^[ \t]*{re.escape(header)}:[ \t]*([^\r\n]+)"
            for value in re.findall(pattern, text):
                findings.append(f"{header}: {value.strip()[:180]}")

        # FRA exposes application fingerprints through raw HTTP responses.
        # Keep the server-supplied banner as packet evidence before any model
        # truncation, without inferring that it proves the product or CVE.
        # A client-sent X-Powered-By header is NOT trusted as server identity.
        if direction == "server->client" and re.search(
            r"(?im)^HTTP/\d(?:\.\d)?[ \t]+\d{3}\b", text
        ):
            for value in re.findall(
                r"(?im)^[ \t]*X-Powered-By:[ \t]*([^\r\n]+)", text
            ):
                banner = value.strip()[:120]
                if banner:
                    findings.append(f"Server response X-Powered-By: {banner}")

        return self.clean(findings)

    def extract_authentication(self, text: str) -> list[str]:
        findings: list[str] = []
        fields = re.findall(
            r"(?i)\b(username|user|login|pma_username|password|passwd|pass|pwd|"
            r"pma_password|token|access_token|refresh_token|api[_-]?key|secret|"
            r"session(?:id)?|csrf(?:token)?)=\[REDACTED\]",
            text,
        )
        findings.extend(f"Sensitive field observed: {field}=[REDACTED]" for field in fields)

        if re.search(
            r"(?im)^[ \t]*(?:authorization|proxy-authorization|x-api-key|x-auth-token):",
            text,
        ):
            findings.append("Authorization header observed: [REDACTED]")
        if re.search(r"(?im)^[ \t]*(?:cookie|set-cookie):", text):
            findings.append("Cookie header observed: [REDACTED]")
        if re.search(r"\broot\b", text, re.IGNORECASE):
            findings.append("root user keyword observed")
        if re.search(r"\badmin\b", text, re.IGNORECASE):
            findings.append("admin keyword observed")

        return self.clean(findings)

    def extract_sql(self, text: str) -> list[str]:
        patterns = (
            r"\bCREATE\s+TABLE\b[^;\r\n]*",
            r"\bINSERT\s+INTO\b[^;\r\n]*",
            r"\bSELECT\b[^;\r\n]*",
            r"\bUPDATE\b[^;\r\n]*",
            r"\bDELETE\s+FROM\b[^;\r\n]*",
            r"\bDROP\s+TABLE\b[^;\r\n]*",
            r"\bSHOW\s+[A-Z\s]+\b[^;\r\n]*",
            r"\bUNHEX\s*\([^)]+\)",
            r"\bUNION\s+SELECT\b[^;\r\n]*",
        )
        findings: list[str] = []
        for pattern in patterns:
            findings.extend(re.findall(pattern, text, re.IGNORECASE))
        return self.clean(findings)

    def extract_commands(self, text: str) -> list[str]:
        patterns = (
            r"system\s*\([^)]+\)",
            r"exec\s*\([^)]+\)",
            r"shell_exec\s*\([^)]+\)",
            r"passthru\s*\([^)]+\)",
            r"popen\s*\([^)]+\)",
            r"proc_open\s*\([^)]+\)",
            r"\bwhoami\b",
            r"\bid\b",
            r"\buid=\d+",
            r"\bgid=\d+",
            r"/bin/sh",
            r"/bin/bash",
            r"cmd\.exe",
            r"powershell",
        )
        findings: list[str] = []
        for pattern in patterns:
            findings.extend(re.findall(pattern, text, re.IGNORECASE))
        return self.clean(findings)

    def extract_response_effects(self, text: str) -> list[str]:
        """Record *possible* effects in a server-to-client packet, not success.

        These observations retain provenance for later request/reply checking.
        An echoed command, benign diagnostic page, or unrelated response must
        never be treated as proof of code execution solely from this signal.
        """
        findings: list[str] = []
        uid = re.search(r"(?i)\buid\s*=\s*\d+(?:\s*\([^\r\n)]{1,40}\))?", text)
        gid = re.search(r"(?i)\bgid\s*=\s*\d+(?:\s*\([^\r\n)]{1,40}\))?", text)
        if uid:
            findings.append(
                f"Server response contains {uid.group(0)} "
                "(possible command output; correlate with request)"
            )
        if gid:
            findings.append(
                f"Server response contains {gid.group(0)} "
                "(possible command output; correlate with request)"
            )
        if re.search(r"(?m)^root:[x*]:0:0:", text):
            findings.append(
                "Server response contains Unix passwd-format root account "
                "entry (possible file disclosure; correlate with request)"
            )
        return self.clean(findings)

    def extract_indicators(self, text: str) -> list[str]:
        patterns = (
            r"preg_replace",
            r"useRegex=on",
            r"find=[^&\s]*?/e",
            r"/e\b",
            r"eval\s*\(",
            r"base64_decode\s*\(",
            r"[A-Za-z0-9+/]{40,}={0,2}",
            r"\.\./",
            r"UNHEX\s*\(",
            r"reverse shell",
            r"bind shell",
            r"phpMyAdmin",
            r"CouchDB",
            r"Erlang",
            r"epmd",
        )
        findings: list[str] = []
        for pattern in patterns:
            findings.extend(re.findall(pattern, text, re.IGNORECASE))
        return self.clean(findings)

    def clean(self, findings: list[object]) -> list[str]:
        """Deduplicate while preserving first-observed chronological order."""
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in findings:
            if isinstance(item, tuple):
                item = " ".join(str(part) for part in item)
            # Decode percent escapes only. Do not convert '+' globally because it
            # may be meaningful in Base64, signatures, or binary-derived text.
            value = unquote(str(item).strip())
            if not value:
                continue
            if len(value) > 300:
                value = value[:300] + "...[TRUNCATED]"
            key = value.casefold()
            if key not in seen:
                seen.add(key)
                cleaned.append(value)
        return cleaned

    def format_for_prompt(self, evidence: dict[str, list[EvidenceItem]]) -> str:
        sections: list[str] = []
        for category in self.CATEGORY_ORDER:
            sections.append(f"{category.value.upper()}:")
            items = evidence.get(category.value, [])
            if not items:
                sections.append("- None")
            for item in items:
                metadata = [item.evidence_id, item.direction]
                if item.timestamp_epoch is not None:
                    metadata.append(f"epoch={item.timestamp_epoch:.6f}")
                sections.append(
                    f"- [{' | '.join(metadata)}] {item.observation}"
                )
            sections.append("")
        return "\n".join(sections)
