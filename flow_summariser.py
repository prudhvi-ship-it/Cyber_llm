"""PCAP-to-evidence flow summarisation with explicit Tshark failures."""

from __future__ import annotations

import csv
import re
import zlib
from dataclasses import replace
import os
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path

import tiktoken

from langchain_core.prompts import PromptTemplate

from evidence_extractor import EvidenceExtractor, PacketRecord
from attack_flow_ranker import find_http_request_leads, format_ranked_flow_leads
from erlang_cookie_evidence import find_verified_cookie_rpc_sequences
from llm_client import get_llm
from prompts import FLOW_SUMMARISER_PROMPT
from structured_output import response_text


_TOKEN_ENCODING = tiktoken.get_encoding("cl100k_base")


class PcapAnalysisError(RuntimeError):
    """Base exception for deterministic PCAP processing failures."""


class TsharkNotFoundError(PcapAnalysisError):
    """Raised when Tshark cannot be located."""


class TsharkExecutionError(PcapAnalysisError):
    """Raised when Tshark times out or returns a non-zero status."""


class FlowSummariser:
    def __init__(
        self,
        *,
        tshark_path: str | None = None,
        tshark_timeout: int = 60,
        max_flow_chars: int = 6000,
    ):
        self.tshark_path = self._resolve_tshark(tshark_path)
        self.tshark_timeout = max(5, int(tshark_timeout))
        self.max_flow_chars = max(1000, int(max_flow_chars))
        self.extractor = EvidenceExtractor()
        self.llm = get_llm("flow_summariser")
        self.prompt = PromptTemplate(
            input_variables=["flow_content"],
            template=FLOW_SUMMARISER_PROMPT,
        )
        self._previous_flow_context = ""
        self._current_flow_header = ""
        self._current_flow_token_limit = 0

    @staticmethod
    def _count_flow_tokens(flow: str) -> int:
        return len(_TOKEN_ENCODING.encode(flow or "")) + 6

    @staticmethod
    def _sqrt_token_allocation(flow_sizes: list[int], budget: int) -> list[int]:
        """Port FRA's square-root allocation across TCP flows."""
        if not flow_sizes:
            return []
        budget = max(0, int(budget))
        if sum(flow_sizes) <= budget:
            return list(flow_sizes)
        positive = [size for size in flow_sizes if size > 0]
        if not positive or budget == 0:
            return [0] * len(flow_sizes)
        root_sum = sum(size ** 0.5 for size in flow_sizes)
        allocations = [
            min(size, int((size ** 0.5 / root_sum) * budget))
            for size in flow_sizes
        ]
        remaining = budget - sum(allocations)
        while remaining > 0:
            eligible = [
                index for index, size in enumerate(flow_sizes)
                if allocations[index] < size
            ]
            if not eligible:
                break
            for index in sorted(eligible, key=lambda item: flow_sizes[item], reverse=True):
                if remaining <= 0:
                    break
                allocations[index] += 1
                remaining -= 1
        return allocations

    def get_tls_streams(self, pcap_file: str) -> set[int]:
        """Return TCP streams containing TLS, matching FRA's normal-PCAP rule."""
        output = self._run_tshark(
            ["-r", pcap_file, "-Y", "tls", "-T", "fields", "-e", "tcp.stream"],
            "TLS stream discovery",
        )
        streams: set[int] = set()
        for value in output.splitlines():
            value = value.strip()
            if value.isdigit():
                streams.add(int(value))
        return streams

    @staticmethod
    def _truncate_flow_tokens(flow: str, token_limit: int) -> str:
        if token_limit <= 0 or FlowSummariser._count_flow_tokens(flow) <= token_limit:
            return flow
        keep = max(1, (token_limit - 20) // 2)
        tokens = _TOKEN_ENCODING.encode(flow)
        return (
            "Beginning of the TCP flow:\n"
            + _TOKEN_ENCODING.decode(tokens[:keep])
            + "\n--- final part of the flow ---\n"
            + _TOKEN_ENCODING.decode(tokens[-keep:])
        )

    @staticmethod
    def _resolve_tshark(configured_path: str | None) -> str:
        configured = configured_path or os.getenv("TSHARK_PATH")
        candidates = [
            configured,
            shutil.which("tshark"),
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ]
        for candidate in candidates:
            if candidate and Path(candidate).is_file():
                return str(Path(candidate))
        raise TsharkNotFoundError(
            "Tshark was not found. Install Wireshark with Tshark or set "
            "TSHARK_PATH to tshark.exe."
        )

    def _run_tshark(self, arguments: list[str], operation: str) -> str:
        command = [self.tshark_path, *arguments]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.tshark_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TsharkExecutionError(
                f"Tshark timed out after {self.tshark_timeout}s during {operation}."
            ) from exc
        except OSError as exc:
            raise TsharkExecutionError(
                f"Tshark could not start during {operation}: {type(exc).__name__}."
            ) from exc

        if result.returncode != 0:
            stderr = (result.stderr or "No Tshark error details").strip()
            raise TsharkExecutionError(
                f"Tshark failed during {operation} with exit code "
                f"{result.returncode}: {stderr[:500]}"
            )
        return result.stdout

    @staticmethod
    def _validate_pcap(pcap_file: str) -> Path:
        path = Path(pcap_file)
        if not path.is_file():
            raise FileNotFoundError(f"PCAP file not found: {path}")
        if path.suffix.casefold() not in {".pcap", ".pcapng", ".cap"}:
            raise PcapAnalysisError(
                f"Unsupported capture extension '{path.suffix}'. "
                "Expected .pcap, .pcapng, or .cap."
            )
        return path

    @classmethod
    def preflight(
        cls,
        pcap_file: str,
        *,
        tshark_path: str | None = None,
        tshark_timeout: int = 60,
    ) -> dict[str, object]:
        """Inspect a capture without constructing an LLM or making API calls."""
        inspector = cls.__new__(cls)
        inspector.tshark_path = cls._resolve_tshark(tshark_path)
        inspector.tshark_timeout = max(5, int(tshark_timeout))
        path = cls._validate_pcap(pcap_file)
        stream_ids = inspector.get_stream_ids(str(path))
        protocol_counts = inspector.get_protocol_counts(str(path))
        packet_counts = {
            str(stream_id): len(inspector.get_packet_records(str(path), stream_id))
            for stream_id in stream_ids
        }
        return {
            "status": "Valid",
            "pcap": str(path.resolve()),
            "size_bytes": path.stat().st_size,
            "tshark": inspector.tshark_path,
            "tcp_stream_ids": stream_ids,
            "tcp_packet_counts": packet_counts,
            "protocol_counts": dict(protocol_counts),
        }

    def get_connections(self, pcap_file: str) -> str:
        return self._run_tshark(
            ["-r", pcap_file, "-q", "-z", "conv,tcp"],
            "TCP conversation discovery",
        )

    def get_stream_ids(self, pcap_file: str) -> list[int]:
        output = self._run_tshark(
            [
                "-r",
                pcap_file,
                "-Y",
                "tcp",
                "-T",
                "fields",
                "-e",
                "tcp.stream",
            ],
            "TCP stream discovery",
        )
        stream_ids: set[int] = set()
        for value in output.splitlines():
            value = value.strip().split(",", maxsplit=1)[0]
            if value.isdigit():
                stream_ids.add(int(value))
        return sorted(stream_ids)

    def count_streams(self, pcap_file: str) -> int:
        """Compatibility helper retained for callers of the previous API."""
        return len(self.get_stream_ids(pcap_file))

    def get_flow_content(self, pcap_file: str, stream_number: int) -> str:
        return self._run_tshark(
            [
                "-r",
                pcap_file,
                "-q",
                "-z",
                f"follow,tcp,ascii,{stream_number}",
            ],
            f"TCP stream {stream_number} reconstruction",
        )

    def get_protocol_counts(self, pcap_file: str) -> Counter[str]:
        output = self._run_tshark(
            [
                "-r",
                pcap_file,
                "-T",
                "fields",
                "-e",
                "_ws.col.Protocol",
            ],
            "protocol inventory",
        )
        return Counter(
            protocol.strip() or "Unknown"
            for protocol in output.splitlines()
            if protocol.strip()
        )

    @staticmethod
    def _decode_tcp_payload(payload_hex: str) -> tuple[str, int]:
        compact = payload_hex.replace(":", "").strip()
        if not compact:
            return "", 0
        try:
            payload_bytes = bytes.fromhex(compact)
        except ValueError:
            return "", 0
        return payload_bytes.decode("utf-8", errors="replace"), len(payload_bytes)

    @staticmethod
    def _bounded_http_gzip_observations(
        packets: list[PacketRecord],
    ) -> list[PacketRecord]:
        """Expose only packet-linked command-output clues in gzip HTTP replies.

        The original payload_hex and packet metadata remain untouched.  This
        method does NOT turn an HTTP 200 or an echoed command into success.
        Malformed, truncated, oversized and non-HTTP bodies are left as-is.
        It does not process TLS ciphertext or decompress data for display.
        """
        max_compressed = 256 * 1024
        max_expanded = 512 * 1024
        changed = list(packets)
        for index, packet in enumerate(packets):
            if packet.direction != "server->client" or not packet.payload_hex:
                continue
            try:
                first = bytes.fromhex(packet.payload_hex)
            except ValueError:
                continue
            if not re.match(rb"^HTTP/1\.[01] [1-5][0-9][0-9]\b", first):
                continue
            split_at = first.find(b"\r\n\r\n")
            if split_at < 0 or split_at > 32768:
                continue
            header = first[:split_at]
            if not re.search(rb"(?im)^content-encoding:\s*gzip\s*$", header):
                continue
            length_match = re.search(rb"(?im)^content-length:\s*(\d+)\s*$", header)
            chunked = bool(re.search(rb"(?im)^transfer-encoding:.*\bchunked\b", header))
            if not length_match and not chunked:
                continue
            length = int(length_match.group(1)) if length_match else None
            if length is not None and not 0 < length <= max_compressed:
                continue
            # Include later server-to-client chunks from the *same TCP stream*
            # without including unrelated client requests.  Reassembly is
            # bounded and only trusted if gzip CRC/end marker validates.
            data = bytearray(first[split_at + 4:])
            for subsequent in packets[index + 1:index + 129]:
                if (len(data) >= max_compressed + 8192 or
                        (length is not None and len(data) >= length)):
                    break
                if (subsequent.direction != "server->client" or
                        subsequent.source != packet.source or
                        subsequent.destination != packet.destination):
                    continue
                try:
                    segment = bytes.fromhex(subsequent.payload_hex)
                except ValueError:
                    break
                if segment.startswith(b"HTTP/1."):
                    break
                data.extend(segment)
            if length is not None:
                if len(data) < length:
                    continue
                compressed = bytes(data[:length])
            else:
                # Parse bounded HTTP chunk framing; no arbitrary gzip search.
                cursor = 0
                assembled = bytearray()
                complete = False
                for _ in range(256):
                    end = data.find(b"\r\n", cursor)
                    if end < 0 or end - cursor > 16:
                        break
                    try:
                        size = int(data[cursor:end].split(b";", 1)[0], 16)
                    except ValueError:
                        break
                    cursor = end + 2
                    if size == 0:
                        complete = True
                        break
                    if (size < 0 or len(assembled) + size > max_compressed or
                            cursor + size + 2 > len(data) or
                            data[cursor + size:cursor + size + 2] != b"\r\n"):
                        break
                    assembled.extend(data[cursor:cursor + size])
                    cursor += size + 2
                if not complete:
                    continue
                compressed = bytes(assembled)
            try:
                decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
                decoded = decompressor.decompress(compressed, max_expanded + 1)
                if (len(decoded) > max_expanded or not decompressor.eof or
                        decompressor.unused_data or decompressor.unconsumed_tail):
                    continue
            except zlib.error:
                continue
            # Only explicitly recognizable command-output observations are
            # carried forward.  Never inject raw HTML/JSON or credentials.
            text = decoded.decode("utf-8", errors="replace")
            uid = re.search(r"(?i)\buid=\d+(?:\([A-Za-z0-9_.-]{1,40}\))?", text)
            gid = re.search(r"(?i)\bgid=\d+(?:\([A-Za-z0-9_.-]{1,40}\))?", text)
            if not uid and not gid:
                continue
            observations = " ".join(m.group(0) for m in (uid, gid) if m)
            note = ("\n[Decoded gzip HTTP server response, packet-linked "
                    "possible command output; correlate with request: "
                    + observations + "]")
            changed[index] = replace(packet, payload=packet.payload + note)
        return changed

    def get_packet_records(
        self,
        pcap_file: str,
        stream_number: int,
    ) -> list[PacketRecord]:
        fields = (
            "frame.number",
            "frame.time_epoch",
            "ip.src",
            "ipv6.src",
            "tcp.srcport",
            "ip.dst",
            "ipv6.dst",
            "tcp.dstport",
            "_ws.col.Protocol",
            "tcp.payload",
        )
        arguments = [
            "-r",
            pcap_file,
            "-Y",
            f"tcp.stream == {stream_number}",
            "-T",
            "fields",
            "-E",
            "separator=,",
            "-E",
            "quote=d",
            "-E",
            "occurrence=f",
        ]
        for field in fields:
            arguments.extend(["-e", field])

        output = self._run_tshark(
            arguments,
            f"packet metadata extraction for TCP stream {stream_number}",
        )
        rows = list(csv.reader(output.splitlines()))
        raw_records: list[dict[str, object]] = []
        for row in rows:
            if len(row) < len(fields):
                row.extend([""] * (len(fields) - len(row)))
            try:
                frame_number = int(row[0])
                timestamp = float(row[1])
            except (TypeError, ValueError):
                continue

            source_ip = row[2] or row[3] or "Unknown"
            destination_ip = row[5] or row[6] or "Unknown"
            source = f"{source_ip}:{row[4]}" if row[4] else source_ip
            destination = f"{destination_ip}:{row[7]}" if row[7] else destination_ip
            payload, payload_size = self._decode_tcp_payload(row[9])
            raw_records.append(
                {
                    "frame_number": frame_number,
                    "timestamp_epoch": timestamp,
                    "source": source,
                    "destination": destination,
                    "protocol": row[8] or "TCP",
                    "payload": payload,
                    "payload_bytes": payload_size,
                    "payload_hex": row[9].replace(":", "").strip(),
                }
            )

        if not raw_records:
            return []
        client = str(raw_records[0]["source"])
        server = str(raw_records[0]["destination"])
        records: list[PacketRecord] = []
        for record in raw_records:
            if record["source"] == client and record["destination"] == server:
                direction = "client->server"
            elif record["source"] == server and record["destination"] == client:
                direction = "server->client"
            else:
                direction = "peer->peer"
            records.append(PacketRecord(direction=direction, **record))
        return self._bounded_http_gzip_observations(records)

    @staticmethod
    def format_packet_timeline(packets: list[PacketRecord], limit: int = 100) -> str:
        lines: list[str] = []
        for packet in packets[:limit]:
            lines.append(
                f"- frame={packet.frame_number} epoch={packet.timestamp_epoch:.6f} "
                f"direction={packet.direction} protocol={packet.protocol} "
                f"payload_bytes={packet.payload_bytes}"
            )
        if len(packets) > limit:
            lines.append(f"- ... {len(packets) - limit} additional packets omitted")
        return "\n".join(lines) or "- None"

    @staticmethod
    def _preserve_flow_edges(flow: str, max_chars: int) -> str:
        """Keep both ends of a redacted flow when the raw text is large.

        The end of a TCP flow often contains the server response that proves
        whether an exploit succeeded.  Keeping only the head can therefore
        hide the most important forensic observation.  This follows the
        packet-flow reference design while retaining MAFRA's redaction step.
        """
        if len(flow) <= max_chars:
            return flow

        marker = "\n...[MIDDLE OF REDACTED FLOW OMITTED]...\n"
        content_chars = max(2, max_chars - len(marker))
        head_chars = content_chars // 2
        tail_chars = content_chars - head_chars
        return flow[:head_chars] + marker + flow[-tail_chars:]

    @classmethod
    def _format_previous_flow_context(
        cls,
        previous_summaries: list[str],
        max_chars: int = 4000,
    ) -> str:
        """Build bounded context from earlier flow summaries.

        CyberSleuth carries earlier flow analysis into later flow analysis.
        MAFRA keeps that useful correlation signal, but passes summaries only,
        not previous raw TCP traffic, and bounds the context size.
        """
        if not previous_summaries:
            return "- None (this is the first analyzed flow)"
        joined = "\n\n".join(previous_summaries)
        return cls._preserve_flow_edges(joined, max_chars)

    @staticmethod
    def _flow_role_hint(packets: list[PacketRecord]) -> str:
        """Return a cautious, non-decisional role hint for a TCP stream.

        FRA gives the analyst the complete flow picture before it chooses the
        attacked application.  MAFRA keeps that behavior without turning
        ports into a service verdict: a capture can contain both a web-facing
        application and its database/cache traffic.
        """
        if not packets:
            return "no packet payloads available"
        first = packets[0]
        server_endpoint = first.destination
        try:
            server_port = int(server_endpoint.rsplit(":", 1)[-1])
        except (TypeError, ValueError):
            server_port = 0
        payload = "\n".join(packet.payload for packet in packets[:30]).casefold()
        http_method = any(
            token in payload
            for token in ("get ", "post ", "put ", "delete ", "head ", "options ")
        )
        http_response = "http/1." in payload or "http/2" in payload
        web_ports = {80, 443, 8000, 8001, 8080, 8081, 8888, 3000, 5000, 5601}
        data_ports = {
            3306, 5432, 6379, 6380, 9042, 9200, 9300, 27017, 5984,
            11211, 1433, 1521, 2181, 2375, 4369, 9100,
        }
        if http_method or http_response or server_port in web_ports:
            return "web/application-facing candidate (heuristic; verify from payload)"
        if server_port in data_ports:
            return "backend/data-plane candidate (heuristic; do not assume primary application)"
        return "other protocol/application candidate (heuristic; verify from payload)"

    @classmethod
    def _build_flow_inventory(
        cls,
        stream_packets: dict[int, list[PacketRecord]],
        max_chars: int = 8000,
    ) -> str:
        """Build the bounded whole-capture map passed to every flow prompt."""
        lines = [
            "FLOW INVENTORY (all observed TCP streams; metadata and role hints "
            "are untrusted observations, not a service/CVE decision):"
        ]
        for stream_id in sorted(stream_packets):
            packets = stream_packets[stream_id]
            if packets:
                first = packets[0]
                endpoints = f"{first.source} -> {first.destination}"
                directions = ", ".join(
                    f"{direction}={sum(p.direction == direction for p in packets)}"
                    for direction in ("client->server", "server->client")
                )
                lines.append(
                    f"- TCP stream {stream_id}: {endpoints}; packets={len(packets)}; "
                    f"{directions}; role_hint={cls._flow_role_hint(packets)}"
                )
            else:
                lines.append(f"- TCP stream {stream_id}: no packet records")
        return cls._preserve_flow_edges("\n".join(lines), max_chars)

    @classmethod
    def _build_application_identity_hints(
        cls,
        stream_packets: dict[int, list[PacketRecord]],
        max_chars: int = 5000,
    ) -> str:
        """Find application fingerprints that can be hidden behind a backend.

        Database traffic often names the application through schema/table
        identifiers even when the HTTP flow is small or absent.  These are
        candidates for Analyst review, not automatic CVE or success claims.
        """
        combined = "\n".join(
            packet.payload for packets in stream_packets.values() for packet in packets
        ).casefold()
        candidates: list[str] = []

        joomla_tables = sorted(set(re.findall(r"\bj_(?:[a-z0-9_]+)", combined)))
        if "joomla" in combined or len(joomla_tables) >= 2 or "manifest_cache" in combined:
            details = ", ".join(joomla_tables[:8]) or "Joomla-specific identifiers"
            candidates.append(
                f"- Joomla application/framework candidate: observed {details}. "
                "A MySQL connection is supporting backend evidence here."
            )
        if "wordpress" in combined or re.search(r"\bwp_[a-z0-9_]+", combined):
            candidates.append(
                "- WordPress application candidate: WordPress name or wp_ schema "
                "identifiers observed. Treat MySQL as supporting backend evidence."
            )
        if "drupal" in combined or re.search(r"\b(?:node|users|watchdog)__", combined):
            candidates.append(
                "- Drupal application candidate: Drupal-specific identifiers observed. "
                "Treat the database protocol as supporting backend evidence."
            )
        if "phpmyadmin" in combined:
            candidates.append(
                "- phpMyAdmin application candidate: phpMyAdmin identifier observed."
            )
        if not candidates:
            candidates.append(
                "- No high-confidence application fingerprint was detected by the "
                "deterministic pre-scan; use flow payloads and web evidence carefully."
            )
        return cls._preserve_flow_edges(
            "APPLICATION IDENTITY CANDIDATES (heuristic observations only):\n"
            + "\n".join(candidates),
            max_chars,
        )

    @classmethod
    def _resolve_primary_application(
        cls,
        stream_packets: dict[int, list[PacketRecord]],
        max_chars: int = 3500,
    ) -> str:
        """Aggregate strong application fingerprints across all TCP flows.

        This is deliberately limited to identity resolution. It does not
        decide the CVE, exploit type, or attack outcome.
        """
        combined = "\n".join(
            packet.payload for packets in stream_packets.values() for packet in packets
        ).casefold()
        joomla_tables = sorted(set(re.findall(r"\bj_(?:[a-z0-9_]+)", combined)))
        if "joomla" in combined or len(joomla_tables) >= 2 or "manifest_cache" in combined:
            return cls._preserve_flow_edges(
                "PRIMARY APPLICATION RESOLUTION (identity only):\n"
                "- Primary application candidate: Joomla\n"
                f"- Supporting fingerprints: {', '.join(joomla_tables[:10]) or 'Joomla identifiers'}\n"
                "- Backend dependency: MySQL\n"
                "- Reason: application-specific schema and version artifacts are "
                "more specific than the database protocol label.\n"
                "- This is not a CVE or attack-success decision.",
                max_chars,
            )
        if "wordpress" in combined or re.search(r"\bwp_[a-z0-9_]+", combined):
            return cls._preserve_flow_edges(
                "PRIMARY APPLICATION RESOLUTION (identity only):\n"
                "- Primary application candidate: WordPress\n"
                "- This is not a CVE or attack-success decision.",
                max_chars,
            )
        if "drupal" in combined or re.search(r"\b(?:node|users|watchdog)__", combined):
            return cls._preserve_flow_edges(
                "PRIMARY APPLICATION RESOLUTION (identity only):\n"
                "- Primary application candidate: Drupal\n"
                "- This is not a CVE or attack-success decision.",
                max_chars,
            )
        return "PRIMARY APPLICATION RESOLUTION (identity only):\n- No deterministic primary application resolved."

    def summarise_flow(
        self,
        flow_content: str,
        stream_number: int,
        packets: list[PacketRecord],
    ) -> str:
        evidence = self.extractor.extract(
            flow_content,
            stream_id=stream_number,
            packets=packets or None,
        )
        evidence_text = self.extractor.format_for_prompt(evidence)
        redacted_flow = self.extractor.redact_text(flow_content)
        token_limit = getattr(self, "_current_flow_token_limit", 0)
        if token_limit:
            redacted_flow = self._truncate_flow_tokens(redacted_flow, token_limit)
        else:
            redacted_flow = self._preserve_flow_edges(redacted_flow, self.max_flow_chars)

        # Add request/body observations to each per-flow LLM prompt before
        # the truncated raw-flow head. This survives large preceding responses.
        request_leads = find_http_request_leads(packets, stream_number)
        previous_flow_context = getattr(self, "_previous_flow_context", "")
        if not previous_flow_context:
            previous_flow_context = "- None (this is the first analyzed flow)"
        flow_inventory = getattr(self, "_flow_inventory", "")
        if not flow_inventory:
            flow_inventory = "- Not available"
        identity_hints = getattr(self, "_application_identity_hints", "")
        if not identity_hints:
            identity_hints = "- Not available"
        primary_resolution = getattr(self, "_primary_application_resolution", "")
        if not primary_resolution:
            primary_resolution = "- Not available"
        enriched_flow = f"""
Processing Status: Valid
TCP Stream: {stream_number}
Current flow header: {getattr(self, '_current_flow_header', '') or 'Not available'}

WHOLE-CAPTURE FLOW INVENTORY:
{flow_inventory}

APPLICATION IDENTITY CANDIDATES:
{identity_hints}

PRIMARY APPLICATION RESOLUTION:
{primary_resolution}

PREVIOUS FLOW CONTEXT (UNTRUSTED OBSERVATIONS ONLY; NOT A CVE DECISION):
{previous_flow_context}

Deterministic Evidence with Packet References:
{evidence_text}

PRIORITIZED HTTP REQUEST OBSERVATIONS (HEURISTIC, NOT A CVE DECISION):
{format_ranked_flow_leads(request_leads, limit=5)}

Packet Timeline:
{self.format_packet_timeline(packets)}

Untrusted Redacted TCP Flow:
<untrusted_flow>
{redacted_flow}
</untrusted_flow>
"""
        chain = self.prompt | self.llm
        response = chain.invoke({"flow_content": enriched_flow})
        summary = response_text(response.content).strip()
        if not summary:
            raise RuntimeError("LLM returned an empty flow summary")
        return summary

    @staticmethod
    def high_signal_packet_lines(evidence: dict[str, list]) -> list[str]:
        """Carry packet-linked candidate clues past the first LLM summary.

        This is a limited observation feed, not a CVE verdict or an assertion
        that an exploit worked. Preserve exact frame IDs and directions.
        """
        patterns = (
            "x-middleware-subrequest:",
            "location:",
            "server response contains uid=",
            "server response contains gid=",
            "server response contains unix passwd-format",
            "/api/v1/validate/code",
            "tbl_find_replace",
            "index.php?target=",
            "?raw??",
            ".session",
        )
        output: list[str] = []
        for category in ("http", "command", "indicator"):
            for item in evidence.get(category, []):
                obs = item.observation
                if any(term in obs.casefold() for term in patterns):
                    output.append(
                        f"- [{item.evidence_id} | {item.direction}] {obs}"
                    )
        return output

    def run(self, pcap_file: str) -> str:
        self.verified_cookie_rpc_sequences = []
        path = self._validate_pcap(pcap_file)
        print(f"Analysing PCAP file: {path}")
        connections = self.get_connections(str(path))
        stream_ids = self.get_stream_ids(str(path))
        protocol_counts = self.get_protocol_counts(str(path))

        print(f"Connections found:\n{connections[:500]}")
        print(f"TCP stream IDs: {stream_ids}")
        print(f"Protocol counts: {dict(protocol_counts)}")

        full_summary = [
            "=== PCAP Analysis Report ===",
            "File: incident.pcap",
            "Processing Status: Valid",
            f"Total TCP Streams: {len(stream_ids)}",
            f"TCP Stream IDs: {', '.join(map(str, stream_ids)) or 'None'}",
            "Protocol Counts: "
            + (", ".join(f"{key}={value}" for key, value in protocol_counts.items()) or "None"),
            f"\nConnections Overview:\n{connections[:1000]}",
            "\n=== Flow Analysis ===",
        ]

        ranked_candidates = []
        high_signal_lines: list[str] = []
        deterministic_evidence_lines: list[str] = []
        previous_flow_summaries: list[str] = []
        self._previous_flow_context = ""
        # Collect packet metadata before the first LLM call.  This is the
        # FRA-style whole-capture context that prevents a backend connection
        # from being mistaken for the attacked application.
        packets_by_stream: dict[int, list[PacketRecord]] = {}
        for stream_number in stream_ids:
            try:
                packets_by_stream[stream_number] = self.get_packet_records(
                    str(path), stream_number
                )
            except Exception as exc:
                print(
                    f"Packet metadata for stream {stream_number} failed: "
                    f"{type(exc).__name__}: {str(exc)[:200]}"
                )
                packets_by_stream[stream_number] = []
        self._flow_inventory = self._build_flow_inventory(packets_by_stream)
        self._application_identity_hints = self._build_application_identity_hints(
            packets_by_stream
        )
        self._primary_application_resolution = self._resolve_primary_application(
            packets_by_stream
        )
        try:
            tls_streams = self.get_tls_streams(str(path))
        except Exception as exc:
            print(
                f"TLS stream discovery failed; continuing without TLS filtering: "
                f"{type(exc).__name__}: {str(exc)[:200]}"
            )
            tls_streams = set()
        flow_contents: dict[int, str] = {}
        flow_sizes: list[int] = []
        for stream_number in stream_ids:
            if stream_number in tls_streams:
                flow_contents[stream_number] = ""
                flow_sizes.append(0)
                continue
            try:
                content = self.get_flow_content(str(path), stream_number)
            except Exception:
                content = ""
            flow_contents[stream_number] = content
            flow_sizes.append(self._count_flow_tokens(content))
        token_budget = int(os.getenv("FRA_FLOW_TOKENS_BUDGET", "12000"))
        allocations = self._sqrt_token_allocation(flow_sizes, token_budget)
        full_summary.append("\n" + self._flow_inventory)
        full_summary.append("\n" + self._application_identity_hints)
        full_summary.append("\n" + self._primary_application_resolution)
        for stream_number in stream_ids:
            print(f"Analysing stream {stream_number}...")
            try:
                if stream_number in tls_streams:
                    full_summary.append(
                        f"\n--- Stream {stream_number} [TLS SKIPPED, FRA rule] ---\n"
                        "Encrypted TLS traffic was excluded from normal PCAP flow "
                        "analysis; no inference was made from its contents."
                    )
                    continue
                flow_content = flow_contents.get(stream_number, "")
                packets = packets_by_stream.get(stream_number, [])
                if not packets and len(flow_content.strip()) < 50:
                    print(f"Skipping empty stream {stream_number}.")
                    continue
                self._current_flow_token_limit = (
                    allocations[stream_ids.index(stream_number)]
                    if stream_number in stream_ids else 0
                )
                self._current_flow_header = (
                    f"TCP stream {stream_number}; packets={len(packets)}; "
                    f"{packets[0].source} -> {packets[0].destination}"
                    if packets else f"TCP stream {stream_number}; no packet records"
                )
                summary = self.summarise_flow(
                    flow_content,
                    stream_number,
                    packets,
                )
                previous_flow_summaries.append(
                    f"Earlier TCP stream {stream_number} summary:\n{summary}"
                )
                full_summary.append(f"\n--- Stream {stream_number} [VALID] ---")
                full_summary.append(summary)
                # FRA passes the growing report, not only the previous model
                # answer, into the next flow analyzer.
                self._previous_flow_context = self._preserve_flow_edges(
                    "\n".join(full_summary), 8000
                )
                # Append packet-derived correlations OUTSIDE the LLM summary.
                # This makes the request/reply link available to the Verifier
                # even if the Flow Summariser omits it in free-form prose.
                parsed_evidence = self.extractor.extract(
                    stream_id=stream_number, packets=packets
                )
                for category in self.extractor.CATEGORY_ORDER:
                    for item in parsed_evidence.get(category.value, []):
                        deterministic_evidence_lines.append(
                            f"- [{item.evidence_id} | {item.direction}] "
                            f"{item.observation}"
                        )
                high_signal_lines.extend(self.high_signal_packet_lines(parsed_evidence))
                ranked_candidates.extend(find_http_request_leads(packets, stream_number))
                verified_sequences = find_verified_cookie_rpc_sequences(packets, stream_number)
                self.verified_cookie_rpc_sequences.extend(verified_sequences)
                if verified_sequences:
                    full_summary.append(
                        "DETERMINISTIC ERLANG DEFAULT-COOKIE AUTHENTICATION "
                        "FROM RAW PACKETS (NOT LLM OR CVE LABEL):"
                    )
                    for sequence in verified_sequences:
                        hs = sequence.handshake
                        matches = [item for item in parsed_evidence.get("authentication", [])
                                   if item.frame_number in (hs.challenge_frame, hs.client_reply_frame, hs.server_ack_frame)
                                   and "Erlang" in item.observation]
                        for item in matches:
                            full_summary.append(f"- [{item.evidence_id}] direction={item.direction}; {item.observation}")
                        full_summary.append(
                            f"Verified legacy default cookie both ways; frames "
                            f"{hs.challenge_frame}, {hs.client_reply_frame}, "
                            f"{hs.server_ack_frame}; correlated RPC frames "
                            f"{sequence.rpc.request_frame}, {sequence.rpc.reply_frame}. "
                            "External exposure and authorization are not established."
                        )

                rpc_evidence = [
                    item for item in parsed_evidence.get("command", [])
                    if item.observation.startswith((
                        "Erlang RPC request: os:cmd('id')",
                        "Server response contains Erlang rex command output",
                    ))
                ]
                if rpc_evidence:
                    full_summary.append(
                        "DETERMINISTIC ERLANG RPC CORRELATION FROM RAW PACKETS "
                        "(not an LLM interpretation):"
                    )
                    for item in rpc_evidence:
                        full_summary.append(
                            f"- [{item.evidence_id}] "
                            f"direction={item.direction}; {item.observation}"
                        )
                    full_summary.append(
                        "Interpretation: command execution response observed; "
                        "authorization and exact CVE are NOT established."
                    )
            except Exception as exc:
                print(
                    f"Stream {stream_number} failed: "
                    f"{type(exc).__name__}: {str(exc)[:300]}"
                )
                full_summary.append(f"\n--- Stream {stream_number} [ERROR] ---")
                full_summary.append(
                    "Processing Status: Error\n"
                    "Service: Unknown\n"
                    "Attack Success: Unknown\n"
                    "Evidence: Stream processing failed; no prediction accepted."
                )

        # Put the shortlist before all verbose per-stream summaries. This
        # helps downstream agents avoid choosing busy background TCP traffic.
        # Every request remains a candidate, not a declared primary attack.
        full_summary.insert(full_summary.index("\n=== Flow Analysis ==="),
                            "\n" + format_ranked_flow_leads(ranked_candidates))
        # Do not depend on the Flow Summariser LLM to repeat diagnostic bytes.
        # Keep the provenance feed near the beginning for downstream Analyst,
        # MCP candidate search and Verifier; bound its size for long captures.
        high_signal_section = (
            "\nDETERMINISTIC PACKET-LINKED ATTACK INDICATORS "
            "(CANDIDATES; NOT EXPLOIT OR CVE CONFIRMATION):\n"
            + "\n".join(high_signal_lines[:80])
            + (f"\n- ... {len(high_signal_lines) - 80} further indicators omitted"
               if len(high_signal_lines) > 80 else "")
        ) if high_signal_lines else ""
        if high_signal_section:
            full_summary.insert(full_summary.index("\n=== Flow Analysis ==="), high_signal_section)

        # Keep a complete, packet-linked catalog separate from the LLM
        # summaries.  The Reporter may cite any evidence ID selected by the
        # Analyst; therefore every deterministic description must remain
        # available to the formatter, not only the small high-signal shortlist.
        evidence_catalog_section = (
            "\nDETERMINISTIC PACKET EVIDENCE CATALOG "
            "(PRIMARY OBSERVATIONS; NOT CVE CONFIRMATION):\n"
            + "\n".join(deterministic_evidence_lines)
        ) if deterministic_evidence_lines else ""
        if evidence_catalog_section:
            full_summary.insert(
                full_summary.index("\n=== Flow Analysis ==="),
                evidence_catalog_section,
            )
        return "\n".join(full_summary)
