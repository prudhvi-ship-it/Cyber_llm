"""PCAP-to-evidence flow summarisation with explicit Tshark failures."""

from __future__ import annotations

import csv
import os
import shutil
import subprocess
from collections import Counter
from pathlib import Path

from langchain_core.prompts import PromptTemplate

from evidence_extractor import EvidenceExtractor, PacketRecord
from llm_client import get_llm
from prompts import FLOW_SUMMARISER_PROMPT
from structured_output import response_text


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
        return records

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
        if len(redacted_flow) > self.max_flow_chars:
            redacted_flow = (
                redacted_flow[: self.max_flow_chars]
                + "\n...[RAW FLOW TRUNCATED AFTER "
                + str(self.max_flow_chars)
                + " CHARACTERS]"
            )

        enriched_flow = f"""
Processing Status: Valid
TCP Stream: {stream_number}

Deterministic Evidence with Packet References:
{evidence_text}

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

    def run(self, pcap_file: str) -> str:
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

        for stream_number in stream_ids:
            print(f"Analysing stream {stream_number}...")
            try:
                flow_content = self.get_flow_content(str(path), stream_number)
                packets = self.get_packet_records(str(path), stream_number)
                if not packets and len(flow_content.strip()) < 50:
                    print(f"Skipping empty stream {stream_number}.")
                    continue
                summary = self.summarise_flow(
                    flow_content,
                    stream_number,
                    packets,
                )
                full_summary.append(f"\n--- Stream {stream_number} [VALID] ---")
                full_summary.append(summary)
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

        return "\n".join(full_summary)
