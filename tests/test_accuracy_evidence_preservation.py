"""Regression tests for packet-linked HTTP indicators and observable effects.

Run from the FRA_Project_V2_MCP root:
  python -m unittest discover -s tests -p 'test_accuracy_evidence_preservation.py' -v
These tests do not call Tshark, the MCP server, an LLM, or external APIs.
"""
import unittest
import tempfile
from pathlib import Path
from collections import Counter

from evidence_extractor import EvidenceExtractor, PacketRecord
from agents.verifier_agent import VerifierAgent
from flow_summariser import FlowSummariser


class AccuracyEvidencePreservationTests(unittest.TestCase):
    def setUp(self):
        self.extractor = EvidenceExtractor()

    @staticmethod
    def packet(frame, direction, payload):
        if direction == "client->server":
            src, dst = "192.0.2.10:50123", "192.0.2.20:80"
        else:
            src, dst = "192.0.2.20:80", "192.0.2.10:50123"
        return PacketRecord(
            frame_number=frame,
            timestamp_epoch=1750000000 + frame,
            source=src,
            destination=dst,
            direction=direction,
            protocol="TCP",
            payload=payload,
            payload_bytes=len(payload.encode("utf-8")),
        )

    def test_nextjs_header_and_redirect_survive_extraction(self):
        packets = [
            self.packet(16, "client->server", "GET / HTTP/1.1\r\nHost: example.test\r\nX-Middleware-Subrequest: middleware:middleware\r\n\r\n"),
            self.packet(18, "server->client", "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nAdmin Dashboard"),
        ]
        data = self.extractor.extract(stream_id=1, packets=packets)
        joined = self.extractor.format_for_prompt(data)
        self.assertIn("X-Middleware-Subrequest: middleware:middleware", joined)
        self.assertRegex(joined, r"E-S0001-F000016-\d{3}")
        self.assertIn("HTTP Status 200", joined)

        redirect = self.extractor.extract_http("HTTP/1.1 307 Temporary Redirect\r\nLocation: /login\r\n\r\n")
        self.assertIn("Location: /login", redirect)
        self.assertIn("HTTP Status 307", redirect)

    def test_server_command_output_has_frame_and_direction(self):
        packets = [
            self.packet(8, "client->server", "POST /api/v1/validate/code HTTP/1.1\r\n\r\nexec('id')"),
            self.packet(12, "server->client", 'HTTP/1.1 200 OK\r\n\r\n{"errors":"uid=0(root) gid=0(root)"}'),
        ]
        data = self.extractor.extract(stream_id=2, packets=packets)
        joined = self.extractor.format_for_prompt(data)
        self.assertIn("Server response contains uid=0(root)", joined)
        self.assertIn("Server response contains gid=0(root)", joined)
        self.assertRegex(joined, r"E-S0002-F000012-\d{3}")
        self.assertIn("server->client", joined)
        # The existing verifier guard must be able to find the new packet ID.
        linked = VerifierAgent._linked_output_ids(joined)
        self.assertTrue(any("F000012" in item for item in linked))

    def test_request_only_is_not_server_output(self):
        req = self.packet(3, "client->server", "POST /api HTTP/1.1\r\n\r\nuid=0(root)")
        data = self.extractor.extract(stream_id=4, packets=[req])
        joined = self.extractor.format_for_prompt(data)
        self.assertNotIn("Server response contains uid=", joined)

    def test_passwd_disclosure_comes_from_response_only(self):
        req = self.packet(3, "client->server", "GET /file?name=/etc/passwd HTTP/1.1\r\n\r\n")
        resp = self.packet(5, "server->client", "HTTP/1.1 200 OK\r\n\r\nroot:x:0:0:root:/root:/bin/bash\n")
        joined = self.extractor.format_for_prompt(self.extractor.extract(stream_id=1, packets=[req,resp]))
        self.assertIn("possible file disclosure", joined)
        self.assertRegex(joined, r"E-S0001-F000005-\d{3}")

    def test_downstream_summary_keeps_indicators_even_if_llm_omits_them(self):
        packets = [
            self.packet(16, "client->server", "GET / HTTP/1.1\r\nX-Middleware-Subrequest: middleware\r\n\r\n"),
            self.packet(18, "server->client", "HTTP/1.1 200 OK\r\n\r\nuid=0(root)"),
        ]
        summariser = FlowSummariser.__new__(FlowSummariser)
        summariser.extractor = self.extractor
        summariser.get_connections = lambda name: "Mock TCP stream"
        summariser.get_stream_ids = lambda name: [0]
        summariser.get_protocol_counts = lambda name: Counter({"TCP": 2})
        summariser.get_flow_content = lambda name, stream: "Mock flow"
        summariser.get_packet_records = lambda name, stream: packets
        summariser.summarise_flow = lambda flow, stream, records: "LLM did not repeat any packet clue"
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "example.pcap"
            target.write_bytes(b"test-only fake pcap")
            summary = summariser.run(str(target))
        self.assertIn("DETERMINISTIC PACKET-LINKED ATTACK INDICATORS", summary)
        self.assertIn("DETERMINISTIC PACKET EVIDENCE CATALOG", summary)
        self.assertIn("X-Middleware-Subrequest: middleware", summary)
        self.assertIn("Server response contains uid=0(root)", summary)
        self.assertIn("E-S0000-F000018", summary)
        self.assertLess(summary.index("DETERMINISTIC PACKET-LINKED"), summary.index("=== Flow Analysis ==="))

    def test_authorization_header_does_not_leak(self):
        payload = "GET / HTTP/1.1\r\nAuthorization: Bearer secretvalue\r\nX-Middleware-Subrequest: middleware\r\n\r\n"
        data = self.extractor.extract(stream_id=1, packets=[self.packet(5, "client->server", payload)])
        joined = self.extractor.format_for_prompt(data)
        self.assertNotIn("secretvalue", joined)
        self.assertIn("X-Middleware-Subrequest: middleware", joined)

    def test_long_flow_preserves_beginning_and_end(self):
        beginning = "GET /initial-request HTTP/1.1\r\n"
        ending = "HTTP/1.1 200 OK\r\n\r\nuid=0(root) gid=0(root)"
        middle = "x" * 500
        bounded = FlowSummariser._preserve_flow_edges(
            beginning + middle + ending,
            max_chars=120,
        )
        self.assertIn("initial-request", bounded)
        self.assertIn("uid=0(root)", bounded)
        self.assertIn("MIDDLE OF REDACTED FLOW OMITTED", bounded)
        self.assertLessEqual(len(bounded), 120)

    def test_previous_flow_context_is_bounded_and_chronological(self):
        context = FlowSummariser._format_previous_flow_context(
            [
                "Earlier TCP stream 0 summary:\nAuthentication succeeded",
                "Earlier TCP stream 1 summary:\nSuspicious request observed",
            ],
            max_chars=200,
        )
        self.assertIn("Authentication succeeded", context)
        self.assertIn("Suspicious request observed", context)
        self.assertLessEqual(len(context), 200)


if __name__ == "__main__":
    unittest.main()
