"""Offline HTTP gzip response tests; does not start TShark, MCP or LLMs."""
import gzip
import json
import unittest
from dataclasses import replace

from evidence_extractor import EvidenceExtractor, PacketRecord
from flow_summariser import FlowSummariser


class GzipHttpResponseEvidenceTests(unittest.TestCase):
    @staticmethod
    def record(frame, raw, direction="server->client"):
        return PacketRecord(
            frame_number=frame, timestamp_epoch=float(frame),
            source="server:80" if direction == "server->client" else "client:1234",
            destination="client:1234" if direction == "server->client" else "server:80",
            direction=direction, protocol="HTTP", payload=raw.decode("utf-8", "replace"),
            payload_bytes=len(raw), payload_hex=raw.hex(),
        )

    @staticmethod
    def response(body, *, chunked=False, compressed=True):
        raw_body = gzip.compress(body) if compressed else body
        if chunked:
            wire = (f"{len(raw_body):x}\r\n".encode() + raw_body + b"\r\n0\r\n\r\n")
            header = b"Transfer-Encoding: chunked\r\n"
        else:
            wire = raw_body
            header = f"Content-Length: {len(raw_body)}\r\n".encode()
        return (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" +
                (b"Content-Encoding: gzip\r\n" if compressed else b"") +
                header + b"\r\n" + wire)

    def test_gzip_json_produces_packet_cited_output(self):
        body = json.dumps({"message": "uid=33(www-data) gid=33(www-data)",
                           "token": "TEST_SECRET_SHOULD_NOT_APPEAR"}).encode()
        packets = [self.record(190, b"POST /tbl_find_replace.php HTTP/1.1\r\n\r\nsystem(id)", "client->server"),
                   self.record(276, self.response(body))]
        result = FlowSummariser._bounded_http_gzip_observations(packets)
        self.assertIn("uid=33(www-data)", result[1].payload)
        self.assertIn("gid=33(www-data)", result[1].payload)
        self.assertNotIn("TEST_SECRET_SHOULD_NOT_APPEAR", result[1].payload)
        self.assertEqual(result[1].frame_number, 276)
        self.assertEqual(result[1].payload_hex, packets[1].payload_hex)
        extracted = EvidenceExtractor().extract(stream_id=0, packets=result)
        command = extracted["command"]
        self.assertTrue(any("F000276-" in item.evidence_id and
                            "uid=33" in item.observation for item in command))

    def test_fragmented_response(self):
        raw = self.response(b'"uid=33(www-data) gid=33(www-data)"')
        split = raw.index(b"\r\n\r\n") + 12
        packets = [self.record(276, raw[:split]), self.record(277, raw[split:])]
        result = FlowSummariser._bounded_http_gzip_observations(packets)
        self.assertIn("uid=33", result[0].payload)
        self.assertEqual(result[1], packets[1])

    def test_chunked_gzip_response(self):
        packets = [self.record(276, self.response(b"uid=33(www-data) gid=33(www-data)", chunked=True))]
        result = FlowSummariser._bounded_http_gzip_observations(packets)
        self.assertIn("uid=33", result[0].payload)

    def test_uncompressed_response_unchanged(self):
        packets = [self.record(276, self.response(b"uid=33(www-data)", compressed=False))]
        self.assertEqual(FlowSummariser._bounded_http_gzip_observations(packets), packets)

    def test_unrelated_gzip_response_unchanged(self):
        packets = [self.record(276, self.response(b'{"message":"OK"}'))]
        self.assertEqual(FlowSummariser._bounded_http_gzip_observations(packets), packets)

    def test_bad_gzip_response_unchanged(self):
        wire = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 10\r\n\r\ninvalidbad"
        packets = [self.record(276, wire)]
        self.assertEqual(FlowSummariser._bounded_http_gzip_observations(packets), packets)

    def test_truncated_gzip_response_unchanged(self):
        raw = self.response(b"uid=33(www-data)")
        packets = [self.record(276, raw[:-8])]
        self.assertEqual(FlowSummariser._bounded_http_gzip_observations(packets), packets)

    def test_oversized_declared_response_unchanged(self):
        raw = (b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n"
               b"Content-Length: 10000000\r\n\r\n" + gzip.compress(b"uid=33(www-data)"))
        packets = [self.record(276, raw)]
        self.assertEqual(FlowSummariser._bounded_http_gzip_observations(packets), packets)

    def test_client_gzip_request_not_processed(self):
        packets = [self.record(190, self.response(b"uid=33(www-data)"), "client->server")]
        self.assertEqual(FlowSummariser._bounded_http_gzip_observations(packets), packets)

    def test_http_status_alone_does_not_imply_success(self):
        packets = [self.record(276, self.response(b'{"message":"failed"}'))]
        result = FlowSummariser._bounded_http_gzip_observations(packets)
        self.assertEqual(result, packets)

    def test_does_not_claim_success_even_with_output(self):
        packets = [self.record(276, self.response(b"uid=33(www-data) gid=33(www-data)"))]
        result = FlowSummariser._bounded_http_gzip_observations(packets)
        self.assertIn("possible command output", result[0].payload)
        self.assertNotIn("Attack Success: Success", result[0].payload)


if __name__ == "__main__":
    unittest.main()
