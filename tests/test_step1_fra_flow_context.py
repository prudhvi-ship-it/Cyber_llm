"""Tests for the FRA-style whole-capture flow context.

These tests are deterministic and do not call Tshark, an LLM, or an API.
"""
import unittest

from evidence_extractor import PacketRecord
from flow_summariser import FlowSummariser


def packet(number, source, destination, direction, payload):
    return PacketRecord(
        frame_number=number,
        timestamp_epoch=float(number),
        source=source,
        destination=destination,
        direction=direction,
        protocol="TCP",
        payload=payload,
        payload_bytes=len(payload.encode()),
    )


class FraFlowContextTests(unittest.TestCase):
    def test_inventory_keeps_application_and_backend_streams(self):
        streams = {
            0: [packet(1, "10.0.0.5:50000", "10.0.0.8:8080", "client->server", "GET /administrator HTTP/1.1")],
            1: [packet(2, "10.0.0.8:40000", "10.0.0.9:3306", "client->server", "SHOW DATABASES")],
        }
        inventory = FlowSummariser._build_flow_inventory(streams)
        self.assertIn("TCP stream 0", inventory)
        self.assertIn("web/application-facing candidate", inventory)
        self.assertIn("TCP stream 1", inventory)
        self.assertIn("backend/data-plane candidate", inventory)
        self.assertIn("do not assume primary application", inventory)

    def test_inventory_is_bounded(self):
        streams = {
            i: [packet(i, "10.0.0.1:1", f"10.0.0.{i+2}:8080", "client->server", "GET /" + "x" * 1000)]
            for i in range(20)
        }
        inventory = FlowSummariser._build_flow_inventory(streams, max_chars=500)
        self.assertLessEqual(len(inventory), 500)


if __name__ == "__main__":
    unittest.main()
