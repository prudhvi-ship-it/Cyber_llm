"""Tests for cross-flow primary application resolution."""
import unittest

from evidence_extractor import PacketRecord
from flow_summariser import FlowSummariser


def packet(number, payload):
    return PacketRecord(
        frame_number=number,
        timestamp_epoch=float(number),
        source="10.0.0.2:40000",
        destination="10.0.0.3:3306",
        direction="client->server",
        protocol="MySQL",
        payload=payload,
        payload_bytes=len(payload.encode()),
    )


class PrimaryApplicationResolutionTests(unittest.TestCase):
    def test_resolves_joomla_above_mysql(self):
        result = FlowSummariser._resolve_primary_application({
            1: [packet(1, "CREATE TABLE j_assets (...)"), packet(2, "INSERT INTO j_users (...)"),
                packet(3, "UPDATE j_extensions SET manifest_cache='4.2.7'")]
        })
        self.assertIn("Primary application candidate: Joomla", result)
        self.assertIn("Backend dependency: MySQL", result)

    def test_does_not_invent_unknown_application(self):
        result = FlowSummariser._resolve_primary_application({
            1: [packet(1, "SELECT 1")]
        })
        self.assertIn("No deterministic primary application resolved", result)


if __name__ == "__main__":
    unittest.main()
