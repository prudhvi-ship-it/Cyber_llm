"""Tests for application identity priority over backend protocol labels."""
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


class ApplicationIdentityTests(unittest.TestCase):
    def test_joomla_identity_beats_mysql_transport(self):
        hints = FlowSummariser._build_application_identity_hints({
            1: [packet(10, "SHOW DATABASES LIKE 'joomla'"),
                packet(11, "CREATE TABLE j_assets (...)"),
                packet(12, "INSERT INTO j_users (...)"),
                packet(13, "UPDATE j_extensions SET manifest_cache='4.2.7'")]
        })
        self.assertIn("Joomla application/framework candidate", hints)
        self.assertIn("MySQL connection is supporting backend", hints)

    def test_no_identity_fingerprint_does_not_invent_application(self):
        hints = FlowSummariser._build_application_identity_hints({
            1: [packet(10, "SELECT 1")]
        })
        self.assertIn("No high-confidence application fingerprint", hints)
        self.assertNotIn("Joomla application", hints)


if __name__ == "__main__":
    unittest.main()
