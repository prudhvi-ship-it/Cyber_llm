"""Generic packet-linked research query tests, no benchmark-case fixtures."""
import unittest

from contracts import AnalystOutput, ConsensusDecision, VerifierOutput
from mcp_online_search import MCPOnlineEvidenceSearch
from packet_search_features import packet_clues, informative_service, query_clue_words


class MCPQueryImprovementTests(unittest.TestCase):
    def setUp(self):
        self.search = MCPOnlineEvidenceSearch(server_url="http://localhost:8000/mcp")
        self.analyst = AnalystOutput()
        self.verifier = VerifierOutput()
        self.consensus = ConsensusDecision()

    def test_uncommon_header_triggers_search_without_product(self):
        flow = "- [E-S0001-F000016-001 | client->server] X-Route-Selection: private-token-value"
        calls = []
        async def offline_server(query, *args):
            calls.append(query)
            return "search_forensic_evidence", {"sources": [{"title": "lead", "url": "https://example.org", "snippet": "lead"}], "candidate_cves": []}, ""
        self.search._call_server = offline_server
        result = self.search.search(self.analyst, self.verifier, self.consensus, flow)
        self.assertEqual(result.status, "Valid")
        self.assertIn("header route selection", calls[0])
        self.assertNotIn("private-token-value", calls[0])

    def test_unlinked_text_never_turns_into_search_clue(self):
        self.assertEqual(packet_clues("Model guesses POST /private/config/update X-Route-Selection:"), [])
        self.assertEqual(packet_clues("- [E-S0001-F000002-002] GET /health HTTP/1.1"), [])

    def test_generic_endpoint_extracts_names_without_sensitive_values(self):
        flow = "- [E-S0002-F000008-004 | client->server] POST /api/v7/configuration/export?token=secret123"
        query = self.search.build_query(self.analyst, self.verifier, self.consensus, flow)
        self.assertIn("endpoint configuration export", query)
        self.assertNotIn("secret123", query)
        self.assertNotIn("token=", query)

    def test_generic_service_names_are_not_products(self):
        self.assertFalse(informative_service("HTTP JSON API"))
        self.assertFalse(informative_service("Unknown"))
        self.assertTrue(informative_service("ExampleServer"))
        self.analyst.service.primary = "HTTP JSON API"
        query = self.search.build_query(self.analyst, self.verifier, self.consensus, "")
        tool = type("Tool", (), {"input_schema": {"properties": {"service": {}, "query": {}}}})()
        args = self.search._build_arguments(tool, query, self.analyst, self.verifier, self.consensus)
        self.assertNotIn("service", args)

    def test_packet_clues_are_independent_of_cve_labels(self):
        query = self.search.build_query(
            self.analyst, self.verifier, self.consensus,
            "- [E-S0000-F000006-001] PUT /content/share/export?session=REDACTED"
        )
        self.assertEqual(query_clue_words(query), ["content", "share", "export"])
        self.assertNotIn("CVE-", query)


if __name__ == "__main__":
    unittest.main()
