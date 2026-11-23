import unittest
from types import SimpleNamespace

from contracts import (
    AnalystOutput,
    AttackFinding,
    AttackOutcome,
    Confidence,
    CVEProposal,
    Decision,
    ServiceFinding,
    VerifierOutput,
    VerificationResult,
)
from evidence_formatter import EvidenceFormatter
from mcp_evidence_policy import derive_online_cve_validation
from mcp_evidence_contracts import OnlineEvidenceResult
from mcp_online_search import MCPOnlineEvidenceSearch
import mcp_online_search


class MCPEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.analyst = AnalystOutput(
            service=ServiceFinding(
                primary="Grafana",
                application="Grafana",
                web_server="nginx/1.18.0",
            ),
            attack=AttackFinding(
                type="Path Traversal",
                technique="Directory Traversal",
                success=AttackOutcome.SUCCESS,
                evidence=["E-S0001-F000123-001"],
            ),
            cve=CVEProposal(
                candidate="CVE-2021-43798",
                confidence=Confidence.HIGH,
                reason="The observed request matches the proposed vulnerability.",
            ),
            confidence=Confidence.HIGH,
        )
        self.verifier = VerifierOutput(
            verification_result=VerificationResult.SUPPORTED,
            service_supported=Decision.YES,
            attack_supported=Decision.YES,
            success_supported=Decision.YES,
            cve_supported=Decision.YES,
            evidence_check=["E-S0001-F000123-001 supports the request."],
            confidence=Confidence.HIGH,
        )
        self.consensus = type(
            "Consensus",
            (),
            {
                "service": "Grafana",
                "attack": "Path Traversal",
                "attack_success": "Success",
            },
        )()

    def test_query_does_not_include_raw_flow_payload(self):
        query = MCPOnlineEvidenceSearch.build_query(
            self.analyst,
            self.verifier,
            self.consensus,
            "SECRET_PACKET_PAYLOAD should never be sent",
        )
        self.assertIn("Grafana", query)
        self.assertIn("Path Traversal", query)
        self.assertNotIn("SECRET_PACKET_PAYLOAD", query)

    def test_structured_result_extracts_sources_and_cves(self):
        sources, cves = MCPOnlineEvidenceSearch._parse_result(
            {
                "sources": [
                    {
                        "source_name": "MITRE ATT&CK",
                        "title": "Traversal reference",
                        "url": "https://example.org/attack",
                        "snippet": "CVE-2021-43798 affects Grafana.",
                    }
                ]
            },
            "",
            "2026-01-01T00:00:00+00:00",
        )
        self.assertEqual(len(sources), 1)
        self.assertEqual(cves, ["CVE-2021-43798"])

    def test_formatter_separates_packet_and_online_evidence(self):
        online = OnlineEvidenceResult(
            status="Valid",
            query="Grafana Path Traversal CVE-2021-43798",
            tool_name="search_forensic_evidence",
            retrieved_at_utc="2026-01-01T00:00:00+00:00",
            sources=[
                {
                    "source_name": "MITRE ATT&CK",
                    "title": "Traversal reference",
                    "url": "https://example.org/attack",
                    "snippet": "Supporting context.",
                    "retrieved_at_utc": "2026-01-01T00:00:00+00:00",
                }
            ],
            candidate_cves=["CVE-2021-43798"],
        )
        formatted = EvidenceFormatter().format(
            "[E-S0001-F000123-001] HTTP request observed",
            self.analyst,
            self.verifier,
            self.consensus,
            online,
        )
        self.assertTrue(formatted.packet_evidence[0].startswith("PCAP ["))
        self.assertTrue(formatted.online_evidence[0].startswith("ONLINE ["))
        self.assertNotEqual(formatted.packet_evidence, formatted.online_evidence)

    def test_online_cve_requires_agent_and_verifier_support(self):
        online = OnlineEvidenceResult(
            status="Valid",
            query="Grafana Path Traversal",
            tool_name="search_forensic_evidence",
            retrieved_at_utc="2026-01-01T00:00:00+00:00",
            candidate_cves=["CVE-2021-43798"],
        )
        decision = derive_online_cve_validation(self.analyst, self.verifier, online)
        self.assertEqual(decision.validated_cve, "CVE-2021-43798")
        self.assertEqual(decision.cve_supported, Decision.YES.value)

    def test_missing_mcp_configuration_abstains_without_crashing(self):
        result = MCPOnlineEvidenceSearch(server_url="").search(
            self.analyst,
            self.verifier,
            self.consensus,
            "[E-S0001-F000123-001] HTTP request observed",
        )
        self.assertEqual(result.status, "Abstain")
        self.assertTrue(result.retrieval_errors)

    def test_no_attack_or_cve_skips_generic_online_search(self):
        result = MCPOnlineEvidenceSearch(
            server_url="http://test.invalid/mcp",
        ).search(
            AnalystOutput(),
            VerifierOutput(),
            self.consensus,
            "Redis service observed without a validated attack",
        )
        self.assertEqual(result.status, "Abstain")
        self.assertIn("no attack, CVE candidate, or packet-linked mechanism signature",
    result.retrieval_errors[0],)

    def test_mcp_client_uses_advertised_tool_and_structured_result(self):
        class FakeClient:
            def __init__(self, _url):
                self.called_with = None

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            async def list_tools(self):
                tool = SimpleNamespace(
                    name="search_forensic_evidence",
                    input_schema={
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                        "required": ["query"],
                    },
                )
                return SimpleNamespace(tools=[tool])

            async def call_tool(self, name, arguments):
                self.called_with = (name, arguments)
                return SimpleNamespace(
                    is_error=False,
                    structured_content={
                        "sources": [
                            {
                                "source_name": "Test source",
                                "title": "Test result",
                                "url": "https://example.org/result",
                                "snippet": "CVE-2021-43798 is relevant.",
                            }
                        ]
                    },
                    content=[],
                )

        previous_client = mcp_online_search.Client
        mcp_online_search.Client = FakeClient
        try:
            result = MCPOnlineEvidenceSearch(
                server_url="http://test.invalid/mcp",
                tool_name="search_forensic_evidence",
            ).search(
                self.analyst,
                self.verifier,
                self.consensus,
                "[E-S0001-F000123-001] HTTP request observed",
            )
        finally:
            mcp_online_search.Client = previous_client

        self.assertEqual(result.status, "Valid")
        self.assertEqual(result.tool_name, "search_forensic_evidence")
        self.assertEqual(result.candidate_cves, ["CVE-2021-43798"])


if __name__ == "__main__":
    unittest.main()
