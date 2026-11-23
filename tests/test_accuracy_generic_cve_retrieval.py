"""Synthetic security-record tests: no evaluated PCAPs, labels or API calls."""
import importlib
import sys
import types
import unittest
from unittest.mock import patch

try:
    import mcp.server  # noqa
except ImportError:
    # Allow isolated tests to run in a dependency-light analysis container.
    # The user's project uses the installed SDK; this stub never ships to runtime.
    module = sys.modules.setdefault("mcp", types.ModuleType("mcp"))
    server_module = types.ModuleType("mcp.server")
    class MCPServer:
        def __init__(self, *args, **kwargs): pass
        def tool(self): return lambda fn: fn
    server_module.MCPServer = MCPServer
    sys.modules["mcp.server"] = server_module

server = importlib.import_module("mcp_server")
import mcp_web_research as web
from packet_search_features import packet_clues


def record(cve, description, product=""):
    return {"cve": {
        "id": cve, "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": description}],
        "configurations": [{"nodes": [{"cpeMatch": [{"criteria": product}]}]}] if product else [],
    }}


class GeneralRetrievalTests(unittest.TestCase):
    def test_no_generic_nvd_dump_for_unknown_application(self):
        with patch.object(server, "_fetch_json", side_effect=AssertionError("no online call")):
            sources, warnings, fetched = server._nvd_sources("HTTP JSON API", "Remote Code Execution", "", "", 5)
        self.assertEqual(sources, [])
        self.assertEqual(fetched, [])

    def test_unknown_product_requires_distinctive_packet_clues(self):
        results = {"vulnerabilities": [
            record("CVE-2099-1234", "WidgetXYZ configuration export allows arbitrary files"),
            record("CVE-2099-5678", "SomeOtherTool remote code execution through generic input"),
        ]}
        with patch.object(server, "_fetch_json", return_value=results):
            sources, warnings, fetched = server._nvd_sources(
                "HTTP JSON API", "Remote Code Execution", "", "", 5,
                query="Remote Code Execution packet clues: endpoint configuration export",
            )
        self.assertEqual([x["cve_id"] for x in sources], ["CVE-2099-1234"])
        self.assertEqual(len(fetched), 1)
        self.assertIn("unverified", sources[0]["supports"][0])

    def test_known_product_ranks_mechanism_not_alphabetic_cve_id(self):
        result = {"vulnerabilities": [
            record("CVE-2099-1001", "OmegaApp logging bug in console"),
            record("CVE-2099-5000", "OmegaApp configuration export missing authorization checks"),
        ]}
        with patch.object(server, "_fetch_json", return_value=result):
            sources, *_ = server._nvd_sources(
                "OmegaApp", "Authorization Bypass", "", "", 5,
                query="OmegaApp Authorization Bypass packet clues: endpoint configuration export",
            )
        self.assertEqual(sources[0]["cve_id"], "CVE-2099-5000")
        self.assertEqual(server._candidate_cves(sources, ""), ["CVE-2099-5000", "CVE-2099-1001"])

    def test_kev_does_not_return_unrelated_products_for_generic_service(self):
        with patch.object(server, "_load_kev", side_effect=AssertionError("no feed needed")):
            sources, warnings = server._kev_sources(
                "HTTP JSON API", "Remote Code Execution", "", "", "RCE", 8
            )
        self.assertFalse(sources)
        self.assertTrue(warnings)

    def test_cve_list_does_not_scrape_generic_attack_descriptions(self):
        sources = [{"source_type": "mitre_attack_context", "snippet": "CVE-2099-0001", "cve_id": ""}]
        self.assertEqual(server._candidate_cves(sources, ""), [])

    def test_unknown_product_web_search_accepts_two_matching_clues(self):
        hits = [{"title": "NovaSuite configuration export advisory", "snippet": "NovaSuite configuration export policy", "url": "https://example.org/advisory"},
                {"title": "Other vendor unrelated issue", "snippet": "Unrelated overflow", "url": "https://example.org/other"}]
        with patch.object(web, "_config", return_value=("brave", "mock", "")), \
             patch.object(web, "_search_results", return_value=hits), \
             patch.object(web, "_read_public_page", side_effect=AssertionError("no unknown-vendor fetching")):
            sources, warnings, queried = web.research_web(
                "", "", "", "", "packet clues: endpoint configuration export", 10
            )
        self.assertEqual(len(sources), 1)
        self.assertEqual(sources[0]["cve_id"], "")
        self.assertIn("configuration", queried[0])

    def test_server_provides_candidates_from_nvd_not_webpage_mentions(self):
        nvd_item = {"source_type": "nvd_cve_candidate", "cve_id": "CVE-2099-8888", "title": "NVD record"}
        web_item = {"source_type": "web_research_lead", "cve_id": "", "snippet": "CVE-2099-9999", "title": "web result"}
        with patch.object(server, "_kev_sources", return_value=([], [])), \
             patch.object(server, "_nvd_sources", return_value=([nvd_item], [], [])), \
             patch.object(server, "_attack_sources", return_value=[]), \
             patch.object(server, "research_web", return_value=([web_item], [], [])):
            value = server.search_forensic_evidence("packet clues: endpoint configuration export", service="", max_results=8)
        self.assertEqual(value["candidate_cves"], ["CVE-2099-8888"])

    def test_clue_extractor_discards_header_values_and_request_bodies(self):
        s = '- [E-S0002-F000014-002] X-Experiment-Feature: password=dont-send /token=private'
        clues = packet_clues(s)
        self.assertEqual(clues, ["header experiment feature"])
        self.assertNotIn("dont-send", str(clues))


if __name__ == "__main__":
    unittest.main()
