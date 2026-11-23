"""Offline tests for MAFRA MCP's NVD vulnerability candidates (no network)."""
import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


def _load_server_without_mcp_dependency():
    # Tests work before installing the optional MCP server SDK.
    mcp_module = types.ModuleType("mcp")
    server_module = types.ModuleType("mcp.server")

    class FakeMCPServer:
        def __init__(self, *args, **kwargs):
            pass

        def tool(self):
            return lambda fn: fn

    server_module.MCPServer = FakeMCPServer
    module_path = Path(__file__).resolve().parents[1] / "mcp_server.py"
    spec = importlib.util.spec_from_file_location("mcp_server_step1_testing", module_path)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"mcp": mcp_module, "mcp.server": server_module}):
        spec.loader.exec_module(module)
    return module


server = _load_server_without_mcp_dependency()


def _record(cve_id, description, status="Analyzed"):
    return {
        "cve": {
            "id": cve_id,
            "vulnStatus": status,
            "descriptions": [{"lang": "en", "value": description}],
            "configurations": [],
        }
    }


class NVDStep1Tests(unittest.TestCase):
    def test_nvd_returns_alternative_cves_even_when_initial_guess_exists(self):
        requested = "CVE-2021-43798"
        alternative = "CVE-2022-11111"
        seen_urls = []

        def fake_fetch(url):
            seen_urls.append(url)
            if "cveId=" in url:
                return {"vulnerabilities": [_record(requested, "Grafana path traversal issue")]}
            if "keywordSearch=" in url:
                return {"vulnerabilities": [
                    _record(alternative, "Grafana directory traversal issue"),
                    _record("CVE-2024-88888", "nginx path traversal issue"),
                    _record("CVE-2020-00001", "Grafana old issue", status="Rejected"),
                ]}
            raise AssertionError(f"Unexpected URL: {url}")

        with patch.object(server, "_load_kev", return_value=[]), \
             patch.object(server, "_load_attack_patterns", return_value=[]), \
             patch.object(server, "_fetch_json", side_effect=fake_fetch):
            result = server.search_forensic_evidence(
                "Grafana path traversal", service="Grafana",
                attack="Path Traversal", cve=requested,
            )

        self.assertIn(requested, result["candidate_cves"])
        self.assertIn(alternative, result["candidate_cves"])
        self.assertNotIn("CVE-2024-88888", result["candidate_cves"])
        self.assertNotIn("CVE-2020-00001", result["candidate_cves"])
        self.assertTrue(any("cveId=" in url for url in seen_urls))
        self.assertTrue(any("keywordSearch=" in url for url in seen_urls))
        self.assertTrue(all("vulnerability" not in str(s.get("supports")).lower()
                            or "unverified" in str(s.get("supports")).lower()
                            for s in result["sources"] if s["source_type"] == "nvd_cve_candidate"))

    def test_claimed_cve_is_rejected_if_product_does_not_match(self):
        with patch.object(server, "_fetch_json", return_value={
            "vulnerabilities": [_record("CVE-2021-99999", "Apache Tomcat RCE")]
        }):
            sources, warnings, urls = server._nvd_sources(
                "Apache Solr", "RCE", "", "CVE-2021-99999", 4,
            )
        self.assertEqual(sources, [])
        self.assertEqual(warnings, [])
        self.assertTrue(urls)

    def test_nvd_failure_is_a_warning_not_an_invented_cve(self):
        with patch.object(server, "_load_kev", return_value=[]), \
             patch.object(server, "_load_attack_patterns", return_value=[]), \
             patch.object(server, "_fetch_json", side_effect=TimeoutError("offline")):
            result = server.search_forensic_evidence(
                "Grafana traversal", service="Grafana", attack="Path Traversal"
            )
        self.assertEqual(result["candidate_cves"], [])
        self.assertTrue(any("NVD lookup failed" in warning for warning in result["warnings"]))

    def test_kev_exact_cve_does_not_override_service_mismatch(self):
        kev_record = {
            "cveID": "CVE-2021-43798",
            "vendorProject": "Grafana Labs",
            "product": "Grafana",
            "vulnerabilityName": "Grafana path traversal",
            "shortDescription": "Grafana plugins path traversal",
        }
        with patch.object(server, "_load_kev", return_value=[kev_record]):
            sources, warnings = server._kev_sources(
                "Apache Solr", "Path Traversal", "", "CVE-2021-43798", "", 5
            )
        self.assertEqual(sources, [])
        self.assertEqual(warnings, [])

    def test_mitre_description_cves_do_not_become_candidates(self):
        sources = [{
            "source_type": "mitre_attack_context",
            "title": "ATT&CK description containing CVE-2021-43798",
            "cve_id": "",
        }]
        self.assertEqual(server._candidate_cves(sources, ""), [])

    def test_client_accepts_wrapped_json_and_configured_limit(self):
        from types import SimpleNamespace
        from mcp_online_search import MCPOnlineEvidenceSearch

        client = MCPOnlineEvidenceSearch(max_results=12)
        result = {
            "result": {
                "sources": [{
                    "source_name": "NIST NVD",
                    "title": "CVE-2021-43798",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-43798",
                    "snippet": "Grafana path traversal",
                    "source_type": "nvd_cve_candidate",
                }],
                "candidate_cves": ["CVE-2021-43798"],
            }
        }
        sources, cves = client._parse_result(result, "", "2026-01-01T00:00:00Z")
        self.assertEqual(len(sources), 1)
        self.assertEqual(cves, ["CVE-2021-43798"])
        tool = SimpleNamespace(input_schema={"properties": {"query": {}, "max_results": {}}})
        args = client._build_arguments(tool, "Grafana", SimpleNamespace(
            service=SimpleNamespace(primary="Grafana", application="Grafana"),
            attack=SimpleNamespace(type="Path Traversal", technique="Path Traversal"),
            cve=SimpleNamespace(candidate="CVE-2021-43798")),
            SimpleNamespace(), SimpleNamespace(attack="Path Traversal"))
        self.assertEqual(args["max_results"], 12)

    def test_nvd_url_has_no_rejected_filter(self):
        url = server._nvd_query_url(keywords="Apache Solr", results=1000)
        self.assertIn("noRejected", url)
        self.assertIn("resultsPerPage=100", url)
        self.assertIn("keywordSearch=Apache+Solr", url)


if __name__ == "__main__":
    unittest.main()
