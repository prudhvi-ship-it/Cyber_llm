"""No-network smoke tests for the MAFRA-MCP evaluation adapter."""
import os
import unittest
from unittest.mock import patch

from evaluation.report_reader import parse_report_text
from evaluation import runner
from experiment_config import experiment_manifest


class MAFRAMCPEvaluationAdapterTests(unittest.TestCase):
    def test_consensus_overrides_intermediate_agent_and_reporter(self):
        example = '''=== INITIAL ANALYZER OUTPUT ===\nService: Redis\nCVE: Not Found\n=== CONSENSUS SUMMARY ===\nService: Redis\nAttack Type: Information Disclosure\nAttack Success: Success\nCVE: Not Found\n=== CONSENSUS SUMMARY ===\nService: GitLab\nAttack Type: Remote Code Execution\nAttack Success: Unknown\nCVE: CVE-2021-22205\nCVE Supported: Yes\n=== MCP ONLINE EVIDENCE SEARCH ===\nCVE: CVE-2019-19628\n=== FINAL REPORT ===\nAffected Service: Redis\nIdentified CVE: CVE-1234'''
        answer = parse_report_text(example)
        self.assertEqual(answer["service"], "GitLab")
        self.assertEqual(answer["cve"], "CVE-2021-22205")
        self.assertEqual(answer["attack_success"], "Unknown")
        self.assertEqual(answer["vulnerable"], "Unknown")
        self.assertEqual(answer["cve_supported"], "Yes")

    def test_legacy_report_still_readable(self):
        legacy = '''=== FINAL REPORT ===\nAffected Service: Grafana\nAttack: Success\nIdentified CVE: CVE-2021-43798\nIs Service Vulnerable: Yes'''
        answer = parse_report_text(legacy)
        self.assertEqual(answer["service"], "Grafana")
        self.assertEqual(answer["attack_success"], "Success")
        self.assertEqual(answer["cve"], "CVE-2021-43798")

    def test_mafra_mcp_runner_uses_direct_pcap(self):
        with patch.object(runner, "run_command", return_value={"crashed": False}) as called:
            runner.run_mafra_mcp("pilot_4/case01.pcap", report_output="out.txt",
                                 mcp_url="http://127.0.0.1:8000/mcp",
                                 profile="fair_same_model", memory_mode="disabled")
        arguments = called.call_args.args[1]
        self.assertEqual(called.call_args.args[0], "main_mafra_mcp.py")
        self.assertEqual(arguments[:2], ["--pcap", "pilot_4/case01.pcap"])
        self.assertNotIn("--flow-summary-file", arguments)
        self.assertEqual(called.call_args.kwargs["system_name"], "MAFRA_MCP")
        self.assertIn("--investigation-notebook", arguments)

    def test_manifest_uses_actual_gpt5_temperature(self):
        with patch.dict(os.environ, {"FRA_EXPERIMENT_PROFILE": "fair_same_model",
                                     "FRA_FAIR_MODEL": "openai/gpt-5"}):
            manifest = experiment_manifest("fair_same_model")
        self.assertIsNone(manifest["temperature"])
        self.assertEqual(set(manifest["models"].values()), {"openai/gpt-5"})


if __name__ == "__main__":
    unittest.main()
