"""Offline regression: MAFRA-MCP no longer runs a post-consensus CVE validator."""
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

sys.modules.setdefault('llm_client', types.SimpleNamespace(get_llm=lambda *_a, **_k: object()))

from contracts import AnalystOutput, VerifierOutput, FinalReport
from mcp_evidence_contracts import OnlineEvidenceResult
from agents.consensus import ConsensusManager
from mafra_agent_mcp import MAFRAMCPAgent

FLOW = '- [E-S0001-F000016-007 | client->server] X-Middleware-Subrequest: middleware:middleware\n'


class ValidatorRemovalTests(unittest.TestCase):
    def run_mock(self, proposed, verifier_support):
        analyst = AnalystOutput.model_validate({
            'service': {'primary': 'Web application'},
            'attack': {'type':'Authentication Bypass', 'technique':'Spoofed header',
                       'success':'Success', 'evidence':['E-S0001-F000016-007']},
            'cve': {'candidate': proposed},
        })
        verifier = VerifierOutput.model_validate({
            'status':'Valid','verification_result':'Supported',
            'service_supported':'Yes','attack_supported':'Yes',
            'success_supported':'Yes', 'cve_supported': verifier_support,
            'confidence':'High',
        })
        online = OnlineEvidenceResult.model_validate({
            'status':'Valid','query':'middleware bypass',
            'retrieved_at_utc':'2026-10-25T00:00:00Z',
            'candidate_cves':['CVE-2025-29927'],
            'sources':[],
        })
        mods = ['AnalystAgent','VerifierAgent','MCPOnlineEvidenceSearch',
                'EvidenceFormatter','MCPReporterAgent','MemoryManager']
        patches = [patch('mafra_agent_mcp.'+m) for m in mods]
        mocks=[p.start() for p in patches]
        try:
            app=MAFRAMCPAgent(memory_mode='disabled')
            app.consensus=ConsensusManager()
            app.analyst.analyze.return_value=analyst
            app.analyst.reconsider_with_online_evidence.return_value=analyst
            app.verifier.verify.return_value=verifier
            app.online_search.search.return_value=online
            app.memory_manager.mode='disabled'
            app.memory_manager.status.return_value='disabled'
            app.memory_manager.last_retrievals=[]
            app.memory_manager.retrieve.return_value='RAG disabled'
            app.evidence_formatter.format.return_value=types.SimpleNamespace(to_prompt_text=lambda: 'packet evidence')
            app.reporter.generate.return_value=FinalReport(status='Valid')
            with patch('mafra_agent_mcp.derive_online_cve_validation', side_effect=AssertionError('legacy validator called')) as extra:
                output=app.run(FLOW)
                self.assertEqual(extra.call_count, 0)
            self.assertNotIn('=== ONLINE CVE DECISION ===', output)
            self.assertIn('=== ANALYST-VERIFIER CVE STATUS (NO SEPARATE VALIDATOR) ===', output)
            self.assertNotIn('Step 6: Online evidence CVE decision', output)
            return app.reporter.generate.call_args.kwargs['validated_cve'], output
        finally:
            for p in reversed(patches): p.stop()

    def test_supported_analyst_cve_survives_without_extra_veto(self):
        cve, _ = self.run_mock('CVE-2025-29927','Yes')
        self.assertEqual(cve.validated_cve, 'CVE-2025-29927')
        self.assertEqual(cve.cve_supported, 'Yes')

    def test_verifier_rejected_cve_not_falsely_confirmed(self):
        cve, _ = self.run_mock('CVE-2025-29927','No')
        self.assertEqual(cve.validated_cve, 'Not Found')
        self.assertEqual(cve.cve_supported, 'No')

    def test_online_candidate_cannot_replace_analyst_not_found(self):
        cve, _ = self.run_mock('Not Found','Yes')
        self.assertEqual(cve.validated_cve, 'Not Found')
        self.assertEqual(cve.cve_supported, 'No')

if __name__=='__main__': unittest.main()
