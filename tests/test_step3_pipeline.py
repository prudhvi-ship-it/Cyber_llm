import sys
import types
from unittest.mock import MagicMock
sys.modules.setdefault("llm_client", types.SimpleNamespace(get_llm=MagicMock()))
import unittest
from unittest.mock import patch
from contracts import AnalystOutput, AttackFinding, ServiceFinding, VerifierOutput
from mcp_evidence_contracts import OnlineEvidenceResult

class PipelineOrderingTests(unittest.TestCase):
    def test_search_revision_verifier_order(self):
        from mafra_agent_mcp import MAFRAMCPAgent
        calls=[]
        original=AnalystOutput(service=ServiceFinding(primary='Apache'))
        revised=AnalystOutput(service=ServiceFinding(primary='Grafana'),attack=AttackFinding(type='Path Traversal'))
        online=OnlineEvidenceResult(status='Abstain',query='Apache',retrieved_at_utc='2026-10-14T00:00:00Z')
        with patch('mafra_agent_mcp.AnalystAgent'),patch('mafra_agent_mcp.VerifierAgent'),patch('mafra_agent_mcp.ConsensusManager'),patch('mafra_agent_mcp.MCPOnlineEvidenceSearch'),patch('mafra_agent_mcp.EvidenceFormatter'),patch('mafra_agent_mcp.MCPReporterAgent'),patch('mafra_agent_mcp.MemoryManager'),patch('mafra_agent_mcp.derive_online_cve_validation'):
            app=MAFRAMCPAgent()
            app.analyst.analyze.side_effect=lambda f:(calls.append('initial') or original)
            app.online_search.search.side_effect=lambda **k:(calls.append('search') or online)
            app.analyst.reconsider_with_online_evidence.side_effect=lambda *args:(calls.append('revise') or revised)
            app.verifier.verify.side_effect=lambda f,a:(calls.append('verify') or VerifierOutput())
            app.consensus.calculate.return_value=type('Consensus',(),{'attack':'Path Traversal'})()
            app.consensus.format.return_value='consensus'
            app.reporter.generate.return_value=type('Report',(),{'status':'Valid','to_text':lambda s:'report','validation_errors':[]})()
            app.memory_manager.last_retrievals=[]
            app.memory_manager.status.return_value='disabled'
            app.evidence_formatter.format.return_value=type('Evid',(),{'to_prompt_text':lambda s:'formatted'})()
            app.online_search.search.return_value=online
            app.run('[E-S0001-F000123-001] GET /')
            self.assertEqual(calls,['initial','search','revise','verify'])
            self.assertIs(app.verifier.verify.call_args.args[1],revised)
            self.assertIs(app.online_search.search.call_args.kwargs['analyst_output'],original)

if __name__ == '__main__': unittest.main()
