import sys
import types
from unittest.mock import MagicMock
sys.modules.setdefault("llm_client", types.SimpleNamespace(get_llm=MagicMock()))
import unittest
from unittest.mock import patch
from contracts import AnalystOutput, AttackFinding, ServiceFinding
from mcp_evidence_contracts import OnlineEvidenceResult, ExternalEvidenceSource
from agents.analyst_agent import AnalystAgent

FLOW = '[E-S0001-F000123-001] HTTP GET /public/plugins/example/../../etc/passwd'


def online(valid=True):
    return OnlineEvidenceResult(status='Valid' if valid else 'Abstain', query='Grafana',
        retrieved_at_utc='2026-10-14T00:00:00Z', sources=[ExternalEvidenceSource(
        title='Vendor advisory', url='https://grafana.com/security/',
        snippet='Grafana directory traversal advisory', retrieved_at_utc='2026-10-14T00:00:00Z')])

class AnalystMCPTests(unittest.TestCase):
    def setUp(self):
        with patch('agents.analyst_agent.get_llm', return_value=object()):
            self.agent = AnalystAgent()
        self.initial = AnalystOutput(service=ServiceFinding(primary='Unknown'))

    def test_no_search_evidence_skips_second_llm_call(self):
        with patch('agents.analyst_agent.invoke_validated') as invoke:
            self.assertIs(self.agent.reconsider_with_online_evidence(FLOW, self.initial, online(False)), self.initial)
            invoke.assert_not_called()

    def test_revised_service_is_passed_forward(self):
        revised = AnalystOutput(service=ServiceFinding(primary='Grafana'),
            attack=AttackFinding(type='Path Traversal', evidence=['E-S0001-F000123-001']))
        with patch('agents.analyst_agent.invoke_validated', return_value=revised) as invoke:
            self.assertEqual(self.agent.reconsider_with_online_evidence(FLOW, self.initial, online()).service.primary, 'Grafana')
            prompt = invoke.call_args.kwargs['prompt']
            self.assertIn('external research', prompt)
            self.assertIn(FLOW, prompt)

    def test_fabricated_packet_id_reverts_to_original(self):
        revised = AnalystOutput(attack=AttackFinding(evidence=['E-S0001-F999999-001']))
        with patch('agents.analyst_agent.invoke_validated', return_value=revised):
            self.assertIs(self.agent.reconsider_with_online_evidence(FLOW, self.initial, online()), self.initial)

    def test_failed_revision_preserves_original(self):
        with patch('agents.analyst_agent.invoke_validated', return_value=AnalystOutput.abstain(['bad output'])):
            self.assertIs(self.agent.reconsider_with_online_evidence(FLOW, self.initial, online()), self.initial)

if __name__ == '__main__': unittest.main()
