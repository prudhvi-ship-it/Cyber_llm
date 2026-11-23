"""Offline tests for general Analyst CVE association reasoning (zero API calls)."""
import os
import sys
import types
import unittest
from unittest.mock import Mock, patch

sys.modules.setdefault('llm_client', types.SimpleNamespace(get_llm=Mock()))
from agents.analyst_agent import AnalystAgent
from contracts import AnalystOutput, AttackFinding, CVEProposal, ServiceFinding
from mcp_evidence_contracts import OnlineEvidenceResult, ExternalEvidenceSource

EVID = 'E-S0001-F000016-007'
FLOW = (
    f'[{EVID}] POST /some_action; option uncommon-mode=true; invoked dynamic operation.\n'
    '[E-S0001-F000018-008] Server response status 200 (outcome not established).\n'
)


def unrelated_online():
    return OnlineEvidenceResult(
        status='Valid', query='sample product issue', candidate_cves=['CVE-2098-10101'],
        sources=[ExternalEvidenceSource(
            source_type='web_research_lead', source_name='Public search',
            title='Unrelated vulnerability', snippet='Different product, unrelated exploit path',
            url='https://example.org/unrelated', retrieved_at_utc='2026-10-25T00:00:00Z')],
        retrieved_at_utc='2026-10-25T00:00:00Z')


class AnalystEvidenceFirstTests(unittest.TestCase):
    def setUp(self):
        self.agent = AnalystAgent.__new__(AnalystAgent)
        self.agent.llm = Mock()
        self.agent._fra_page_summary_cache = {}
        self.agent._fra_reasoning_queue = ''

    def test_four_questions_allow_knowledge_when_search_misses(self):
        guide = self.agent._fra_investigation_guide()
        self.assertIn('CVE ASSOCIATED WITH THE OBSERVED ATTACK', guide)
        self.assertIn('missing search result', guide)
        self.assertIn('cybersecurity knowledge', guide)
        self.assertIn('Never invent a CVE', guide)
        self.assertIn('not just a generic', guide)

    def test_initial_prompt_uses_packet_mechanism_without_search(self):
        outcome = AnalystOutput(service=ServiceFinding(primary='ExampleApp'),
                                attack=AttackFinding(type='Code execution attempt', success='Unknown', evidence=[EVID]))
        with patch('agents.analyst_agent.invoke_validated', return_value=outcome) as call:
            self.agent.analyze(FLOW)
        p = call.call_args.kwargs['prompt']
        self.assertIn('before web research', p)
        self.assertIn('existing', p)
        self.assertIn('Not Found', p)
        self.assertIn(EVID, p)
        self.assertNotIn('CVE-2016-5734', p)  # no benchmark label embedded in prompt

    def test_research_prompt_requires_independent_packet_comparison_not_mcp_hit(self):
        answer = AnalystOutput(
            service=ServiceFinding(primary='ExampleApp'),
            attack=AttackFinding(type='Code execution attempt', success='Unknown', evidence=[EVID]),
            cve=CVEProposal(candidate='CVE-2099-12345', confidence='Low', reason=f'Observed {EVID}'))
        with patch.dict(os.environ, {'MAFRA_FRA_WEB_SUMMARY':'0','MAFRA_FRA_SECOND_PASS':'0',
                                      'MAFRA_FRA_LEGACY_SECOND_PASS':'0'}), \
             patch('agents.analyst_agent.invoke_validated', return_value=answer) as call:
            actual = self.agent.reconsider_with_online_evidence(
                FLOW, AnalystOutput(), unrelated_online())
        p = call.call_args.kwargs['prompt']
        self.assertIn('NOT required', p)
        self.assertIn('Search results are not a', p)
        self.assertIn('endpoint names', p)
        self.assertIn('model knowledge and packet observations', p)
        self.assertIn('CVE-2098-10101', p)  # misleading research is included but not mandated
        self.assertIn(EVID, p)
        self.assertEqual(actual.cve.candidate, 'CVE-2099-12345')

    def test_not_found_is_still_valid_when_only_irrelevant_research(self):
        answer = AnalystOutput(service=ServiceFinding(primary='ExampleApp'),
                               attack=AttackFinding(type='Unknown', success='Unknown', evidence=[EVID]))
        with patch.dict(os.environ, {'MAFRA_FRA_WEB_SUMMARY':'0','MAFRA_FRA_SECOND_PASS':'0',
                                      'MAFRA_FRA_LEGACY_SECOND_PASS':'0'}), \
             patch('agents.analyst_agent.invoke_validated', return_value=answer):
            actual = self.agent.reconsider_with_online_evidence(FLOW, AnalystOutput(), unrelated_online())
        self.assertEqual(actual.cve.candidate, 'Not Found')

    def test_research_revision_rejects_hallucinated_packet_reference(self):
        answer = AnalystOutput(
            attack=AttackFinding(type='Code execution attempt', success='Unknown', evidence=['E-S0001-F999999-009']),
            cve=CVEProposal(candidate='CVE-2099-12345', confidence='High'))
        initial = AnalystOutput()
        with patch.dict(os.environ, {'MAFRA_FRA_WEB_SUMMARY':'0','MAFRA_FRA_SECOND_PASS':'0',
                                      'MAFRA_FRA_LEGACY_SECOND_PASS':'0'}), \
             patch('agents.analyst_agent.invoke_validated', return_value=answer):
            actual = self.agent.reconsider_with_online_evidence(FLOW, initial, unrelated_online())
        self.assertIs(actual, initial)


if __name__ == '__main__': unittest.main()
