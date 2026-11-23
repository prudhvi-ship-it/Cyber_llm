"""Offline FRA research/Analyst contract tests, without model or web traffic."""
import os
import sys
import types
import unittest
from unittest.mock import Mock, patch
sys.modules.setdefault('llm_client', types.SimpleNamespace(get_llm=Mock()))

from contracts import AnalystOutput, CVEProposal, AttackFinding, ServiceFinding, VerifierOutput, ConsensusDecision
from agents.analyst_agent import AnalystAgent
from mcp_online_search import MCPOnlineEvidenceSearch
from mcp_evidence_contracts import ExternalEvidenceSource, OnlineEvidenceResult

EVIDENCE_ID='E-S0001-F000016-007'
FLOW=(f'[{EVIDENCE_ID}] X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware.\n'
      '[E-S0001-F000018-008] HTTP Status 200.\n'
      '[E-S0001-F000020-010] admin keyword observed.')

def evidence(n=1):
    sources=[ExternalEvidenceSource(source_type='web_research_lead',title=f'Next.js authorization middleware advisory {i}',
             snippet='Next.js x-middleware-subrequest authorization bypass CVE-2025-29927',
             url=f'https://example.org/{i}',retrieved_at_utc='2026-10-25T00:00:00Z') for i in range(n)]
    return OnlineEvidenceResult(status='Valid',query='middleware authorization',sources=sources,
          candidate_cves=['CVE-2025-29927'],retrieved_at_utc='2026-10-25T00:00:00Z')

class FRAPortV9Tests(unittest.TestCase):
    def setUp(self):
        self.agent=AnalystAgent.__new__(AnalystAgent)
        self.agent.llm=Mock()

    def test_guidance_follows_original_four_questions_and_separates_candidate(self):
        g=self.agent._fra_investigation_guide()
        for token in ['ONE incident','service/application','CVE ASSOCIATED','vulnerable','Success / Fail / Unknown','PROVISIONAL']:
            self.assertIn(token,g)
        self.assertNotIn('service/version AND distinctive',g)

    def test_reconsideration_proposes_candidate_not_forced_result(self):
        revised=AnalystOutput(service=ServiceFinding(primary='Web application'),
                attack=AttackFinding(type='Authorization Bypass',success='Success',evidence=[EVIDENCE_ID]),
                cve=CVEProposal(candidate='CVE-2025-29927',confidence='Low',reason=f'Mechanism observed {EVIDENCE_ID}; version unknown'))
        with patch.dict(os.environ,{'MAFRA_FRA_WEB_SUMMARY':'0','MAFRA_FRA_SECOND_PASS':'0'}), \
             patch('agents.analyst_agent.invoke_validated',return_value=revised) as call:
            output=self.agent.reconsider_with_online_evidence(FLOW,AnalystOutput(),evidence())
        self.assertEqual(output.cve.candidate,'CVE-2025-29927')
        p=call.call_args.kwargs['prompt']
        self.assertIn('CVE *candidate*',p)
        self.assertIn('independent Verifier',p)
        self.assertIn('missing',p)

    def test_reconsideration_rejects_fake_packet_ids(self):
        bad=AnalystOutput(attack=AttackFinding(type='Authorization Bypass',evidence=['E-S0001-F999999-001']),
                          cve=CVEProposal(candidate='CVE-2025-29927'))
        original=AnalystOutput()
        with patch.dict(os.environ,{'MAFRA_FRA_WEB_SUMMARY':'0'}), \
             patch('agents.analyst_agent.invoke_validated',return_value=bad):
            output=self.agent.reconsider_with_online_evidence(FLOW,original,evidence())
        self.assertIs(output,original)

    def test_search_query_has_no_cve_and_no_application_in_version(self):
        a=AnalystOutput(service=ServiceFinding(primary='Apache',application='phpMyAdmin'),
                attack=AttackFinding(type='Remote Code Execution'),
                cve=CVEProposal(candidate='CVE-2016-5734'))
        s=MCPOnlineEvidenceSearch(server_url='')
        v=VerifierOutput();c=ConsensusDecision()
        q=s.build_query(a,v,c,'service apache phpMyAdmin')
        self.assertNotIn('CVE-2016-5734',q)
        tool=types.SimpleNamespace(input_schema={'properties':{'query':{},'version':{},'service':{}}})
        d=s._build_arguments(tool,q,a,v,c)
        self.assertNotEqual(d.get('version'),'phpMyAdmin')

    def test_search_query_blocks_cve_and_private_values(self):
        self.agent.llm.invoke.return_value=types.SimpleNamespace(
          content='Next.js authorization bypass CVE-2025-29927 172.18.0.1 privateSECRET')
        with patch.dict(os.environ,{'MAFRA_FRA_AGENT_SEARCH':'1'}):
            q=self.agent.plan_fra_search_query(FLOW,AnalystOutput(attack=AttackFinding(type='Authorization Bypass')),
                                               evidence())
        self.assertNotIn('CVE-',q)
        self.assertNotIn('172.',q)
        self.assertNotIn('privateSECRET',q)
        self.assertIn('authorization',q.lower())

    def test_digest_is_per_page_plus_aggregation(self):
        self.agent.llm.invoke.side_effect=[types.SimpleNamespace(content='First CVE advisory'),
                                            types.SimpleNamespace(content='Second CVE advisory'),
                                            types.SimpleNamespace(content='Aggregated CVE overview')]
        with patch.dict(os.environ,{'MAFRA_FRA_WEB_SUMMARY':'1','MAFRA_FRA_SUMMARY_PAGES':'2'}):
            digest=self.agent._fra_research_digest(evidence(2))
        self.assertEqual(self.agent.llm.invoke.call_count,3)
        self.assertIn('Aggregated CVE overview',digest)

    def test_second_search_only_when_query_changes(self):
        # Explicit opt-out preserves the baseline for controlled comparisons.
        a=AnalystOutput(attack=AttackFinding(type='Authorization Bypass'))
        self.agent.llm.invoke.return_value=types.SimpleNamespace(content='Authorization Bypass')
        with patch.dict(os.environ,{'MAFRA_FRA_AGENT_SEARCH':'0'}):
            self.assertEqual(self.agent.plan_fra_search_query(FLOW,a),'')
        self.agent.llm.invoke.assert_not_called()

if __name__ == '__main__': unittest.main()

class FRAPipelineLoopTests(unittest.TestCase):
    def test_agent_revises_after_one_extra_research_query_then_verifies(self):
        from mafra_agent_mcp import MAFRAMCPAgent
        from mcp_evidence_contracts import FormattedEvidence
        from contracts import VerifierOutput, ConsensusDecision
        from cve_mechanism_matcher import CVEMechanismTriage
        agent=MAFRAMCPAgent.__new__(MAFRAMCPAgent)
        agent.notebook_mode='disabled'
        agent.verified_cookie_rpc_sequences=()
        agent.current_case_id='case_test'
        agent.memory_manager=Mock()
        agent.memory_manager.mode='disabled'
        agent.memory_manager.retrieve.return_value=''
        agent.memory_manager.status.return_value='disabled'
        agent.memory_manager.last_retrievals=[]
        agent.last_online_result=None
        agent.last_initial_analyst=None
        agent.last_revised_analyst=None
        agent.last_cve_triage=CVEMechanismTriage()
        agent.last_formatted_evidence=None
        initial=AnalystOutput(attack=AttackFinding(type='Authorization Bypass',success='Success',evidence=[EVIDENCE_ID]))
        after_first=AnalystOutput(attack=AttackFinding(type='Authorization Bypass',success='Success',evidence=[EVIDENCE_ID]))
        after_second=AnalystOutput(service=ServiceFinding(primary='Next.js'),
                 attack=AttackFinding(type='Authorization Bypass',success='Success',evidence=[EVIDENCE_ID]),
                 cve=CVEProposal(candidate='CVE-2025-29927',confidence='Medium'))
        agent.analyst=Mock()
        agent.analyst.analyze.return_value=initial
        agent.analyst.reconsider_with_online_evidence.side_effect=[after_first,after_second]
        agent.analyst.plan_fra_search_query.side_effect=['middleware bypass','Next.js middleware authentication bypass']
        agent.online_search=Mock()
        result1=evidence(1)
        result2=evidence(1)
        result2.sources[0].url='https://second.example.org/advisory'
        agent.online_search.search.side_effect=[result1,result2]
        agent.verifier=Mock()
        agent.verifier.verify.return_value=VerifierOutput(verification_result='Supported',service_supported='Yes',
                     attack_supported='Yes',success_supported='Yes',cve_supported='Yes')
        agent.consensus=Mock()
        agent.consensus.calculate.return_value=ConsensusDecision(service='Next.js',attack='Authorization Bypass',
                                                                  cve='CVE-2025-29927')
        agent.consensus.format.return_value='consensus'
        agent.evidence_formatter=Mock()
        agent.evidence_formatter.format.return_value=FormattedEvidence()
        agent.reporter=Mock()
        agent.reporter.generate.return_value=Mock(status='Valid',validation_errors=[],to_text=lambda:'report')
        with patch.dict(os.environ,{'MAFRA_FRA_MAX_SEARCH_ROUNDS':'2'}), \
             patch('mafra_agent_mcp.rank_cve_mechanisms',return_value=CVEMechanismTriage()):
            result=agent.run(FLOW)
        self.assertEqual(agent.online_search.search.call_count,2)
        self.assertEqual(agent.analyst.reconsider_with_online_evidence.call_count,2)
        agent.verifier.verify.assert_called_once()
        self.assertEqual(agent.last_revised_analyst.cve.candidate,'CVE-2025-29927')
        self.assertIn('FINAL REPORT',result)


class FRAFollowupSafetyTests(unittest.TestCase):
    def _agent(self, first, second, followups):
        from mafra_agent_mcp import MAFRAMCPAgent
        from mcp_evidence_contracts import FormattedEvidence
        from cve_mechanism_matcher import CVEMechanismTriage
        a=MAFRAMCPAgent.__new__(MAFRAMCPAgent)
        a.notebook_mode='disabled'; a.verified_cookie_rpc_sequences=()
        a.current_case_id='case_test'; a.last_notebook=None
        a.memory_manager=Mock(mode='disabled',last_retrievals=[])
        a.memory_manager.status.return_value='disabled'
        a.analyst=Mock()
        initial=AnalystOutput(attack=AttackFinding(type='Authorization Bypass',evidence=[EVIDENCE_ID]))
        a.analyst.analyze.return_value=initial
        a.analyst.reconsider_with_online_evidence.return_value=initial
        a.analyst.plan_fra_search_query.side_effect=followups
        a.online_search=Mock()
        a.online_search.search.side_effect=[first,second]
        a.verifier=Mock()
        a.verifier.verify.return_value=VerifierOutput(verification_result='Supported',service_supported='Yes',attack_supported='Yes',success_supported='Yes')
        a.consensus=Mock()
        a.consensus.calculate.return_value=ConsensusDecision()
        a.consensus.format.return_value='consensus'
        a.evidence_formatter=Mock()
        a.evidence_formatter.format.return_value=FormattedEvidence()
        a.reporter=Mock()
        a.reporter.generate.return_value=Mock(status='Valid',validation_errors=[],to_text=lambda:'report')
        return a

    def test_first_research_sources_survive_second_search_context_window(self):
        first=evidence(8); first.query='middleware authorization'
        second=evidence(8); second.query='Next.js middleware bypass'
        for i,s in enumerate(second.sources):s.url=f'https://second.example.org/{i}'
        a=self._agent(first,second,['middleware authorization','Next.js middleware bypass'])
        with patch.dict(os.environ,{'MAFRA_FRA_MAX_SEARCH_ROUNDS':'2'}),patch('mafra_agent_mcp.rank_cve_mechanisms') as rank:
            from cve_mechanism_matcher import CVEMechanismTriage
            rank.return_value=CVEMechanismTriage()
            a.run(FLOW)
        sources=a.analyst.reconsider_with_online_evidence.call_args.args[2].sources[:8]
        self.assertTrue(any(x.url.startswith('https://example.org/') for x in sources))
        self.assertTrue(any(x.url.startswith('https://second.example.org/') for x in sources))

    def test_nonstring_planner_output_never_triggers_search(self):
        first=evidence(1);first.query='middleware authorization'
        second=evidence(1)
        a=self._agent(first,second,['middleware authorization',Mock()])
        with patch.dict(os.environ,{'MAFRA_FRA_MAX_SEARCH_ROUNDS':'2'}),patch('mafra_agent_mcp.rank_cve_mechanisms') as rank:
            from cve_mechanism_matcher import CVEMechanismTriage
            rank.return_value=CVEMechanismTriage()
            a.run(FLOW)
        self.assertEqual(a.online_search.search.call_count,1)

    def test_same_words_reordered_do_not_trigger_duplicate_search(self):
        first=evidence(1);first.query='middleware authorization'
        second=evidence(1)
        a=self._agent(first,second,['middleware authorization','authorization middleware'])
        with patch.dict(os.environ,{'MAFRA_FRA_MAX_SEARCH_ROUNDS':'2'}),patch('mafra_agent_mcp.rank_cve_mechanisms') as rank:
            from cve_mechanism_matcher import CVEMechanismTriage
            rank.return_value=CVEMechanismTriage()
            a.run(FLOW)
        self.assertEqual(a.online_search.search.call_count,1)
