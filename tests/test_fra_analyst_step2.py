"""Step 2 Analyst loop tests: FRA source behavior with MAFRA contracts.
All tests use mocked LLM and online tool; zero network/paid model calls.
"""
import os
import sys
import types
import unittest
from unittest.mock import Mock, patch
sys.modules.setdefault("llm_client",types.SimpleNamespace(get_llm=Mock()))

from agents.analyst_agent import AnalystAgent
from contracts import AnalystOutput, AttackFinding, CVEProposal, ServiceFinding, VerifierOutput, ConsensusDecision
from mcp_evidence_contracts import OnlineEvidenceResult, ExternalEvidenceSource, FormattedEvidence
from cve_mechanism_matcher import CVEMechanismTriage

EID='E-S0001-F000016-007'
FLOW=(f'[{EID}] X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware.\n'
      '[E-S0001-F000018-008] HTTP Status 200.\n'
      '[E-S0001-F000020-010] Admin Dashboard.')

def online(n, ids=(), page_count=1):
    sources=[ExternalEvidenceSource(
         source_type='web_research_lead',source_name='Public web research',
         title='Next.js middleware security',url=f'https://example.org/advisory/{n}/{i}',
         snippet=f'Research on x-middleware-subrequest authorization bypass {n} {i}',
         retrieved_at_utc='2026-10-25T00:00:00Z') for i in range(page_count)]
    for cve in ids:
        sources.append(ExternalEvidenceSource(
          source_type='nvd_cve_candidate', source_name='NIST NVD', title=cve,
          url=f'https://nvd.nist.gov/vuln/detail/{cve}',
          snippet='Next.js bypass authorization with x-middleware-subrequest header',
          retrieved_at_utc='2026-10-25T00:00:00Z'))
    return OnlineEvidenceResult(status='Valid',query=f'nextjs middleware authorization {n}',
           retrieved_at_utc='2026-10-25T00:00:00Z',sources=sources,candidate_cves=list(ids))

class Step2Tests(unittest.TestCase):
    def test_page_summary_default_ten_and_per_page_cache(self):
        analyst=AnalystAgent.__new__(AnalystAgent); analyst.llm=Mock()
        analyst.llm.invoke.return_value=types.SimpleNamespace(content='Source content summary')
        r=online('a',page_count=12)
        with patch.dict(os.environ,{'MAFRA_FRA_WEB_SUMMARY':'1'},clear=False), \
             patch.dict(sys.modules,{'structured_output':types.SimpleNamespace(response_text=lambda x: str(x))}):
            os.environ.pop('MAFRA_FRA_SUMMARY_PAGES',None)
            text1=analyst._fra_research_digest(r)
            count1=analyst.llm.invoke.call_count
            text2=analyst._fra_research_digest(r)
        self.assertIn('Source content summary',text1)
        self.assertIn('Source content summary',text2)
        self.assertEqual(count1,11) # ten pages + one aggregate
        self.assertEqual(analyst.llm.invoke.call_count,12) # cached pages + aggregate

    def test_prompt_includes_fifo_and_all_authoritative_sources(self):
        a=AnalystAgent.__new__(AnalystAgent);a.llm=Mock()
        result=AnalystOutput(attack=AttackFinding(type='Authorization Bypass',success='Success',evidence=[EID]),
            cve=CVEProposal(candidate='CVE-2025-29927',confidence='Medium'))
        r=online('b',ids=['CVE-2025-29927'],page_count=16)
        with patch.dict(os.environ,{'MAFRA_FRA_WEB_SUMMARY':'0', 'MAFRA_FRA_SECOND_PASS':'0'}), \
             patch('agents.analyst_agent.invoke_validated',return_value=result) as invoke:
            a.reconsider_with_online_evidence(FLOW,AnalystOutput(),r,
                        reasoning_queue='Message number 1: Initial search found middleware header')
        p=invoke.call_args.kwargs['prompt']
        self.assertIn('Message number 1:',p)
        self.assertIn('CVE-2025-29927',p)
        self.assertIn('https://nvd.nist.gov/vuln/detail/CVE-2025-29927',p)
        self.assertIn('https://example.org/advisory/b/15',p)
        self.assertIn(EID,p)

    def test_three_search_turns_preserve_first_cve_and_verifier_order(self):
        from mafra_agent_mcp import MAFRAMCPAgent
        agent=MAFRAMCPAgent.__new__(MAFRAMCPAgent)
        agent.notebook_mode='disabled';agent.verified_cookie_rpc_sequences=()
        agent.current_case_id='case_test';agent.last_notebook=None
        agent.last_cve_triage=CVEMechanismTriage()
        agent.last_online_result=None;agent.last_initial_analyst=None;agent.last_revised_analyst=None
        agent.memory_manager=Mock(mode='disabled',last_retrievals=[])
        agent.memory_manager.status.return_value='disabled'
        a0=AnalystOutput(service=ServiceFinding(primary='Web Application'),
                         attack=AttackFinding(type='Authorization Bypass',success='Success',evidence=[EID]))
        a1=AnalystOutput(service=ServiceFinding(primary='Custom Web Application'),
                         attack=AttackFinding(type='Authorization Bypass',success='Success',evidence=[EID]))
        a2=AnalystOutput(service=ServiceFinding(primary='Web Application'),
                         attack=AttackFinding(type='Authorization Bypass',success='Success',evidence=[EID]))
        a3=AnalystOutput(service=ServiceFinding(primary='Next.js'),
                         attack=AttackFinding(type='Authorization Bypass',success='Success',evidence=[EID]),
                         cve=CVEProposal(candidate='CVE-2025-29927',confidence='Medium'))
        agent.analyst=Mock()
        agent.analyst.analyze.return_value=a0
        agent.analyst.plan_fra_search_query.side_effect=[
            'middleware bypass authentication','Next.js middleware authorization',
            'Node.js middleware header spoofing']
        agent.analyst.reconsider_with_online_evidence.side_effect=[a1,a2,a3]
        agent.online_search=Mock()
        agent.online_search.search.side_effect=[
            online(1,ids=['CVE-2025-29927']),online(2,ids=['CVE-2025-30218']),online(3)]
        agent.verifier=Mock()
        agent.verifier.verify.return_value=VerifierOutput(
            verification_result='Supported',service_supported='Yes',attack_supported='Yes',
            success_supported='Yes',cve_supported='Yes')
        agent.consensus=Mock()
        agent.consensus.calculate.return_value=ConsensusDecision(
            service='Next.js',attack='Authorization Bypass',cve='CVE-2025-29927')
        agent.consensus.format.return_value='consensus'
        agent.evidence_formatter=Mock()
        agent.evidence_formatter.format.return_value=FormattedEvidence()
        agent.reporter=Mock()
        agent.reporter.generate.return_value=Mock(status='Valid',validation_errors=[],to_text=lambda:'report')
        with patch.dict(os.environ,{'MAFRA_FRA_MAX_SEARCH_ROUNDS':'3'}), \
             patch('mafra_agent_mcp.rank_cve_mechanisms',return_value=CVEMechanismTriage()):
            output=agent.run(FLOW)
        self.assertEqual(agent.online_search.search.call_count,3)
        self.assertEqual(agent.analyst.reconsider_with_online_evidence.call_count,3)
        agent.verifier.verify.assert_called_once()
        self.assertEqual(agent.last_revised_analyst.cve.candidate,'CVE-2025-29927')
        self.assertIn('CVE-2025-29927',agent.last_online_result.candidate_cves)
        self.assertIn('CVE-2025-30218',agent.last_online_result.candidate_cves)
        self.assertIn('CVE-2025-29927', [s.title for s in agent.last_online_result.sources])
        self.assertIn('Research 2',agent.analyst._fra_reasoning_queue)
        self.assertIn('CVE-2025-29927',agent.analyst._fra_reasoning_queue)
        self.assertIn('FINAL REPORT',output)

if __name__ == '__main__': unittest.main()
