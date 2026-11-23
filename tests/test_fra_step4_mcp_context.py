"""Step 4: offline tests only; mocks every LLM/MCP action."""
import json
import os
import sys
import types
import unittest
from unittest.mock import Mock, patch

sys.modules.setdefault("llm_client", types.SimpleNamespace(get_llm=Mock()))
from contracts import AnalystOutput, AttackFinding, CVEProposal, ServiceFinding, VerifierOutput, ConsensusDecision
from cve_mechanism_matcher import CVEMechanismTriage, MechanismCandidate
from mcp_evidence_contracts import OnlineEvidenceResult, ExternalEvidenceSource, FormattedEvidence
from mcp_verifier_context import build_verifier_mcp_context

CVE = 'CVE-2025-29927'
ID = 'E-S0001-F000016-007'
BANNER = 'E-S0001-F000018-010'
FLOW=(f'[{ID}] X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware.\n'
      f'[{BANNER}] X-Powered-By: Next.js\n')

def proposal(candidate=CVE, success='Fail'):
    return AnalystOutput(
        service=ServiceFinding(primary='Next.js'),
        attack=AttackFinding(type='Authorization Bypass', success=success,
                             evidence=[ID]),
        cve=CVEProposal(candidate=candidate, confidence='Medium'))

def source(cve=CVE, kind='nvd_cve_candidate', url=None, text='x-middleware-subrequest Next.js bypass'):
    return ExternalEvidenceSource(
        source_name='NIST NVD' if kind=='nvd_cve_candidate' else 'Serper web result',
        source_type=kind, title=cve, url=url or f'https://nvd.nist.gov/vuln/detail/{cve}',
        snippet=text, supports=['CVE mechanism research only'],
        retrieved_at_utc='2026-10-25T00:00:00Z')

def research(*sources, candidates=(CVE,), status='Valid'):
    return OnlineEvidenceResult(status=status, query='Next.js bypass',
        retrieved_at_utc='2026-10-25T00:00:00Z',
        sources=list(sources), candidate_cves=list(candidates))

class MCPVerifierContextTests(unittest.TestCase):
    def test_only_proposed_cve_sources_and_ids_are_included(self):
        other = source('CVE-2025-30218', text='A different Next.js flaw mentions CVE-2025-29927')
        primary = source()
        web = source(kind='web_research_lead',url='https://example.org/nextjs',
                     text=f'How to understand {CVE} attack')
        triage = CVEMechanismTriage((MechanismCandidate(
            cve_id=CVE,level='Preliminary mechanism overlap',
            mechanism_features=('http_header:x-middleware-subrequest',),
            mechanism_explanation='header bypass',packet_ids=(BANNER,'E-S0000-F000999-999'),
            reference=primary.url,
            missing_conditions=('Version unknown',)),))
        blob=build_verifier_mcp_context(FLOW, proposal(), research(other,web,primary),triage)
        data=json.loads(blob)
        self.assertEqual(data['proposed_cve'], CVE)
        self.assertEqual(len(data['cve_specific_research_sources']),2)
        self.assertEqual(data['cve_specific_research_sources'][0]['url'], primary.url)
        self.assertNotIn('CVE-2025-30218', blob)
        self.assertEqual(set(data['current_case_packet_ids']),{ID,BANNER})
        self.assertNotIn('E-S0000-F000999-999', blob)
        self.assertIn('Version unknown',blob)

    def test_failed_attack_still_can_have_cve_as_research_candidate(self):
        blob=build_verifier_mcp_context(FLOW,proposal(success='Fail'),research(source()))
        self.assertIn('failed attempt',blob)
        self.assertIn(CVE,blob)

    def test_unknown_cve_or_unavailable_research_has_no_context(self):
        self.assertEqual(build_verifier_mcp_context(FLOW,proposal('Not Found'),research(source())), '')
        self.assertEqual(build_verifier_mcp_context(FLOW,proposal(),research(source(),status='Abstain')), '')
        self.assertEqual(build_verifier_mcp_context(FLOW,proposal(),research(source(),candidates=())), '')
        self.assertEqual(build_verifier_mcp_context(FLOW,proposal(),research(source('CVE-2025-30218'))), '')

    def test_never_includes_research_for_different_cve_even_if_snippet_mentions_one(self):
        unrelated=source('CVE-2025-30218',text='This mentions CVE-2025-29927 in narrative')
        self.assertEqual(build_verifier_mcp_context(FLOW,proposal(),research(unrelated)), '')

    def test_bounded_duplicate_sources_and_no_network(self):
        long_text='safe mechanism '+('M' * 3700)
        entries=[source(kind='web_research_lead',url=f'https://example.org/s/{i}',text=f'{CVE} {long_text}')
                 for i in range(20)]
        entries.insert(0,source(text=f'{CVE} {long_text}'))
        entries.append(source())
        blob=build_verifier_mcp_context(FLOW,proposal(),research(*entries))
        data=json.loads(blob)
        self.assertEqual(len(data['cve_specific_research_sources']),3)
        self.assertLess(len(blob),4300)

    def test_fake_cve_in_packet_alone_does_not_get_research_context(self):
        data=build_verifier_mcp_context(FLOW + f'[{ID}] {CVE}',proposal(),research())
        self.assertEqual(data,'')

    def test_verifier_prompt_receives_untrusted_mcp_context_and_preserves_packet_source(self):
        from agents.verifier_agent import VerifierAgent
        verifier=VerifierAgent.__new__(VerifierAgent)
        verifier.llm=Mock()
        with patch('agents.verifier_agent.invoke_validated', return_value=VerifierOutput()) as mock:
            verifier.verify(FLOW,proposal(),mcp_evidence_context=build_verifier_mcp_context(FLOW,proposal(),research(source())))
        prompt=mock.call_args.kwargs['prompt']
        self.assertIn('untrusted_mcp_research_json',prompt)
        self.assertIn('UNTRUSTED ONLINE CONTEXT',prompt)
        self.assertIn(CVE,prompt)
        self.assertIn(ID,prompt)
        self.assertIn('<flow_summary>',prompt)

    def test_verifier_no_mcp_context_uses_previous_prompt_shape(self):
        from agents.verifier_agent import VerifierAgent
        verifier=VerifierAgent.__new__(VerifierAgent); verifier.llm=Mock()
        with patch('agents.verifier_agent.invoke_validated', return_value=VerifierOutput()) as mock:
            verifier.verify(FLOW,proposal())
        self.assertNotIn('untrusted_mcp_research_json',mock.call_args.kwargs['prompt'])

    def test_pipeline_passes_research_after_analyst_to_verifier_without_upgrading_cve(self):
        from mafra_agent_mcp import MAFRAMCPAgent
        app=MAFRAMCPAgent.__new__(MAFRAMCPAgent)
        app.notebook_mode='disabled';app.verified_cookie_rpc_sequences=()
        app.current_case_id='case_test';app.last_notebook=None
        app.memory_manager=Mock(mode='disabled',last_retrievals=[])
        app.memory_manager.status.return_value='disabled'
        initial=proposal('Not Found',success='Fail')
        revised=proposal(success='Fail')
        app.analyst=Mock()
        app.analyst.analyze.return_value=initial
        app.analyst.plan_fra_search_query.return_value='middleware header bypass'
        app.analyst.reconsider_with_online_evidence.return_value=revised
        app.online_search=Mock();app.online_search.search.return_value=research(source())
        app.verifier=Mock();app.verifier.verify.return_value=VerifierOutput(cve_supported='Unknown')
        app.consensus=Mock();app.consensus.calculate.return_value=ConsensusDecision(cve=CVE,attack_success='Fail')
        app.consensus.format.return_value='consensus output'
        app.evidence_formatter=Mock();app.evidence_formatter.format.return_value=FormattedEvidence()
        app.reporter=Mock();app.reporter.generate.return_value=Mock(status='Valid',validation_errors=[],to_text=lambda:'report')
        with patch.dict(os.environ,{'MAFRA_FRA_MAX_SEARCH_ROUNDS':'1'}),\
             patch('mafra_agent_mcp.rank_cve_mechanisms',return_value=CVEMechanismTriage()):
            output=app.run(FLOW)
        kwargs=app.verifier.verify.call_args.kwargs
        self.assertIn('mcp_evidence_context',kwargs)
        self.assertIn(CVE,kwargs['mcp_evidence_context'])
        self.assertEqual(app.last_revised_analyst.cve.candidate,CVE)
        self.assertIn('"validated_cve": "Not Found"',output)
        app.verifier.verify.assert_called_once()
        app.online_search.search.assert_called_once()

if __name__=='__main__':unittest.main()
