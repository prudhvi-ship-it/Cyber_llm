"""Offline reproductions of the observed Next.js binary-mechanism false negative."""
import unittest
from unittest.mock import patch

from contracts import AnalystOutput, ConsensusDecision, VerifierOutput
from mcp_evidence_contracts import OnlineEvidenceResult
from cve_mechanism_matcher import rank_cve_mechanisms
from binary_benchmark_policy import assess_binary_benchmark

CVE = 'CVE-2025-29927'
PACKET = 'E-S0001-F000016-007'
FLOW = '''
- [E-S0000-F000008-008 | server->client] HTTP Status 307.
- [E-S0000-F000008-009 | server->client] Location: /login.
- [E-S0001-F000016-007 | client->server] X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware.
- [E-S0001-F000018-008 | server->client] HTTP Status 200.
- [E-S0001-F000018-010 | server->client] Server response X-Powered-By: Next.js.
- [E-S0001-F000020-011 | server->client] admin keyword observed.
'''
NVD = dict(source_name='NIST NVD', title='CVE-2025-29927 NVD vulnerability record',
           url='https://nvd.nist.gov/vuln/detail/CVE-2025-29927',
           snippet='Next.js is a React framework. Authorization bypass using the x-middleware-subrequest header when middleware controls access.',
           retrieved_at_utc='2026-10-25T00:00:00Z')


def online(sources=None, cves=None):
    return OnlineEvidenceResult(status='Valid', query='subrequest bypass',
        retrieved_at_utc='2026-10-25T00:00:00Z',
        candidate_cves=[CVE] if cves is None else cves,
        sources=[NVD] if sources is None else sources)


def analyst(service='Next.js web application', framework='Next.js',
            evidence=None, cve=CVE):
    return AnalystOutput(service={'primary':service,'framework':framework},
        cve={'candidate':cve},
        attack={'type':'Authentication Bypass','technique':'x-middleware-subrequest',
                'success':'Success','evidence':[] if evidence is None else evidence})


def binary(a, triage, flow=FLOW, web=None):
    return assess_binary_benchmark(flow, a, VerifierOutput(cve_supported='Unknown'),
        ConsensusDecision(service=a.service.primary, attack='Authentication Bypass',
                          attack_success='Success', cve=a.cve.candidate,
                          overall_confidence='Medium'),
        online() if web is None else web, triage)


class NextJsMechanismRegression(unittest.TestCase):
    def test_original_full_service_label_matches_distinctive_header(self):
        t=rank_cve_mechanisms(FLOW, analyst(), online())
        self.assertEqual([c.cve_id for c in t.candidates],[CVE])
        self.assertIn('http_header:x-middleware-subrequest',t.candidates[0].mechanism_features)
        self.assertIn(PACKET,t.candidates[0].packet_ids)

    def test_plain_product_and_full_label_same_candidate(self):
        a=rank_cve_mechanisms(FLOW, analyst('Next.js','Unknown'), online())
        b=rank_cve_mechanisms(FLOW, analyst('Next.js web application','Unknown'), online())
        self.assertEqual(a.candidates,b.candidates)

    def test_framework_field_works_with_generic_primary(self):
        t=rank_cve_mechanisms(FLOW, analyst('HTTP web application', 'Next.js'), online())
        self.assertEqual(t.candidates[0].cve_id,CVE)

    def test_generic_service_without_framework_only_matched_by_exact_header(self):
        t=rank_cve_mechanisms(FLOW, analyst('HTTP web application', 'Unknown'), online())
        self.assertEqual(t.candidates[0].cve_id,CVE)
        # Do not establish CVE applicability from a generic service label.
        self.assertTrue(t.candidates[0].missing_conditions)

    def test_no_header_packet_stays_no_match(self):
        flow='- [E-S0001-F000018-010 | server->client] X-Powered-By: Next.js\n'
        self.assertFalse(rank_cve_mechanisms(flow, analyst(), online()).candidates)

    def test_unrelated_product_with_header_not_sufficient(self):
        self.assertFalse(rank_cve_mechanisms(FLOW, analyst('Grafana','Unknown'), online()).candidates)

    def test_unrelated_cve_subject_does_not_count(self):
        wrong={**NVD, 'title':'CVE-2025-30218',
               'url':'https://nvd.nist.gov/vuln/detail/CVE-2025-30218'}
        self.assertFalse(rank_cve_mechanisms(FLOW, analyst(),online([wrong])).candidates)

    def test_non_authoritative_webpage_not_counted(self):
        blog={**NVD,'source_name':'Random blog','url':'https://example.org/blog'}
        self.assertFalse(rank_cve_mechanisms(FLOW, analyst(),online([blog])).candidates)

    def test_similar_but_different_header_is_not_match(self):
        flow=FLOW.replace('X-Middleware-Subrequest:', 'X-Middleware-Subrequest-Id:')
        self.assertFalse(rank_cve_mechanisms(flow,analyst(),online()).candidates)

    def test_binary_yes_when_analyst_and_packet_ids_support_mechanism(self):
        a=analyst(evidence=[PACKET])
        triage=rank_cve_mechanisms(FLOW,a,online())
        b=binary(a,triage)
        self.assertEqual(b.cve_mechanism_match,'Yes')
        self.assertEqual(b.exact_applicability_established,'No')
        self.assertIn(PACKET,b.packet_ids)

    def test_binary_no_when_analyst_has_no_packet_evidence_refs(self):
        a=analyst(evidence=[])
        t=rank_cve_mechanisms(FLOW,a,online())
        self.assertEqual(binary(a,t).cve_mechanism_match,'No')

    def test_binary_no_when_evidence_id_not_in_flow(self):
        a=analyst()
        t=rank_cve_mechanisms(FLOW,a,online())
        self.assertEqual(binary(a,t,flow='not a packet summary').cve_mechanism_match,'No')

    def test_binary_no_when_authoritative_cve_missing(self):
        a=analyst()
        t=rank_cve_mechanisms(FLOW,a,online())
        self.assertEqual(binary(a,t,web=online(sources=[])).cve_mechanism_match,'No')

    def test_binary_no_when_analyst_cve_differs_from_evidence(self):
        a=analyst(cve='CVE-2025-30218')
        t=rank_cve_mechanisms(FLOW,a,online())
        self.assertEqual(binary(a,t).cve_mechanism_match,'No')

    def test_final_analyst_revision_refreshes_triage_before_verifier(self):
        from unittest.mock import MagicMock
        import sys, types
        sys.modules.setdefault('llm_client', types.SimpleNamespace(get_llm=MagicMock()))
        from mafra_agent_mcp import MAFRAMCPAgent
        with patch.multiple('mafra_agent_mcp',
            AnalystAgent=MagicMock(),VerifierAgent=MagicMock(),
            ConsensusManager=MagicMock(),MCPOnlineEvidenceSearch=MagicMock(),
            EvidenceFormatter=MagicMock(),MCPReporterAgent=MagicMock(),
            MemoryManager=MagicMock()):
            app=MAFRAMCPAgent(memory_mode='disabled')
            old=analyst('Grafana','Unknown',cve='Not Found')
            new=analyst(evidence=[PACKET])
            app.analyst.analyze.return_value=old
            app.analyst.reconsider_with_online_evidence.return_value=new
            app.analyst.plan_fra_search_query.return_value='middleware bypass'
            app.analyst.plan_next_fra_search.return_value=''
            app.online_search.search.return_value=online()
            app.verifier.verify.return_value=VerifierOutput(
                verification_result='Partially Supported',
                service_supported='Yes',attack_supported='Yes',
                success_supported='Yes',cve_supported='Unknown',confidence='High')
            app.consensus.calculate.return_value=ConsensusDecision(
                service='Next.js web application',attack='Authentication Bypass',
                attack_success='Success',cve=CVE,overall_confidence='Medium')
            app.consensus.format.return_value='consensus report'
            app.evidence_formatter.format.return_value=type('E',(),{'to_prompt_text':lambda self:'formatted'})()
            app.memory_manager.mode='disabled'
            app.memory_manager.last_retrievals=[]
            app.memory_manager.status.return_value='disabled'
            app.reporter.generate.return_value=type('R',(),{
                'status':'Valid','validation_errors':[], 'to_text':lambda self:'report'})()
            result=app.run(FLOW)
            self.assertIn('report',result)
            self.assertEqual(app.last_cve_triage.candidates[0].cve_id,CVE)
            self.assertIn('CVE-2025-29927', app.verifier.verify.call_args.kwargs['cve_mechanism_hints'])
            assessment=app.reporter.generate.call_args.kwargs['binary_assessment']
            self.assertEqual(assessment.cve_mechanism_match,'Yes')

if __name__=='__main__':unittest.main()
