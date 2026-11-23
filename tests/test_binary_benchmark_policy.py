"""Offline, deterministic regression tests; never call LLM, MCP or TShark."""
import unittest
from contracts import AnalystOutput, VerifierOutput, ConsensusDecision, FinalReport, CVEValidationOutput
from binary_benchmark_policy import assess_binary_benchmark
from cve_mechanism_matcher import CVEMechanismTriage, MechanismCandidate
from mcp_evidence_contracts import OnlineEvidenceResult, ExternalEvidenceSource
from decision_enforcement import enforce_mafra_report, enforce_fra_report

CVE='CVE-2025-29927'
ID='E-S0001-F000016-007'
FLOW=(f'- [{ID} | client->server] X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware\n'
      '- [E-S0001-F000018-010 | server->client] X-Powered-By: Next.js\n'
      '- [E-S0001-F000018-008 | server->client] HTTP Status 200\n')

def fixtures(attack='Success', consensus='Success', verify_cve='Unknown', source=True,
             triage=True, online_candidate=True, packet=True):
    a=AnalystOutput(service={'primary':'Next.js'},attack={'type':'Authentication Bypass',
        'technique':'x-middleware-subrequest', 'success':attack,
        'evidence':[ID] if packet else []}, cve={'candidate':CVE})
    v=VerifierOutput(verification_result='Partially Supported', service_supported='Yes',
       attack_supported='Yes',success_supported='Yes',cve_supported=verify_cve,confidence='High')
    c=ConsensusDecision(service='Next.js', attack='Authentication Bypass',
       attack_success=consensus, cve=CVE, overall_confidence='Medium')
    sources=[ExternalEvidenceSource(source_name='NIST NVD', source_type='nvd_cve_candidate',
        title=CVE,url='https://nvd.nist.gov/vuln/detail/'+CVE,
        snippet='Next.js X-Middleware-Subrequest authorization bypass',
        retrieved_at_utc='2026-10-25T00:00:00Z')] if source else []
    online=OnlineEvidenceResult(status='Valid',query='Next.js bypass',
        retrieved_at_utc='2026-10-25T00:00:00Z',sources=sources,
        candidate_cves=[CVE] if online_candidate else [])
    t=CVEMechanismTriage((MechanismCandidate(cve_id=CVE,
        level='Preliminary mechanism overlap',
        mechanism_features=('http_header:x-middleware-subrequest',),
        mechanism_explanation='Next.js internal header',packet_ids=(ID,),
        reference='https://nvd.nist.gov/vuln/detail/'+CVE,
        missing_conditions=('Version unknown',)),)) if triage else CVEMechanismTriage()
    return a,v,c,online,t

class BinaryPolicyTests(unittest.TestCase):
    def assess(self, **kw):
        a,v,c,o,t=fixtures(**kw)
        return assess_binary_benchmark(FLOW,a,v,c,o,t)
    def test_attack_success_and_fail_verified_preserved(self):
        for label in ['Success','Fail']:
            with self.subTest(label=label):
                result=self.assess(attack=label,consensus=label)
                self.assertEqual(result.attack_prediction,label)
                self.assertTrue(result.attack_prediction_verified)
    def test_rejects_unknown_consensus_but_keeps_analyst_binary_prediction_low(self):
        r=self.assess(attack='Success',consensus='Unknown')
        self.assertEqual((r.attack_prediction,r.attack_prediction_confidence,r.attack_prediction_verified),('Success','Low',False))
    def test_unknown_analyst_does_not_become_proven_fail(self):
        r=self.assess(attack='Unknown',consensus='Unknown')
        self.assertEqual((r.attack_prediction,r.attack_prediction_verified),('Fail',False))
        self.assertIn('NOT evidence', ' '.join(r.notes))
    def test_nextjs_candidate_mechanism_match_yes_without_version(self):
        r=self.assess()
        self.assertEqual((r.cve_mechanism_match,r.exact_applicability_established),('Yes','No'))
        self.assertEqual(r.packet_ids,(ID,))
    def test_not_upgraded_by_raw_verifier_yes_if_version_missing(self):
        self.assertEqual(self.assess(verify_cve='Yes').exact_applicability_established,'No')
    def test_no_authoritative_subject_no_match(self):
        self.assertEqual(self.assess(source=False).cve_mechanism_match,'No')
    def test_no_packet_mechanism_no_match(self):
        self.assertEqual(self.assess(triage=False).cve_mechanism_match,'No')
    def test_no_packet_ref_no_match(self):
        self.assertEqual(self.assess(packet=False).cve_mechanism_match,'No')
    def test_no_online_candidate_no_match(self):
        self.assertEqual(self.assess(online_candidate=False).cve_mechanism_match,'No')
    def test_no_unrelated_cve_source(self):
        a,v,c,o,t=fixtures();o.sources[0].url='https://nvd.nist.gov/vuln/detail/CVE-2025-30218'
        self.assertEqual(assess_binary_benchmark(FLOW,a,v,c,o,t).cve_mechanism_match,'No')
    def test_no_fake_packet_ids(self):
        a,v,c,o,t=fixtures();t=CVEMechanismTriage((MechanismCandidate(
            cve_id=CVE,level='Preliminary mechanism overlap',
            mechanism_features=('http_header:x-middleware-subrequest',),
            mechanism_explanation='Header',packet_ids=('E-S0001-F000999-001',),
            reference='https://nvd.nist.gov/vuln/detail/'+CVE,missing_conditions=()),))
        self.assertEqual(assess_binary_benchmark(FLOW,a,v,c,o,t).cve_mechanism_match,'No')
    def test_same_evidence_same_policy_decision_25_times(self):
        outcomes={self.assess() for _ in range(25)}
        self.assertEqual(len(outcomes),1)
    def test_binary_display_and_raw_audit_retained(self):
        a,v,c,o,t=fixtures(attack='Fail',consensus='Unknown')
        policy=assess_binary_benchmark(FLOW,a,v,c,o,t)
        r=enforce_mafra_report(FinalReport(),a,v,CVEValidationOutput(),c,FLOW,binary_assessment=policy)
        output=r.to_text()
        self.assertIn('Associated CVE mechanism match (binary): Yes',output)
        self.assertIn('Exact CVE applicability established: No',output)
        self.assertIn('Attack: Failed',output)
        self.assertIn('Attack prediction confidence: Low',output)
        self.assertIn('Attack outcome evidence-verified: No',output)
        self.assertIn('Identified CVE: Not Found',output)
        self.assertIn('Consensus attack outcome: Unknown',output)
        self.assertNotIn('Verifier support for exact CVE:',output)
    def test_unverified_success_does_not_prove_vulnerability(self):
        a,v,c,o,t=fixtures(attack='Success',consensus='Unknown')
        r=enforce_mafra_report(FinalReport(),a,v,CVEValidationOutput(),c,FLOW,
            binary_assessment=assess_binary_benchmark(FLOW,a,v,c,o,t))
        self.assertEqual(r.is_service_vulnerable,'Unknown')
    def test_no_binary_assessment_preserves_step5_step6_display(self):
        a,v,c,o,t=fixtures(attack='Unknown',consensus='Unknown')
        r=enforce_mafra_report(FinalReport(),a,v,CVEValidationOutput(),c,FLOW)
        self.assertIn('Attack: Unknown',r.to_text())
        self.assertIn('Verifier support for exact CVE: Unknown',r.to_text())
    def test_reporter_integration_uses_binary_assessment_without_model_call(self):
        from unittest.mock import Mock, patch
        from agents.mcp_reporter_agent import MCPReporterAgent
        from mcp_evidence_contracts import FormattedEvidence
        a,v,c,o,t=fixtures(attack='Fail',consensus='Unknown')
        assessment=assess_binary_benchmark(FLOW,a,v,c,o,t)
        reporter=MCPReporterAgent.__new__(MCPReporterAgent)
        reporter.llm=Mock()
        with patch('agents.mcp_reporter_agent.invoke_validated',
                   return_value=FinalReport()) as call:
            report=reporter.generate(
                flow_summary=FLOW,analyst_output=a,verifier_output=v,
                consensus=c,validated_cve=CVEValidationOutput(),
                online_result=o,formatted_evidence=FormattedEvidence(),
                rag_context='',binary_assessment=assessment)
        self.assertEqual(call.call_count,1)
        self.assertIn('Attack: Failed',report.to_text())
        self.assertIn('Associated CVE mechanism match (binary): Yes',report.to_text())
        self.assertIn('Attack outcome evidence-verified: No',report.to_text())

    def test_fra_report_remains_unmodified(self):
        a,v,c,o,t=fixtures();r=FinalReport(attack='Unknown')
        self.assertIn('Attack: Failed',r.to_text())
if __name__ == '__main__':unittest.main()
