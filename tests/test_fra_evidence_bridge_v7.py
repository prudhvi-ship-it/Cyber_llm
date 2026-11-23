"""Offline regression of packet-linked, non-hardcoded advisory triage."""
import unittest
from unittest.mock import patch, MagicMock
import sys
import types
from contracts import AnalystOutput, ServiceFinding, VerifierOutput
from mcp_evidence_contracts import OnlineEvidenceResult
from cve_mechanism_matcher import rank_cve_mechanisms, _packet_observations
from mcp_evidence_policy import derive_online_cve_validation

WHEN = '2026-10-25T00:00:00Z'
FLOW = '''
- [E-S0000-F000008-009 | server->client] Location: /login
- [E-S0001-F000016-007 | client->server] X-Middleware-Subrequest: middleware:middleware:middleware
- [E-S0001-F000018-008 | server->client] HTTP Status 200
- [E-S0001-F000020-010 | server->client] Admin Dashboard body
'''

def online(cve='CVE-2025-29927', header='x-middleware-subrequest'):
    return OnlineEvidenceResult(status='Valid', query='middleware bypass', retrieved_at_utc=WHEN,
        candidate_cves=[cve], sources=[dict(
          source_name='NIST NVD', title=cve, url=f'https://nvd.nist.gov/vuln/detail/{cve}',
          snippet=f'Next.js authorization bypass when a {header} header is trusted in middleware.',
          retrieved_at_utc=WHEN,
        )])

def analyst():
    a=AnalystOutput(service=ServiceFinding(primary='Web application'))
    a.cve.candidate='CVE-2025-29927'
    return a

class ResearchMechanismBridge(unittest.TestCase):
    def test_directional_packet_catalog_is_parsed(self):
        catalog=_packet_observations(FLOW)
        self.assertIn('E-S0001-F000016-007',catalog)
        self.assertIn('E-S0000-F000008-009',catalog)

    def test_authoritative_exact_custom_header_is_candidate(self):
        result=rank_cve_mechanisms(FLOW, analyst(), online())
        self.assertEqual([c.cve_id for c in result.candidates], ['CVE-2025-29927'])
        self.assertIn('http_header:x-middleware-subrequest',result.candidates[0].mechanism_features)
        self.assertIn('E-S0001-F000016-007',result.candidates[0].packet_ids)
        self.assertIn('candidate',result.candidates[0].level.lower()+result.to_text().lower())

    def test_distinct_header_suffix_not_equal(self):
        self.assertFalse(rank_cve_mechanisms(FLOW, analyst(), online('CVE-2025-30218','x-middleware-subrequest-id')).candidates)

    def test_unrelated_authoritative_cve_not_inferred(self):
        self.assertFalse(rank_cve_mechanisms(FLOW, analyst(), online('CVE-2024-99999','x-another-header')).candidates)

    def test_header_missing_from_packet_no_candidate(self):
        no_header='- [E-S0001-F000018-008 | server->client] HTTP Status 200'
        self.assertFalse(rank_cve_mechanisms(no_header, analyst(), online()).candidates)

    def test_mismatched_named_application_no_candidate(self):
        a=AnalystOutput(service=ServiceFinding(primary='Grafana'))
        self.assertFalse(rank_cve_mechanisms(FLOW,a,online()).candidates)

    def test_cross_cve_support_not_nvd_subject(self):
        r=OnlineEvidenceResult(status='Valid',query='test',retrieved_at_utc=WHEN,
            candidate_cves=['CVE-2025-29927'],sources=[dict(
             source_name='NIST NVD', title='CVE-2025-30218',
             url='https://nvd.nist.gov/vuln/detail/CVE-2025-30218',
             snippet='Next.js x-middleware-subrequest header',
             supports=['References CVE-2025-29927'],retrieved_at_utc=WHEN)])
        self.assertFalse(rank_cve_mechanisms(FLOW,analyst(),r).candidates)

    def test_triage_cannot_override_verifier_rejection(self):
        a=analyst();o=online();t=rank_cve_mechanisms(FLOW,a,o)
        v=VerifierOutput(status='Valid',service_supported='Yes',attack_supported='Yes',
             success_supported='Yes',cve_supported='No')
        self.assertEqual(derive_online_cve_validation(a,v,o,cve_triage=t).validated_cve,'Not Found')

    def test_triage_and_independent_verifier_can_confirm(self):
        a=analyst();o=online();t=rank_cve_mechanisms(FLOW,a,o)
        v=VerifierOutput(status='Valid',service_supported='Yes',attack_supported='Yes',
             success_supported='Yes',cve_supported='Yes')
        out=derive_online_cve_validation(a,v,o,cve_triage=t)
        self.assertEqual(out.validated_cve,'CVE-2025-29927')

    def test_verifier_hint_is_optional_and_does_not_change_call_count(self):
        # Avoid importing installed LLM SDK: verifier calls are mocked.
        sys.modules.setdefault('llm_client', types.SimpleNamespace(get_llm=lambda *a,**kw: object()))
        sys.modules.setdefault('structured_output', types.SimpleNamespace(invoke_validated=lambda **kw: None))
        from agents.verifier_agent import VerifierAgent
        v=VerifierAgent()
        fake=VerifierOutput(status='Valid', verification_result='Partially Supported',
             success_supported='Unknown', cve_supported='Unknown')
        with patch('agents.verifier_agent.invoke_validated', return_value=fake) as call:
            v.verify(FLOW,analyst(),cve_mechanism_hints='Rank 1: CVE-2025-29927 — Preliminary')
            self.assertEqual(call.call_count,1)
            self.assertIn('candidate_mechanisms',call.call_args.kwargs['prompt'])
            self.assertIn('CVE-2025-29927',call.call_args.kwargs['prompt'])
        with patch('agents.verifier_agent.invoke_validated', return_value=fake) as call:
            v.verify(FLOW,analyst())
            self.assertEqual(call.call_count,1)
            self.assertNotIn('candidate_mechanisms',call.call_args.kwargs['prompt'])

if __name__=='__main__':unittest.main()
