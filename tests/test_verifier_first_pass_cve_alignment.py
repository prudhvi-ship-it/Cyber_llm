"""Offline, multi-protocol first-pass CVE verification tests; no LLM/network."""
import json
import unittest
import sys
import types
from unittest.mock import MagicMock, patch

sys.modules.setdefault("llm_client", types.SimpleNamespace(get_llm=MagicMock()))

from contracts import AnalystOutput, AttackFinding, CVEProposal, ServiceFinding, VerifierOutput
from agents.verifier_agent import VerifierAgent


class VerifierFirstPassCVETests(unittest.TestCase):
    ID = 'E-S0001-F000016-007'
    REPLY = 'E-S0001-F000018-008'

    def agent(self):
        agent = VerifierAgent.__new__(VerifierAgent)
        agent.llm = MagicMock()
        return agent

    def analyst(self, service, cve, technique='Attempted exploitation', success='Fail'):
        return AnalystOutput(
            service=ServiceFinding(primary=service),
            attack=AttackFinding(type='Attack', technique=technique,
                                 success=success, evidence=[self.ID]),
            cve=CVEProposal(candidate=cve, confidence='Medium', reason='Mechanism matches'),
        )

    def research(self, cve, mechanism):
        return json.dumps({
            'proposed_cve': cve,
            'current_case_packet_ids': [self.ID],
            'cve_specific_research_sources': [{
                'source_name': 'NVD', 'source_type': 'nvd_cve_candidate',
                'url': 'https://nvd.nist.gov/vuln/detail/'+cve,
                'title': cve,
                'description_excerpt': mechanism,
            }],
            'unverified_requirements_from_mechanism_triage': ['Exact version unknown'],
        })

    def output(self, cve='Yes', success='Yes', status='Supported'):
        return VerifierOutput(
            verification_result=status, service_supported='Yes', attack_supported='Yes',
            success_supported=success, cve_supported=cve,
            evidence_check=[self.ID], confidence='Medium',
        )

    def test_five_attack_families_get_same_first_pass_instructions(self):
        cases = [
            ('Next.js web application','CVE-2025-29927','X-Middleware-Subrequest header', 'Authentication bypass'),
            ('CouchDB','CVE-2022-24706','Erlang distribution RPC cookie access','Erlang RPC'),
            ('phpMyAdmin','CVE-2016-5734','preg_replace exploit payload','PHP code execution'),
            ('Grafana','CVE-2021-43798','/public/plugins/../ path traversal','Path traversal'),
            ('Log4j','CVE-2021-44228','JNDI lookup injection','JNDI injection'),
        ]
        for service, cve, indicator, technique in cases:
            with self.subTest(service=service):
                flow=f'[{self.ID}] Attacker sends: {indicator}\n'
                a=self.analyst(service,cve,technique)
                with patch('agents.verifier_agent.invoke_validated', return_value=self.output()) as mock:
                    verified=self.agent().verify(flow,a,mcp_evidence_context=self.research(cve,indicator))
                self.assertEqual(mock.call_count,1, 'No conditional second CVE model call')
                prompt=mock.call_args.kwargs['prompt']
                self.assertIn('FOR EVERY PCAP',prompt)
                self.assertIn('this FIRST pass',prompt)
                self.assertIn('without the exact installed version',prompt)
                self.assertIn(indicator,prompt)
                self.assertIn(cve,prompt)
                self.assertEqual(verified.cve_supported,'Yes')
                self.assertEqual(verified.success_supported,'Yes')

    def test_unknown_first_pass_becomes_no_when_candidate_exists(self):
        analyst=self.analyst('CouchDB','CVE-2022-24706')
        with patch('agents.verifier_agent.invoke_validated',return_value=self.output('Unknown')) as mock:
            out=self.agent().verify(f'[{self.ID}] Erlang cookie attempt',analyst)
        self.assertEqual(mock.call_count,1)
        self.assertEqual(out.cve_supported,'No')
        self.assertEqual(out.verification_result,'Partially Supported')
        self.assertIn('not sufficiently supported', ' '.join(out.unsupported_claims))

    def test_no_is_not_automatically_turned_into_yes(self):
        analyst=self.analyst('phpMyAdmin','CVE-2016-5734')
        out_initial=self.output('No',status='Partially Supported')
        out_initial.unsupported_claims=['The packet does not show the described exploit mechanism']
        with patch('agents.verifier_agent.invoke_validated',return_value=out_initial) as mock:
            out=self.agent().verify(f'[{self.ID}] generic page load',analyst)
        self.assertEqual(mock.call_count,1)
        self.assertEqual(out.cve_supported,'No')

    def test_without_candidate_not_applicable_even_if_model_says_yes(self):
        analyst=self.analyst('Joomla','Not Found')
        with patch('agents.verifier_agent.invoke_validated',return_value=self.output('Yes')) as mock:
            out=self.agent().verify(f'[{self.ID}] request',analyst)
        self.assertEqual(mock.call_count,1)
        self.assertEqual(out.cve_supported,'Not Applicable')

    def test_model_validation_failure_stays_abstained(self):
        analyst=self.analyst('Next.js','CVE-2025-29927')
        with patch('agents.verifier_agent.invoke_validated',return_value=VerifierOutput.abstain()):
            out=self.agent().verify(f'[{self.ID}] X-Middleware-Subrequest',analyst)
        self.assertEqual(out.status,'Abstain')
        self.assertEqual(out.cve_supported,'Not Applicable')

    def test_outcome_specific_rce_review_cannot_erase_cve_yes(self):
        a=self.analyst('CouchDB','CVE-2022-24706',technique='Remote Code Execution',success='Success')
        flow=(f'[{self.ID}] Client sends Erlang RPC os:cmd(id).\n'
              f'[{self.REPLY}] Server response: Command output observed uid=0(root).')
        first=self.output('Yes',success='Unknown',status='Partially Supported')
        second=self.output('No',success='Yes',status='Supported')
        second.evidence_check=[self.REPLY]
        with patch('agents.verifier_agent.invoke_validated',side_effect=[first,second]) as mock:
            out=self.agent().verify(flow,a)
        self.assertEqual(mock.call_count,2, 'Only existing ATTACK outcome second-pass is allowed')
        self.assertEqual(out.success_supported,'Yes')
        self.assertEqual(out.cve_supported,'Yes')

    def test_attack_outcome_recheck_cannot_erase_binary_no(self):
        a=self.analyst('CouchDB','CVE-2022-24706',technique='Remote Code Execution',success='Success')
        flow=(f'[{self.ID}] Client sends Erlang RPC os:cmd(id).\n'
              f'[{self.REPLY}] Server response: Command output observed uid=0(root).')
        first=self.output('Unknown',success='Unknown',status='Partially Supported')
        second=self.output('Yes',success='Yes',status='Supported')
        second.evidence_check=[self.REPLY]
        with patch('agents.verifier_agent.invoke_validated',side_effect=[first,second]):
            out=self.agent().verify(flow,a)
        self.assertEqual(out.success_supported,'Yes')
        self.assertEqual(out.cve_supported,'No')
        self.assertEqual(out.verification_result,'Partially Supported')
        self.assertIn('not sufficiently supported',' '.join(out.unsupported_claims))

    def test_no_version_requirement_even_for_failed_attempt(self):
        a=self.analyst('Next.js','CVE-2025-29927', 'Authentication bypass',success='Fail')
        # Don't include response IDs to avoid triggering existing outcome recheck.
        flow=f'[{self.ID}] x-middleware-subrequest header, attacker request'
        with patch('agents.verifier_agent.invoke_validated',return_value=self.output('Yes',success='Yes')) as mock:
            out=self.agent().verify(flow,a,mcp_evidence_context=self.research('CVE-2025-29927','x-middleware-subrequest'))
        self.assertEqual(mock.call_count,1)
        self.assertEqual(out.cve_supported,'Yes')
        self.assertEqual(out.success_supported,'Yes')

if __name__ == '__main__':
    unittest.main()
