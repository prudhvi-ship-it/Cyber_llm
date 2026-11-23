"""Offline FRA merge regression tests. No network/API calls or keys required."""
import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

# Avoid importing real OpenRouter client during offline prompt-only tests.
if 'llm_client' not in sys.modules:
    stub = types.ModuleType('llm_client')
    stub.get_llm = lambda role='': object()
    sys.modules['llm_client'] = stub

from contracts import AnalystOutput, VerifierOutput, ConsensusDecision
from agents.consensus import ConsensusManager
from agents.analyst_agent import AnalystAgent
from mcp_online_search import MCPOnlineEvidenceSearch

class KnownAttackAndAbstention(unittest.TestCase):
    def setUp(self):
        self.consensus = ConsensusManager()
        self.v = VerifierOutput(
            status='Valid', verification_result='Supported', service_supported='Yes',
            attack_supported='Yes', success_supported='Yes', confidence='High')

    def test_no_attack_cannot_be_reported_failed_or_high_confidence(self):
        a = AnalystOutput(service={'primary':'Joomla'}, attack={
            'type':'Unknown', 'technique':'Unknown', 'success':'Fail'})
        result = self.consensus.calculate(a,self.v)
        self.assertEqual(result.attack_success, 'Unknown')
        self.assertEqual(result.score,1)
        self.assertEqual(result.overall_confidence,'Low')
        self.assertEqual(result.verification_result,'Partially Supported')
        self.assertEqual(result.attack_supported,'Unknown')

    def test_no_attack_cannot_be_reported_success(self):
        a=AnalystOutput(attack={'type':'None','technique':'Unknown','success':'Success', 'evidence':['E-S0001-F000021-001']})
        self.assertEqual(self.consensus.calculate(a,self.v).attack_success,'Unknown')

    def test_known_supported_success_keeps_current_binary_rule(self):
        a=AnalystOutput(attack={'type':'RCE','technique':'Command Injection','success':'Success',
                                'evidence':['E-S0001-F000021-001']})
        self.assertEqual(self.consensus.calculate(a,self.v).attack_success,'Success')

    def test_known_verified_failed_attack_is_preserved(self):
        a=AnalystOutput(attack={'type':'Unauthorized access','technique':'Access attempt',
                                'success':'Fail', 'evidence':['E-S0001-F000021-001']})
        self.assertEqual(self.consensus.calculate(a,self.v).attack_success,'Fail')

    def test_explicit_verifier_rejection_is_not_success(self):
        a=AnalystOutput(attack={'type':'RCE','success':'Success','evidence':['E-S0001-F000021-001']})
        v=self.v.model_copy(update={'attack_supported':'No'})
        self.assertNotEqual(self.consensus.calculate(a,v).attack_success,'Success')

class ResearchTests(unittest.TestCase):
    def setUp(self):
        self.s=MCPOnlineEvidenceSearch(server_url='http://test.invalid/mcp')
        self.v=VerifierOutput()
        self.c=ConsensusDecision()
        self.queries=[]
        async def mocked_server(q,*args):
            self.queries.append(q)
            return ('search_forensic_evidence',{'sources':[{
                'title':'Vendor advisory','url':'https://example.org/a',
                'snippet':'Product information'}], 'candidate_cves':['CVE-2099-1234']},'')
        self.s._call_server=mocked_server

    def test_version_query_trigger(self):
        a=AnalystOutput(service={'primary':'ExampleServer'})
        res=self.s.search(a,self.v,self.c,'[E-S0002-F000010-001] ExampleServer version 2.4.7')
        self.assertEqual(res.status,'Valid')
        self.assertIn('ExampleServer 2.4.7',self.queries[0])
        self.assertTrue(any('Context-only' in note for note in res.retrieval_errors))

    def test_no_version_skips(self):
        a=AnalystOutput(service={'primary':'ExampleServer'})
        res=self.s.search(a,self.v,self.c,'[E-S0002-F000010-001] ExampleServer seen')
        self.assertEqual(res.status,'Abstain')
        self.assertEqual(len(self.queries),0)

    def test_generic_product_skips(self):
        a=AnalystOutput(service={'primary':'HTTP JSON API'})
        res=self.s.search(a,self.v,self.c,'[E-S0002-F000010-001] HTTP JSON API version 2.4.7')
        self.assertEqual(res.status,'Abstain')

    def test_cve_in_filename_cannot_trigger(self):
        a=AnalystOutput(service={'primary':'ExampleServer'})
        res=self.s.search(a,self.v,self.c,'File: CVE-2099-1234.pcap\nExampleServer')
        self.assertEqual(res.status,'Abstain')

    def test_explicit_version_forwarded_to_mcp_tool(self):
        a=AnalystOutput(service={'primary':'ExampleServer'})
        tool=types.SimpleNamespace(input_schema={'properties':{
            'query':{},'service':{},'version':{}}})
        args=self.s._build_arguments(tool,'ExampleServer 2.4.7',a,self.v,self.c)
        self.assertEqual(args['version'],'2.4.7')

class AnalystPrompts(unittest.TestCase):
    def setUp(self):
        self.agent=AnalystAgent()
        self.flow='--- Stream 1 [VALID] ---\n[E-S0001-F000022-001] GET /health\n'

    def test_guidance_in_first_prompt(self):
        with patch.dict(os.environ,{'MAFRA_FRA_ANALYST_GUIDANCE':'1'}), \
             patch('agents.analyst_agent.invoke_validated',return_value=AnalystOutput()) as llm:
            self.agent.analyze(self.flow)
        prompt=llm.call_args.kwargs['prompt']
        for term in ['ONE incident','normal installation','attacker requests',
                     'target responses','CVE candidates','Unknown, NOT Fail']:
            self.assertIn(term,prompt)

    def test_guidance_optional_and_no_extra_llm_calls(self):
        with patch.dict(os.environ,{'MAFRA_FRA_ANALYST_GUIDANCE':'0'}), \
             patch('agents.analyst_agent.invoke_validated',return_value=AnalystOutput()) as llm:
            self.agent.analyze(self.flow)
        self.assertEqual(llm.call_count,1)
        self.assertNotIn('FRA-style INCIDENT INVESTIGATION',llm.call_args.kwargs['prompt'])

    def test_guidance_in_revision(self):
        from mcp_evidence_contracts import OnlineEvidenceResult, ExternalEvidenceSource
        online=OnlineEvidenceResult(status='Valid',query='Test',retrieved_at_utc='2026-10-25T00:00:00Z',sources=[
            ExternalEvidenceSource(title='Advisory',url='https://example.org',snippet='Background', retrieved_at_utc='2026-10-25T00:00:00Z')])
        with patch('agents.analyst_agent.invoke_validated',return_value=AnalystOutput()) as llm:
            self.agent.reconsider_with_online_evidence(self.flow,AnalystOutput(),online)
        self.assertEqual(llm.call_count,1)
        self.assertIn('FRA-style INCIDENT INVESTIGATION',llm.call_args.kwargs['prompt'])

if __name__=='__main__':unittest.main()
