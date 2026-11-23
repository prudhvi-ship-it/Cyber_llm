"""FRA research adaptation: no remote requests or paid LLM calls."""
import importlib.util
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

from packet_search_features import informative_service
from mcp_web_research import _config, _relevant, _search_results, research_web


def server_module():
    sdk = types.ModuleType('mcp')
    sdk_server = types.ModuleType('mcp.server')
    class FakeServer:
        def __init__(self, *args, **kwargs): pass
        def tool(self): return lambda f: f
    sdk_server.MCPServer = FakeServer
    path = Path(__file__).resolve().parents[1] / 'mcp_server.py'
    spec = importlib.util.spec_from_file_location('fra_alignment_v6_server', path)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {'mcp': sdk, 'mcp.server': sdk_server}):
        spec.loader.exec_module(module)
    return module


server = server_module()


def record(cve, description):
    return {'vulnerabilities':[{'cve':{'id':cve, 'vulnStatus':'Analyzed',
                                     'descriptions':[{'lang':'en','value':description}],
                                     'configurations':[]}}]}


class FRAResearchV6Tests(unittest.TestCase):
    def test_generic_http_port_is_not_product(self):
        self.assertFalse(informative_service('HTTP web application (port 3000)'))
        self.assertFalse(informative_service('HTTP application on port 8000'))
        self.assertFalse(informative_service('Web app with Next.js-style middleware behavior'))
        self.assertTrue(informative_service('Next.js'))
        self.assertTrue(informative_service('Apache CouchDB'))

    def test_hyphenated_http_headers_match_unknown_product_clues(self):
        self.assertIn('middleware', __import__('mcp_web_research')._service_terms('x-middleware-subrequest'))
        self.assertTrue(_relevant('x-middleware-subrequest', 'middleware subrequest authorization bypass'))

    def test_google_fra_provider_auto_selection(self):
        with patch.dict(os.environ, {'FRA_WEB_SEARCH_PROVIDER':'auto',
             'GOOGLE_API_KEY_1':'dummy_key', 'GOOGLE_CSE_ID':'dummy_cse', 'SERPER_API_KEY':''}):
            self.assertEqual(_config()[0], 'google')

    def test_google_retries_second_key_and_parses_cse_items(self):
        from urllib.error import HTTPError
        fake_result={'items':[{'link':'https://example.org/nextjs-advisory',
                                'title':'Next.js middleware bypass',
                                'snippet':'x-middleware-subrequest CVE-2025-29927'}]}
        calls=[]
        def mocked_http(url, *,key, provider,query,count):
            calls.append((key,provider,query))
            if key=='blocked':
                raise HTTPError(url,429,'rate limit',{},None)
            return fake_result
        with patch.dict(os.environ, {'GOOGLE_API_KEY_1':'blocked', 'GOOGLE_API_KEY_2':'working',
                                      'GOOGLE_API_KEY':'','GOOGLE_CSE_ID':'dummy_cse'}), \
             patch('mcp_web_research._http_json',side_effect=mocked_http):
            hits=_search_results('google','blocked','middleware bypass',10)
        self.assertEqual([x[0] for x in calls], ['blocked','working'])
        self.assertEqual(len(hits),1)
        self.assertIn('CVE-2025-29927',hits[0]['snippet'])

    def test_unknown_product_search_keeps_relevant_web_hit(self):
        results=[{'url':'https://example.org/security','title':'Next.js middleware security advisory',
                 'snippet':'x-middleware-subrequest header can bypass authorization CVE-2025-29927'}]
        with patch.dict(os.environ, {'FRA_WEB_SEARCH_PROVIDER':'serper', 'SERPER_API_KEY':'dummy',
                                      'FRA_WEB_FETCH_MAX_PAGES':'0'}), \
             patch('mcp_web_research._search_results',return_value=results) as mocked:
            sources, _, queries=research_web('', 'Access Control Bypass','', '',
                'Access Control Bypass packet clues: header middleware subrequest', 8)
        self.assertEqual(len(sources),1)
        self.assertEqual(sources[0]['source_type'],'web_research_lead')
        self.assertIn('x-middleware-subrequest',queries[0])
        self.assertEqual(len(mocked.call_args_list),1)
        # Webpage CVEs do not automatically enter candidate_cves.
        self.assertEqual(sources[0]['cve_id'],'')

    def test_nvd_followup_requires_two_packet_clue_words(self):
        web=[{'source_type':'web_research_lead','title':'Next.js issue CVE-2025-29927',
              'snippet':'x-middleware-subrequest authorization bypass'}]
        with patch.object(server,'_fetch_json', return_value=record('CVE-2025-29927',
              'Next.js middleware authorization bypass via x-middleware-subrequest')) as fetch:
            sources, warnings, _=server._nvd_web_research_followups(web,
                  'Access Control Bypass packet clues: header middleware subrequest','',2)
        self.assertEqual([s['cve_id'] for s in sources],['CVE-2025-29927'])
        self.assertEqual(fetch.call_count,1)
        with patch.object(server,'_fetch_json',return_value=record('CVE-2025-29927',
             'Next.js framework unrelated behavior, no header matching')):
            sources,_,_=server._nvd_web_research_followups(web,
                  'Access Control Bypass packet clues: header middleware subrequest','',2)
        self.assertEqual(sources,[])

    def test_one_candidate_retrieval_does_not_assign_case_cve(self):
        web=[{'source_type':'web_research_lead','source_name':'Google CSE web result',
              'title':'Next.js CVE-2025-29927 security disclosure',
              'url':'https://example.org/nextjs','snippet':'x-middleware-subrequest bypass',
              'cve_id':'','supports':[],'contradicts':[]}]
        def fake_nvd(url):
            if 'cveId=CVE-2025-29927' in url:
                return record('CVE-2025-29927',
                    'Next.js middleware authorization bypass via x-middleware-subrequest')
            if 'known_exploited' in url: return {'vulnerabilities':[]}
            return {'vulnerabilities':[]}
        with patch.object(server,'_load_kev',return_value=[]), \
             patch.object(server,'_load_attack_patterns',return_value=[]), \
             patch.object(server,'_fetch_json',side_effect=fake_nvd), \
             patch.object(server,'research_web',return_value=(web,[],['google search: middleware'])):
            result=server.search_forensic_evidence(
                'Access Control Bypass packet clues: header middleware subrequest',
                service='', attack='Access Control Bypass', max_results=8)
        self.assertIn('CVE-2025-29927',result['candidate_cves'])
        self.assertTrue(any(s['source_type']=='nvd_cve_candidate' for s in result['sources']))
        self.assertFalse(any('confirmed exploit' in str(s.get('supports','')).lower()
                             for s in result['sources']))

    def test_optional_second_research_reasoning_bounded(self):
        sys.modules.setdefault('llm_client', types.SimpleNamespace(get_llm=MagicMock()))
        from agents.analyst_agent import AnalystAgent
        from contracts import AnalystOutput, CVEProposal, AttackFinding
        from mcp_evidence_contracts import ExternalEvidenceSource, OnlineEvidenceResult
        agent=AnalystAgent.__new__(AnalystAgent)
        agent.llm=MagicMock()
        marker='E-S0001-F000016-007'
        flow=f'[{marker}] X-Middleware-Subrequest: middleware repeated'
        first=AnalystOutput(attack=AttackFinding(type='Access Control Bypass',success='Success',evidence=[marker]))
        second=AnalystOutput(attack=AttackFinding(type='Access Control Bypass',success='Success',evidence=[marker]),
                             cve=CVEProposal(candidate='CVE-2025-29927'))
        online=OnlineEvidenceResult(status='Valid',query='Next.js',
              candidate_cves=['CVE-2025-29927'],
              retrieved_at_utc='2026-10-25T00:00:00Z',sources=[ExternalEvidenceSource(
              source_type='nvd_cve_candidate',title='CVE-2025-29927 record',
              url='https://nvd.nist.gov/vuln/detail/CVE-2025-29927',
              snippet='Next.js middleware authorization bypass',
              retrieved_at_utc='2026-10-25T00:00:00Z')])
        with patch.dict(os.environ, {'MAFRA_FRA_SECOND_PASS':'1','MAFRA_FRA_WEB_SUMMARY':'0'}), \
             patch('agents.analyst_agent.invoke_validated',side_effect=[first,second]) as model:
            result=agent.reconsider_with_online_evidence(flow,AnalystOutput(),online)
        self.assertEqual(model.call_count,2)
        self.assertEqual(result.cve.candidate,'CVE-2025-29927')

    def test_second_research_reasoning_cannot_invent_cve(self):
        sys.modules.setdefault('llm_client', types.SimpleNamespace(get_llm=MagicMock()))
        from agents.analyst_agent import AnalystAgent
        from contracts import AnalystOutput, CVEProposal, AttackFinding
        from mcp_evidence_contracts import ExternalEvidenceSource, OnlineEvidenceResult
        agent=AnalystAgent.__new__(AnalystAgent); agent.llm=MagicMock()
        first=AnalystOutput(attack=AttackFinding(type='Access Control Bypass',success='Success'))
        hallucinated=AnalystOutput(attack=AttackFinding(type='Access Control Bypass',success='Fail'),
                                   cve=CVEProposal(candidate='CVE-2000-12345'))
        online=OnlineEvidenceResult(status='Valid',query='middleware',
              candidate_cves=['CVE-2025-29927'], retrieved_at_utc='2026-10-25T00:00:00Z',
              sources=[ExternalEvidenceSource(source_type='nvd_cve_candidate',
              title='CVE-2025-29927',url='https://nvd.nist.gov/vuln/detail/CVE-2025-29927',
              snippet='Next.js middleware bypass',retrieved_at_utc='2026-10-25T00:00:00Z')])
        with patch.dict(os.environ, {'MAFRA_FRA_SECOND_PASS':'1','MAFRA_FRA_WEB_SUMMARY':'0'}), \
             patch('agents.analyst_agent.invoke_validated',side_effect=[first,hallucinated]) as model:
            result=agent.reconsider_with_online_evidence('packet summary',AnalystOutput(),online)
        self.assertEqual(model.call_count,2)
        self.assertEqual(result.cve.candidate,'Not Found')
        self.assertEqual(result.attack.success,'Success')

    def test_google_webpage_synthesis_one_optional_call(self):
        # Tests opt-in path only, defaults to no extra model call.
        fake_llm=MagicMock()
        fake_llm.invoke.return_value=types.SimpleNamespace(content='NVD: unconfirmed lead; source https://example.org')
        sys.modules.setdefault('llm_client', types.SimpleNamespace(get_llm=MagicMock()))
        from agents.analyst_agent import AnalystAgent
        from mcp_evidence_contracts import ExternalEvidenceSource,OnlineEvidenceResult
        agent=AnalystAgent.__new__(AnalystAgent)
        agent.llm=fake_llm
        online=OnlineEvidenceResult(status='Valid',query='header middleware',
              retrieved_at_utc='2026-10-25T00:00:00Z',sources=[ExternalEvidenceSource(
              source_type='web_research_lead',title='Next.js middleware advisory',
              url='https://example.org',snippet='Next.js auth bypass',
              retrieved_at_utc='2026-10-25T00:00:00Z')])
        with patch.dict(os.environ,{'MAFRA_FRA_WEB_SUMMARY':'0'}):
            self.assertEqual(agent._fra_research_digest(online),'')
        fake_llm.invoke.assert_not_called()
        with patch.dict(os.environ,{'MAFRA_FRA_WEB_SUMMARY':'1'}):
            self.assertIn('unconfirmed lead',agent._fra_research_digest(online))
        self.assertEqual(fake_llm.invoke.call_count,1)


if __name__=='__main__': unittest.main()
