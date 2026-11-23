"""Offline, no-key validation of FRA browser logic adapted for the MCP contract."""
import importlib
import os
import sys
import types
import unittest
from unittest.mock import patch

# The Linux audit runner lacks the Windows project's mcp dependency.
# Stub only the server registration interface; production uses real mcp.
if 'mcp' not in sys.modules:
    mcp = types.ModuleType('mcp'); server = types.ModuleType('mcp.server')
    class MCPServer:
        def __init__(self, *args, **kwargs): pass
        def tool(self): return lambda f: f
    server.MCPServer = MCPServer; mcp.server = server
    sys.modules['mcp'] = mcp;sys.modules['mcp.server'] = server

import packet_search_features as features
import mcp_web_research as web
import mcp_server as srv

CASE_QUERY = 'subrequest header authentication bypass packet clues: header middleware subrequest'

def record(cve, description):
    return {'vulnerabilities': [{'cve': {'id':cve, 'vulnStatus':'Analyzed',
                     'descriptions':[{'lang':'en','value':description}], 'configurations':[]}}]}

class OnlineSearchFRA(unittest.TestCase):
    def test_generic_service_is_not_a_product(self):
        for x in ['Custom Web Application','HTTP Web Application','web application',
                  'Generic HTTP Application','Unknown','custom web application (port 3000)']:
            self.assertFalse(features.informative_service(x),x)
        self.assertTrue(features.informative_service('Apache CouchDB'))
        self.assertTrue(features.informative_service('Next.js'))

    @patch.object(web, '_config',return_value=('serper','mock-key',''))
    @patch.object(web, '_search_results')
    @patch.object(web, '_read_public_page',return_value='Text from actual webpage mentioning middleware authorization issues and CVE-2025-29927.')
    def test_direct_analyst_query_keeps_top_ten_and_fetches_without_product(self,read,search,config):
        search.return_value=[{'url':f'https://example{i}.com/article','title':f'CVE analysis {i}',
                              'snippet':'An x-middleware-subrequest attack'} for i in range(12)]
        with patch.dict(os.environ, {'FRA_WEB_SEARCH_RESULTS':'10','FRA_WEB_FETCH_MAX_PAGES':'10'}):
            sources,warnings,queried=web.research_web('Custom Web Application',
                   'Authentication Bypass','', '',CASE_QUERY,10)
        self.assertEqual(len(sources),10)
        self.assertEqual(read.call_count,10)
        self.assertIn('Webpage text:',sources[0]['snippet']) if False else None
        self.assertIn('Webpage text:',sources[0]['snippet'])
        self.assertEqual(search.call_args.args[2], 'subrequest header authentication bypass')
        self.assertEqual(queried,['serper search: subrequest header authentication bypass'])
        self.assertEqual(warnings,[])
        self.assertTrue(all(item['cve_id']=='' for item in sources))

    @patch.object(web, '_config',return_value=('serper','mock-key',''))
    @patch.object(web, '_search_results',return_value=[
          {'url':'https://example.org/security','title':'Next.js security','snippet':'x-middleware-subrequest'}])
    @patch.object(web, '_read_public_page',side_effect=ValueError('mocked blocked endpoint'))
    def test_page_failure_keeps_search_lead_without_faking_page_text(self,read,search,config):
        sources,warnings,_=web.research_web('Unknown','Auth Bypass','', '',CASE_QUERY,10)
        self.assertEqual(len(sources),1)
        self.assertIn('not fetched',sources[0]['match_reason'])
        self.assertEqual(len(warnings),1)

    def test_html_without_product_filter_preserves_CVE_mechanism(self):
        html='<html><head><script>ignore</script></head><body>' \
             '<h1>CVE-2025-29927</h1><p>Next.js authorization bypass using x-middleware-subrequest header.</p></body></html>'
        actual=web._extract_relevant_text(html,'','', '')
        self.assertIn('CVE-2025-29927', actual)
        self.assertIn('x-middleware-subrequest', actual)
        self.assertNotIn('ignore',actual)

    def test_safety_rejects_private_web_addresses(self):
        for url in ['http://example.com/','https://localhost/internal','https://127.0.0.1/private',
                    'https://site.local/','file:///etc/passwd']:
            with self.assertRaises(ValueError): web._public_https_url(url)

    @patch.object(srv, '_fetch_json')
    def test_generic_nvd_mechanism_search_finds_real_header_not_unrelated_description(self,fetch):
        fetch.return_value={'vulnerabilities':[
            record('CVE-2025-29927','Next.js middleware authorization bypass using x-middleware-subrequest header')['vulnerabilities'][0],
            record('CVE-2000-0001','Unrelated web denial of service')['vulnerabilities'][0]
        ]}
        sources,warnings,urls=srv._nvd_sources('','Authentication Bypass','', '',10,query=CASE_QUERY)
        self.assertEqual([x['cve_id'] for x in sources],['CVE-2025-29927'])
        self.assertEqual(warnings,[])
        self.assertTrue(urls)

    @patch.object(srv, '_fetch_json')
    def test_followup_web_cve_must_pass_independent_nvd_match(self,fetch):
        fetch.side_effect=lambda url: (record('CVE-2025-29927','Next.js middleware authorization bypass using x-middleware-subrequest header')
                if 'CVE-2025-29927' in url else record('CVE-2025-30218','Unrelated bug'))
        leads=[{'source_type':'web_research_lead','title':'CVE-2025-29927: Next.js middleware bypass',
                'snippet':'x-middleware-subrequest','url':'https://example.com/'},
               {'source_type':'web_research_lead','title':'CVE-2025-30218: unrelated bug',
                'snippet':'Unrelated issue', 'url':'https://example.org/'}]
        sources,warnings,urls=srv._nvd_web_research_followups(leads, CASE_QUERY, '', limit=2)
        self.assertEqual([x['cve_id'] for x in sources],['CVE-2025-29927'])
        self.assertEqual(len(urls),2)

    @patch.object(srv,'_kev_sources',return_value=([],[]))
    @patch.object(srv,'_nvd_sources',return_value=([],[],[]))
    @patch.object(srv,'_attack_sources',return_value=[])
    @patch.object(srv,'research_web',return_value=([
        {'source_type':'web_research_lead','title':'CVE-2025-29927: Next.js bypass',
         'snippet':'x-middleware-subrequest', 'source_name':'Serper', 'url':'https://example.org/a',
         'cve_id':'','supports':[],'contradicts':[],'match_reason':'fetched'}],[],['Serper search']))
    @patch.object(srv,'_fetch_json',return_value=record('CVE-2025-29927',
         'Next.js authorization middleware bypass using x-middleware-subrequest header'))
    def test_full_mocked_mcp_research_yields_candidate_without_forcing_verdict(self,*mocks):
        result=srv.search_forensic_evidence(query=CASE_QUERY,service='Custom Web Application',
                                           attack='Authentication Bypass',max_results=8)
        self.assertIn('CVE-2025-29927',result['candidate_cves'])
        self.assertTrue(any(s.get('source_type')=='nvd_cve_candidate' for s in result['sources']))
        self.assertTrue(any(s.get('source_type')=='web_research_lead' for s in result['sources']))
        self.assertFalse(any(s.get('cve_id')=='CVE-2025-29927' and s.get('source_type')=='web_research_lead'
                             for s in result['sources']))

if __name__=='__main__': unittest.main()
