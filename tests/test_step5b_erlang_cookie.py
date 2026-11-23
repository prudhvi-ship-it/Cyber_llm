"""Step 5B: packet-level default-cookie authentication and safe CVE attribution."""
import ipaddress
import struct
import unittest
from pathlib import Path
from dataclasses import replace

from evidence_extractor import PacketRecord, EvidenceExtractor
from erlang_cookie_evidence import (find_default_cookie_handshakes,
    find_verified_cookie_rpc_sequences)
from mcp_evidence_policy import derive_online_cve_validation
from cve_mechanism_matcher import rank_cve_mechanisms
from contracts import AnalystOutput, ServiceFinding, VerifierOutput
from mcp_evidence_contracts import OnlineEvidenceResult

WHEN='2026-10-14T00:00:00Z'
FLOW='''
[E-S0000-F000007-003] Client sends EPMD names query.
[E-S0000-F000011-004] EPMD lists couchdb at port 9100.
[E-S0001-F000023-003] Erlang node couchdb@127.0.0.1.
[E-S0001-F000029-007] Erlang RPC request: os:cmd('id').
[E-S0001-F000031-008] Server response: rex uid=0(root) gid=0(root).
'''


def online(url='https://www.cisa.gov/known-exploited-vulnerabilities-catalog'):
    return OnlineEvidenceResult(status='Valid',query='CouchDB Erlang',retrieved_at_utc=WHEN,
        candidate_cves=['CVE-2022-24706'],sources=[dict(source_name='CISA KEV',
        title='Apache CouchDB default initialization',url=url,
        snippet='Insecure default cookie',retrieved_at_utc=WHEN,
        supports=['CVE-2022-24706 is listed in KEV'])])


def packet_records():
    """Read the real PCAP without tshark, so this test verifies original bytes."""
    path=Path(__file__).resolve().parents[1]/'MAFRA_Eval30/pcaps/CFA_event0_CVE-2022-24706.pcap'
    if not path.is_file():
        raise unittest.SkipTest('PCAP fixture absent')
    data=path.read_bytes()
    assert data[:4]==b'\xd4\xc3\xb2\xa1'
    offset=24;frame=0;records=[]
    while offset+16<=len(data):
        sec,usec,length,_=struct.unpack_from('<IIII',data,offset);offset+=16
        raw=data[offset:offset+length];offset+=length;frame+=1
        if len(raw)<54 or raw[12:14]!=b'\x08\x00':continue
        ip=raw[14:]; ihl=(ip[0]&15)*4
        if ip[9]!=6:continue
        tcp=ip[ihl:]
        src_port,dst_port=struct.unpack('!HH',tcp[:4])
        if 9100 not in (src_port,dst_port):continue
        payload=tcp[(tcp[12]>>4)*4:]
        if not payload:continue
        src=f'{ipaddress.IPv4Address(ip[12:16])}:{src_port}'
        dst=f'{ipaddress.IPv4Address(ip[16:20])}:{dst_port}'
        direction='client->server' if dst_port==9100 else 'server->client'
        records.append(PacketRecord(frame_number=frame,timestamp_epoch=sec+usec/1e6,
            source=src,destination=dst,direction=direction,protocol='TCP',
            payload=payload.decode('utf-8','replace'),payload_bytes=len(payload),
            payload_hex=payload.hex()))
    return records


class CookiePacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records=packet_records()

    def test_real_pcap_both_auth_digests_and_rpc_pair(self):
        sequences=find_verified_cookie_rpc_sequences(self.records,1)
        self.assertEqual(len(sequences),1)
        hs=sequences[0].handshake
        self.assertEqual((hs.challenge_frame,hs.client_reply_frame,hs.server_ack_frame),(23,25,27))
        self.assertEqual((sequences[0].rpc.request_frame,sequences[0].rpc.reply_frame),(29,31))
        self.assertTrue(hs.client_digest_matched and hs.server_digest_matched)
        self.assertTrue(hs.server_node.startswith('couchdb@'))

    def test_evidence_ids_point_to_three_real_authentication_frames(self):
        extracted=EvidenceExtractor().extract(stream_id=1,packets=self.records)
        matched=[x for x in extracted['authentication'] if 'Erlang' in x.observation]
        self.assertEqual({x.frame_number for x in matched},{23,25,27})
        self.assertEqual({x.direction for x in matched},{'client->server','server->client'})
        self.assertTrue(all(x.evidence_id.startswith('E-S0001-F') for x in matched))
        self.assertTrue(all('ee5c9e8e' not in x.observation for x in matched))

    def test_wrong_client_digest_is_rejected(self):
        mutated=[]
        for item in self.records:
            if item.frame_number==25:
                b=bytearray(bytes.fromhex(item.payload_hex));b[8]^=0x10
                item=replace(item,payload_hex=b.hex())
            mutated.append(item)
        self.assertEqual(find_default_cookie_handshakes(mutated),[])
        self.assertFalse(find_verified_cookie_rpc_sequences(mutated,1))

    def test_wrong_server_ack_digest_is_rejected(self):
        mutated=[]
        for item in self.records:
            if item.frame_number==27:
                b=bytearray(bytes.fromhex(item.payload_hex));b[-1]^=0x01
                item=replace(item,payload_hex=b.hex())
            mutated.append(item)
        self.assertFalse(find_verified_cookie_rpc_sequences(mutated,1))

    def test_missing_auth_packet_is_rejected(self):
        self.assertFalse(find_default_cookie_handshakes([x for x in self.records if x.frame_number!=27]))
        self.assertFalse(find_default_cookie_handshakes([x for x in self.records if x.frame_number!=23]))

    def test_wrong_endpoint_and_reply_order_rejected(self):
        swapped=[replace(x,source='10.0.0.9:9100') if x.frame_number==27 else x for x in self.records]
        self.assertFalse(find_default_cookie_handshakes(swapped))
        delayed=[replace(x,timestamp_epoch=x.timestamp_epoch+100) if x.frame_number==27 else x for x in self.records]
        self.assertFalse(find_default_cookie_handshakes(delayed))

    def test_handshake_without_rpc_never_proves_attack(self):
        records=[x for x in self.records if x.frame_number not in (29,31)]
        self.assertEqual(len(find_default_cookie_handshakes(records)),1)
        self.assertFalse(find_verified_cookie_rpc_sequences(records,1))

    def test_text_claim_does_not_substitute_for_binary_bytes(self):
        fake=replace(next(x for x in self.records if x.frame_number==25),
            payload='default Erlang cookie is monster',payload_hex='')
        packets=[fake if x.frame_number==25 else x for x in self.records]
        self.assertFalse(find_default_cookie_handshakes(packets))


class CVEDecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sequences=tuple(find_verified_cookie_rpc_sequences(packet_records(),1))

    def decide(self, seq=None, svc='CouchDB', sources=None, v=None, flow=FLOW):
        analyst=AnalystOutput(service=ServiceFinding(primary=svc))
        result=sources if sources is not None else online()
        triage=rank_cve_mechanisms(flow,analyst,result,
            verified_cookie_rpc_sequences=seq if seq is not None else self.sequences)
        verifier=v if v is not None else VerifierOutput(
            status='Valid',service_supported='Yes',attack_supported='Yes',success_supported='Yes')
        return derive_online_cve_validation(analyst,verifier,result,cve_triage=triage,
            verified_cookie_rpc_sequences=seq if seq is not None else self.sequences)

    def test_raw_packet_proof_allows_high_confidence_cve(self):
        decision=self.decide()
        self.assertEqual(decision.validated_cve,'CVE-2022-24706')
        self.assertEqual(decision.cve_supported,'Yes')
        self.assertEqual(decision.confidence,'High')
        self.assertIn('not observable', ' '.join(decision.reasons))

    def test_no_cookie_proof_remains_not_found(self):
        self.assertEqual(self.decide(seq=()).validated_cve,'Not Found')

    def test_different_product_and_untrusted_web_result_rejected(self):
        self.assertEqual(self.decide(svc='Grafana').validated_cve,'Not Found')
        self.assertEqual(self.decide(sources=online('https://randomblog.example/post')).validated_cve,'Not Found')

    def test_verifier_without_success_cannot_confirm_cve(self):
        verifier=VerifierOutput(status='Valid',service_supported='Yes',attack_supported='Yes',success_supported='Unknown')
        self.assertEqual(self.decide(v=verifier).validated_cve,'Not Found')

    def test_false_text_summary_with_valid_bytes_but_no_packet_link_rejected(self):
        self.assertEqual(self.decide(flow='[E-S0001-F000029-007] Generic RCE only').validated_cve,'Not Found')


if __name__=='__main__':unittest.main()

class PipelineIntegrationTests(unittest.TestCase):
    def test_verified_packet_cve_replaces_not_found_in_consensus_and_report(self):
        import sys
        import types
        from unittest.mock import MagicMock, patch
        sys.modules.setdefault('llm_client', types.SimpleNamespace(get_llm=MagicMock()))
        from mafra_agent_mcp import MAFRAMCPAgent
        from contracts import ConsensusDecision
        seq=tuple(find_verified_cookie_rpc_sequences(packet_records(),1))
        targets=('AnalystAgent','VerifierAgent','ConsensusManager',
                 'MCPOnlineEvidenceSearch','EvidenceFormatter','MCPReporterAgent','MemoryManager')
        patches=[patch('mafra_agent_mcp.'+x) for x in targets]
        for p in patches: p.start()
        try:
            app=MAFRAMCPAgent(memory_mode='disabled',verified_cookie_rpc_sequences=seq)
            app.memory_manager.mode='disabled'
            app.memory_manager.last_retrievals=[]
            app.memory_manager.status.return_value='disabled'
            analyst=AnalystOutput(service=ServiceFinding(primary='CouchDB'))
            app.analyst.analyze.return_value=analyst
            app.analyst.reconsider_with_online_evidence.return_value=analyst
            app.online_search.search.return_value=online()
            app.verifier.verify.return_value=VerifierOutput(
                status='Valid',verification_result='Supported',
                service_supported='Yes',attack_supported='Yes',success_supported='Yes')
            consensus=ConsensusDecision(service='CouchDB',attack='RCE',score=4,max_score=4)
            app.consensus.calculate.return_value=consensus
            app.consensus.format.side_effect=lambda x:x.to_text()
            app.evidence_formatter.format.return_value=type('E',(),{
                'to_prompt_text':lambda self:'packet evidence'})()
            app.reporter.generate.return_value=type('R',(),{
                'status':'Valid','validation_errors':[], 'to_text':lambda self:'report'})()
            report=app.run(FLOW)
            self.assertIn('CVE: CVE-2022-24706',report)
            self.assertIn('CVE Supported: Yes',report)
            self.assertEqual(consensus.score,5)
            self.assertEqual(consensus.max_score,5)
            self.assertEqual(app.reporter.generate.call_args.kwargs['validated_cve'].validated_cve,
                             'CVE-2022-24706')
            self.assertEqual(app.evidence_formatter.format.call_args.kwargs['consensus'].cve,
                             'CVE-2022-24706')
        finally:
            for p in reversed(patches):p.stop()

class FlowSummariserIntegrationTests(unittest.TestCase):
    def test_raw_packet_cookie_proof_is_appended_outside_llm_and_typed(self):
        import importlib.util
        import sys
        import types
        from tempfile import TemporaryDirectory
        from collections import Counter
        from unittest.mock import patch
        fake_prompts=types.ModuleType('langchain_core.prompts')
        fake_prompts.PromptTemplate=object
        fake_root=types.ModuleType('langchain_core')
        fake_client=types.ModuleType('llm_client')
        fake_client.get_llm=lambda *args,**kw:None
        fake_prompt_text=types.ModuleType('prompts')
        fake_prompt_text.FLOW_SUMMARISER_PROMPT=''
        fake_structured=types.ModuleType('structured_output')
        fake_structured.response_text=lambda response:str(response)
        imports={'langchain_core':fake_root,'langchain_core.prompts':fake_prompts,
                 'llm_client':fake_client,'prompts':fake_prompt_text,
                 'structured_output':fake_structured}
        code=Path(__file__).resolve().parents[1]/'flow_summariser.py'
        with patch.dict(sys.modules,imports):
            spec=importlib.util.spec_from_file_location('step5b_flow_module',code)
            module=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        flow=module.FlowSummariser.__new__(module.FlowSummariser)
        flow.extractor=EvidenceExtractor()
        flow.get_connections=lambda _: 'one Erlang distribution conversation'
        flow.get_stream_ids=lambda _:[1]
        flow.get_protocol_counts=lambda _:Counter({'TCP':20})
        flow.get_flow_content=lambda *_: 'untrusted raw flow'
        flow.get_packet_records=lambda *_:packet_records()
        flow.summarise_flow=lambda *_:'LLM omitted cookie discussion.'
        with TemporaryDirectory() as tmp:
            path=Path(tmp)/'case.pcap';path.write_bytes(b'fixture')
            text=flow.run(str(path))
        self.assertIn('LLM omitted cookie discussion.',text)
        self.assertIn('DETERMINISTIC ERLANG DEFAULT-COOKIE AUTHENTICATION',text)
        self.assertIn('E-S0001-F000025-',text)
        self.assertIn('E-S0001-F000027-',text)
        self.assertIn('Verified legacy default cookie both ways',text)
        self.assertEqual(len(flow.verified_cookie_rpc_sequences),1)
        self.assertNotIn('ee5c9e8e',text)
