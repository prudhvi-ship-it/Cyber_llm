"""Regression tests for pairing Erlang RPC request and server reply by packet."""
import ipaddress
import struct
import unittest
from pathlib import Path

from evidence_extractor import EvidenceExtractor, PacketRecord
from erlang_rpc_evidence import find_erlang_id_rpc_pairs

REQ = (b'\x00\x00\x00fp\x83h\x04a\x06gw\x0eAAAAAAAAAAAAAA'
       b'\x00\x00\x00\x03\x00\x00\x00\x00\x00w\x00w\x03rex\x83h\x02'
       b'gw\x0eAAAAAAAAAAAAAA\x00\x00\x00\x03\x00\x00\x00\x00\x00'
       b'h\x05w\x04callw\x02osw\x03cmdl\x00\x00\x00\x01k\x00\x02idjw\x04user')
OUT = b'uid=0(root) gid=0(root) groups=0(root)\n'
REPLY = b'\x00\x00\x00Wp\x83h\x03a\x02w\x00Xw\x0eAAAAAAAAAAAAAA\x00\x00\x00\x03\x00\x00\x00\x00\x00\x83h\x02w\x03rexk' + len(OUT).to_bytes(2, 'big') + OUT


def pkt(number, payload, direction, source=None, destination=None, epoch=1.0):
    src = source or ('172.18.0.1:58612' if direction == 'client->server' else '172.18.0.2:9100')
    dst = destination or ('172.18.0.2:9100' if direction == 'client->server' else '172.18.0.1:58612')
    return PacketRecord(frame_number=number,timestamp_epoch=epoch,
                        source=src,destination=dst,direction=direction,
                        protocol='TCP',payload=payload.decode('utf-8','replace'),
                        payload_bytes=len(payload))


class ErlangRPCPairTests(unittest.TestCase):
    def test_exact_request_response_has_two_evidence_ids(self):
        packets = [pkt(29,REQ,'client->server',epoch=1),pkt(31,REPLY,'server->client',epoch=1.01)]
        pairs = find_erlang_id_rpc_pairs(packets)
        self.assertEqual([(p.request_frame,p.reply_frame) for p in pairs], [(29,31)])
        evidence = EvidenceExtractor().extract(stream_id=1, packets=packets)
        cmd = evidence['command']
        self.assertTrue(any(e.evidence_id.startswith('E-S0001-F000029-') and "os:cmd('id')" in e.observation for e in cmd))
        self.assertTrue(any(e.evidence_id.startswith('E-S0001-F000031-') and 'paired with client' in e.observation and 'uid=0(root)' in e.observation for e in cmd))
        self.assertTrue(any('server response frame 31' in e.observation for e in cmd))

    def test_response_only_never_proves_execution(self):
        self.assertEqual(find_erlang_id_rpc_pairs([pkt(31,REPLY,'server->client')]), [])

    def test_request_only_never_proves_execution(self):
        self.assertEqual(find_erlang_id_rpc_pairs([pkt(29,REQ,'client->server')]), [])

    def test_wrong_endpoint_not_matched(self):
        req=pkt(29,REQ,'client->server',epoch=1)
        reply=pkt(31,REPLY,'server->client',source='172.18.0.9:9100',epoch=1.01)
        self.assertEqual(find_erlang_id_rpc_pairs([req,reply]), [])

    def test_wrong_order_and_delay_not_matched(self):
        self.assertEqual(find_erlang_id_rpc_pairs([pkt(31,REPLY,'server->client',epoch=1),pkt(29,REQ,'client->server',epoch=2)]), [])
        self.assertEqual(find_erlang_id_rpc_pairs([pkt(29,REQ,'client->server',epoch=1),pkt(31,REPLY,'server->client',epoch=50)]), [])

    def test_words_in_http_or_comment_are_not_erlang_rpc(self):
        fake=b'GET /?q=call+os+cmd+id HTTP/1.1\r\nHost: example.org\r\n\r\n'
        self.assertEqual(find_erlang_id_rpc_pairs([pkt(29,fake,'client->server'),pkt(31,REPLY,'server->client',epoch=1.01)]), [])

    def test_reply_without_rex_etf_tags_is_not_proof(self):
        fake=b'HTTP/1.1 200 OK\r\n\r\n'+OUT
        self.assertEqual(find_erlang_id_rpc_pairs([pkt(29,REQ,'client->server'),pkt(31,fake,'server->client',epoch=1.01)]), [])

    def test_original_couchdb_pcap_packets_29_and_31(self):
        """Use original PCAP fixture; parse Ethernet/IP/TCP without Wireshark dependency."""
        path = Path(__file__).resolve().parents[1]/'MAFRA_Eval30/pcaps/CFA_event0_CVE-2022-24706.pcap'
        if not path.is_file():
            self.skipTest('CouchDB PCAP fixture not installed')
        data=path.read_bytes()
        self.assertEqual(data[:4],b'\xd4\xc3\xb2\xa1')
        offset=24; frame=0; records=[]
        while offset+16<=len(data):
            sec,usec,n,_=struct.unpack('<IIII',data[offset:offset+16]);offset+=16
            raw=data[offset:offset+n];offset+=n;frame+=1
            if len(raw)<54 or raw[12:14]!=b'\x08\x00':continue
            ip=raw[14:];ip_len=(ip[0]&15)*4
            if ip[9]!=6:continue
            tcp=ip[ip_len:];src_port,dst_port=struct.unpack('!HH',tcp[:4]);
            if 9100 not in (src_port,dst_port):continue
            payload=tcp[(tcp[12]>>4)*4:]
            if not payload:continue
            src=f'{ipaddress.IPv4Address(ip[12:16])}:{src_port}'
            dst=f'{ipaddress.IPv4Address(ip[16:20])}:{dst_port}'
            direction='client->server' if dst_port==9100 else 'server->client'
            records.append(pkt(frame,payload,direction,source=src,destination=dst,epoch=sec+usec/1e6))
        matches=find_erlang_id_rpc_pairs(records)
        self.assertEqual([(pair.request_frame,pair.reply_frame) for pair in matches],[(29,31)])
        self.assertEqual(matches[0].observed_output,'uid=0(root) gid=0(root)')


if __name__=='__main__': unittest.main()

class FlowSummaryIntegrationTests(unittest.TestCase):
    def test_packet_pair_appended_outside_generated_llm_summary(self):
        """Avoid dependencies unavailable in bare test runners with import stubs."""
        import importlib.util
        import sys
        import types
        from tempfile import TemporaryDirectory
        from unittest.mock import patch
        from collections import Counter

        fake_prompts=types.ModuleType('langchain_core.prompts')
        fake_prompts.PromptTemplate=object
        fake_root=types.ModuleType('langchain_core')
        fake_client=types.ModuleType('llm_client')
        fake_client.get_llm=lambda *a,**kw: None
        fake_project_prompts=types.ModuleType('prompts')
        fake_project_prompts.FLOW_SUMMARISER_PROMPT=''
        fake_structured=types.ModuleType('structured_output')
        fake_structured.response_text=lambda response: str(response)
        mapping={'langchain_core':fake_root, 'langchain_core.prompts':fake_prompts,
                 'llm_client':fake_client, 'prompts':fake_project_prompts,
                 'structured_output':fake_structured}
        source=Path(__file__).resolve().parents[1]/'flow_summariser.py'
        with patch.dict(sys.modules,mapping):
            spec=importlib.util.spec_from_file_location('test_flow_summariser_rpc',source)
            module=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        flow=module.FlowSummariser.__new__(module.FlowSummariser)
        flow.extractor=EvidenceExtractor()
        flow.get_connections=lambda path:'TCP conversation'
        flow.get_stream_ids=lambda path:[1]
        flow.get_protocol_counts=lambda path:Counter({'TCP':2})
        flow.get_flow_content=lambda path,stream:'UNTRUSTED FLOW CONTENT'
        flow.get_packet_records=lambda path,stream:[pkt(29,REQ,'client->server',epoch=1),pkt(31,REPLY,'server->client',epoch=1.01)]
        flow.summarise_flow=lambda content,stream,packets:'LLM did not report RPC pairing.'
        with TemporaryDirectory() as td:
            path=Path(td)/'fixture.pcap';path.write_bytes(b'test')
            result=flow.run(str(path))
        self.assertIn('LLM did not report RPC pairing.',result)
        self.assertIn('DETERMINISTIC ERLANG RPC CORRELATION FROM RAW PACKETS',result)
        self.assertIn('E-S0001-F000029-',result)
        self.assertIn('E-S0001-F000031-',result)
        self.assertIn('os:cmd(\'id\')',result)
        self.assertIn('uid=0(root) gid=0(root)',result)
        self.assertIn('authorization and exact CVE are NOT established',result)
