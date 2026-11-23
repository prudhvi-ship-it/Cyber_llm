"""Offline safety/ordering checks for Step 4 pre-analysis memory."""
import sys
import types
from unittest.mock import MagicMock, patch

sys.modules.setdefault('llm_client', types.SimpleNamespace(get_llm=MagicMock()))
import unittest

from contracts import AnalystOutput, AttackFinding, ServiceFinding, VerifierOutput
from agents.analyst_agent import AnalystAgent
from memory_manager import MemoryManager
from mcp_evidence_contracts import OnlineEvidenceResult

FLOW = '[E-S0001-F000029-007] client Erlang os:cmd id request\n[E-S0001-F000031-008] server output uid=0'


class FakeTrainingCollection:
    def __init__(self):
        self.rows = [
            ('current', 'CURRENT PRIVATE ANSWER', {'case_id': 'case_current', 'approved': True, 'split': 'training'}, .01),
            ('eval', 'EVAL LABEL CVE-2022-24706', {'case_id': 'case_eval', 'approved': True, 'split': 'evaluation'}, .02),
            ('unapproved', 'UNAPPROVED CVE ANSWER', {'case_id': 'case_unapproved', 'approved': False, 'split': 'training'}, .04),
            ('unmarked', 'UNMARKED OLD DATA', {'case_id': 'case_old'}, .08),
            ('approved', 'APPROVED DEFENSIVE EXAMPLE', {'case_id': 'case_train', 'approved': True, 'split': 'training'}, .15),
            ('far', 'DISTANT APPROVED EXAMPLE', {'case_id': 'case_far', 'approved': True, 'split': 'training'}, .96),
        ]
    def count(self):
        return len(self.rows)
    def query(self, **kwargs):
        return dict(ids=[[x[0] for x in self.rows]], documents=[[x[1] for x in self.rows]],
                    metadatas=[[x[2] for x in self.rows]], distances=[[x[3] for x in self.rows]])


class Step4MemoryTests(unittest.TestCase):
    def test_approved_only_retrieval_excludes_current_eval_unapproved_far(self):
        manager = MemoryManager(mode='read_only', collection=FakeTrainingCollection(),
                                current_case_id='case_current', audit_path='')
        context = manager.retrieve(FLOW, require_approved_training=True)
        self.assertIn('APPROVED DEFENSIVE EXAMPLE', context)
        for forbidden in ('CURRENT PRIVATE ANSWER', 'EVAL LABEL', 'UNAPPROVED CVE',
                          'UNMARKED OLD', 'DISTANT APPROVED'):
            self.assertNotIn(forbidden, context)
        self.assertEqual(manager.last_retrievals, [{'source_id': 'approved', 'distance': 0.15}])

    def test_legacy_retrieval_without_filter_keeps_existing_behavior(self):
        manager = MemoryManager(mode='isolated', collection=FakeTrainingCollection(),
                                current_case_id='case_current', audit_path='')
        context = manager.retrieve(FLOW)
        self.assertIn('EVAL LABEL', context)  # legacy semantics unchanged

    def test_disabled_mode_cannot_load_any_memory(self):
        manager = MemoryManager(mode='disabled', collection=FakeTrainingCollection(), audit_path='')
        self.assertEqual(manager.retrieve(FLOW, require_approved_training=True),
                         'RAG memory disabled for this run.')
        self.assertEqual(manager.last_retrievals, [])

    def test_analyst_prompt_explicitly_demotes_past_cases_to_leads(self):
        with patch('agents.analyst_agent.get_llm', return_value=object()), \
             patch('agents.analyst_agent.invoke_validated', return_value=AnalystOutput()) as invoke:
            agent = AnalystAgent()
            agent.analyze(FLOW, past_case_context='A PAST CASE CVE-2020-1234')
        prompt = invoke.call_args.kwargs['prompt']
        self.assertIn('A PAST CASE CVE-2020-1234', prompt)
        self.assertIn('current flow summary is the only primary evidence', prompt)
        self.assertIn(FLOW, prompt)

    def test_memory_fabricated_packet_id_causes_safe_retry_without_memory(self):
        wrong = AnalystOutput(attack=AttackFinding(evidence=['E-S0001-F999999-001']))
        correct = AnalystOutput(attack=AttackFinding(evidence=['E-S0001-F000029-007']))
        with patch('agents.analyst_agent.get_llm', return_value=object()), \
             patch('agents.analyst_agent.invoke_validated', side_effect=[wrong, correct]) as invoke:
            out = AnalystAgent().analyze(FLOW, past_case_context='PAST CASE')
        self.assertIs(out, correct)
        self.assertEqual(invoke.call_count, 2)
        self.assertIn('PAST CASE', invoke.call_args_list[0].kwargs['prompt'])
        self.assertNotIn('PAST CASE', invoke.call_args_list[1].kwargs['prompt'])

    def test_memory_success_without_current_evidence_causes_safe_retry(self):
        unsupported = AnalystOutput(attack=AttackFinding(success='Success', evidence=[]))
        safe = AnalystOutput(attack=AttackFinding(success='Unknown', evidence=[]))
        with patch('agents.analyst_agent.get_llm', return_value=object()), \
             patch('agents.analyst_agent.invoke_validated', side_effect=[unsupported, safe]) as invoke:
            out = AnalystAgent().analyze(FLOW, past_case_context='PAST CASE')
        self.assertIs(out, safe)
        self.assertEqual(invoke.call_count, 2)

    def test_reconsideration_receives_memory_and_still_checks_evidence_ids(self):
        revised = AnalystOutput(attack=AttackFinding(evidence=['E-S0001-F999999-001']))
        initial = AnalystOutput()
        online = OnlineEvidenceResult(status='Valid', query='example',
            retrieved_at_utc='2026-10-14T00:00:00Z', sources=[
                __import__('mcp_evidence_contracts').ExternalEvidenceSource(
                    title='Vendor', url='https://example.org', snippet='example',
                    retrieved_at_utc='2026-10-14T00:00:00Z')])
        with patch('agents.analyst_agent.get_llm', return_value=object()), \
             patch('agents.analyst_agent.invoke_validated', return_value=revised) as invoke:
            out = AnalystAgent().reconsider_with_online_evidence(FLOW, initial, online, past_case_context='PAST CASE')
        self.assertIs(out, initial)
        self.assertIn('PAST CASE', invoke.call_args.kwargs['prompt'])

    def _pipeline(self, mode):
        from mafra_agent_mcp import MAFRAMCPAgent
        calls=[]
        orig = AnalystOutput(service=ServiceFinding(primary='CouchDB'))
        revised = AnalystOutput(service=ServiceFinding(primary='CouchDB'), attack=AttackFinding(type='RCE'))
        online = OnlineEvidenceResult(status='Abstain', query='CouchDB', retrieved_at_utc='2026-10-14T00:00:00Z')
        patches = [patch('mafra_agent_mcp.' + key) for key in (
            'AnalystAgent', 'VerifierAgent', 'ConsensusManager', 'MCPOnlineEvidenceSearch',
            'EvidenceFormatter', 'MCPReporterAgent', 'MemoryManager', 'derive_online_cve_validation')]
        for p in patches: p.start()
        try:
            app = MAFRAMCPAgent()
            app.memory_manager.mode=mode
            app.memory_manager.last_retrievals=[]
            app.memory_manager.status.return_value=mode
            def retrieve(*args, **kwargs):
                calls.append(('retrieve', kwargs))
                if kwargs.get('require_approved_training'):
                    app.memory_manager.last_retrievals=[{'source_id': 'approved', 'distance': 0.1}]
                    return 'APPROVED TRAINING REFERENCE'
                return 'report-only context'
            app.memory_manager.retrieve.side_effect=retrieve
            app.analyst.analyze.side_effect=lambda *a, **k: (calls.append(('initial', k)) or orig)
            app.online_search.search.side_effect=lambda **k: (calls.append(('search', {})) or online)
            app.analyst.reconsider_with_online_evidence.side_effect=lambda *a, **k: (calls.append(('revise', k)) or revised)
            app.verifier.verify.side_effect=lambda *a: (calls.append(('verify', {})) or VerifierOutput())
            app.consensus.calculate.return_value=MagicMock()
            app.consensus.format.return_value='consensus'
            app.reporter.generate.return_value=type('Report', (), {
                'status': 'Valid', 'to_text': lambda self: 'report', 'validation_errors': []})()
            app.evidence_formatter.format.return_value=type('Evidence', (), {
                'to_prompt_text': lambda self: 'evidence'})()
            app.run(FLOW)
            return calls, app.reporter.generate.call_args.kwargs['rag_context'], app.memory_manager.retrieve.call_count
        finally:
            for p in reversed(patches): p.stop()

    def test_read_only_retrieval_precedes_initial_and_reused_for_report(self):
        calls, report_context, count = self._pipeline('read_only')
        self.assertEqual([x[0] for x in calls], ['retrieve', 'initial', 'search', 'revise', 'verify'])
        self.assertEqual(calls[0][1], {'require_approved_training': True})
        self.assertEqual(calls[1][1], {'past_case_context': 'APPROVED TRAINING REFERENCE'})
        self.assertEqual(calls[3][1], {'past_case_context': 'APPROVED TRAINING REFERENCE'})
        self.assertEqual(report_context, 'APPROVED TRAINING REFERENCE')
        self.assertEqual(count, 1)

    def test_disabled_mode_leaves_both_analyst_calls_unchanged(self):
        calls, report_context, count = self._pipeline('disabled')
        self.assertEqual([x[0] for x in calls], ['initial', 'search', 'revise', 'verify', 'retrieve'])
        self.assertEqual(calls[0][1], {})
        self.assertEqual(calls[2][1], {})
        self.assertEqual(count, 1)

    def test_isolated_mode_keeps_memory_report_only(self):
        calls, report_context, count = self._pipeline('isolated')
        self.assertEqual([x[0] for x in calls], ['initial', 'search', 'revise', 'verify', 'retrieve'])
        self.assertEqual(calls[0][1], {})
        self.assertEqual(report_context, 'report-only context')
        self.assertEqual(count, 1)

if __name__ == '__main__': unittest.main()
