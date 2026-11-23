"""Step 4B: offline controls for a run-local, opt-in investigation notebook."""
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

sys.modules.setdefault('llm_client', types.SimpleNamespace(get_llm=MagicMock()))

from contracts import AnalystOutput, AttackFinding, ServiceFinding, VerifierOutput
from investigation_notebook import InvestigationNotebook
from mcp_evidence_contracts import OnlineEvidenceResult

FLOW = '''[E-S0001-F000029-007] Erlang RPC request os:cmd('id') paired with reply frame 31
[E-S0001-F000031-008] Server response contains command output uid=0(root)
[E-S0001-F000031-005] Server response contains uid=0
Untrusted external: E-S9999-F999999-999 is not a packet observation'''


class NotebookUnitTests(unittest.TestCase):
    def test_observations_evidence_linked_and_sorted(self):
        note = InvestigationNotebook('case_one', FLOW)
        text = note.context()
        self.assertIn('E-S0001-F000029-007', text)
        self.assertIn('E-S0001-F000031-008', text)
        self.assertNotIn('E-S9999-F999999-999', text)
        self.assertIn('not independently decoded', text)

    def test_stage_claim_does_not_create_primary_evidence(self):
        note = InvestigationNotebook('case_one', FLOW)
        out = AnalystOutput(service=ServiceFinding(primary='CouchDB'),
                            attack=AttackFinding(type='RCE', success='Success',
                                 evidence=['E-S9999-F999999-999', 'E-S0001-F000029-007']))
        note.note_analyst('INITIAL ANALYST', out)
        text = note.context()
        self.assertIn('HYPOTHESIS (not verified)', text)
        self.assertNotIn('E-S9999-F999999-999', text)
        self.assertIn('E-S0001-F000029-007', text)

    def test_external_cve_leads_are_not_claimed_as_pcap(self):
        note = InvestigationNotebook('case_one', FLOW)
        note.note_research(OnlineEvidenceResult(status='Valid', query='query',
                                                retrieved_at_utc='2026-10-14T00:00:00Z'))
        self.assertIn('EXTERNAL RESEARCH LEADS (not PCAP evidence)', note.context())

    def test_separate_instances_do_not_leak(self):
        case1 = InvestigationNotebook('one', FLOW)
        case1.note_analyst('INITIAL ANALYST', AnalystOutput(service=ServiceFinding(primary='CouchDB')))
        case2 = InvestigationNotebook('two', '[E-S0002-F000009-001] HTTP GET /')
        self.assertNotIn('CouchDB', case2.context())
        self.assertNotIn('E-S0001-F000031-008', case2.context())

    def test_redacts_basic_secrets_in_observations(self):
        n = InvestigationNotebook('one', '[E-S0001-F000012-001] Cookie: secret123 Bearer abcdefg')
        text = n.context()
        self.assertNotIn('secret123', text)
        self.assertNotIn('abcdefg', text)


class NotebookPipelineTests(unittest.TestCase):
    def _run_pipeline(self, mode, memory_mode='disabled'):
        from mafra_agent_mcp import MAFRAMCPAgent
        initial = AnalystOutput(service=ServiceFinding(primary='CouchDB'),
                                attack=AttackFinding(type='RCE', success='Success',
                                    evidence=['E-S0001-F000029-007']))
        revised = AnalystOutput(service=ServiceFinding(primary='CouchDB'),
                                attack=AttackFinding(type='RCE', success='Success',
                                    evidence=['E-S0001-F000031-008']))
        verifier = VerifierOutput(success_supported='Yes')
        online = OnlineEvidenceResult(status='Abstain', query='CouchDB',
                                     retrieved_at_utc='2026-10-14T00:00:00Z')
        patches = [patch('mafra_agent_mcp.'+key) for key in (
            'AnalystAgent', 'VerifierAgent', 'ConsensusManager', 'MCPOnlineEvidenceSearch',
            'EvidenceFormatter', 'MCPReporterAgent', 'MemoryManager', 'derive_online_cve_validation')]
        for p in patches: p.start()
        try:
            app = MAFRAMCPAgent(current_case_id='case_one', investigation_notebook=mode,
                                memory_mode=memory_mode)
            app.memory_manager.mode = memory_mode
            app.memory_manager.last_retrievals = []
            app.memory_manager.status.return_value = memory_mode
            app.memory_manager.retrieve.return_value = 'RAG memory disabled for this run.'
            app.analyst.analyze.return_value = initial
            app.analyst.reconsider_with_online_evidence.return_value = revised
            app.verifier.verify.return_value = verifier
            app.online_search.search.return_value = online
            app.consensus.calculate.return_value = MagicMock()
            app.consensus.format.return_value = 'consensus'
            app.reporter.generate.return_value = type('Report', (), {
                'status':'Valid', 'validation_errors': [], 'to_text':lambda self:'report'})()
            app.evidence_formatter.format.return_value = type('Evidence', (), {'to_prompt_text':lambda self:'evidence'})()
            result = app.run(FLOW)
            revision_kwargs = app.analyst.reconsider_with_online_evidence.call_args.kwargs
            verifier_kwargs = app.verifier.verify.call_args.kwargs
            reporter_kwargs = app.reporter.generate.call_args.kwargs
            memory_calls = app.memory_manager.retrieve.call_count
            return app, result, revision_kwargs, verifier_kwargs, reporter_kwargs, memory_calls
        finally:
            for p in reversed(patches): p.stop()

    def test_enabled_notes_feed_revision_verifier_report_only(self):
        app, result, revision, verify, report, memory_calls = self._run_pipeline('enabled')
        self.assertIsNotNone(app.last_notebook)
        self.assertEqual(memory_calls, 1) # unchanged disabled-mode Chroma behavior
        self.assertIn('INITIAL ANALYST HYPOTHESIS', revision['investigation_notes'])
        self.assertIn('EXTERNAL RESEARCH LEADS', revision['investigation_notes'])
        self.assertIn('REVISED ANALYST HYPOTHESIS', verify['investigation_notes'])
        self.assertIn('VERIFIER DECISION', report['investigation_notes'])
        self.assertIn('SINGLE-CASE INVESTIGATION NOTEBOOK', result)
        self.assertIn('E-S0001-F000031-008', result)

    def test_default_disabled_does_not_change_agent_signatures_or_outputs(self):
        app, result, revision, verify, report, memory_calls = self._run_pipeline('disabled')
        self.assertIsNone(app.last_notebook)
        self.assertNotIn('investigation_notes', revision)
        self.assertNotIn('investigation_notes', verify)
        self.assertNotIn('investigation_notes', report)
        self.assertNotIn('SINGLE-CASE INVESTIGATION NOTEBOOK', result)
        self.assertEqual(memory_calls, 1)

    def test_invalid_mode_is_rejected(self):
        from mafra_agent_mcp import MAFRAMCPAgent
        with self.assertRaises(ValueError):
            MAFRAMCPAgent(investigation_notebook='bad')


if __name__ == '__main__': unittest.main()
