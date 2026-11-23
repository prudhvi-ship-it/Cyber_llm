import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.modules["llm_client"] = types.SimpleNamespace(get_llm=lambda *a, **kw: None)
sys.modules["structured_output"] = types.SimpleNamespace(invoke_validated=lambda **kw: None)
from contracts import AnalystOutput, VerifierOutput
from agents.verifier_agent import VerifierAgent

ID = 'E-S0001-F000031-005'
SUMMARY = f'''[E-S0001-F000027-001] Client sends Erlang RPC os:cmd(id) to node on TCP 9100.
[{ID}] Server response: Command output observed: uid=0(root) gid=0(root) groups=0(root).'''

def analyst():
    a = AnalystOutput()
    a.attack.type = 'Remote Command Execution'
    a.attack.technique = 'Erlang distribution RPC os:cmd'
    a.attack.success = 'Success'
    a.attack.evidence = [ID]
    return a

def verifier(success, status='Partially Supported', evidence=None):
    return VerifierOutput(verification_result=status, service_supported='Yes',
       attack_supported='Yes', success_supported=success, cve_supported='Not Applicable',
       evidence_check=evidence or [ID],
       unsupported_claims=['No observable command output'] if success == 'Unknown' else [])

class VerifierReviewTests(unittest.TestCase):
    def setup_agent(self):
        with patch('agents.verifier_agent.get_llm', return_value=MagicMock()):
            return VerifierAgent()

    def test_disputed_command_output_requests_second_verification(self):
        obj = self.setup_agent()
        first = verifier('Unknown')
        second = verifier('Yes', 'Supported')
        with patch('agents.verifier_agent.invoke_validated', side_effect=[first, second]) as mock:
            out = obj.verify(SUMMARY, analyst())
        self.assertEqual(mock.call_count, 2)
        self.assertEqual(out.success_supported, 'Yes')
        self.assertIn('disputed', mock.call_args.kwargs['prompt'])

    def test_no_response_output_does_not_trigger_review(self):
        obj = self.setup_agent()
        with patch('agents.verifier_agent.invoke_validated', return_value=verifier('Unknown')) as mock:
            obj.verify('[E-S0001-F000027-001] Client sends os:cmd(id), no reply.', analyst())
        self.assertEqual(mock.call_count, 1)

    def test_fabricated_review_evidence_does_not_upgrade(self):
        obj = self.setup_agent()
        second = verifier('Yes','Supported',['E-S9999-F999999-001'])
        with patch('agents.verifier_agent.invoke_validated', side_effect=[verifier('Unknown'), second]):
            out = obj.verify(SUMMARY, analyst())
        self.assertEqual(out.success_supported, 'Unknown')
        self.assertIn('Verification discrepancy', out.unsupported_claims[-1])

    def test_failed_recheck_preserves_unknown(self):
        obj = self.setup_agent()
        with patch('agents.verifier_agent.invoke_validated', side_effect=[verifier('Unknown'), VerifierOutput.abstain()]):
            out = obj.verify(SUMMARY, analyst())
        self.assertEqual(out.success_supported, 'Unknown')

    def test_real_summary_spaced_root_output_does_not_downgrade_yes(self):
        obj = self.setup_agent()
        real_summary = ("Relevant Events:\n"
            "- [E-S0001-F000031-005] Command output observed: uid=0 (root)\n"
            "Exploit Indicators:\n"
            "- [E-S0001-F000031-006] gid=0\n"
            "Malicious Activities: system command executed and returned output.\n")
        with patch('agents.verifier_agent.invoke_validated', return_value=verifier('Yes','Supported')) as mock:
            result = obj.verify(real_summary, analyst())
        self.assertEqual(result.success_supported, 'Yes')
        self.assertEqual(mock.call_count, 1)

    def test_actual_october_summary_wording_does_not_downgrade_yes(self):
        obj = self.setup_agent()
        real_summary = ("Relevant Events:\n"
            '- [E-S0001-F000031-005] Server response contains "uid=0".\n'
            '- [E-S0001-F000031-006] Server response contains "gid=0".\n')
        with patch('agents.verifier_agent.invoke_validated', return_value=verifier('Yes', 'Supported')) as mock:
            out = obj.verify(real_summary, analyst())
        self.assertEqual(out.success_supported, 'Yes')
        self.assertEqual(mock.call_count, 1)
        self.assertEqual(VerifierAgent._linked_output_ids(real_summary), {
            'E-S0001-F000031-005', 'E-S0001-F000031-006'
        })

    def test_server_returns_command_output_wording(self):
        obj = self.setup_agent()
        real_summary = ('- [E-S0001-F000031-005] Server returns command output '
                        'indicating uid=0 (root).')
        self.assertEqual(VerifierAgent._linked_output_ids(real_summary), {ID})
        with patch('agents.verifier_agent.invoke_validated', return_value=verifier('Yes', 'Supported')):
            self.assertEqual(obj.verify(real_summary, analyst()).success_supported, 'Yes')

    def test_actual_october_summary_unknown_requires_second_review(self):
        obj = self.setup_agent()
        real_summary = '- [E-S0001-F000031-005] Server response contains "uid=0".'
        with patch('agents.verifier_agent.invoke_validated',
                   side_effect=[verifier('Unknown'), verifier('Yes','Supported')]) as mock:
            out = obj.verify(real_summary, analyst())
        self.assertEqual(mock.call_count, 2)
        self.assertEqual(out.success_supported, 'Yes')

    def test_hypothetical_or_negative_output_not_counted(self):
        examples = (
          '- [E-S0001-F000031-005] Server response: no command output observed; expected uid=0.',
          '- [E-S0001-F000031-005] Server response contains no uid=0.',
          '- [E-S0001-F000031-005] Client request contains uid=0; server response unavailable.',
          '- Server response contains uid=0, but there is no packet evidence ID.',
        )
        for s in examples:
            with self.subTest(s=s):
                self.assertEqual(VerifierAgent._linked_output_ids(s), set())

    def test_request_only_spaced_uid_does_not_prove_execution(self):
        obj = self.setup_agent()
        request_summary = ('[E-S0001-F000027-001] Client sends literal command '
            'echo uid=0 (root); no response captured.')
        with patch('agents.verifier_agent.invoke_validated', return_value=verifier('Yes','Supported')):
            result = obj.verify(request_summary, analyst())
        self.assertEqual(result.success_supported, 'Unknown')

    def test_trace_explains_review_result(self):
        obj = self.setup_agent()
        with patch('os.environ', {'FRA_VERIFIER_TRACE':'1'}), \
             patch('builtins.print') as output, \
             patch('agents.verifier_agent.invoke_validated', side_effect=[verifier('Unknown'),verifier('Unknown')]):
            result = obj.verify(SUMMARY, analyst())
        self.assertEqual(result.success_supported,'Unknown')
        messages='\n'.join(str(call.args[0]) for call in output.call_args_list)
        self.assertIn('second_pass=started',messages)
        self.assertIn('second_pass_result=Unknown',messages)
        self.assertIn('accepted=True',messages)

    def test_request_only_uid_does_not_trigger_review(self):
        obj = self.setup_agent()
        summary = f'[E-S0001-F000027-001] Client sent command string echo uid=0(root); server response unavailable'
        with patch('agents.verifier_agent.invoke_validated', return_value=verifier('Unknown')) as mock:
            obj.verify(summary, analyst())
        self.assertEqual(mock.call_count, 1)

if __name__ == '__main__': unittest.main()
