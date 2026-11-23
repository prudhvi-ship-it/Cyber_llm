"""Regression checks for fail-claim verification: no network or paid LLM calls."""
import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Load this single implementation in isolation. Existing project tests and
# real API clients are neither imported nor mutated by this offline test.
fake_llm_client = types.ModuleType('llm_client')
fake_llm_client.get_llm = lambda role: object()
fake_structured = types.ModuleType('structured_output')
fake_structured.invoke_validated = lambda **kwargs: None
spec = importlib.util.spec_from_file_location(
    '_accuracy_verifier_under_test', ROOT / 'agents' / 'verifier_agent.py'
)
module = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {
    'llm_client': fake_llm_client,
    'structured_output': fake_structured,
}):
    spec.loader.exec_module(module)

from contracts import AnalystOutput, VerifierOutput
VerifierAgent = module.VerifierAgent

REQUEST = 'E-S0001-F000006-001'
REJECT = 'E-S0001-F000008-002'
OTHER = 'E-S9999-F000001-001'
FLOW = f'''DETERMINISTIC PACKET-LINKED ATTACK INDICATORS:
- [{REQUEST} | client->server] POST /api/v1/validate/code
- [{REJECT} | server->client] HTTP Status 403
'''


def analyst(outcome='Fail'):
    return AnalystOutput(attack={
        'type': 'Remote Code Execution',
        'technique': 'RCE attempt against code validation endpoint',
        'success': outcome,
        'evidence': [REQUEST],
    })


def verifier(support='Unknown', checked=None, attack='Yes'):
    return VerifierOutput(
        verification_result='Partially Supported',
        service_supported='Yes',
        attack_supported=attack,
        success_supported=support,
        evidence_check=checked or [REQUEST],
    )


class AccuracyVerifierTests(unittest.TestCase):
    def setUp(self):
        self.agent=VerifierAgent()

    def test_supported_fail_survives_missing_command_output(self):
        with patch.object(module, 'invoke_validated',return_value=verifier('Yes')) as p:
            got=self.agent.verify(FLOW,analyst())
            self.assertEqual(got.success_supported,'Yes')
            self.assertEqual(p.call_count,1)

    def test_failure_403_can_trigger_grounded_second_review(self):
        first=verifier('Unknown')
        second=verifier('Yes', [REQUEST, REJECT])
        with patch.object(module, 'invoke_validated',side_effect=[first,second]) as p:
            got=self.agent.verify(FLOW,analyst())
            self.assertIs(got,second)
            self.assertEqual(p.call_count,2)

    def test_second_review_cannot_upgrade_using_fabricated_ids(self):
        first=verifier('Unknown')
        second=verifier('Yes',[OTHER])
        with patch.object(module, 'invoke_validated',side_effect=[first,second]):
            got=self.agent.verify(FLOW,analyst())
            self.assertIs(got,first)
            self.assertEqual(got.success_supported,'Unknown')

    def test_second_review_cannot_upgrade_using_request_id_only(self):
        first=verifier('Unknown')
        second=verifier('Yes',[REQUEST])
        with patch.object(module, 'invoke_validated',side_effect=[first,second]):
            got=self.agent.verify(FLOW,analyst())
            self.assertIs(got,first)
            self.assertEqual(got.success_supported,'Unknown')

    def test_attacker_request_status_text_does_not_count_as_response(self):
        only_request=f'- [{REQUEST} | client->server] body says HTTP Status 403'
        with patch.object(module, 'invoke_validated',return_value=verifier('Unknown')) as p:
            got=self.agent.verify(only_request,analyst())
            self.assertEqual(got.success_supported,'Unknown')
            self.assertEqual(p.call_count,1)

    def test_no_rejection_does_not_force_second_review(self):
        only_request=f'- [{REQUEST} | client->server] POST /api/v1/validate/code'
        with patch.object(module, 'invoke_validated',return_value=verifier('Unknown')) as p:
            got=self.agent.verify(only_request,analyst())
            self.assertEqual(got.success_supported,'Unknown')
            self.assertEqual(p.call_count,1)

    def test_success_guard_remains_active(self):
        no_output=f'- [{REQUEST} | client->server] command execution payload'
        with patch.object(module, 'invoke_validated',return_value=verifier('Yes')) as p:
            got=self.agent.verify(no_output,analyst('Success'))
            self.assertEqual(got.success_supported,'Unknown')
            self.assertEqual(p.call_count,1)

    def test_server_response_is_not_benign_http_201_signal(self):
        benign=f'- [{REQUEST} | client->server] PUT /check.txt\n- [{REJECT} | server->client] HTTP Status 201'
        self.assertFalse(self.agent._linked_rejection_ids(benign))

    def test_rejection_ids_are_directional(self):
        self.assertEqual(self.agent._linked_rejection_ids(FLOW),{REJECT})

    def test_login_redirect_is_review_signal_not_a_verdict(self):
        login=f'- [{REJECT} | server->client] Location: /login'
        self.assertEqual(self.agent._linked_rejection_ids(login), {REJECT})

    def test_mismatched_tcp_streams_cannot_upgrade(self):
        first=verifier('Unknown')
        second=verifier('Yes',[REQUEST, 'E-S0002-F000008-002'])
        other=f'- [E-S0002-F000008-002 | server->client] HTTP Status 403'
        with patch.object(module, 'invoke_validated', side_effect=[first, second]):
            got=self.agent.verify(FLOW.splitlines()[0]+'\n'+FLOW.splitlines()[1]+'\n'+other, analyst())
            self.assertIs(got,first)

    def test_cannot_upgrade_when_response_not_cited(self):
        first=verifier('Unknown')
        second=verifier('Yes',[REQUEST,OTHER])
        with patch.object(module, 'invoke_validated',side_effect=[first,second]):
            self.assertIs(self.agent.verify(FLOW,analyst()),first)

if __name__=='__main__': unittest.main(verbosity=2)
