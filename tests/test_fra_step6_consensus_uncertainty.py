"""Step 6: deterministic, offline tri-state MAFRA outcome regression tests."""
import unittest

from agents.consensus import ConsensusManager
from contracts import (
    AnalystOutput, AttackOutcome, ConsensusDecision, CVEValidationOutput,
    FinalReport, VerifierOutput,
)
from decision_enforcement import enforce_fra_report, enforce_mafra_report

E = 'E-S0001-F000018-007'
FLOW = f'- [{E} | server->client] HTTP 307 Location: /login'


class MAFRAOutcomeUncertaintyTests(unittest.TestCase):
    def analyst(self, outcome='Unknown', evidence=True, attack='Authorization bypass',
                status='Valid', cve='CVE-2025-29927'):
        return AnalystOutput(status=status,
                             service={'primary': 'Next.js'},
                             attack={'type': attack, 'technique': 'HTTP bypass',
                                     'success': outcome,
                                     'evidence': [E] if evidence else []},
                             cve={'candidate': cve})

    def verifier(self, success_support='Yes', attack_support='Yes',
                 verification='Supported', status='Valid', cve='Unknown'):
        return VerifierOutput(status=status, verification_result=verification,
                              service_supported='Yes', attack_supported=attack_support,
                              success_supported=success_support, cve_supported=cve)

    def consensus(self, analyst, verifier):
        return ConsensusManager().calculate(analyst, verifier)

    def test_success_remains_success_when_supported(self):
        self.assertEqual(self.consensus(self.analyst('Success'), self.verifier()).attack_success, 'Success')

    def test_fail_remains_fail_when_supported(self):
        self.assertEqual(self.consensus(self.analyst('Fail'), self.verifier()).attack_success, 'Fail')

    def test_cve_unknown_does_not_erase_observed_success_or_fail(self):
        for outcome in ('Success', 'Fail'):
            with self.subTest(outcome=outcome):
                v = self.verifier(verification='Partially Supported', cve='Unknown')
                self.assertEqual(self.consensus(self.analyst(outcome), v).attack_success, outcome)

    def test_analyst_unknown_stays_unknown_even_if_verifier_says_yes(self):
        self.assertEqual(self.consensus(self.analyst(), self.verifier()).attack_success, 'Unknown')

    def test_unverified_failed_attempt_stays_unknown(self):
        self.assertEqual(self.consensus(self.analyst('Fail'), self.verifier(success_support='Unknown')).attack_success, 'Unknown')

    def test_unverified_success_stays_unknown(self):
        self.assertEqual(self.consensus(self.analyst('Success'), self.verifier(success_support='Unknown')).attack_success, 'Unknown')

    def test_explicitly_rejected_claim_does_not_become_fail(self):
        self.assertEqual(self.consensus(self.analyst('Success'), self.verifier(success_support='No')).attack_success, 'Unknown')

    def test_unverified_attack_does_not_become_fail(self):
        self.assertEqual(self.consensus(self.analyst('Fail'), self.verifier(attack_support='Unknown')).attack_success, 'Unknown')

    def test_unsupported_or_abstain_verifier_cannot_finalize_outcome(self):
        for status, verification in [('Abstain', 'Unknown'), ('Valid', 'Unsupported'), ('Valid', 'Unknown')]:
            with self.subTest(status=status, verification=verification):
                v = self.verifier(verification=verification, status=status)
                self.assertEqual(self.consensus(self.analyst('Fail'), v).attack_success, 'Unknown')

    def test_missing_packet_reference_does_not_finalize_fail(self):
        self.assertEqual(self.consensus(self.analyst('Fail', evidence=False), self.verifier()).attack_success, 'Unknown')

    def test_unknown_attack_type_cannot_be_classified_failed(self):
        a = self.analyst('Fail', attack='Unknown')
        a.attack.technique = 'Unknown'
        self.assertEqual(self.consensus(a, self.verifier()).attack_success, 'Unknown')

    def test_invalid_analyst_cannot_finalize_fail(self):
        self.assertEqual(self.consensus(self.analyst('Fail', status='Abstain'), self.verifier()).attack_success, 'Unknown')

    def test_final_report_preserves_unknown_without_leaking_to_fra(self):
        a, v = self.analyst(), self.verifier()
        c = self.consensus(a, v)
        r = enforce_mafra_report(FinalReport(), a, v, CVEValidationOutput(), c, FLOW)
        self.assertEqual(r.attack, AttackOutcome.ABSTAIN.value)
        self.assertIn('Attack: Unknown', r.to_text())
        self.assertIn('Consensus attack outcome: Unknown.', r.verification_summary)
        self.assertIn('Identified CVE: Not Found', r.to_text())
        self.assertIn('Associated CVE candidate (Analyst): CVE-2025-29927', r.to_text())
        self.assertIn('Verifier support for exact CVE: Unknown', r.to_text())
        self.assertIn('Is Service Vulnerable: Unknown', r.to_text())
        self.assertEqual(FinalReport(attack='Unknown').to_text().split('Attack: ')[1].splitlines()[0], 'Failed')

    def test_mafra_success_and_fail_stay_unchanged_in_report(self):
        for outcome, label in [('Success', 'Successful'), ('Fail', 'Failed')]:
            with self.subTest(outcome=outcome):
                a,v=self.analyst(outcome),self.verifier(verification='Partially Supported')
                c=self.consensus(a,v)
                r=enforce_mafra_report(FinalReport(),a,v,CVEValidationOutput(),c,FLOW)
                self.assertIn(f'Attack: {label}',r.to_text())
                self.assertEqual(r.attack,outcome)

    def test_no_consensus_fallback_keeps_existing_behavior(self):
        a,v=self.analyst('Success'),self.verifier()
        r=enforce_mafra_report(FinalReport(),a,v,CVEValidationOutput(),None,FLOW)
        self.assertEqual(r.attack,'Success')
        self.assertIn('Attack: Successful',r.to_text())

    def test_mcp_context_and_cve_decisions_not_recomputed(self):
        a,v=self.analyst('Unknown'),self.verifier(cve='No')
        c=self.consensus(a,v)
        self.assertEqual(c.cve,'CVE-2025-29927')
        self.assertEqual(c.cve_supported,'No')
        self.assertEqual(c.attack_success,'Unknown')

    def test_report_reader_and_labels_treat_unknown_as_abstention(self):
        from evaluation.report_reader import parse_report_text
        from evaluation.labels import parse_binary_label
        a,v=self.analyst(),self.verifier()
        c=self.consensus(a,v)
        r=enforce_mafra_report(FinalReport(),a,v,CVEValidationOutput(),c,FLOW)
        parsed=parse_report_text(r.to_text())
        self.assertEqual(parsed['attack_success'],'Unknown')
        self.assertIsNone(parse_binary_label(parsed['attack_success'], 'success'))

if __name__ == '__main__':
    unittest.main()
