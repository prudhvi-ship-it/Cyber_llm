"""Offline contract tests for disclosure of Analyst CVE vs Verifier support.

No LLM calls, PCAP processing, network access, or filesystem writes.
"""
import unittest
from contracts import (
    AnalystOutput, AttackOutcome, CVEValidationOutput, Decision, FinalReport,
    VerifierOutput, ConsensusDecision, NOT_FOUND,
)
from decision_enforcement import enforce_mafra_report, enforce_fra_report

PACKET = 'E-S0001-F000018-010'
FLOW = f'- [{PACKET} | server->client] Server response X-Powered-By: Next.js.\n'


class CVEReportingTests(unittest.TestCase):
    @staticmethod
    def inputs(verifier_support='Unknown', confirmed=False, outcome='Fail', candidate='CVE-2025-29927'):
        analyst = AnalystOutput.model_validate({
            'service': {'primary': 'Next.js' if outcome == 'Success' else 'HTTP web application'},
            'attack': {'type': 'Authentication bypass', 'success': outcome,
                       'evidence': [PACKET]},
            'cve': {'candidate': candidate, 'reason': 'Mechanism aligns with external CVE research'},
        })
        verifier = VerifierOutput.model_validate({
            'verification_result': 'Supported' if confirmed else 'Partially Supported',
            'service_supported': 'Yes', 'attack_supported': 'Yes',
            'success_supported': 'Yes', 'cve_supported': verifier_support,
        })
        consensus = ConsensusDecision.model_validate({
            'attack_success': outcome,
            'cve': candidate, 'cve_supported': verifier_support,
        })
        validated = CVEValidationOutput.model_validate({
            'validated_cve': candidate if confirmed else NOT_FOUND,
            'cve_supported': 'Yes' if confirmed else verifier_support,
        })
        return analyst, verifier, consensus, validated

    def report(self, *args, **kwargs):
        a, v, c, cv = self.inputs(*args, **kwargs)
        return enforce_mafra_report(FinalReport(), a, v, cv, c, FLOW)

    def test_failed_nextjs_attempt_displays_candidate_but_not_confirmed(self):
        r = self.report(verifier_support='Unknown', confirmed=False, outcome='Fail')
        t = r.to_text()
        self.assertIn('Associated CVE candidate (Analyst): CVE-2025-29927', t)
        self.assertIn('Verifier support for exact CVE: Unknown', t)
        self.assertIn('Identified CVE: Not Found', t)
        self.assertIn('Attack: Failed', t)
        self.assertEqual(r.identified_cve, NOT_FOUND)
        self.assertEqual(r.attack, AttackOutcome.FAILURE.value)

    def test_successful_nextjs_attack_displays_confirmed_cve(self):
        r = self.report(verifier_support='Yes', confirmed=True, outcome='Success')
        t = r.to_text()
        self.assertIn('Associated CVE candidate (Analyst): CVE-2025-29927', t)
        self.assertIn('Verifier support for exact CVE: Yes', t)
        self.assertIn('Identified CVE: CVE-2025-29927', t)
        self.assertIn('Attack: Successful', t)
        self.assertEqual(r.identified_cve, 'CVE-2025-29927')
        self.assertEqual(r.attack, AttackOutcome.SUCCESS.value)

    def test_explicit_verifier_no_is_not_relabelled(self):
        r = self.report(verifier_support='No')
        self.assertIn('Verifier support for exact CVE: No', r.to_text())
        self.assertIn('Identified CVE: Not Found', r.to_text())

    def test_no_candidate_is_clear_without_inventing_cve(self):
        r = self.report(candidate='Not Found')
        self.assertIn('Associated CVE candidate (Analyst): Not Found', r.to_text())
        self.assertIn('Identified CVE: Not Found', r.to_text())

    def test_output_contract_and_llm_json_schema_unchanged(self):
        r = self.report()
        schema = FinalReport.model_json_schema()
        self.assertNotIn('associated_cve_candidate', schema['properties'])
        self.assertNotIn('verifier_cve_support', schema['properties'])
        dumped = r.model_dump()
        self.assertNotIn('associated_cve_candidate', dumped)
        self.assertNotIn('verifier_cve_support', dumped)
        self.assertEqual(dumped['identified_cve'], NOT_FOUND)

    def test_fra_report_output_is_not_affected(self):
        r = FinalReport(identified_cve='CVE-2020-1000')
        self.assertNotIn('Associated CVE candidate', r.to_text())
        self.assertNotIn('Verifier support for exact CVE', r.to_text())

    def test_reporter_model_cannot_override_deterministic_fields(self):
        a, v, c, cv = self.inputs()
        r = FinalReport(identified_cve='CVE-2025-30218')
        result = enforce_mafra_report(r, a, v, cv, c, FLOW)
        self.assertIn('Identified CVE: Not Found', result.to_text())
        self.assertIn('Associated CVE candidate (Analyst): CVE-2025-29927', result.to_text())
        self.assertNotIn('Identified CVE: CVE-2025-30218', result.to_text())

    def test_evaluation_reader_still_extracts_identified_cve(self):
        from evaluation.report_reader import extract_field
        t = self.report().to_text()
        self.assertEqual(extract_field(t, 'Identified CVE'), NOT_FOUND)
        t = self.report('Yes', True, 'Success').to_text()
        self.assertEqual(extract_field(t, 'Identified CVE'), 'CVE-2025-29927')

    def test_does_not_change_case_evidence(self):
        r = self.report()
        self.assertEqual(len(r.evidence), 1)
        self.assertIn(PACKET, r.evidence[0])
        self.assertIn('Next.js', r.evidence[0])

    def test_independent_private_metadata_per_report(self):
        a = self.report('Unknown', False, 'Fail')
        b = self.report('Yes', True, 'Success')
        self.assertIn('Verifier support for exact CVE: Unknown', a.to_text())
        self.assertIn('Verifier support for exact CVE: Yes', b.to_text())
        self.assertNotIn('Verifier support for exact CVE: Yes', a.to_text())

    def test_mafra_unknown_outcome_is_not_relabelled_failed(self):
        r = self.report(outcome='Unknown')
        self.assertEqual(r.attack, AttackOutcome.ABSTAIN.value)
        self.assertIn('Attack: Unknown', r.to_text())
        self.assertIn('Consensus attack outcome: Unknown.', r.verification_summary)

    def test_existing_final_report_unknown_rendering_is_preserved(self):
        r = FinalReport(attack='Unknown')
        self.assertIn('Attack: Failed', r.to_text())
        self.assertNotIn('Associated CVE candidate', r.to_text())


if __name__ == '__main__':
    unittest.main()
