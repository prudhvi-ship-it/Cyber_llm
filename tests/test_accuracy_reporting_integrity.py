"""Generic reporting-integrity tests; only synthetic fixtures are used."""
import unittest
from types import SimpleNamespace
from contracts import (
    AnalystOutput, VerifierOutput, ConsensusDecision, CVEValidationOutput,
    FinalReport, AttackOutcome, Decision,
)
from decision_enforcement import enforce_mafra_report, _build_evidence_catalog
from evidence_formatter import EvidenceFormatter, _packet_catalog
from mcp_evidence_contracts import ExternalEvidenceSource

E_REQ = "E-S0001-F000013-004"
E_RES = "E-S0001-F000014-009"
E_MISSING = "E-S0002-F000020-001"
FLOW = (
    "DETERMINISTIC PACKET-LINKED ATTACK INDICATORS:\\n"
    f"- [{E_REQ} | client->server] POST /private/settings.\\n"
    f"- [{E_RES} | server->client] Server responds HTTP 403 Forbidden.\\n"
).replace("\\n", "\n")

class ReportingIntegrityTests(unittest.TestCase):
    def _inputs(self, outcome='Fail', identified='Not Found', ids=None):
        analysis = AnalystOutput.model_validate({
            'service': {'primary': 'ExampleService'},
            'attack': {'type': 'Path Traversal', 'technique': 'Attempted traversal',
                       'success': outcome, 'evidence': ids or [E_REQ, E_RES]}
        })
        verify = VerifierOutput.model_validate({
            'verification_result': 'Supported', 'service_supported': 'Yes',
            'attack_supported': 'Yes', 'success_supported': 'Yes',
            'cve_supported': 'Not Applicable', 'confidence': 'High'
        })
        consensus = ConsensusDecision.model_validate({
            'service': 'ExampleService', 'attack': 'Path Traversal',
            'attack_success': outcome, 'verification_result': 'Supported',
            'service_supported': 'Yes', 'attack_supported': 'Yes',
            'success_supported': 'Yes'
        })
        validated = CVEValidationOutput.model_validate({'validated_cve': identified})
        return analysis, verify, consensus, validated

    def test_catalog_recognizes_directional_and_normal_ids(self):
        for catalog in (_packet_catalog(FLOW), _build_evidence_catalog(FLOW)):
            self.assertIn(E_REQ, catalog)
            self.assertIn(E_RES, catalog)
            self.assertIn('HTTP 403', catalog[E_RES])

    def test_no_guess_from_unrelated_packet_evidence(self):
        catalog = _packet_catalog(FLOW)
        self.assertNotIn(E_MISSING, catalog)

    def test_failure_does_not_imply_service_not_vulnerable(self):
        analyst, verifier, consensus, validated = self._inputs('Fail')
        report = FinalReport(is_service_vulnerable='No')
        updated = enforce_mafra_report(report, analyst, verifier, validated, consensus, FLOW)
        self.assertEqual(updated.attack, 'Fail')
        self.assertEqual(updated.is_service_vulnerable, 'Unknown')
        self.assertEqual(updated.affected_service, 'ExampleService')

    def test_unknown_outcome_does_not_imply_service_safe(self):
        analyst, verifier, consensus, validated = self._inputs('Unknown')
        report = FinalReport(is_service_vulnerable='No')
        updated = enforce_mafra_report(report, analyst, verifier, validated, consensus, FLOW)
        self.assertEqual(updated.is_service_vulnerable, 'Unknown')

    def test_observed_success_supports_vulnerable(self):
        analyst, verifier, consensus, validated = self._inputs('Success')
        report = FinalReport(is_service_vulnerable='No')
        updated = enforce_mafra_report(report, analyst, verifier, validated, consensus, FLOW)
        self.assertEqual(updated.attack, 'Success')
        self.assertEqual(updated.is_service_vulnerable, 'Yes')

    def test_enforcement_packet_descriptions_have_real_text(self):
        analyst, verifier, consensus, validated = self._inputs('Fail')
        out = enforce_mafra_report(FinalReport(), analyst, verifier, validated, consensus, FLOW)
        self.assertTrue(any('POST /private/settings' in e for e in out.evidence))
        self.assertTrue(any('HTTP 403' in e for e in out.evidence))

    def test_enforcement_marks_unresolved_reference(self):
        analyst, verifier, consensus, validated = self._inputs('Fail', ids=[E_MISSING])
        out = enforce_mafra_report(FinalReport(), analyst, verifier, validated, consensus, FLOW)
        self.assertIn('Description unavailable', out.evidence[0])
        self.assertNotIn('validated Analyst', out.evidence[0])

    def test_formatter_uses_grounded_descriptions_and_audits_missing_ids(self):
        analyst, verifier, consensus, validated = self._inputs('Fail', ids=[E_REQ, E_RES, E_MISSING])
        online = SimpleNamespace(sources=[], retrieval_errors=[], query='test', status='Valid')
        formatted = EvidenceFormatter().format(FLOW, analyst, verifier, consensus, online)
        self.assertIn('POST /private/settings', formatted.packet_evidence[0])
        self.assertIn('HTTP 403', formatted.packet_evidence[1])
        self.assertIn('Description unavailable', formatted.packet_evidence[2])
        self.assertTrue(any('1 cited packet reference' in s for s in formatted.limitations))

    def test_unselected_online_cves_are_research_leads(self):
        analyst, verifier, consensus, validated = self._inputs('Success')
        consensus.cve = 'CVE-2022-24706'
        online = SimpleNamespace(
            sources=[ExternalEvidenceSource(
                source_name='NIST NVD',
                title='CVE-2018-8007',
                url='https://nvd.nist.gov/vuln/detail/CVE-2018-8007',
                snippet='Related product record.',
                retrieved_at_utc='2026-10-25T00:00:00Z',
            )],
            retrieval_errors=[], query='CouchDB RCE', status='Valid',
        )
        formatted = EvidenceFormatter().format(
            FLOW, analyst, verifier, consensus, online
        )
        self.assertTrue(
            formatted.online_evidence[0].startswith('ONLINE RESEARCH LEAD')
        )
        self.assertTrue(any('research lead' in item for item in formatted.limitations))

if __name__ == '__main__':
    unittest.main()
