"""Step 2 tests: final attack outcome follows FRA's binary format."""
import unittest

from agents.consensus import ConsensusManager
from contracts import AnalystOutput, ConsensusDecision, VerifierOutput
from decision_enforcement import enforce_mafra_report


class FraBinaryOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.analyst = AnalystOutput.model_validate({
            "status": "Valid",
            "service": {"primary": "Joomla"},
            "attack": {
                "type": "SQL Injection",
                "success": "Unknown",
                "evidence": ["E-S0013-F000088-010"],
            },
        })
        self.verifier = VerifierOutput.model_validate({
            "status": "Valid",
            "verification_result": "Partially Supported",
            "service_supported": "Yes",
            "attack_supported": "Yes",
            "success_supported": "Unknown",
        })

    def test_consensus_never_returns_unknown_final_attack(self):
        result = ConsensusManager().calculate(self.analyst, self.verifier)
        self.assertIn(result.attack_success, {"Success", "Fail"})
        self.assertEqual(result.attack_success, "Fail")

    def test_packet_supported_success_survives_uncertain_verifier(self):
        self.analyst.attack.success = "Success"
        result = ConsensusManager().calculate(self.analyst, self.verifier)
        self.assertEqual(result.attack_success, "Success")

    def test_report_never_prints_unknown_attack(self):
        consensus = ConsensusDecision(
            service="Joomla", attack="SQL Injection", attack_success="Unknown"
        )
        report = enforce_mafra_report(
            __import__("contracts").FinalReport(), self.analyst, self.verifier,
            __import__("contracts").CVEValidationOutput(), consensus,
            "[E-S0013-F000088-010] INSERT INTO j_assets",
        )
        self.assertEqual(report.attack, "Fail")
        self.assertNotIn("Unknown", report.to_text().split("Attack:", 1)[1].split("\n", 1)[0])


if __name__ == "__main__":
    unittest.main()
