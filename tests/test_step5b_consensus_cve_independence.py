"""Step 5B regression: CVE uncertainty must not hide verified attack success."""
import unittest

from agents.consensus import ConsensusManager
from contracts import AnalystOutput, VerifierOutput


class IndependentAttackOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.manager = ConsensusManager()
        self.analyst = AnalystOutput(
            status="Valid",
            service={"primary": "CouchDB"},
            attack={"type": "Remote Code Execution", "success": "Success",
                    "evidence": ["E-S0001-F000029-007", "E-S0001-F000031-008"]},
            cve={"candidate": "CVE-2022-24706"},
        )
        self.verifier = VerifierOutput(
            status="Valid", verification_result="Partially Supported",
            service_supported="Yes", attack_supported="Yes",
            success_supported="Yes", cve_supported="Unknown",
        )

    def test_cve_uncertainty_does_not_erase_success(self):
        result = self.manager.calculate(self.analyst, self.verifier)
        self.assertEqual(result.attack_success, "Success")
        self.assertEqual(result.verification_result, "Partially Supported")
        self.assertEqual(result.cve_supported, "Unknown")

    def test_overall_supported_preserves_success(self):
        v = self.verifier.model_copy(update={"verification_result": "Supported",
                                             "cve_supported": "Yes"})
        self.assertEqual(self.manager.calculate(self.analyst, v).attack_success, "Success")

    def test_uncertain_success_is_not_promoted(self):
        v = self.verifier.model_copy(update={"success_supported": "Unknown"})
        self.assertEqual(self.manager.calculate(self.analyst, v).attack_success, "Unknown")

    def test_unsupported_attack_is_not_promoted(self):
        v = self.verifier.model_copy(update={"attack_supported": "No"})
        self.assertEqual(self.manager.calculate(self.analyst, v).attack_success, "Unknown")

    def test_overall_unsupported_is_not_promoted(self):
        v = self.verifier.model_copy(update={"verification_result": "Unsupported"})
        self.assertEqual(self.manager.calculate(self.analyst, v).attack_success, "Unknown")

    def test_abstaining_verifier_cannot_promote_success(self):
        v = self.verifier.model_copy(update={"status": "Abstain"})
        self.assertEqual(self.manager.calculate(self.analyst, v).attack_success, "Unknown")

    def test_verified_failed_attack_remains_fail(self):
        a = self.analyst.model_copy(deep=True)
        a.attack.success = "Fail"
        self.assertEqual(self.manager.calculate(a, self.verifier).attack_success, "Fail")

    def test_analyst_unknown_never_becomes_success(self):
        a = self.analyst.model_copy(deep=True)
        a.attack.success = "Unknown"
        self.assertEqual(self.manager.calculate(a, self.verifier).attack_success, "Unknown")


if __name__ == "__main__":
    unittest.main()
