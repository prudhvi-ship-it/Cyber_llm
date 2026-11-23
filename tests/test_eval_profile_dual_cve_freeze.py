"""Offline tests: preserve verified CVE while measuring candidate CVE separately."""
import os
import sys
import unittest
from unittest.mock import patch

import pandas as pd

from evaluation.report_reader import parse_report_text
from evaluation.matcher import match_cve
from evaluation.metrics import calculate_summary, SYSTEM_LABELS
from evaluation import run_eval
from evaluation.labels import parse_binary_label


EXAMPLE = '''============================================================
FINAL SECURITY REPORT
============================================================
Affected Service: Next.js application
Associated CVE candidate (Analyst): CVE-2025-29927
Verifier support for exact CVE: Unknown
Identified CVE: Not Found
Attack: Successful
Is Service Vulnerable: Yes
'''


class EvaluationFreezeTests(unittest.TestCase):
    def test_candidate_distinct_from_verified(self):
        got = parse_report_text(EXAMPLE)
        self.assertEqual(got['cve_candidate'], 'CVE-2025-29927')
        self.assertEqual(got['cve_candidate_support'], 'Unknown')
        self.assertEqual(got['cve'], 'Not Found')
        self.assertTrue(match_cve('CVE-2025-29927', got['cve_candidate']))
        self.assertFalse(match_cve('CVE-2025-29927', got['cve']))

    def test_success_label_is_normalized_during_scoring(self):
        self.assertEqual(parse_binary_label('Successful', 'success'), 1)
        self.assertEqual(parse_binary_label('Failed', 'success'), 0)
        self.assertIsNone(parse_binary_label('Unknown', 'success'))

    def test_verified_result_is_unmodified(self):
        got = parse_report_text(EXAMPLE.replace('Unknown\nIdentified CVE: Not Found', 'Yes\nIdentified CVE: CVE-2025-29927'))
        self.assertEqual(got['cve'], 'CVE-2025-29927')
        self.assertEqual(got['cve_candidate'], 'CVE-2025-29927')
        self.assertEqual(got['cve_candidate_support'], 'Yes')

    def test_legacy_fra_without_candidate(self):
        got = parse_report_text('=== FINAL REPORT ===\nAffected Service: Apache\nIdentified CVE: CVE-2024-11111\nAttack: Failed')
        self.assertEqual(got['cve'], 'CVE-2024-11111')
        self.assertEqual(got['cve_candidate'], 'Not Found')

    def test_consensus_final_precedence_unchanged(self):
        got = parse_report_text('=== CONSENSUS SUMMARY ===\nService: HTTP\nCVE: CVE-2025-29927\nAttack Success: Success\n=== FINAL REPORT ===\nAssociated CVE candidate (Analyst): CVE-2025-29927\nIdentified CVE: Not Found')
        self.assertEqual(got['cve'], 'CVE-2025-29927') # legacy established parsing contract
        self.assertEqual(got['cve_candidate'], 'CVE-2025-29927')

    def test_separate_metric_cannot_change_original_cve_accuracy(self):
        df = pd.DataFrame([{
            'mafra_service_match': True, 'mafra_cve_match': False,
            'mafra_cve_candidate_match': True,
            'mafra_vulnerable_match': True, 'mafra_success_match': True,
            'mafra_vulnerable':'Yes', 'mafra_attack_success':'Successful',
            'expected_vulnerable':'Yes', 'expected_success':'Success',
            'mafra_report_found':True, 'mafra_runtime':1.0,
            'mafra_crashed':False,
        }])
        s=calculate_summary(df, systems=['mafra']).set_index('Metric')[SYSTEM_LABELS['mafra']]
        self.assertEqual(s['CVE Accuracy (Strict)'], 0.0)
        self.assertEqual(s['Associated CVE Candidate Accuracy (Strict, Diagnostic)'], 1.0)
        self.assertEqual(s['Overall Accuracy (Strict)'], .75)

    def test_heterogeneous_mafra_only_profile_allowed_without_running_cases(self):
        class StopAtBuild(Exception): pass
        with patch.object(sys, 'argv', ['run_eval', '--mafra-mcp-only', '--profile', 'heterogeneous', '--memory-mode', 'disabled', '--run-id','offline_test']), \
             patch.object(run_eval,'build_run_paths', side_effect=StopAtBuild):
            with self.assertRaises(StopAtBuild):
                run_eval.main()

    def test_fair_same_model_profile_still_allowed(self):
        class StopAtBuild(Exception): pass
        with patch.object(sys, 'argv', ['run_eval', '--mafra-mcp-only', '--profile', 'fair_same_model', '--memory-mode', 'disabled', '--run-id','offline_test']), \
             patch.object(run_eval,'build_run_paths', side_effect=StopAtBuild):
            with self.assertRaises(StopAtBuild):
                run_eval.main()

    def test_memory_disabled_guard_retained(self):
        with patch.object(sys, 'argv', ['run_eval', '--mafra-mcp-only', '--profile', 'heterogeneous', '--memory-mode', 'read_only']):
            with self.assertRaises(SystemExit):
                run_eval.main()

if __name__ == '__main__':
    unittest.main()
