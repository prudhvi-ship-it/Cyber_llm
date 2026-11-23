import csv
import json
from pathlib import Path
import tempfile
import unittest

from evaluation.reconcile_completed_case import reconcile


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.base = Path(self.td.name)
        (self.base / "reports").mkdir()
        (self.base / "raw_outputs").mkdir()
        (self.base / "evaluation_status.json").write_text(
            json.dumps({"observed_case_count": 30, "expected_case_count": 30}),
            encoding="utf-8",
        )
        self.log = self.base / "raw_outputs" / "TS-05_mafra_stdout.txt"
        self.log.write_text("starting...\nMAFRA MCP analysis complete!\n", encoding="utf-8")
        self.report = self.base / "reports" / "TS-05_mafra_report.txt"
        self.report.write_text("=== CONSENSUS SUMMARY ===\nService: Unknown\nCVE: Not Found\n", encoding="utf-8")
        self.csv = self.base / "evaluation_results.csv"
        self.csv.write_text(
            "id,mafra_crashed,mafra_report_found,mafra_service,mafra_attack_type,mafra_cve\n"
            "TS-05,True,True,Unknown,Unknown,Not Found\n",
            encoding="utf-8",
        )

    def test_change_only_crash_flag_and_preserve_backup(self):
        result = reconcile(self.base, "TS-05")
        with self.csv.open(newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(rows[0]["mafra_crashed"], "False")
        self.assertEqual(rows[0]["mafra_cve"], "Not Found")
        self.assertTrue(Path(result["backup"]).exists())
        self.assertTrue(Path(result["audit"]).exists())

    def test_no_change_without_completion_marker(self):
        original = self.csv.read_bytes()
        self.log.write_text("still running", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            reconcile(self.base, "TS-05")
        self.assertEqual(self.csv.read_bytes(), original)

    def test_no_change_if_no_final_consensus(self):
        self.report.write_text("Only an intermediate analyst result", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            reconcile(self.base, "TS-05")

    def test_no_change_if_dataset_incomplete(self):
        (self.base / "evaluation_status.json").write_text(
            json.dumps({"observed_case_count": 29, "expected_case_count": 30}),
            encoding="utf-8",
        )
        with self.assertRaises(RuntimeError):
            reconcile(self.base, "TS-05")


if __name__ == "__main__":
    unittest.main()
