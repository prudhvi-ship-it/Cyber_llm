"""Offline regression test for corrected evaluation logic."""

import json
import math
import tempfile
from pathlib import Path

import pandas as pd

from evaluation.labels import parse_binary_label
from evaluation.graphs import tri_state_confusion_matrix
from evaluation.loader import load_ground_truth
from evaluation.matcher import match_success, match_vulnerable
from evaluation.metrics import calculate_classification_stats, calculate_summary
from evaluation.report_reader import parse_saved_report


def metric_value(table, metric, system):
    return float(table.loc[table["Metric"] == metric, system].iloc[0])


def close(actual, expected):
    return math.isclose(float(actual), float(expected), rel_tol=1e-9, abs_tol=1e-9)


def synthetic_results():
    frame = pd.DataFrame({
        "expected_vulnerable": ["Yes", "Yes", "No", "No"],
        "fra_vulnerable": ["Yes", "Unknown", "No", "Not Found"],
        "mafra_vulnerable": ["No", "Yes", "Yes", "No"],
        "expected_success": ["Success", "Fail", "Success", "Fail"],
        "fra_attack_success": ["Successful", "Failed", "Unknown", "Not Found"],
        "mafra_attack_success": ["Failed", "Successful", "Successful", "Failed"],
        "fra_service_match": [True, True, True, True],
        "mafra_service_match": [True, True, True, True],
        "fra_cve_match": [True, True, True, True],
        "mafra_cve_match": [True, True, True, True],
        "fra_report_found": [True, True, True, True],
        "mafra_report_found": [True, True, True, True],
        "fra_runtime": [1.0, 1.0, 1.0, 1.0],
        "mafra_runtime": [2.0, 2.0, 2.0, 2.0],
        "fra_crashed": [False, False, False, False],
        "mafra_crashed": [False, False, False, False],
    })
    for model in ["fra", "mafra"]:
        frame[f"{model}_vulnerable_match"] = [
            match_vulnerable(expected, actual)
            for expected, actual in zip(
                frame["expected_vulnerable"], frame[f"{model}_vulnerable"]
            )
        ]
        frame[f"{model}_success_match"] = [
            match_success(expected, actual)
            for expected, actual in zip(
                frame["expected_success"], frame[f"{model}_attack_success"]
            )
        ]
    return frame


def parser_uses_final_report():
    content = """=== FLOW SUMMARY ===
Attack: Failed
Analyst Output: {"attack": {"success": "yes"}}
=== FINAL REPORT ===
Affected Service: Example Service
Identified CVE: Not Found
Attack: Unknown
Is Service Vulnerable: Unknown
"""
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "report.txt"
        path.write_text(content, encoding="utf-8")
        parsed = parse_saved_report(path)
    return parsed["attack_success"] == "Unknown"


def main():
    frame = synthetic_results()
    summary = calculate_summary(frame)
    stats = calculate_classification_stats(frame)
    ground_truth = load_ground_truth()

    checks = {
        "ground_truth_labels_valid": len(ground_truth) == 30,
        "success_string_maps_positive": parse_binary_label("Success", "success") == 1,
        "fail_string_maps_negative": parse_binary_label("Fail", "success") == 0,
        "unknown_is_abstention": parse_binary_label("Unknown", "success") is None,
        "not_found_is_abstention": parse_binary_label("Not Found", "vulnerability") is None,
        "unknown_not_counted_as_failed": not match_success("Fail", "Unknown"),
        "unknown_not_counted_as_not_vulnerable": not match_vulnerable("No", "Unknown"),
        "final_report_is_scored": parser_uses_final_report(),
        "fra_success_strict_accuracy": close(
            metric_value(summary, "Attack Success Accuracy (Strict)", "FRA"), 0.5
        ),
        "fra_success_coverage": close(
            metric_value(summary, "Attack Success Prediction Coverage", "FRA"), 0.5
        ),
        "fra_vulnerability_strict_accuracy": close(
            metric_value(summary, "Vulnerability Accuracy (Strict)", "FRA"), 0.5
        ),
        "fra_vulnerability_coverage": close(
            metric_value(summary, "Vulnerability Prediction Coverage", "FRA"), 0.5
        ),
        "f1_uses_predictions_not_match_flags": close(
            metric_value(
                stats,
                "Attack Success F1 Macro (Answered Only)",
                "FRA",
            ),
            1.0,
        ),
        "mcc_uses_predictions_not_match_flags": close(
            metric_value(
                stats,
                "Attack Success MCC (Answered Only)",
                "FRA",
            ),
            1.0,
        ),
        "confusion_matrix_uses_actual_predictions": (
            tri_state_confusion_matrix(
                frame["expected_success"],
                frame["fra_attack_success"],
                "success",
            )
            == [[1, 0, 1], [0, 1, 1]]
        ),
    }

    status = "Valid" if all(checks.values()) else "Invalid"
    print(json.dumps({"status": status, "checks": checks}, indent=2))
    if status != "Valid":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
