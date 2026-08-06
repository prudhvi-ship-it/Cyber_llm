"""Offline checks for the consolidated Steps 3-8 audit corrections."""

import json
import tempfile
from pathlib import Path

from evaluation.experiment import evaluate_completeness
from evaluation.graphs import create_graphs
from evaluation.metrics import calculate_classification_stats, calculate_summary
from evaluation.report import save_reports
from evaluation.run_paths import build_run_paths, validate_run_id
from evaluation_preflight import synthetic_results
from experiment_preflight import complete_frame


def rejects_unsafe_run_id():
    try:
        validate_run_id("../overwrite-old-results")
    except ValueError:
        return True
    return False


def main():
    frame = synthetic_results()
    frame["id"] = ["CASE-00", "CASE-01", "CASE-02", "CASE-03"]
    frame["benchmark"] = ["Synthetic"] * 4
    frame["expected_service"] = ["Service"] * 4
    frame["expected_cve"] = ["CVE-2022-24706"] * 4
    summary = calculate_summary(frame)
    stats = calculate_classification_stats(frame)

    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        run_a = build_run_paths(base, "audit_run_a")
        run_b = build_run_paths(base, "audit_run_b")
        save_reports(
            frame,
            summary,
            stats,
            output_dir=run_a.root,
        )
        create_graphs(frame, summary, stats, graph_dir=run_a.graphs)
        output_checks = {
            "results_csv_is_run_specific": run_a.results_csv.is_file(),
            "excel_is_run_specific": run_a.results_xlsx.is_file(),
            "graphs_are_run_specific": (
                run_a.graphs / "01_core_accuracy_metrics.png"
            ).is_file(),
            "second_run_has_distinct_folder": run_a.root != run_b.root,
            "second_run_not_created_implicitly": not run_b.root.exists(),
        }

    complete = complete_frame()
    complete["fra_memory_status"] = "read_only"
    complete["mafra_memory_status"] = "read_only"
    expected_ids = complete["id"].tolist()
    rag_status = evaluate_completeness(
        complete,
        expected_ids,
        profile="heterogeneous",
        memory_mode="read_only",
    )
    unavailable = complete.copy()
    unavailable.loc[0, "mafra_memory_status"] = "unavailable"
    unavailable_status = evaluate_completeness(
        unavailable,
        expected_ids,
        profile="heterogeneous",
        memory_mode="read_only",
    )

    checks = {
        **output_checks,
        "unsafe_run_id_rejected": rejects_unsafe_run_id(),
        "training_rag_run_labeled_as_proposed_system": (
            rag_status["status"]
            == "COMPLETE_PROPOSED_MULTI_LLM_WITH_TRAINING_RAG"
        ),
        "unavailable_training_rag_invalidates_run": (
            unavailable_status["status"] == "PRELIMINARY_INCOMPLETE"
        ),
    }

    status = "Valid" if all(checks.values()) else "Invalid"
    print(json.dumps({"status": status, "checks": checks}, indent=2))
    if status != "Valid":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
