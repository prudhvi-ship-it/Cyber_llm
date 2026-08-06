from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

from evaluation.config import GRAPH_DIR
from evaluation.labels import parse_binary_label


SYSTEM_LABELS = {"fra": "FRA", "mafra": "MAFRA"}


def _normalise_systems(systems=None) -> list[str]:
    selected = list(systems) if systems is not None else ["fra", "mafra"]
    invalid = [system for system in selected if system not in SYSTEM_LABELS]
    if invalid:
        raise ValueError(f"Unsupported systems: {invalid}")
    if not selected:
        raise ValueError("At least one evaluation system must be active.")
    return selected


def _display_columns(systems: list[str]) -> list[str]:
    return [SYSTEM_LABELS[system] for system in systems]


def save_bar_chart(data, title, ylabel, filename, graph_dir=None):
    destination = Path(graph_dir) if graph_dir is not None else GRAPH_DIR
    destination.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(data)
    df.plot(kind="bar", figsize=(10, 6))
    plt.title(title)
    plt.ylabel(ylabel)
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(destination / filename)
    plt.close()


def create_graphs(results_df, summary_df, stats_df, graph_dir=None, systems=None):
    selected = _normalise_systems(systems)
    labels = _display_columns(selected)
    destination = Path(graph_dir) if graph_dir is not None else GRAPH_DIR
    destination.mkdir(parents=True, exist_ok=True)
    comparison_name = " vs ".join(labels)

    core = summary_df[summary_df["Metric"].isin([
        "Service Accuracy (Strict)",
        "CVE Accuracy (Strict)",
        "Vulnerability Accuracy (Strict)",
        "Attack Success Accuracy (Strict)",
        "Overall Accuracy (Strict)",
    ])].set_index("Metric")[labels]
    core.plot(kind="bar", figsize=(10, 6))
    plt.title(f"{comparison_name} Core Accuracy Metrics")
    plt.ylabel("Accuracy")
    plt.ylim(0, 1)
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(destination / "01_core_accuracy_metrics.png")
    plt.close()

    stats_plot = stats_df[
        ~stats_df["Metric"].str.contains("Answered Cases|Abstained Cases", regex=True)
    ].set_index("Metric")[labels]
    stats_plot.plot(kind="bar", figsize=(12, 6))
    plt.title("Classification Metrics (Abstentions Reported as Coverage)")
    plt.ylabel("Score")
    plt.ylim(-1, 1)
    plt.xticks(rotation=35, ha="right")
    plt.tight_layout()
    plt.savefig(destination / "02_f1_mcc_precision_recall.png")
    plt.close()

    runtime_columns = [f"{system}_runtime" for system in selected]
    runtime_frame = results_df[runtime_columns].rename(
        columns={f"{system}_runtime": SYSTEM_LABELS[system] for system in selected}
    )
    runtime_frame.plot(kind="box", figsize=(8, 6))
    plt.title("Runtime Distribution")
    plt.ylabel("Seconds")
    plt.tight_layout()
    plt.savefig(destination / "03_runtime_distribution.png")
    plt.close()

    avg_runtime = pd.Series({
        SYSTEM_LABELS[system]: results_df[f"{system}_runtime"].mean()
        for system in selected
    })
    avg_runtime.plot(kind="bar", figsize=(7, 5))
    plt.title("Average Runtime")
    plt.ylabel("Seconds")
    plt.tight_layout()
    plt.savefig(destination / "04_average_runtime.png")
    plt.close()

    crash_count = pd.Series({
        SYSTEM_LABELS[system]: results_df[f"{system}_crashed"].sum()
        for system in selected
    })
    crash_count.plot(kind="bar", figsize=(7, 5))
    plt.title("Crash Count")
    plt.ylabel("Number of Crashes")
    plt.tight_layout()
    plt.savefig(destination / "05_crash_count.png")
    plt.close()

    benchmark_columns = []
    for system in selected:
        benchmark_columns.extend([
            f"{system}_service_match",
            f"{system}_cve_match",
            f"{system}_vulnerable_match",
            f"{system}_success_match",
        ])
    by_benchmark = results_df.groupby("benchmark")[benchmark_columns].mean()
    by_benchmark.plot(kind="bar", figsize=(12, 6))
    plt.title("Accuracy by Benchmark")
    plt.ylabel("Accuracy")
    plt.ylim(0, 1)
    plt.tight_layout()
    plt.savefig(destination / "06_accuracy_by_benchmark.png")
    plt.close()

    service_columns = [f"{system}_service_match" for system in selected]
    by_service = results_df.groupby("expected_service")[service_columns].mean()
    by_service.plot(kind="bar", figsize=(14, 6))
    plt.title("Service Identification Accuracy by Service")
    plt.ylabel("Accuracy")
    plt.ylim(0, 1)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(destination / "07_service_accuracy_by_service.png")
    plt.close()

    cve_columns = [f"{system}_cve_match" for system in selected]
    by_cve = results_df.groupby("expected_cve")[cve_columns].mean()
    by_cve.plot(kind="bar", figsize=(14, 6))
    plt.title("CVE Identification Accuracy by CVE")
    plt.ylabel("Accuracy")
    plt.ylim(0, 1)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(destination / "08_cve_accuracy_by_cve.png")
    plt.close()

    success_columns = [f"{system}_success_match" for system in selected]
    by_success = results_df.groupby("expected_success")[success_columns].mean()
    by_success.plot(kind="bar", figsize=(8, 5))
    plt.title("Attack Success Detection: Success vs Failure Cases")
    plt.ylabel("Accuracy")
    plt.ylim(0, 1)
    plt.tight_layout()
    plt.savefig(destination / "09_success_vs_failure_accuracy.png")
    plt.close()

    vulnerability_columns = [f"{system}_vulnerable_match" for system in selected]
    by_vuln = results_df.groupby("expected_vulnerable")[vulnerability_columns].mean()
    by_vuln.plot(kind="bar", figsize=(8, 5))
    plt.title("Vulnerability Detection: Vulnerable vs Not Vulnerable Cases")
    plt.ylabel("Accuracy")
    plt.ylim(0, 1)
    plt.tight_layout()
    plt.savefig(destination / "10_vulnerable_vs_not_vulnerable_accuracy.png")
    plt.close()

    correctness_cols = []
    for system in selected:
        correctness_cols.extend([
            f"{system}_service_match",
            f"{system}_cve_match",
            f"{system}_vulnerable_match",
            f"{system}_success_match",
        ])
    heat = results_df[correctness_cols].astype(int)
    plt.figure(figsize=(12, max(6, len(results_df) * 0.25)))
    plt.imshow(heat, aspect="auto")
    plt.title("Per-Case Correctness Matrix")
    plt.yticks(range(len(results_df)), results_df["id"])
    plt.xticks(range(len(correctness_cols)), correctness_cols, rotation=45, ha="right")
    plt.colorbar(label="Correct = 1, Incorrect = 0")
    plt.tight_layout()
    plt.savefig(destination / "11_per_case_correctness_matrix.png")
    plt.close()

    for model in selected:
        _save_tri_state_confusion(
            expected=results_df["expected_vulnerable"],
            predicted=results_df[f"{model}_vulnerable"],
            task="vulnerability",
            title=f"{model.upper()} Vulnerability Confusion Matrix",
            filename=f"12_{model}_vulnerability_confusion_matrix.png",
            graph_dir=destination,
        )
        _save_tri_state_confusion(
            expected=results_df["expected_success"],
            predicted=results_df[f"{model}_attack_success"],
            task="success",
            title=f"{model.upper()} Attack Success Confusion Matrix",
            filename=f"13_{model}_success_confusion_matrix.png",
            graph_dir=destination,
        )


def _save_tri_state_confusion(
    expected,
    predicted,
    task,
    title,
    filename,
    graph_dir=None,
):
    """Plot 2 actual classes by 3 prediction classes, including abstentions."""
    matrix = tri_state_confusion_matrix(expected, predicted, task)

    if task == "vulnerability":
        y_labels = ["Actual Not Vulnerable", "Actual Vulnerable"]
        x_labels = ["Pred Not Vulnerable", "Pred Vulnerable", "Pred Unknown"]
    else:
        y_labels = ["Actual Failed", "Actual Successful"]
        x_labels = ["Pred Failed", "Pred Successful", "Pred Unknown"]

    figure, axis = plt.subplots(figsize=(8, 5))
    image = axis.imshow(matrix, cmap="Blues", aspect="auto")
    for row_index, row in enumerate(matrix):
        for column_index, count in enumerate(row):
            axis.text(column_index, row_index, str(count), ha="center", va="center")
    axis.set_xticks(range(3), labels=x_labels, rotation=20, ha="right")
    axis.set_yticks(range(2), labels=y_labels)
    axis.set_xlabel("Predicted label")
    axis.set_ylabel("Ground-truth label")
    axis.set_title(title)
    figure.colorbar(image, ax=axis, label="Number of cases")
    figure.tight_layout()
    destination = Path(graph_dir) if graph_dir is not None else GRAPH_DIR
    destination.mkdir(parents=True, exist_ok=True)
    figure.savefig(destination / filename)
    plt.close(figure)


def tri_state_confusion_matrix(expected, predicted, task):
    """Return rows=[actual negative, positive], columns=[negative, positive, unknown]."""
    matrix = [[0, 0, 0], [0, 0, 0]]
    for expected_value, predicted_value in zip(expected, predicted):
        truth = parse_binary_label(expected_value, task)
        guess = parse_binary_label(predicted_value, task)
        if truth is None:
            raise ValueError(f"Unknown ground-truth label for {task}: {expected_value}")
        prediction_column = 2 if guess is None else int(guess)
        matrix[int(truth)][prediction_column] += 1
    return matrix
