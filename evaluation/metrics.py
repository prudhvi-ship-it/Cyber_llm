"""Research-safe metrics for FRA versus MAFRA."""

from __future__ import annotations

import math

import pandas as pd
from sklearn.metrics import f1_score, matthews_corrcoef, precision_score, recall_score

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


def classification_vectors(df, model: str, task: str):
    """Return strict tri-state labels and answered-only binary vectors."""
    if task == "vulnerability":
        expected_column = "expected_vulnerable"
        predicted_column = f"{model}_vulnerable"
        parser_task = "vulnerability"
    elif task == "success":
        expected_column = "expected_success"
        predicted_column = f"{model}_attack_success"
        parser_task = "success"
    else:
        raise ValueError(f"Unsupported task: {task}")

    expected = [
        parse_binary_label(value, parser_task) for value in df[expected_column]
    ]
    predicted = [
        parse_binary_label(value, parser_task) for value in df[predicted_column]
    ]
    if any(value is None for value in expected):
        raise ValueError(f"Ground truth contains an unknown {task} label.")

    answered_mask = [value is not None for value in predicted]
    answered_true = [
        int(truth) for truth, answered in zip(expected, answered_mask) if answered
    ]
    answered_pred = [
        int(prediction)
        for prediction, answered in zip(predicted, answered_mask)
        if answered
    ]
    total = len(expected)
    answered_count = sum(answered_mask)
    strict_correct = sum(
        prediction is not None and prediction == truth
        for truth, prediction in zip(expected, predicted)
    )

    return {
        "expected": expected,
        "predicted": predicted,
        "answered_true": answered_true,
        "answered_pred": answered_pred,
        "total": total,
        "answered": answered_count,
        "abstained": total - answered_count,
        "coverage": answered_count / total if total else math.nan,
        "strict_accuracy": strict_correct / total if total else math.nan,
    }


def _mean(df, columns):
    if df.empty:
        return math.nan
    return float(df[columns].astype(float).mean(axis=1).mean())


def _column_mean(df, column):
    return math.nan if df.empty else float(df[column].astype(float).mean())


def calculate_summary(df, systems=None):
    selected = _normalise_systems(systems)
    metric_rows = [
        "Cases Evaluated",
        "Service Accuracy (Strict)",
        "CVE Accuracy (Strict)",
        "Vulnerability Accuracy (Strict)",
        "Attack Success Accuracy (Strict)",
        "Overall Accuracy (Strict)",
        "Vulnerability Prediction Coverage",
        "Attack Success Prediction Coverage",
        "Report Coverage",
        "Average Runtime (Seconds)",
        "Crash Count",
    ]
    values = {"Metric": metric_rows}

    for prefix in selected:
        display_name = SYSTEM_LABELS[prefix]
        vulnerability = classification_vectors(df, prefix, "vulnerability")
        success = classification_vectors(df, prefix, "success")
        strict_columns = [
            f"{prefix}_service_match",
            f"{prefix}_cve_match",
            f"{prefix}_vulnerable_match",
            f"{prefix}_success_match",
        ]
        values[display_name] = [
            len(df),
            _column_mean(df, f"{prefix}_service_match"),
            _column_mean(df, f"{prefix}_cve_match"),
            vulnerability["strict_accuracy"],
            success["strict_accuracy"],
            _mean(df, strict_columns),
            vulnerability["coverage"],
            success["coverage"],
            _column_mean(df, f"{prefix}_report_found"),
            _column_mean(df, f"{prefix}_runtime"),
            int(df[f"{prefix}_crashed"].sum()) if not df.empty else 0,
        ]

    return pd.DataFrame(values)


def _answered_metrics(vectors):
    y_true = vectors["answered_true"]
    y_pred = vectors["answered_pred"]
    if not y_true:
        return {
            "f1_macro": math.nan,
            "mcc": math.nan,
            "precision": math.nan,
            "recall": math.nan,
        }
    return {
        "f1_macro": f1_score(
            y_true,
            y_pred,
            labels=[0, 1],
            average="macro",
            zero_division=0,
        ),
        "mcc": matthews_corrcoef(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
    }


def calculate_classification_stats(df, systems=None):
    selected = _normalise_systems(systems)
    vectors = {
        (model, task): classification_vectors(df, model, task)
        for model in selected
        for task in ["vulnerability", "success"]
    }
    scores = {key: _answered_metrics(value) for key, value in vectors.items()}

    rows = []
    for task, title in [
        ("vulnerability", "Vulnerability"),
        ("success", "Attack Success"),
    ]:
        metric_specs = [
            ("Answered Cases", lambda v, _s: v["answered"]),
            ("Abstained Cases", lambda v, _s: v["abstained"]),
            ("Coverage", lambda v, _s: v["coverage"]),
            ("Strict Accuracy", lambda v, _s: v["strict_accuracy"]),
            ("F1 Macro (Answered Only)", lambda _v, s: s["f1_macro"]),
            ("MCC (Answered Only)", lambda _v, s: s["mcc"]),
            ("Precision Positive (Answered Only)", lambda _v, s: s["precision"]),
            ("Recall Positive (Answered Only)", lambda _v, s: s["recall"]),
        ]
        for suffix, extractor in metric_specs:
            row = {"Metric": f"{title} {suffix}"}
            for model in selected:
                row[SYSTEM_LABELS[model]] = extractor(
                    vectors[(model, task)],
                    scores[(model, task)],
                )
            rows.append(row)

    return pd.DataFrame(rows)
