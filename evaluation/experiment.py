"""Experiment manifests, telemetry tables, and completeness checks."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from experiment_config import experiment_manifest
from llm_telemetry import load_telemetry


TELEMETRY_COLUMNS = [
    "timestamp_utc",
    "experiment_run_id",
    "case_id",
    "system",
    "profile",
    "role",
    "provider_gateway",
    "model",
    "temperature",
    "status",
    "latency_seconds",
    "prompt_characters",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "provider_reported_cost_usd",
    "error_type",
    "error_message",
    "http_status_code",
    "provider_request_id",
    "retry_after_seconds",
    "provider_response_body",
]


def telemetry_dataframe(path) -> pd.DataFrame:
    frame = pd.DataFrame(load_telemetry(path))
    for column in TELEMETRY_COLUMNS:
        if column not in frame.columns:
            frame[column] = None
    return frame[TELEMETRY_COLUMNS]


def telemetry_summary_dataframe(frame: pd.DataFrame) -> pd.DataFrame:
    columns = [
        "system",
        "role",
        "model",
        "calls",
        "successful_calls",
        "failed_calls",
        "latency_seconds_total",
        "latency_seconds_mean",
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "provider_reported_cost_usd",
    ]
    if frame.empty:
        return pd.DataFrame(columns=columns)

    working = frame.copy()
    for column in [
        "latency_seconds",
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "provider_reported_cost_usd",
    ]:
        working[column] = pd.to_numeric(working[column], errors="coerce")
    working["successful_calls"] = working["status"].eq("success").astype(int)
    working["failed_calls"] = working["status"].eq("error").astype(int)
    working["calls"] = 1

    grouped = working.groupby(["system", "role", "model"], dropna=False)
    rows = []
    for (system, role, model), group in grouped:
        rows.append({
            "system": system,
            "role": role,
            "model": model,
            "calls": int(group["calls"].sum()),
            "successful_calls": int(group["successful_calls"].sum()),
            "failed_calls": int(group["failed_calls"].sum()),
            "latency_seconds_total": group["latency_seconds"].sum(min_count=1),
            "latency_seconds_mean": group["latency_seconds"].mean(),
            "input_tokens": group["input_tokens"].sum(min_count=1),
            "output_tokens": group["output_tokens"].sum(min_count=1),
            "total_tokens": group["total_tokens"].sum(min_count=1),
            "provider_reported_cost_usd": group[
                "provider_reported_cost_usd"
            ].sum(min_count=1),
        })
    return pd.DataFrame(rows, columns=columns)


def manifest_dataframe(profile, run_id) -> pd.DataFrame:
    manifest = experiment_manifest(profile)
    rows = [
        {"Setting": "run_id", "Value": run_id},
        {"Setting": "profile", "Value": manifest["profile"]},
        {"Setting": "provider_gateway", "Value": manifest["provider_gateway"]},
        {"Setting": "temperature", "Value": manifest["temperature"]},
        {"Setting": "timeout_seconds", "Value": manifest["timeout_seconds"]},
        {
            "Setting": "max_provider_retries",
            "Value": manifest["max_provider_retries"],
        },
        {"Setting": "memory_mode", "Value": manifest["memory_mode"]},
    ]
    rows.extend(
        {"Setting": f"model.{role}", "Value": model}
        for role, model in manifest["models"].items()
    )
    return pd.DataFrame(rows)


def evaluate_completeness(
    results_df,
    expected_ids,
    *,
    profile,
    memory_mode="disabled",
    skipped_fra=False,
    skipped_mafra=False,
    telemetry_error_count=0,
    single_system_evaluation=False,
):
    expected = {str(value) for value in expected_ids}
    observed = set(results_df.get("id", pd.Series(dtype=str)).astype(str))
    missing_ids = sorted(expected - observed)
    extra_ids = sorted(observed - expected)
    duplicate_count = int(results_df.get("id", pd.Series(dtype=str)).duplicated().sum())

    dataset_reasons = []
    if missing_ids:
        dataset_reasons.append(f"{len(missing_ids)} dataset cases are missing")
    if extra_ids:
        dataset_reasons.append(f"{len(extra_ids)} unexpected case IDs are present")
    if duplicate_count:
        dataset_reasons.append(f"{duplicate_count} duplicate case rows are present")
    if skipped_fra and not single_system_evaluation:
        dataset_reasons.append("FRA was skipped")
    if skipped_mafra:
        dataset_reasons.append("MAFRA was skipped")

    active_systems = []
    if not skipped_fra:
        active_systems.append("fra")
    if not skipped_mafra:
        active_systems.append("mafra")

    for system in active_systems:
        report_column = f"{system}_report_found"
        crash_column = f"{system}_crashed"
        if report_column in results_df and not results_df.empty:
            missing_reports = int((~results_df[report_column].astype(bool)).sum())
            if missing_reports:
                dataset_reasons.append(f"{system.upper()} has {missing_reports} missing reports")
        if crash_column in results_df and not results_df.empty:
            crashes = int(results_df[crash_column].astype(bool).sum())
            if crashes:
                dataset_reasons.append(f"{system.upper()} has {crashes} crashed cases")
    if "shared_preprocessing_crashed" in results_df and not results_df.empty:
        failures = int(results_df["shared_preprocessing_crashed"].astype(bool).sum())
        if failures:
            dataset_reasons.append(f"shared preprocessing failed for {failures} cases")
    if memory_mode == "read_only" and not results_df.empty:
        for system in active_systems:
            status_column = f"{system}_memory_status"
            if status_column not in results_df:
                dataset_reasons.append(f"{system.upper()} memory status was not recorded")
                continue
            unavailable = int(
                (~results_df[status_column].astype(str).eq("read_only")).sum()
            )
            if unavailable:
                dataset_reasons.append(
                    f"{system.upper()} training RAG was unavailable for "
                    f"{unavailable} cases"
                )

    dataset_complete = not dataset_reasons
    provider_error_count = int(telemetry_error_count)
    reasons = list(dataset_reasons)
    if provider_error_count:
        reasons.append(
            f"{provider_error_count} provider/LLM call errors were recorded"
        )

    clean_run = dataset_complete and provider_error_count == 0
    if not dataset_complete:
        status = "PRELIMINARY_INCOMPLETE"
    elif provider_error_count:
        status = "COMPLETE_WITH_PROVIDER_ERROR_WARNINGS"
    elif single_system_evaluation:
        status = "COMPLETE_MAFRA_MCP_SINGLE_SYSTEM"
    elif profile == "heterogeneous" and memory_mode == "read_only":
        status = "COMPLETE_PROPOSED_MULTI_LLM_WITH_TRAINING_RAG"
    elif profile == "heterogeneous":
        status = "COMPLETE_MULTI_LLM_NO_MEMORY_ABLATION"
    else:
        status = "COMPLETE_CONTROLLED_SAME_MODEL_ABLATION"

    return {
        "status": status,
        "dataset_complete": dataset_complete,
        "clean_run": clean_run,
        "provider_error_free": provider_error_count == 0,
        "provider_error_call_count": provider_error_count,
        "proposed_multi_llm_run": (
            clean_run and profile == "heterogeneous" and memory_mode == "read_only"
        ),
        "multi_llm_no_memory_ablation": (
            clean_run and profile == "heterogeneous" and memory_mode == "disabled"
        ),
        "controlled_same_model_run": (
            clean_run and profile == "fair_same_model" and not single_system_evaluation
        ),
        "single_system_evaluation": bool(single_system_evaluation),
        "profile": profile,
        "memory_mode": memory_mode,
        "expected_case_count": len(expected),
        "observed_case_count": len(observed),
        "missing_case_ids": missing_ids,
        "extra_case_ids": extra_ids,
        "duplicate_row_count": duplicate_count,
        "reasons": reasons,
    }


def write_json(path, value):
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(value, indent=2), encoding="utf-8")
