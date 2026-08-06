"""Offline checks for fair model configuration and experiment telemetry."""

import json
import tempfile
from pathlib import Path

import pandas as pd

from evaluation.experiment import (
    evaluate_completeness,
    telemetry_dataframe,
    telemetry_summary_dataframe,
)
from evaluation.loader import load_ground_truth
from experiment_config import (
    DEFAULT_EXPERIMENT_PROFILE,
    MODEL_ROLES,
    experiment_manifest,
)
from llm_telemetry import TelemetryCallback
from flow_summary_io import sanitize_summary


class FakeResponse:
    llm_output = {
        "token_usage": {
            "prompt_tokens": 100,
            "completion_tokens": 25,
            "total_tokens": 125,
            "cost": 0.00125,
        }
    }
    generations = []


def complete_frame(case_count=30):
    return pd.DataFrame({
        "id": [f"CASE-{index:02d}" for index in range(case_count)],
        "fra_report_found": [True] * case_count,
        "mafra_report_found": [True] * case_count,
        "fra_crashed": [False] * case_count,
        "mafra_crashed": [False] * case_count,
        "shared_preprocessing_crashed": [False] * case_count,
    })


def main():
    fair_manifest = experiment_manifest("fair_same_model")
    heterogeneous_manifest = experiment_manifest("heterogeneous")
    fair_models = set(fair_manifest["models"].values())
    heterogeneous_models = set(heterogeneous_manifest["models"].values())

    with tempfile.TemporaryDirectory() as directory:
        telemetry_path = Path(directory) / "telemetry.jsonl"
        callback = TelemetryCallback(
            role="fra_reasoner",
            model="test/model",
            profile="fair_same_model",
            path=telemetry_path,
        )
        callback.on_chat_model_start(
            {},
            [["test prompt"]],
            run_id="fake-call-1",
        )
        callback.on_llm_end(FakeResponse(), run_id="fake-call-1")
        telemetry = telemetry_dataframe(telemetry_path)
        telemetry_summary = telemetry_summary_dataframe(telemetry)

    complete = complete_frame()
    expected_ids = complete["id"].tolist()
    actual_case_count = len(load_ground_truth())
    proposed_status = evaluate_completeness(
        complete,
        expected_ids,
        profile="heterogeneous",
        memory_mode="disabled",
    )
    controlled_status = evaluate_completeness(
        complete,
        expected_ids,
        profile="fair_same_model",
        memory_mode="disabled",
    )
    partial_status = evaluate_completeness(
        complete.head(29),
        expected_ids,
        profile="fair_same_model",
    )

    leaked_name = "CFA_event0_CVE-2022-24706.pcap"
    sanitized = sanitize_summary(
        f"File: {leaked_name}\nCase {Path(leaked_name).stem}",
        leaked_name,
    )

    checks = {
        "all_roles_configured": set(fair_manifest["models"]) == set(MODEL_ROLES),
        "normal_default_is_multi_llm": DEFAULT_EXPERIMENT_PROFILE == "heterogeneous",
        "proposed_profile_uses_different_llms": len(heterogeneous_models) >= 3,
        "controlled_profile_uses_one_model": len(fair_models) == 1,
        "fra_and_mafra_analyst_both_use_gpt5": (
            heterogeneous_manifest["models"]["fra_reasoner"] == "openai/gpt-5"
            and heterogeneous_manifest["models"]["mafra_analyst"]
            == "openai/gpt-5"
        ),
        "temperature_is_zero": fair_manifest["temperature"] == 0,
        "telemetry_call_recorded": len(telemetry) == 1,
        "telemetry_model_and_role_recorded": (
            telemetry.iloc[0]["model"] == "test/model"
            and telemetry.iloc[0]["role"] == "fra_reasoner"
        ),
        "telemetry_tokens_recorded": int(telemetry.iloc[0]["total_tokens"]) == 125,
        "telemetry_cost_recorded_when_provider_returns_it": (
            float(telemetry.iloc[0]["provider_reported_cost_usd"]) == 0.00125
        ),
        "telemetry_summary_created": int(telemetry_summary.iloc[0]["calls"]) == 1,
        "no_memory_run_marked_as_ablation": (
            proposed_status["status"] == "COMPLETE_MULTI_LLM_NO_MEMORY_ABLATION"
        ),
        "same_model_run_marked_as_controlled_test": (
            controlled_status["status"]
            == "COMPLETE_CONTROLLED_SAME_MODEL_ABLATION"
        ),
        "ground_truth_has_thirty_cases": actual_case_count == 30,
        "twenty_nine_of_thirty_cases_marked_preliminary": (
            partial_status["status"] == "PRELIMINARY_INCOMPLETE"
            and partial_status["expected_case_count"] == 30
            and partial_status["observed_case_count"] == 29
        ),
        "filename_answer_removed_from_shared_summary": (
            "CVE-2022-24706" not in sanitized and leaked_name not in sanitized
        ),
    }

    status = "Valid" if all(checks.values()) else "Invalid"
    print(json.dumps({"status": status, "checks": checks}, indent=2))
    if status != "Valid":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
