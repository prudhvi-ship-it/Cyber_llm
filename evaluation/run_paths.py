"""Safe, run-specific evaluation output paths."""

from dataclasses import dataclass
from pathlib import Path
import re


RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")


def validate_run_id(run_id: str) -> str:
    value = str(run_id).strip()
    if not RUN_ID_PATTERN.fullmatch(value):
        raise ValueError(
            "Run ID must start with a letter or number and contain only letters, "
            "numbers, dot, underscore, or hyphen (maximum 80 characters)."
        )
    return value


@dataclass(frozen=True)
class RunPaths:
    root: Path
    results_csv: Path
    results_xlsx: Path
    raw_outputs: Path
    reports: Path
    shared_summaries: Path
    graphs: Path
    telemetry: Path
    memory_audit: Path
    manifest: Path
    status: Path


def build_run_paths(base_output_dir, run_id: str) -> RunPaths:
    safe_run_id = validate_run_id(run_id)
    root = Path(base_output_dir) / "runs" / safe_run_id
    return RunPaths(
        root=root,
        results_csv=root / "evaluation_results.csv",
        results_xlsx=root / "MAFRA_Evaluation_Results.xlsx",
        raw_outputs=root / "raw_outputs",
        reports=root / "reports",
        shared_summaries=root / "shared_flow_summaries",
        graphs=root / "graphs",
        telemetry=root / "llm_telemetry.jsonl",
        memory_audit=root / "memory_audit.jsonl",
        manifest=root / "experiment_manifest.json",
        status=root / "evaluation_status.json",
    )
