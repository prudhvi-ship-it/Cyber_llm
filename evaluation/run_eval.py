import argparse
from datetime import datetime, timezone
import os
import re
import pandas as pd

from evaluation.loader import load_ground_truth
from evaluation.runner import run_fra, run_mafra, run_shared_preprocessing
from evaluation.report_reader import parse_saved_report
from evaluation.matcher import match_text, match_cve, match_vulnerable, match_success
from evaluation.labels import display_label, parse_binary_label
from evaluation.metrics import calculate_summary, calculate_classification_stats
from evaluation.graphs import create_graphs
from evaluation.report import save_reports
from evaluation.experiment import (
    evaluate_completeness,
    manifest_dataframe,
    telemetry_dataframe,
    telemetry_summary_dataframe,
    write_json,
)
from evaluation.config import DATASET_DIR, OUTPUT_DIR
from evaluation.run_paths import build_run_paths, validate_run_id
from experiment_config import EXPERIMENT_PROFILES, experiment_manifest
from memory_manager import MemoryManager


EVALUATION_SCHEMA_VERSION = "4.1-evidence-rag-audited-runs"


def parse_memory_status(output):
    match = re.search(r"RAG:\s*mode=([a-z_]+)", str(output), re.IGNORECASE)
    return match.group(1).lower() if match else "unavailable"


def require_training_rag(run_id):
    """Fail before paid evaluation calls when approved training RAG is absent."""
    manager = MemoryManager(
        system_name="EVALUATION_PREFLIGHT",
        current_case_id="training_rag_preflight",
        mode="read_only",
        run_id=run_id,
        audit_path="",
    )
    health = manager.health()
    if health["status"] != "read_only" or int(health["count"]) <= 0:
        details = health.get("error") or "collection is empty"
        raise RuntimeError(
            "Approved training RAG is not ready. "
            f"Collection [{health['collection']}] status={health['status']}, "
            f"count={health['count']}. Details: {details}. "
            "Build it from an independent approved training-only JSONL file with "
            "training_memory_builder.py. Do not use MAFRA_Eval30 or "
            "evaluation_outputs as training data."
        )
    return health


def load_existing_results(results_csv):
    if results_csv.exists():
        existing = pd.read_csv(results_csv)
        if (
            "evaluation_schema_version" not in existing.columns
            or not existing["evaluation_schema_version"]
            .astype(str)
            .eq(EVALUATION_SCHEMA_VERSION)
            .all()
        ):
            raise ValueError(
                "The existing evaluation CSV uses the old incorrect scoring. "
                "Do not use --resume with it. Run a fresh evaluation so every "
                "case is recalculated with tri-state scoring."
            )
        return existing
    return pd.DataFrame()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--skip-fra", action="store_true")
    parser.add_argument("--skip-mafra", action="store_true")
    parser.add_argument(
        "--run-id",
        default=None,
        help="Optional experiment ID written to audit output.",
    )
    parser.add_argument(
        "--memory-mode",
        choices=["disabled", "read_only"],
        default="disabled",
        help="Use disabled for leakage-free ablation or read_only for approved training RAG.",
    )
    parser.add_argument(
        "--profile",
        choices=sorted(EXPERIMENT_PROFILES),
        default="heterogeneous",
        help="Default preserves the proposed GPT/Claude/Gemini MAFRA system.",
    )
    args = parser.parse_args()
    if args.resume and not args.run_id:
        raise ValueError("--resume requires the original --run-id.")
    run_id = validate_run_id(args.run_id or datetime.now(timezone.utc).strftime(
        "evaluation_%Y%m%dT%H%M%SZ"
    ))
    memory_mode = args.memory_mode
    profile = args.profile
    if args.skip_fra and args.skip_mafra:
        raise ValueError("FRA and MAFRA cannot both be skipped.")
    active_systems = []
    if not args.skip_fra:
        active_systems.append("fra")
    if not args.skip_mafra:
        active_systems.append("mafra")

    os.environ["FRA_RUN_ID"] = run_id
    os.environ["FRA_MEMORY_MODE"] = memory_mode
    os.environ["FRA_EXPERIMENT_PROFILE"] = profile
    training_rag_health = None
    if memory_mode == "read_only":
        training_rag_health = require_training_rag(run_id)

    paths = build_run_paths(OUTPUT_DIR, run_id)
    run_output_dir = paths.root
    results_csv = paths.results_csv
    raw_output_dir = paths.raw_outputs
    telemetry_path = paths.telemetry
    memory_audit_path = paths.memory_audit
    if paths.root.exists() and not args.resume:
        raise FileExistsError(
            f"Output already exists for run ID '{run_id}'. Use a new --run-id "
            "or use --resume for the same experiment."
        )
    if args.resume and not paths.root.exists():
        raise FileNotFoundError(
            f"Cannot resume because the run folder does not exist: {run_output_dir}"
        )
    print(f"Evaluation run ID: {run_id}")
    print(f"Memory mode: {memory_mode}")
    if memory_mode == "disabled":
        print("This run is a no-memory ablation; test cases cannot leak through RAG.")
    else:
        print("Training RAG is read-only; evaluation cases cannot be stored.")
        print(
            "Training RAG ready: "
            f"collection={training_rag_health['collection']}, "
            f"cases={training_rag_health['count']}"
        )
    print(f"Experiment profile: {profile}")
    print("Shared flow summary: enabled (same input for FRA and MAFRA)")

    initial_manifest = experiment_manifest(profile)
    initial_manifest["run_id"] = run_id
    initial_manifest["evaluation_schema_version"] = EVALUATION_SCHEMA_VERSION
    initial_manifest["active_systems"] = active_systems
    initial_manifest["training_rag_health"] = training_rag_health
    write_json(paths.manifest, initial_manifest)

    raw_output_dir.mkdir(parents=True, exist_ok=True)

    full_ground_truth = load_ground_truth()
    gt = load_ground_truth(limit=args.limit)
    existing_df = (
        load_existing_results(results_csv) if args.resume else pd.DataFrame()
    )
    if not existing_df.empty:
        existing_run_ids = set(existing_df["run_id"].astype(str))
        if existing_run_ids != {run_id}:
            raise ValueError(
                f"Resume run ID mismatch. Existing run IDs: {sorted(existing_run_ids)}"
            )
        existing_profiles = set(existing_df["experiment_profile"].astype(str))
        if existing_profiles != {profile}:
            raise ValueError(
                "Resume profile does not match the existing experiment results."
            )
        existing_memory_modes = set(existing_df["memory_mode"].astype(str))
        if existing_memory_modes != {memory_mode}:
            raise ValueError(
                "Resume memory mode does not match the existing experiment results."
            )

    completed_ids = set()
    rows = []

    if not existing_df.empty:
        completed_ids = set(existing_df["id"].astype(str))
        rows = existing_df.to_dict("records")
        print(f"Resume enabled. Found {len(completed_ids)} completed cases.")

    total = len(gt)

    for index, case in gt.iterrows():
        case_id = str(case["ID"])

        if args.resume and case_id in completed_ids:
            print(f"Skipping completed case: {case_id}")
            continue

        pcap_path = DATASET_DIR / case["PCAP Path"]
        report_directory = paths.reports
        fra_report_path = report_directory / f"{case_id}_fra_report.txt"
        mafra_report_path = report_directory / f"{case_id}_mafra_report.txt"
        shared_summary_path = (
            paths.shared_summaries / f"{case_id}.txt"
        )

        print(f"\n[{index + 1}/{total}] Running {case_id}: {pcap_path}")

        if args.skip_fra and args.skip_mafra:
            shared_run = {"output": "Skipped", "runtime": 0, "crashed": False}
        else:
            shared_run = run_shared_preprocessing(
                pcap_path,
                shared_summary_path,
                run_id=run_id,
                profile=profile,
                telemetry_path=telemetry_path,
                memory_audit_path=memory_audit_path,
            )
            (raw_output_dir / f"{case_id}_shared_stdout.txt").write_text(
                shared_run["output"], encoding="utf-8"
            )
            if not shared_summary_path.exists():
                shared_run["crashed"] = True

        if args.skip_fra:
            fra_run = {"output": "", "runtime": 0, "crashed": False}
            fra = {
                "service": "Skipped",
                "attack_type": "Skipped",
                "attack_success": "Skipped",
                "cve": "Skipped",
                "vulnerable": "Skipped",
                "report_found": False,
            }
        elif shared_run["crashed"]:
            fra_run = {"output": "Shared preprocessing failed", "runtime": 0, "crashed": True}
            fra = {
                "service": "Not Found",
                "attack_type": "Not Found",
                "attack_success": "Not Found",
                "cve": "Not Found",
                "vulnerable": "Not Found",
                "report_found": False,
            }
        else:
            fra_run = run_fra(
                pcap_path,
                flow_summary_file=shared_summary_path,
                report_output=fra_report_path,
                run_id=run_id,
                memory_mode=memory_mode,
                profile=profile,
                telemetry_path=telemetry_path,
                memory_audit_path=memory_audit_path,
            )
            (raw_output_dir / f"{case_id}_fra_stdout.txt").write_text(
                fra_run["output"], encoding="utf-8"
            )
            fra = parse_saved_report(fra_report_path)
            fra_run["crashed"] = bool(fra_run["crashed"] or not fra["report_found"])

        if args.skip_mafra:
            mafra_run = {"output": "", "runtime": 0, "crashed": False}
            mafra = {
                "service": "Skipped",
                "attack_type": "Skipped",
                "attack_success": "Skipped",
                "cve": "Skipped",
                "vulnerable": "Skipped",
                "report_found": False,
            }
        elif shared_run["crashed"]:
            mafra_run = {"output": "Shared preprocessing failed", "runtime": 0, "crashed": True}
            mafra = {
                "service": "Not Found",
                "attack_type": "Not Found",
                "attack_success": "Not Found",
                "cve": "Not Found",
                "vulnerable": "Not Found",
                "report_found": False,
            }
        else:
            mafra_run = run_mafra(
                pcap_path,
                flow_summary_file=shared_summary_path,
                report_output=mafra_report_path,
                run_id=run_id,
                memory_mode=memory_mode,
                profile=profile,
                telemetry_path=telemetry_path,
                memory_audit_path=memory_audit_path,
            )
            (raw_output_dir / f"{case_id}_mafra_stdout.txt").write_text(
                mafra_run["output"], encoding="utf-8"
            )
            mafra = parse_saved_report(mafra_report_path)
            mafra_run["crashed"] = bool(mafra_run["crashed"] or not mafra["report_found"])

        row = {
            "evaluation_schema_version": EVALUATION_SCHEMA_VERSION,
            "id": case_id,
            "run_id": run_id,
            "memory_mode": memory_mode,
            "experiment_profile": profile,
            "shared_flow_summary": True,
            "benchmark": case["Benchmark"],
            "pcap": case["PCAP File"],

            "expected_service": case["Expected Service"],
            "expected_cve": case["Expected CVE"],
            "expected_success": case["Expected Success"],
            "expected_vulnerable": case["Expected Vulnerable"],

            "fra_service": fra["service"],
            "fra_attack_type": fra["attack_type"],
            "fra_attack_success": fra["attack_success"],
            "fra_cve": fra["cve"],
            "fra_vulnerable": fra["vulnerable"],
            "fra_report_found": fra["report_found"],
            "fra_memory_status": (
                "skipped" if args.skip_fra else parse_memory_status(fra_run["output"])
            ),
            "shared_preprocessing_runtime": shared_run["runtime"],
            "shared_preprocessing_crashed": shared_run["crashed"],
            "fra_reasoning_runtime": fra_run["runtime"],
            "fra_runtime": round(shared_run["runtime"] + fra_run["runtime"], 2),
            "fra_crashed": fra_run["crashed"],

            "mafra_service": mafra["service"],
            "mafra_attack_type": mafra["attack_type"],
            "mafra_attack_success": mafra["attack_success"],
            "mafra_cve": mafra["cve"],
            "mafra_vulnerable": mafra["vulnerable"],
            "mafra_report_found": mafra["report_found"],
            "mafra_memory_status": (
                "skipped"
                if args.skip_mafra
                else parse_memory_status(mafra_run["output"])
            ),
            "mafra_reasoning_runtime": mafra_run["runtime"],
            "mafra_runtime": round(shared_run["runtime"] + mafra_run["runtime"], 2),
            "mafra_crashed": mafra_run["crashed"],
        }

        row["fra_service_match"] = match_text(row["expected_service"], row["fra_service"])
        row["mafra_service_match"] = match_text(row["expected_service"], row["mafra_service"])

        row["fra_cve_match"] = match_cve(row["expected_cve"], row["fra_cve"])
        row["mafra_cve_match"] = match_cve(row["expected_cve"], row["mafra_cve"])

        row["fra_vulnerable_match"] = match_vulnerable(row["expected_vulnerable"], row["fra_vulnerable"])
        row["mafra_vulnerable_match"] = match_vulnerable(row["expected_vulnerable"], row["mafra_vulnerable"])

        row["fra_success_match"] = match_success(row["expected_success"], row["fra_attack_success"])
        row["mafra_success_match"] = match_success(row["expected_success"], row["mafra_attack_success"])

        # Keep canonical tri-state predictions in the raw results for auditing.
        row["expected_vulnerability_label"] = display_label(
            parse_binary_label(row["expected_vulnerable"], "vulnerability"),
            "vulnerability",
        )
        row["fra_vulnerability_label"] = display_label(
            parse_binary_label(row["fra_vulnerable"], "vulnerability"),
            "vulnerability",
        )
        row["mafra_vulnerability_label"] = display_label(
            parse_binary_label(row["mafra_vulnerable"], "vulnerability"),
            "vulnerability",
        )
        row["expected_success_label"] = display_label(
            parse_binary_label(row["expected_success"], "success"),
            "success",
        )
        row["fra_success_label"] = display_label(
            parse_binary_label(row["fra_attack_success"], "success"),
            "success",
        )
        row["mafra_success_label"] = display_label(
            parse_binary_label(row["mafra_attack_success"], "success"),
            "success",
        )

        rows.append(row)

        temp_df = pd.DataFrame(rows)
        temp_summary = calculate_summary(temp_df, systems=active_systems)
        temp_stats = calculate_classification_stats(
            temp_df, systems=active_systems
        )

        current_telemetry = telemetry_dataframe(telemetry_path)
        save_reports(
            temp_df,
            temp_summary,
            temp_stats,
            telemetry_df=current_telemetry,
            telemetry_summary_df=telemetry_summary_dataframe(current_telemetry),
            manifest_df=manifest_dataframe(profile, run_id),
            output_dir=run_output_dir,
        )
        progress_status = evaluate_completeness(
            temp_df,
            full_ground_truth["ID"],
            profile=profile,
            memory_mode=memory_mode,
            skipped_fra=args.skip_fra,
            skipped_mafra=args.skip_mafra,
            telemetry_error_count=int(
                current_telemetry["status"].eq("error").sum()
            ),
        )
        write_json(paths.status, progress_status)
        print(f"Saved progress after {case_id}")

    results_df = pd.DataFrame(rows)

    summary_df = calculate_summary(results_df, systems=active_systems)
    stats_df = calculate_classification_stats(
        results_df, systems=active_systems
    )

    final_telemetry = telemetry_dataframe(telemetry_path)
    save_reports(
        results_df,
        summary_df,
        stats_df,
        telemetry_df=final_telemetry,
        telemetry_summary_df=telemetry_summary_dataframe(final_telemetry),
        manifest_df=manifest_dataframe(profile, run_id),
        output_dir=run_output_dir,
    )
    create_graphs(
        results_df,
        summary_df,
        stats_df,
        graph_dir=paths.graphs,
        systems=active_systems,
    )

    completeness = evaluate_completeness(
        results_df,
        full_ground_truth["ID"],
        profile=profile,
        memory_mode=memory_mode,
        skipped_fra=args.skip_fra,
        skipped_mafra=args.skip_mafra,
        telemetry_error_count=int(final_telemetry["status"].eq("error").sum()),
    )
    manifest = experiment_manifest(profile)
    manifest["run_id"] = run_id
    manifest["evaluation_schema_version"] = EVALUATION_SCHEMA_VERSION
    manifest["active_systems"] = active_systems
    manifest["training_rag_health"] = training_rag_health
    write_json(paths.status, completeness)
    write_json(paths.manifest, manifest)

    print(f"\nEvaluation status: {completeness['status']}")
    if completeness["reasons"]:
        for reason in completeness["reasons"]:
            print(f"- {reason}")
    print(f"Results saved in: {run_output_dir}")


if __name__ == "__main__":
    main()
