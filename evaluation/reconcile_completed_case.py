"""Reconcile an already-complete PCAP that was mislabeled crashed by the old evaluator.

Conservative, offline and narrowly scoped. It never calls LLMs or writes a
report. It retains the error telemetry for auditing.
"""

import argparse
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys


def reconcile(run_dir: Path, case_id: str) -> dict:
    run_dir = Path(run_dir)
    csv_path = run_dir / "evaluation_results.csv"
    status_path = run_dir / "evaluation_status.json"
    log_path = run_dir / "raw_outputs" / f"{case_id}_mafra_stdout.txt"
    report_path = run_dir / "reports" / f"{case_id}_mafra_report.txt"

    for path in (csv_path, status_path, log_path, report_path):
        if not path.is_file():
            raise FileNotFoundError(f"Required evaluation artifact missing: {path}")
    status = json.loads(status_path.read_text(encoding="utf-8"))
    observed = int(status.get("observed_case_count", -1))
    expected = int(status.get("expected_case_count", -2))
    if observed != expected or expected != 30:
        raise RuntimeError(
            f"Refusing to refresh an incomplete dataset: observed={observed}, expected={expected}."
        )

    console = log_path.read_text(encoding="utf-8", errors="replace")
    marker = "MAFRA MCP analysis complete!"
    if marker not in console:
        raise RuntimeError(f"No normal completion marker in {log_path}")
    if "Traceback (most recent call last)" in console.split(marker)[-1]:
        raise RuntimeError("Traceback found after completion marker; aborting")
    report_text = report_path.read_text(encoding="utf-8", errors="replace")
    if "=== CONSENSUS SUMMARY ===" not in report_text:
        raise RuntimeError("Report lacks a final consensus section; aborting")

    with csv_path.open("r", newline="", encoding="utf-8-sig") as infile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames
        rows = list(reader)
    if not fieldnames or "id" not in fieldnames or "mafra_crashed" not in fieldnames:
        raise RuntimeError("Missing required CSV columns")
    matches = [r for r in rows if r["id"] == case_id]
    if len(matches) != 1:
        raise RuntimeError(f"Expected one result for {case_id}; found {len(matches)}")
    row = matches[0]
    if row.get("mafra_report_found", "").strip().lower() != "true":
        raise RuntimeError("Report was not marked present; aborting")
    if row["mafra_crashed"].strip().lower() != "true":
        raise RuntimeError(f"{case_id} is not recorded as crashed; no correction needed")
    if not all(row.get(k, "") in ("Unknown", "Not Found") for k in
               ("mafra_service", "mafra_attack_type", "mafra_cve")):
        raise RuntimeError("This case is not the all-inconclusive false-crash pattern")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = csv_path.with_name(f"evaluation_results.before_{case_id}_{timestamp}.csv")
    shutil.copy2(csv_path, backup_path)
    row["mafra_crashed"] = "False"
    staged_path = csv_path.with_suffix(".csv.tmp")
    try:
        with staged_path.open("w", newline="", encoding="utf-8") as outfile:
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        staged_path.replace(csv_path)
    finally:
        staged_path.unlink(missing_ok=True)
    audit = {
        "case_id": case_id,
        "timestamp_utc": timestamp,
        "reason": "completed subprocess was incorrectly marked crashed for all Unknown/Not Found fields",
        "change": {"mafra_crashed": {"old": "True", "new": "False"}},
        "original_csv_backup": backup_path.name,
        "telemetry": "Unmodified: recorded JSONDecodeError is retained as a separate warning",
        "forensic_predictions": "Unmodified: all conclusions and correctness labels preserved",
    }
    audit_path = run_dir / f"reconciliation_{case_id}.json"
    audit_path.write_text(json.dumps(audit, indent=2), encoding="utf-8")
    return {"backup": str(backup_path), "audit": str(audit_path)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--case-id", required=True)
    args = parser.parse_args()
    try:
        result = reconcile(args.run_dir, args.case_id)
    except Exception as exc:
        print(f"No changes made: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    print("Corrected false-crash flag; predictions and telemetry unchanged.")
    print("Original CSV backup:", result["backup"])
    print("Audit:", result["audit"])


if __name__ == "__main__":
    main()
