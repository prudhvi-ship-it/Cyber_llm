import os
import subprocess
import sys
import time

from evaluation.config import PROJECT_ROOT
from experiment_config import DEFAULT_EXPERIMENT_PROFILE


def run_command(
    script_name,
    arguments,
    *,
    run_id="evaluation",
    memory_mode="disabled",
    profile=DEFAULT_EXPERIMENT_PROFILE,
    system_name="UNKNOWN",
    telemetry_path=None,
    memory_audit_path=None,
):
    start = time.time()
    child_environment = os.environ.copy()
    child_environment["FRA_RUN_ID"] = str(run_id)
    child_environment["FRA_MEMORY_MODE"] = str(memory_mode)
    child_environment["FRA_EXPERIMENT_PROFILE"] = str(profile)
    child_environment["FRA_SYSTEM_NAME"] = str(system_name)
    child_environment["PYTHONUTF8"] = "1"
    if telemetry_path is not None:
        child_environment["FRA_TELEMETRY_PATH"] = str(telemetry_path)
    if memory_audit_path is not None:
        child_environment["FRA_MEMORY_AUDIT_PATH"] = str(memory_audit_path)

    result = subprocess.run(
        [sys.executable, script_name, *[str(value) for value in arguments]],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=child_environment,
    )
    runtime = round(time.time() - start, 2)
    return {
        "output": result.stdout + "\n" + result.stderr,
        "runtime": runtime,
        "crashed": result.returncode != 0,
        "returncode": result.returncode,
    }


def run_shared_preprocessing(
    pcap_path,
    output_path,
    *,
    run_id="evaluation",
    profile=DEFAULT_EXPERIMENT_PROFILE,
    telemetry_path=None,
    memory_audit_path=None,
):
    return run_command(
        "prepare_flow_summary.py",
        ["--pcap", pcap_path, "--output", output_path],
        run_id=run_id,
        memory_mode="disabled",
        profile=profile,
        system_name="SHARED",
        telemetry_path=telemetry_path,
        memory_audit_path=memory_audit_path,
    )


def run_fra(
    pcap_path,
    *,
    flow_summary_file=None,
    report_output=None,
    run_id="evaluation",
    memory_mode="disabled",
    profile=DEFAULT_EXPERIMENT_PROFILE,
    telemetry_path=None,
    memory_audit_path=None,
):
    arguments = ["--pcap", pcap_path, "--memory-mode", memory_mode]
    if flow_summary_file is not None:
        arguments.extend(["--flow-summary-file", flow_summary_file])
    if report_output is not None:
        arguments.extend(["--report-output", report_output])
    return run_command(
        "main.py",
        arguments,
        run_id=run_id,
        memory_mode=memory_mode,
        profile=profile,
        system_name="FRA",
        telemetry_path=telemetry_path,
        memory_audit_path=memory_audit_path,
    )


def run_mafra(
    pcap_path,
    *,
    flow_summary_file=None,
    report_output=None,
    run_id="evaluation",
    memory_mode="disabled",
    profile=DEFAULT_EXPERIMENT_PROFILE,
    telemetry_path=None,
    memory_audit_path=None,
):
    arguments = ["--pcap", pcap_path, "--memory-mode", memory_mode]
    if flow_summary_file is not None:
        arguments.extend(["--flow-summary-file", flow_summary_file])
    if report_output is not None:
        arguments.extend(["--report-output", report_output])
    return run_command(
        "main_mafra.py",
        arguments,
        run_id=run_id,
        memory_mode=memory_mode,
        profile=profile,
        system_name="MAFRA",
        telemetry_path=telemetry_path,
        memory_audit_path=memory_audit_path,
    )


def run_mafra_mcp(
    pcap_path,
    *,
    report_output=None,
    mcp_url=None,
    investigation_notebook="enabled",
    run_id="evaluation",
    memory_mode="disabled",
    profile=DEFAULT_EXPERIMENT_PROFILE,
    telemetry_path=None,
    memory_audit_path=None,
):
    """Run MCP directly on the PCAP so in-process packet checks are preserved."""
    arguments = [
        "--pcap", pcap_path,
        "--memory-mode", memory_mode,
        "--investigation-notebook", investigation_notebook,
    ]
    if report_output is not None:
        arguments.extend(["--report-output", report_output])
    if mcp_url is not None:
        arguments.extend(["--mcp-url", mcp_url])
    return run_command(
        "main_mafra_mcp.py",
        arguments,
        run_id=run_id,
        memory_mode=memory_mode,
        profile=profile,
        system_name="MAFRA_MCP",
        telemetry_path=telemetry_path,
        memory_audit_path=memory_audit_path,
    )
