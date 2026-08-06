import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from flow_summariser import FlowSummariser
from mafra_agent import MAFRAAgent
from memory_manager import VALID_MEMORY_MODES, anonymous_case_id
from pipeline_errors import PipelineAbortError


def run_analysis(
    pcap_file: str,
    memory_mode: str | None = None,
    flow_summary_file: str | None = None,
    report_output: str | None = None,
):
    """Run complete MAFRA analysis on a PCAP file."""
    print("=" * 50)
    print("MAFRA - Multi-Agent Forensic Reasoning Architecture")
    print("Cybersecurity Forensic Analysis")
    print("=" * 50)

    if not os.path.exists(pcap_file):
        print(f"Error: PCAP file not found: {pcap_file}")
        return None

    safe_name = "incident.pcap"
    real_name = os.path.basename(pcap_file)
    case_id = anonymous_case_id(pcap_file)
    os.environ["FRA_CASE_ID"] = case_id
    os.environ["FRA_SYSTEM_NAME"] = "MAFRA"
    print(f"\nAnalysing: {safe_name}")
    print(f"Anonymous case ID: {case_id}")

    print("\n--- STAGE 1: Flow Summariser ---")
    if flow_summary_file:
        shared_path = Path(flow_summary_file)
        if not shared_path.is_file():
            raise FileNotFoundError(f"Shared flow summary not found: {shared_path}")
        flow_summary = shared_path.read_text(encoding="utf-8", errors="replace")
        print(f"Using shared evaluation input: {shared_path}")
    else:
        summariser = FlowSummariser()
        flow_summary = summariser.run(pcap_file)

    # Remove possible ground-truth answers contained in benchmark filenames.
    flow_summary = flow_summary.replace(real_name, safe_name)
    flow_summary = flow_summary.replace(real_name.replace(".pcap", ""), "incident")

    if not flow_summary_file:
        summary_file = pcap_file.replace(".pcap", "_mafra_flow_summary.txt")
        with open(summary_file, "w", encoding="utf-8") as handle:
            handle.write(flow_summary)
        print(f"\nFlow summary saved to: {summary_file}")
    else:
        print("\nShared flow summary already stored in the experiment folder.")

    print("\n--- STAGE 2: MAFRA Multi-Agent Analysis ---")
    agent = MAFRAAgent(
        current_case_id=case_id,
        memory_mode=memory_mode,
    )
    final_report = agent.run(flow_summary)

    print("\n--- FINAL MAFRA REPORT ---")
    print(final_report)

    report_file = report_output or pcap_file.replace(".pcap", "_mafra_report.txt")
    Path(report_file).parent.mkdir(parents=True, exist_ok=True)
    with open(report_file, "w", encoding="utf-8") as handle:
        handle.write("=== MAFRA FORENSIC REPORT ===\n\n")
        handle.write(f"PCAP File: {safe_name}\n\n")
        handle.write("=== FLOW SUMMARY ===\n")
        handle.write(flow_summary)
        handle.write("\n\n")
        handle.write(final_report)
    print(f"\nFull MAFRA report saved to: {report_file}")

    print("\n--- STAGE 3: Memory (ChromaDB) ---")
    stored = agent.memory_manager.store(
        case_id=case_id,
        flow_summary=flow_summary,
        report=final_report,
    )
    if stored:
        print(f"Stored anonymous case: {case_id}")
    else:
        print(f"Memory storage skipped: mode={agent.memory_manager.status()}")
    print(f"Total cases in this isolated collection: {agent.memory_manager.count()}")

    print("\nMAFRA analysis complete!")
    return final_report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="MAFRA - Multi-Agent Forensic Reasoning Architecture"
    )
    parser.add_argument(
        "--pcap",
        type=str,
        required=True,
        help="Path to the PCAP file to analyse",
    )
    parser.add_argument(
        "--memory-mode",
        choices=sorted(VALID_MEMORY_MODES),
        default=None,
        help="Memory mode. Evaluation should use disabled.",
    )
    parser.add_argument(
        "--flow-summary-file",
        default=None,
        help="Pre-generated shared summary used for a fair comparison.",
    )
    parser.add_argument(
        "--report-output",
        default=None,
        help="Optional run-specific report destination.",
    )
    arguments = parser.parse_args()
    try:
        run_analysis(
            arguments.pcap,
            memory_mode=arguments.memory_mode,
            flow_summary_file=arguments.flow_summary_file,
            report_output=arguments.report_output,
        )
    except PipelineAbortError as exc:
        print(f"PIPELINE_ABORTED: {exc}", file=sys.stderr)
        raise SystemExit(2)
