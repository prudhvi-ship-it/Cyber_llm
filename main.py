import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from agent import MainAgent
from flow_summariser import FlowSummariser
from memory_manager import VALID_MEMORY_MODES, anonymous_case_id
from pipeline_errors import PipelineAbortError


def run_analysis(
    pcap_file: str,
    memory_mode: str | None = None,
    flow_summary_file: str | None = None,
    report_output: str | None = None,
):
    """Run complete FRA analysis on a PCAP file."""
    print("=" * 50)
    print("FRA - Flow Reporter Agent")
    print("Cybersecurity Forensic Analysis")
    print("=" * 50)

    if not os.path.exists(pcap_file):
        print(f"Error: PCAP file not found: {pcap_file}")
        return None

    safe_name = "incident.pcap"
    real_name = os.path.basename(pcap_file)
    case_id = anonymous_case_id(pcap_file)
    os.environ["FRA_CASE_ID"] = case_id
    os.environ["FRA_SYSTEM_NAME"] = "FRA"
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

    # The ground-truth CVE may be present in a benchmark filename. Never send it
    # to an LLM or memory collection.
    flow_summary = flow_summary.replace(real_name, safe_name)
    flow_summary = flow_summary.replace(real_name.replace(".pcap", ""), "incident")

    print("\nFlow Summary completed:")
    print(flow_summary[:500])
    print("...")

    if not flow_summary_file:
        summary_file = pcap_file.replace(".pcap", "_flow_summary.txt")
        with open(summary_file, "w", encoding="utf-8") as handle:
            handle.write(flow_summary)
        print(f"\nFlow summary saved to: {summary_file}")
    else:
        print("\nShared flow summary already stored in the experiment folder.")

    print("\n--- STAGE 2: Main Agent Analysis ---")
    agent = MainAgent(
        current_case_id=case_id,
        memory_mode=memory_mode,
    )
    final_report = agent.run(flow_summary)

    print("\n--- FINAL FORENSIC REPORT ---")
    print(final_report)

    report_file = report_output or pcap_file.replace(".pcap", "_report.txt")
    Path(report_file).parent.mkdir(parents=True, exist_ok=True)
    with open(report_file, "w", encoding="utf-8") as handle:
        handle.write("=== FRA FORENSIC REPORT ===\n\n")
        handle.write(f"PCAP File: {safe_name}\n\n")
        handle.write("=== FLOW SUMMARY ===\n")
        handle.write(flow_summary)
        handle.write("\n\n=== FINAL REPORT ===\n")
        handle.write(final_report)
    print(f"\nFull report saved to: {report_file}")

    print("\n--- STAGE 4: Memory (ChromaDB) ---")
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

    print("\nAnalysis complete!")
    return final_report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="FRA - Flow Reporter Agent for Forensic Analysis"
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
