import os
import argparse
from dotenv import load_dotenv
load_dotenv()
from flow_summariser import FlowSummariser
from agent import MainAgent

def run_analysis(pcap_file):
    """Run complete FRA analysis on a PCAP file"""
    print("=" * 50)
    print("FRA - Flow Reporter Agent")
    print("Cybersecurity Forensic Analysis")
    print("=" * 50)

    if not os.path.exists(pcap_file):
        print(f"Error: PCAP file not found: {pcap_file}")
        return

    # Strip filename for prompts only — keep real name for storage
    safe_name = "incident.pcap"
    real_name = os.path.basename(pcap_file)
    print(f"\nAnalysing: {safe_name}")

    # Stage 1: Flow Summariser
    print("\n--- STAGE 1: Flow Summariser ---")
    summariser = FlowSummariser()
    flow_summary = summariser.run(pcap_file)

    # Remove filename leakage from flow summary (for prompts only)
    flow_summary = flow_summary.replace(real_name, safe_name)
    flow_summary = flow_summary.replace(
        real_name.replace(".pcap", ""), "incident"
    )

    print("\nFlow Summary completed:")
    print(flow_summary[:500])
    print("...")

    summary_file = pcap_file.replace(".pcap", "_flow_summary.txt")
    with open(summary_file, "w") as f:
        f.write(flow_summary)
    print(f"\nFlow summary saved to: {summary_file}")

    # Stage 2: Main Agent Analysis
    print("\n--- STAGE 2: Main Agent Analysis ---")
    agent = MainAgent()
    final_report = agent.run(flow_summary)

    # Stage 3: Save report
    print("\n--- FINAL FORENSIC REPORT ---")
    print(final_report)

    report_file = pcap_file.replace(".pcap", "_report.txt")
    with open(report_file, "w") as f:
        f.write("=== FRA FORENSIC REPORT ===\n\n")
        f.write(f"PCAP File: {safe_name}\n\n")
        f.write("=== FLOW SUMMARY ===\n")
        f.write(flow_summary)
        f.write("\n\n=== FINAL REPORT ===\n")
        f.write(final_report)

    print(f"\nFull report saved to: {report_file}")

    # Stage 4: Store in ChromaDB — use REAL filename as key
    # This ensures each PCAP gets its own entry, not overwritten
    print("\n--- STAGE 4: Storing in Memory (ChromaDB) ---")
    agent.memory_manager.store(
        pcap_name=real_name,  # CVE-2022-24706.pcap, CVE-2016-5734.pcap etc.
        flow_summary=flow_summary,
        report=final_report
    )
    count = agent.memory_manager.count()
    print(f"Stored analysis for: {real_name}")
    print(f"Total cases in memory: {count}")

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
        help="Path to the PCAP file to analyse"
    )
    args = parser.parse_args()
    run_analysis(args.pcap)