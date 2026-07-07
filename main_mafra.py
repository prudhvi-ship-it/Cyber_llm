import os
import argparse
from dotenv import load_dotenv
from flow_summariser import FlowSummariser
from mafra_agent import MAFRAAgent

load_dotenv()


def run_analysis(pcap_file):
    print("=" * 50)
    print("MAFRA - Multi-Agent Forensic Reasoning Architecture")
    print("Cybersecurity Forensic Analysis")
    print("=" * 50)

    if not os.path.exists(pcap_file):
        print(f"Error: PCAP file not found: {pcap_file}")
        return

    safe_name = "incident.pcap"
    real_name = os.path.basename(pcap_file)

    print(f"\nAnalysing: {safe_name}")

    print("\n--- STAGE 1: Flow Summariser ---")
    summariser = FlowSummariser()
    flow_summary = summariser.run(pcap_file)

    flow_summary = flow_summary.replace(real_name, safe_name)
    flow_summary = flow_summary.replace(
        real_name.replace(".pcap", ""),
        "incident"
    )

    summary_file = pcap_file.replace(".pcap", "_mafra_flow_summary.txt")
    with open(summary_file, "w") as f:
        f.write(flow_summary)

    print(f"\nFlow summary saved to: {summary_file}")

    print("\n--- STAGE 2: MAFRA Multi-Agent Analysis ---")
    agent = MAFRAAgent()
    final_report = agent.run(flow_summary)

    print("\n--- FINAL MAFRA REPORT ---")
    print(final_report)

    report_file = pcap_file.replace(".pcap", "_mafra_report.txt")
    with open(report_file, "w") as f:
        f.write("=== MAFRA FORENSIC REPORT ===\n\n")
        f.write(f"PCAP File: {safe_name}\n\n")
        f.write("=== FLOW SUMMARY ===\n")
        f.write(flow_summary)
        f.write("\n\n")
        f.write(final_report)

    print(f"\nFull MAFRA report saved to: {report_file}")

    print("\n--- STAGE 3: Storing in Memory (ChromaDB) ---")
    agent.memory_manager.store(
        pcap_name=f"MAFRA_{real_name}",
        flow_summary=flow_summary,
        report=final_report
    )

    count = agent.memory_manager.count()
    print(f"Stored MAFRA analysis for: {real_name}")
    print(f"Total cases in memory: {count}")

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
        help="Path to the PCAP file to analyse"
    )

    args = parser.parse_args()
    run_analysis(args.pcap)