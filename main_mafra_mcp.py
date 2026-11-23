"""Entry point for the isolated MCP evidence-enrichment MAFRA version."""

import argparse
from contextlib import redirect_stdout
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from mafra_agent_mcp import MAFRAMCPAgent
from memory_manager import VALID_MEMORY_MODES, anonymous_case_id
from pipeline_errors import PipelineAbortError


def run_analysis(
    pcap_file: str,
    memory_mode: str | None = None,
    flow_summary_file: str | None = None,
    report_output: str | None = None,
    mcp_server_url: str | None = None,
    mcp_tool_name: str | None = None,
    investigation_notebook: str = "disabled",
    verbose_terminal: bool = False,
):
    """Run the new MAFRA MCP evidence-enrichment workflow."""
    print("=" * 60)
    print("MAFRA MCP - Online Evidence-Enrichment Forensic Analysis")
    print("=" * 60)

    if not os.path.exists(pcap_file):
        print(f"Error: PCAP file not found: {pcap_file}")
        return None

    safe_name = "incident.pcap"
    real_name = os.path.basename(pcap_file)
    case_id = anonymous_case_id(pcap_file)
    os.environ["FRA_CASE_ID"] = case_id
    os.environ["FRA_SYSTEM_NAME"] = "MAFRA_MCP"

    print(f"\nAnalysing: {safe_name}")
    print(f"Anonymous case ID: {case_id}")

    # Detailed diagnostic output goes to a separate file by default. The
    # evaluation report and evidence audit retain their original format.
    diagnostic_path = Path(report_output or pcap_file.replace(
        ".pcap", "_mafra_mcp_report.txt"
    )).with_suffix(".terminal.log")
    diagnostic_path.parent.mkdir(parents=True, exist_ok=True)
    diagnostic_log = None if verbose_terminal else diagnostic_path.open(
        "w", encoding="utf-8"
    )
    print("\n[1/3] Preparing network evidence...")
    verified_cookie_rpc_sequences = ()
    if flow_summary_file:
        shared_path = Path(flow_summary_file)
        if not shared_path.is_file():
            raise FileNotFoundError(f"Shared flow summary not found: {shared_path}")
        flow_summary = shared_path.read_text(encoding="utf-8", errors="replace")
        print(f"Using shared evaluation input: {shared_path}")
    else:
        from flow_summariser import FlowSummariser

        summariser = FlowSummariser()
        if verbose_terminal:
            flow_summary = summariser.run(pcap_file)
        else:
            with redirect_stdout(diagnostic_log):
                flow_summary = summariser.run(pcap_file)
        verified_cookie_rpc_sequences = tuple(summariser.verified_cookie_rpc_sequences)

    # Keep the same ground-truth protection as the original entry point.
    flow_summary = flow_summary.replace(real_name, safe_name)
    flow_summary = flow_summary.replace(real_name.replace(".pcap", ""), "incident")

    if not flow_summary_file:
        summary_file = pcap_file.replace(".pcap", "_mafra_mcp_flow_summary.txt")
        Path(summary_file).write_text(flow_summary, encoding="utf-8")
        print(f"\nFlow summary saved to: {summary_file}")

    print("[2/3] Running forensic agents and online research...")
    agent = MAFRAMCPAgent(
        current_case_id=case_id,
        memory_mode=memory_mode,
        mcp_server_url=mcp_server_url,
        mcp_tool_name=mcp_tool_name,
        investigation_notebook=investigation_notebook,
        verified_cookie_rpc_sequences=verified_cookie_rpc_sequences,
    )
    try:
        if verbose_terminal:
            final_report = agent.run(flow_summary)
        else:
            with redirect_stdout(diagnostic_log):
                final_report = agent.run(flow_summary)
    finally:
        if diagnostic_log is not None:
            diagnostic_log.close()

    # Display the existing consensus fields without changing their content.
    import re
    match = re.search(
        r"=== CONSENSUS SUMMARY ===\s*(.*?)(?=\n=== |\Z)",
        final_report, flags=re.S,
    )
    if match:
        print("\nInvestigation findings:")
        for line in match.group(1).splitlines():
            if line.startswith(("Service:", "Attack Type:", "Attack Success:",
                                "CVE:", "Overall Confidence:")):
                print("  " + line)
    else:
        print("Investigation completed. See saved report for findings.")
    if verbose_terminal:
        print("\n--- FINAL MAFRA MCP REPORT ---")
        print(final_report)

    report_file = report_output or pcap_file.replace(
        ".pcap", "_mafra_mcp_report.txt"
    )
    Path(report_file).parent.mkdir(parents=True, exist_ok=True)
    Path(report_file).write_text(
        "=== MAFRA MCP FORENSIC REPORT ===\n\n"
        f"PCAP File: {safe_name}\n\n"
        "=== FLOW SUMMARY ===\n"
        f"{flow_summary}\n\n"
        f"{final_report}",
        encoding="utf-8",
    )
    print(f"\nFull MAFRA MCP report saved to: {report_file}")

    if agent.last_online_result is not None:
        evidence_log = Path(report_file).with_suffix(".mcp_evidence.json")
        evidence_log.write_text(
            agent.last_online_result.model_dump_json(indent=2),
            encoding="utf-8",
        )
        print(f"MCP evidence audit saved to: {evidence_log}")

    print("[3/3] Saving investigation results...")
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

    if not verbose_terminal:
        print(f"Detailed terminal log saved to: {diagnostic_path}")
    import re
    final_section = re.search(
        r"^=== FINAL REPORT ===\s*\n(.*?)(?=^=== |\Z)",
        final_report,
        flags=re.MULTILINE | re.DOTALL,
    )
    print("\n" + "=" * 60)
    print("FINAL SECURITY REPORT")
    print("=" * 60)

    if final_section:
        print(final_section.group(1).strip())
    else:
         print("Final report section was not found.")
         print(f"Please review the saved technical report: {report_file}")

    print("=" * 60)
    print("MAFRA MCP analysis complete!")
    return final_report




if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="MAFRA MCP online evidence-enrichment forensic analysis"
    )
    parser.add_argument("--pcap", type=str, required=True, help="Path to the PCAP file")
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
    parser.add_argument(
        "--mcp-url",
        default=None,
        help="MCP Streamable HTTP URL; defaults to FRA_MCP_SERVER_URL.",
    )
    parser.add_argument(
        "--mcp-tool",
        default=None,
        help="MCP evidence-search tool name; defaults to FRA_MCP_SEARCH_TOOL.",
    )
    parser.add_argument(
        "--investigation-notebook", choices=["disabled", "enabled"],
        default="disabled",
        help="Opt-in ephemeral single-case notes across agent stages; "
             "never reads or stores ChromaDB memory.",
    )
    parser.add_argument(
        "--verbose-terminal", action="store_true",
        help="Print the original detailed agent and evidence output to the terminal.",
    )
    arguments = parser.parse_args()
    try:
        run_analysis(
            arguments.pcap,
            memory_mode=arguments.memory_mode,
            flow_summary_file=arguments.flow_summary_file,
            report_output=arguments.report_output,
            mcp_server_url=arguments.mcp_url,
            mcp_tool_name=arguments.mcp_tool,
            investigation_notebook=arguments.investigation_notebook,
            verbose_terminal=arguments.verbose_terminal,
        )
    except PipelineAbortError as exc:
        print(f"PIPELINE_ABORTED: {exc}", file=sys.stderr)
        raise SystemExit(2)
