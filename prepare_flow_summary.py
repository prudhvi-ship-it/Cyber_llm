"""Generate one shared LLM flow summary for a fair FRA/MAFRA comparison."""

import argparse
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from flow_summariser import FlowSummariser
from flow_summary_io import sanitize_summary
from memory_manager import anonymous_case_id


def prepare(pcap_file: str, output_file: str) -> str:
    path = Path(pcap_file)
    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    case_id = anonymous_case_id(path)
    os.environ["FRA_CASE_ID"] = case_id
    os.environ["FRA_SYSTEM_NAME"] = "SHARED"

    summary = sanitize_summary(FlowSummariser().run(str(path)), str(path))
    destination = Path(output_file)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(summary, encoding="utf-8")
    print(f"Shared flow summary saved: {destination}")
    print(f"Anonymous case ID: {case_id}")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create one shared flow summary")
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args()
    prepare(arguments.pcap, arguments.output)
