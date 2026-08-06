"""Offline PCAP/Tshark preflight check. This script makes no LLM API calls."""

import argparse
import json

from flow_summariser import FlowSummariser, PcapAnalysisError


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate Tshark access and inspect a PCAP without an LLM call."
    )
    parser.add_argument("--pcap", required=True, help="Path to .pcap/.pcapng/.cap")
    parser.add_argument(
        "--tshark",
        default=None,
        help="Optional explicit path to tshark.exe",
    )
    args = parser.parse_args()

    try:
        result = FlowSummariser.preflight(args.pcap, tshark_path=args.tshark)
    except (PcapAnalysisError, FileNotFoundError) as exc:
        print(
            json.dumps(
                {"status": "Error", "error_type": type(exc).__name__, "message": str(exc)},
                indent=2,
            )
        )
        return 1

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
