import subprocess
from langchain_core.prompts import PromptTemplate
from prompts import FLOW_SUMMARISER_PROMPT
from llm_client import get_llm
from evidence_extractor import EvidenceExtractor


class FlowSummariser:
    def __init__(self):
        self.llm = get_llm()
        self.extractor = EvidenceExtractor()
        self.prompt = PromptTemplate(
            input_variables=["flow_content"],
            template=FLOW_SUMMARISER_PROMPT
        )

    def get_connections(self, pcap_file):
        """Get list of all TCP connections from PCAP file."""
        try:
            result = subprocess.run(
                ["tshark", "-r", pcap_file, "-q", "-z", "conv,tcp"],
                capture_output=True,
                text=True
            )
            return result.stdout
        except Exception as e:
            return f"Error reading PCAP: {e}"

    def get_flow_content(self, pcap_file, stream_number):
        """Get content of a specific TCP flow."""
        try:
            result = subprocess.run(
                [
                    "tshark", "-r", pcap_file, "-q", "-z",
                    f"follow,tcp,ascii,{stream_number}"
                ],
                capture_output=True,
                text=True
            )
            return result.stdout
        except Exception as e:
            return f"Error reading flow: {e}"

    def count_streams(self, pcap_file):
        """Count total number of TCP streams."""
        try:
            result = subprocess.run(
                [
                    "tshark", "-r", pcap_file, "-T", "fields",
                    "-e", "tcp.stream"
                ],
                capture_output=True,
                text=True
            )
            streams = set(result.stdout.strip().split("\n"))
            streams.discard("")
            return len(streams)
        except Exception:
            return 0

    def summarise_flow(self, flow_content):
        """Use LLM to summarise a single flow with structured evidence."""
        try:
            evidence = self.extractor.extract(flow_content)
            evidence_text = self.extractor.format_for_prompt(evidence)

            enriched_flow = f"""
Structured Evidence Extracted by Python:
{evidence_text}

Raw TCP Flow:
{flow_content[:3000]}
"""

            chain = self.prompt | self.llm
            response = chain.invoke({"flow_content": enriched_flow})
            return response.content

        except Exception as e:
            return f"Error summarising flow: {e}"

    def run(self, pcap_file):
        """Main function - summarise all flows in PCAP file."""
        print(f"Analysing PCAP file: {pcap_file}")

        connections = self.get_connections(pcap_file)
        print(f"Connections found:\n{connections[:500]}")

        total_streams = self.count_streams(pcap_file)
        print(f"Total TCP streams: {total_streams}")

        full_summary = []
        full_summary.append("=== PCAP Analysis Report ===")
        full_summary.append("File: incident.pcap")
        full_summary.append(f"Total TCP Streams: {total_streams}")
        full_summary.append(f"\nConnections Overview:\n{connections[:1000]}")
        full_summary.append("\n=== Flow Analysis ===")

        for stream_num in range(total_streams):
            print(f"Analysing stream {stream_num}...")

            flow_content = self.get_flow_content(pcap_file, stream_num)

            if len(flow_content) < 50:
                continue

            summary = self.summarise_flow(flow_content)
            full_summary.append(f"\n--- Stream {stream_num} ---")
            full_summary.append(summary)

        return "\n".join(full_summary)