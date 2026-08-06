"""Pure file-label sanitization shared by preprocessing and tests."""

from pathlib import Path


def sanitize_summary(summary: str, pcap_file: str) -> str:
    real_name = Path(pcap_file).name
    sanitized = summary.replace(real_name, "incident.pcap")
    return sanitized.replace(Path(real_name).stem, "incident")
