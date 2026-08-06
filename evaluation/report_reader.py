"""Read only the final system decision from saved FRA/MAFRA reports."""

from pathlib import Path
import re


FINAL_REPORT_MARKER = "=== FINAL REPORT ==="


def report_paths_for_pcap(pcap_path):
    pcap_path = Path(pcap_path)
    fra_report = pcap_path.with_name(pcap_path.stem + "_report.txt")
    mafra_report = pcap_path.with_name(pcap_path.stem + "_mafra_report.txt")
    return fra_report, mafra_report


def read_text(path):
    path = Path(path)
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def clean(value):
    return str(value).replace("*", "").replace("`", "").strip()


def extract_final_report_section(text):
    """Use the final decision, not a flow summary or intermediate agent."""
    if FINAL_REPORT_MARKER in text:
        return text.rsplit(FINAL_REPORT_MARKER, maxsplit=1)[1]
    return text


def extract_field(text, field_name):
    pattern = re.compile(
        rf"(?im)^\s*(?:\*\*)?{re.escape(field_name)}(?:\*\*)?\s*:\s*(.+?)\s*$"
    )
    match = pattern.search(text)
    if match:
        return clean(match.group(1))
    return "Not Found"


def extract_json_value(text, object_name, field_name):
    pattern = re.compile(
        rf'"{re.escape(object_name)}"\s*:\s*\{{.*?'
        rf'"{re.escape(field_name)}"\s*:\s*"([^"]+)"',
        re.IGNORECASE | re.DOTALL,
    )
    match = pattern.search(text)
    return clean(match.group(1)) if match else "Not Found"


def extract_attack_type(full_text):
    # Attack type is not a final-report field, so retain it only as a diagnostic.
    attack_type = extract_json_value(full_text, "attack", "type")
    if attack_type != "Not Found":
        return attack_type
    attack_type = extract_field(full_text, "Attack Type")
    if attack_type != "Not Found":
        return attack_type
    return "Not Found"


def parse_saved_report(report_path):
    full_text = read_text(report_path)
    final_text = extract_final_report_section(full_text)

    return {
        "service": extract_field(final_text, "Affected Service"),
        "attack_type": extract_attack_type(full_text),
        "attack_success": extract_field(final_text, "Attack"),
        "cve": extract_field(final_text, "Identified CVE"),
        "vulnerable": extract_field(final_text, "Is Service Vulnerable"),
        "report_found": bool(full_text.strip()),
    }
