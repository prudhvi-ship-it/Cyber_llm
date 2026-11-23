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


CONSENSUS_MARKER = "=== CONSENSUS SUMMARY ==="


def extract_consensus_section(full_text):
    """Take the LAST final consensus, never the initial or revised Analyst block."""
    all_markers = list(re.finditer(
        r"(?im)^\s*===\s*CONSENSUS SUMMARY\s*===\s*$", full_text
    ))
    if not all_markers:
        return None
    section = full_text[all_markers[-1].end():]
    next_heading = re.search(r"(?m)^\s*===\s*[^\n]+?\s*===\s*$", section)
    if next_heading:
        section = section[:next_heading.start()]
    return section


def parse_report_text(full_text):
    # The Analyst candidate is a separate research finding, never a
    # substitute for the final report's "Identified CVE" decision.
    final_text = extract_final_report_section(full_text)
    candidate = extract_field(final_text, "Associated CVE candidate (Analyst)")
    candidate_support = extract_field(final_text, "Verifier support for exact CVE")
    consensus = extract_consensus_section(full_text)
    if consensus is not None:
        # Do not infer "Vulnerable: Yes" from a candidate CVE alone.
        # The consensus typically has no explicit vulnerability classification.
        vulnerable = extract_field(consensus, "Is Service Vulnerable")
        if vulnerable == "Not Found":
            vulnerable = extract_field(consensus, "Vulnerable")
        return {
            "service": extract_field(consensus, "Service"),
            "attack_type": extract_field(consensus, "Attack Type"),
            "attack_success": extract_field(consensus, "Attack Success"),
            "cve": extract_field(consensus, "CVE"),
            "cve_candidate": candidate,
            "cve_candidate_support": candidate_support,
            "cve_supported": extract_field(consensus, "CVE Supported"),
            "verification_result": extract_field(consensus, "Verification Result"),
            "overall_confidence": extract_field(consensus, "Overall Confidence"),
            "vulnerable": vulnerable if vulnerable != "Not Found" else "Unknown",
            "report_found": bool(full_text.strip()),
        }

    # Keep original FRA and legacy MAFRA formats working.
    final_text = extract_final_report_section(full_text)
    return {
        "service": extract_field(final_text, "Affected Service"),
        "attack_type": extract_attack_type(full_text),
        "attack_success": extract_field(final_text, "Attack"),
        "cve": extract_field(final_text, "Identified CVE"),
        "cve_candidate": candidate,
        "cve_candidate_support": candidate_support,
        "vulnerable": extract_field(final_text, "Is Service Vulnerable"),
        "report_found": bool(full_text.strip()),
    }


def parse_saved_report(report_path):
    return parse_report_text(read_text(report_path))
