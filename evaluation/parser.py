"""Parser retained for callers that evaluate report text directly."""

from evaluation.report_reader import (
    extract_attack_type,
    extract_field,
    extract_final_report_section,
)


def parse_report(output):
    final_text = extract_final_report_section(output)
    return {
        "service": extract_field(final_text, "Affected Service"),
        "attack_type": extract_attack_type(output),
        "attack_success": extract_field(final_text, "Attack"),
        "cve": extract_field(final_text, "Identified CVE"),
        "vulnerable": extract_field(final_text, "Is Service Vulnerable"),
    }
