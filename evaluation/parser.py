"""Parser retained for callers that evaluate report text directly."""

from evaluation.report_reader import parse_report_text


def parse_report(output):
    result = parse_report_text(output)
    result.pop("report_found", None)
    return result
