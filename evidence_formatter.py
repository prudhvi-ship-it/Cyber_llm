"""Deterministic formatting of packet and online supporting evidence."""

from __future__ import annotations

import re

from contracts import AnalystOutput, ConsensusDecision, VerifierOutput
from mcp_evidence_contracts import (
    FormattedEvidence,
    OnlineEvidenceResult,
)


EVIDENCE_LINE = re.compile(
    r"\[(E-S\d{4}-F(?:\d{6}|UNKNOWN)-\d{3})"
    r"(?:\s*\|\s*[^\]]+)?\]\s*(.+)"
)
CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _packet_catalog(flow_summary: str) -> dict[str, str]:
    catalog: dict[str, str] = {}
    for line in flow_summary.splitlines():
        match = EVIDENCE_LINE.search(line)
        if match:
            description = match.group(2).strip().strip("-").strip()
            if description and description.casefold() != "none":
                catalog.setdefault(match.group(1), description)
    return catalog


def _source_cve_ids(source: object) -> set[str]:
    """Extract CVE IDs explicitly present in one online source record."""
    values = [
        getattr(source, "title", ""),
        getattr(source, "snippet", ""),
        getattr(source, "url", ""),
        *getattr(source, "supports", []),
        *getattr(source, "contradicts", []),
    ]
    return {
        match.group(0).upper()
        for value in values
        for match in CVE_ID_PATTERN.finditer(str(value))
    }


class EvidenceFormatter:
    """Build a report-ready evidence package without changing findings."""

    def format(
        self,
        flow_summary: str,
        analyst_output: AnalystOutput,
        verifier_output: VerifierOutput,
        consensus: ConsensusDecision,
        online_result: OnlineEvidenceResult,
    ) -> FormattedEvidence:
        catalog = _packet_catalog(flow_summary)
        packet_evidence: list[str] = []
        unresolved_count = 0
        for evidence_id in analyst_output.attack.evidence:
            description = catalog.get(evidence_id)
            if description:
                packet_evidence.append(
                    f"PCAP [{evidence_id}]: {description.rstrip('.')}."
                )
            else:
                unresolved_count += 1
                packet_evidence.append(
                    f"PCAP [{evidence_id}]: Description unavailable in flow "
                    "summary; verify this reference against the original capture."
                )

        online_evidence: list[str] = []
        source_urls: list[str] = []
        selected_cve = str(getattr(consensus, "cve", "Not Found")).upper()
        research_lead_count = 0
        for source in online_result.sources:
            source_cves = _source_cve_ids(source)
            is_unselected_cve_lead = bool(
                source_cves
                and source_cves.isdisjoint({selected_cve})
                and any(cve.startswith("CVE-") for cve in source_cves)
            )
            label = "ONLINE RESEARCH LEAD" if is_unselected_cve_lead else "ONLINE"
            if is_unselected_cve_lead:
                research_lead_count += 1
            line = f"{label} [{source.source_name}] {source.title}: {source.snippet}"
            if source.url != "Unknown":
                line += f" Source: {source.url}"
                source_urls.append(source.url)
            if source.supports:
                line += " Supports: " + "; ".join(source.supports)
            if source.contradicts:
                line += " Contradicts: " + "; ".join(source.contradicts)
            online_evidence.append(line)

        limitations: list[str] = [
            "Online sources are supporting context; packet evidence remains primary.",
            "The Analyzer and Verifier findings were retained without rewriting.",
        ]
        if not online_result.sources:
            limitations.append("No online source was returned by the MCP search.")
        limitations.extend(online_result.retrieval_errors)
        if unresolved_count:
            limitations.append(
                f"{unresolved_count} cited packet reference(s) lack a matching "
                "description in the saved flow summary; they are NOT "
                "independently verified by the report formatter."
            )
        if research_lead_count:
            limitations.append(
                f"{research_lead_count} online CVE record(s) were retained as "
                "product-related research leads only; they were not used as "
                "the validated CVE."
            )

        return FormattedEvidence(
            packet_evidence=packet_evidence,
            online_evidence=online_evidence,
            source_urls=list(dict.fromkeys(source_urls)),
            search_query=online_result.query,
            search_status=online_result.status,
            limitations=limitations,
        )
