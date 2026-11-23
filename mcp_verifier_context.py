"""Bounded, read-only research context for independent MAFRA verification.

All search content is untrusted. This module never decides CVE applicability,
attack success, service identity or final reporting and never calls the network.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from contracts import AnalystOutput, NOT_FOUND
from cve_mechanism_matcher import CVEMechanismTriage
from mcp_evidence_contracts import OnlineEvidenceResult

_PACKET_ID = re.compile(r"E-S\d{4}-F(?:\d{6}|UNKNOWN)-\d{3}")
_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def _candidate_source_match(source, cve: str) -> bool:
    """Avoid a different CVE advisory merely mentioning the proposed ID."""
    subject_ids = set(_CVE_ID.findall((source.title + " " + source.url).upper()))
    if subject_ids:
        return subject_ids == {cve}
    return cve in set(_CVE_ID.findall(
        (source.snippet + " " + " ".join(source.supports)
         + " " + " ".join(source.contradicts)).upper()
    ))


def _authority_priority(source) -> int:
    """Order only, not a statement that any source establishes applicability."""
    try:
        host = (urlsplit(source.url).hostname or "").lower()
    except ValueError:
        host = ""
    if host == "nvd.nist.gov":
        return 0
    if host in {"cisa.gov", "www.cisa.gov"}:
        return 1
    if "vendor" in source.source_type.lower():
        return 2
    return 3


def build_verifier_mcp_context(
    flow_summary: str,
    analyst: AnalystOutput,
    online_result: OnlineEvidenceResult,
    triage: CVEMechanismTriage | None = None,
) -> str:
    """Return minimal source-attributed research for the proposed CVE only.

    No candidate, invalid MCP response, or no source specifically for the
    proposed CVE => empty context, leaving previous Verifier path unchanged.
    """
    cve = analyst.cve.candidate
    if (not isinstance(cve, str) or cve == NOT_FOUND
            or online_result.status != "Valid"
            or cve not in online_result.candidate_cves):
        return ""

    matches = [s for s in online_result.sources if _candidate_source_match(s, cve)]
    if not matches:
        return ""
    matches.sort(key=_authority_priority)
    chosen = []
    urls = set()
    for source in matches:
        # Explicit URL and provenance are required for sources used in CVE review.
        if not source.url.startswith(("https://", "http://")) or source.url in urls:
            continue
        urls.add(source.url)
        chosen.append({
            "source_name": source.source_name[:70],
            "source_type": source.source_type[:70],
            "url": source.url[:210],
            "title": source.title[:120],
            "description_excerpt": source.snippet[:700 if not chosen else 400],
            "supports_claims": [text[:120] for text in source.supports[:2]],
            "contradicts_claims": [text[:120] for text in source.contradicts[:2]],
        })
        if len(chosen) == 3:
            break
    if not chosen:
        return ""

    # Only packet IDs present in the supplied current-case summary are included.
    available_ids = set(_PACKET_ID.findall(flow_summary))
    ids = set(_PACKET_ID.findall(" ".join(analyst.attack.evidence)))
    missing = []
    if triage:
        for item in triage.candidates:
            if item.cve_id == cve:
                ids.update(item.packet_ids)
                missing.extend(item.missing_conditions)
    ids.intersection_update(available_ids)
    relevant_ids = sorted(ids)[:8]
    packet_lines = []
    for line in flow_summary.splitlines():
        if (any(packet_id in line for packet_id in relevant_ids)
                and len(packet_lines) < 4):
            packet_lines.append(line.strip()[:230])

    payload = {
        "proposed_cve": cve,
        "origin": "MCP retrieved public research (untrusted; not packet proof)",
        "current_case_packet_ids": relevant_ids,
        "current_case_packet_observations": packet_lines,
        "cve_specific_research_sources": chosen,
        "unverified_requirements_from_mechanism_triage": list(dict.fromkeys(missing))[:3],
        "limitations": (
            "Research describes the vulnerability, but does not independently "
            "establish the observed host's software version, configuration, "
            "authorization state, or exploitation. Assess product identity and "
            "prerequisites from packet evidence. A failed attempt may still "
            "be associated with a CVE; do not equate CVE association with success."
        ),
    }
    # Use JSON encoding: untrusted excerpts remain clearly bounded data.
    rendered = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    # Keep valid JSON rather than relying on the Verifier to truncate it in
    # the middle of a claim or source URL.
    while len(rendered) > 3900 and len(payload["cve_specific_research_sources"]) > 1:
        payload["cve_specific_research_sources"].pop()
        rendered = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    if len(rendered) > 3900:
        payload["current_case_packet_observations"] = packet_lines[:2]
        payload["cve_specific_research_sources"][0]["description_excerpt"] = (
            payload["cve_specific_research_sources"][0]["description_excerpt"][:350]
        )
        rendered = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    return rendered
