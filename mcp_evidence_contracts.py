"""Contracts for MCP-backed online evidence retrieval.

The MCP result is supporting knowledge for the report.  It is deliberately
kept separate from packet evidence so the reporter cannot confuse an online
source with an observation from the PCAP.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import Field, field_validator

from contracts import (
    ContractModel,
    ResultStatus,
    StrictModel,
    UNKNOWN,
)


CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class ExternalEvidenceSource(StrictModel):
    """One source returned by the configured MCP search tool."""

    source_name: str = "Unknown"
    title: str = "Untitled source"
    url: str = "Unknown"
    snippet: str = Field(default=UNKNOWN, max_length=4000)
    source_type: str = "online_security_source"
    supports: list[str] = Field(default_factory=list)
    contradicts: list[str] = Field(default_factory=list)
    retrieved_at_utc: str

    @field_validator("source_name", "title", "url", "snippet", mode="before")
    @classmethod
    def replace_blank_text(cls, value: Any) -> str:
        if value is None or not str(value).strip():
            return UNKNOWN
        return str(value).strip()


class OnlineEvidenceResult(ContractModel):
    """Validated result of the post-verification MCP search."""

    query: str
    tool_name: str = UNKNOWN
    retrieved_at_utc: str
    sources: list[ExternalEvidenceSource] = Field(default_factory=list)
    candidate_cves: list[str] = Field(default_factory=list)
    retrieval_errors: list[str] = Field(default_factory=list)

    @field_validator("candidate_cves", mode="before")
    @classmethod
    def normalize_cves(cls, values: Any) -> list[str]:
        if values is None:
            return []
        if isinstance(values, str):
            values = [values]
        normalized: list[str] = []
        for value in values:
            match = CVE_PATTERN.search(str(value).upper())
            if match and match.group(0) not in normalized:
                normalized.append(match.group(0))
        return normalized

    def to_prompt_json(self) -> str:
        return json.dumps(
            self.model_dump(exclude={"validation_errors"}),
            indent=2,
        )

    def to_text(self) -> str:
        lines = [
            "=== MCP ONLINE EVIDENCE SEARCH ===",
            f"Status: {self.status}",
            f"Query: {self.query}",
            f"Tool: {self.tool_name}",
            f"Retrieved At UTC: {self.retrieved_at_utc}",
            f"Candidate CVEs: {', '.join(self.candidate_cves) or 'None'}",
            f"Sources: {len(self.sources)}",
        ]
        for index, source in enumerate(self.sources, start=1):
            lines.extend(
                [
                    "",
                    f"Source {index}: {source.source_name}",
                    f"Title: {source.title}",
                    f"URL: {source.url}",
                    f"Summary: {source.snippet}",
                    f"Supports: {', '.join(source.supports) or 'None'}",
                    f"Contradicts: {', '.join(source.contradicts) or 'None'}",
                ]
            )
        if self.retrieval_errors:
            lines.append("Warnings: " + " | ".join(self.retrieval_errors))
        return "\n".join(lines)


class FormattedEvidence(StrictModel):
    """Deterministic evidence package passed to the report writer."""

    packet_evidence: list[str] = Field(default_factory=list)
    online_evidence: list[str] = Field(default_factory=list)
    source_urls: list[str] = Field(default_factory=list)
    search_query: str = UNKNOWN
    search_status: str = ResultStatus.ABSTAIN.value
    limitations: list[str] = Field(default_factory=list)

    def to_prompt_text(self) -> str:
        sections = [
            "=== PRIMARY PCAP EVIDENCE ===",
            "\n".join(f"- {item}" for item in self.packet_evidence) or "- None",
            "",
            "=== EXTERNAL ONLINE SUPPORTING EVIDENCE ===",
            "\n".join(f"- {item}" for item in self.online_evidence) or "- None",
            "",
            "=== SOURCE URLS ===",
            "\n".join(f"- {url}" for url in self.source_urls) or "- None",
            "",
            f"Search status: {self.search_status}",
            f"Search query: {self.search_query}",
            "Limitations:",
            "\n".join(f"- {item}" for item in self.limitations) or "- None",
        ]
        return "\n".join(sections)
