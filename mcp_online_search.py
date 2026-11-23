"""MCP client for investigation-specific online evidence retrieval.

The project does not create a new vulnerability database.  It calls a
configured MCP server and validates the returned tool result into a stable
internal contract for the rest of the pipeline.
"""

from __future__ import annotations

import json
import os
import re
import asyncio
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from contracts import (
    AnalystOutput,
    ConsensusDecision,
    NOT_FOUND,
    ResultStatus,
    VerifierOutput,
)
from packet_search_features import packet_clues, informative_service
from mcp_evidence_contracts import (
    CVE_PATTERN,
    ExternalEvidenceSource,
    OnlineEvidenceResult,
)

try:  # Optional until the MCP dependency is installed in the new version.
    from mcp import Client
except ImportError:  # pragma: no cover - exercised in dependency-free installs.
    Client = None  # type: ignore[assignment,misc]


class MCPOnlineEvidenceSearch:
    """Search one configured MCP server after Analyzer/Verifier completion."""

    DEFAULT_TOOL = "search_forensic_evidence"

    def __init__(
        self,
        server_url: str | None = None,
        tool_name: str | None = None,
        max_results: int | None = None,
    ) -> None:
        self.server_url = (
            server_url 
            if server_url is not None
            else os.getenv("FRA_MCP_SERVER_URL", "")
        ).strip()
        self.tool_name = (
            tool_name or os.getenv("FRA_MCP_SEARCH_TOOL", self.DEFAULT_TOOL)
        ).strip()
        configured_limit = max_results if max_results is not None else int(
            os.getenv("FRA_MCP_MAX_RESULTS", "8")
        )
        self.max_results = max(1, min(int(configured_limit), 20))

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _packet_signature_query_terms(flow_summary: str) -> list[str]:
        """Generic, packet-linked, sanitized search leads (never benchmark signatures)."""
        return packet_clues(flow_summary)

    @staticmethod
    def _observed_version(
        service: str, flow_summary: str, analyst_output: AnalystOutput,
    ) -> str:
        """Find an explicitly product-adjacent version, never IP/port/CVE digits.

        This is only a bounded research lead; not proof of any exploit or CVE.
        """
        if not informative_service(service):
            return ""
        try:
            from web_search import WebSearch
            version = WebSearch.extract_observed_version(
                service, flow_summary, analyst_output.to_prompt_json()
            )
            return version if version != "Unknown" else ""
        except (ImportError, AttributeError):
            return ""

    @staticmethod
    def build_query(
        analyst_output: AnalystOutput,
        verifier_output: VerifierOutput,
        consensus: ConsensusDecision,
        flow_summary: str,
    ) -> str:
        """Build a compact query without sending raw packet payloads online."""

        service = analyst_output.service.primary
        attack = analyst_output.attack.type
        application = analyst_output.service.application
        # Broad protocol labels cannot justify selecting vulnerabilities of an
        # arbitrary product. Fall back to the explicitly named application,
        # never the generic HTTP/API label or a guessed vendor.
        if not informative_service(service):
            service = application if informative_service(application) else ""
        version = ""  # Application/product labels are never software versions.
        try:
            # Reuse the baseline's conservative banner parser without invoking
            # the NVD network path.
            from web_search import WebSearch

            observed_version = WebSearch.extract_observed_version(
                service,
                flow_summary,
                analyst_output.to_prompt_json(),
            )
            if observed_version != "Unknown":
                version = observed_version
        except Exception:
            pass
        # As in FRA's web_quick_search instructions, do not place a CVE
        # identifier in the search query; search by service and mechanism.

        # The application field may contain a banner/version combination.  It
        # is intentionally kept concise; raw flow content is not sent to MCP.
        # Place distinctive observed mechanisms before generic model guesses.
        clues = MCPOnlineEvidenceSearch._packet_signature_query_terms(flow_summary)
        # Keep LLM-authored technique prose (which can quote a payload or
        # private path) out of the external query. Use the structured attack
        # category and sanitized packet-derived vocabulary instead.
        terms = [service, version, attack]

        query = " ".join(
            str(term).strip()
            for term in terms
            if str(term).strip() and str(term).strip().lower() not in {"unknown", "none"}
        )
        query = " ".join(query.split())
        if clues:
            query += " packet clues: " + "; ".join(clues)
        return query or "network forensic investigation"

    @staticmethod
    def _packet_signature_query_terms_from_query(query: str) -> list[str]:
        # These terms are already sanitized and packet-linked by build_query.
        marker = "packet clues:"
        return ([item.strip() for item in query.split(marker, 1)[1].split(";")]
                if marker in query else [])

    @staticmethod
    def _tool_names(tool_result: Any) -> list[str]:
        return [str(getattr(tool, "name", "")) for tool in tool_result.tools]

    def _select_tool(self, tools: list[Any]) -> Any:
        for tool in tools:
            if getattr(tool, "name", None) == self.tool_name:
                return tool

        # A configured name is authoritative.  The fallback is useful when a
        # compatible server exposes a clear search tool under another name.
        search_tools = [
            tool
            for tool in tools
            if any(
                token in str(getattr(tool, "name", "")).casefold()
                for token in ("search", "evidence", "vulnerability", "attack")
            )
        ]
        if len(search_tools) == 1:
            return search_tools[0]

        available = ", ".join(
            str(getattr(tool, "name", "")) for tool in tools
        )
        raise RuntimeError(
            f"MCP search tool '{self.tool_name}' was not found. Available tools: {available or 'none'}"
        )

    def _build_arguments(
        self,
        tool: Any,
        query: str,
        analyst_output: AnalystOutput,
        verifier_output: VerifierOutput,
        consensus: ConsensusDecision,
    ) -> dict[str, Any]:
        schema = getattr(tool, "input_schema", {}) or {}
        properties = schema.get("properties", {}) or {}
        arguments: dict[str, Any] = {}

        values: dict[str, Any] = {
            "query": query,
            "search_query": query,
            "service": (analyst_output.service.primary if informative_service(analyst_output.service.primary)
                        else analyst_output.service.application if informative_service(analyst_output.service.application)
                        else ""),
            "attack": analyst_output.attack.type,
            "attack_type": analyst_output.attack.type,
            "version": self._observed_version(
                analyst_output.service.primary
                if informative_service(analyst_output.service.primary)
                else analyst_output.service.application,
                query,
                analyst_output,
            ),
            "cve": analyst_output.cve.candidate,
            "evidence_keywords": MCPOnlineEvidenceSearch._packet_signature_query_terms_from_query(query),
            "max_results": self.max_results,
            "limit": self.max_results,
            "include_contradictions": True,
        }
        for name in properties:
            if name in values and values[name] not in (None, "", []):
                arguments[name] = values[name]

        required = schema.get("required", []) or []
        for name in required:
            if name not in arguments:
                if name in {"query", "search_query", "q", "text"}:
                    arguments[name] = query
                else:
                    raise RuntimeError(
                        f"MCP tool requires unsupported argument '{name}'"
                    )
        return arguments

    @staticmethod
    def _text_content(result: Any) -> str:
        parts: list[str] = []
        for block in getattr(result, "content", []) or []:
            text = getattr(block, "text", None)
            if text:
                parts.append(str(text))
        return "\n".join(parts).strip()

    @staticmethod
    def _as_items(payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if not isinstance(payload, dict):
            return []
        for key in ("sources", "results", "items", "evidence", "records"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return [payload]

    @staticmethod
    def _source_from_item(
        item: dict[str, Any],
        retrieved_at_utc: str,
    ) -> ExternalEvidenceSource:
        url = str(
            item.get("url")
            or item.get("source_url")
            or item.get("link")
            or "Unknown"
        ).strip()
        parsed = urlparse(url)
        source_name = str(
            item.get("source_name")
            or item.get("source")
            or item.get("site")
            or parsed.netloc
            or "MCP source"
        ).strip()
        snippet = str(
            item.get("snippet")
            or item.get("summary")
            or item.get("description")
            or item.get("content")
            or item.get("text")
            or "Unknown"
        ).strip()
        supports = item.get("supports") or item.get("supporting_claims") or []
        contradicts = item.get("contradicts") or item.get("contradictory_claims") or []
        if isinstance(supports, str):
            supports = [supports]
        if isinstance(contradicts, str):
            contradicts = [contradicts]
        return ExternalEvidenceSource(
            source_name=source_name,
            title=str(item.get("title") or "Untitled source"),
            url=url,
            snippet=snippet[:4000],
            source_type=str(item.get("source_type") or "online_security_source"),
            supports=[str(value) for value in supports],
            contradicts=[str(value) for value in contradicts],
            retrieved_at_utc=retrieved_at_utc,
        )

    @classmethod
    def _parse_result(
        cls,
        structured_content: Any,
        text_content: str,
        retrieved_at_utc: str,
    ) -> tuple[list[ExternalEvidenceSource], list[str]]:
        # Some tool adapters wrap the JSON object in {"result": {...}}.
        if (
            isinstance(structured_content, dict)
            and set(structured_content) == {"result"}
            and isinstance(structured_content["result"], dict)
        ):
            structured_content = structured_content["result"]
        sources = [
            cls._source_from_item(item, retrieved_at_utc)
            for item in cls._as_items(structured_content)
        ]
        if not sources and text_content:
            urls = re.findall(r"https?://[^\s)<>]+", text_content)
            sources = [
                ExternalEvidenceSource(
                    source_name=urlparse(url).netloc or "MCP source",
                    title="MCP search result",
                    url=url,
                    snippet=text_content[:4000],
                    retrieved_at_utc=retrieved_at_utc,
                )
                for url in dict.fromkeys(urls)
            ]
            if not sources:
                sources = [
                    ExternalEvidenceSource(
                        source_name="MCP source",
                        title="MCP search result",
                        snippet=text_content[:4000],
                        retrieved_at_utc=retrieved_at_utc,
                    )
                ]

        # Prefer the server's explicit candidate list.  Otherwise, CVEs cited
        # inside long MITRE descriptions can be mistaken for case findings.
        explicit_cves = (
            structured_content.get("candidate_cves")
            if isinstance(structured_content, dict)
            else None
        )
        if isinstance(explicit_cves, list):
            cves = list(
                dict.fromkeys(
                    match.group(0).upper()
                    for value in explicit_cves
                    for match in [CVE_PATTERN.search(str(value).upper())]
                    if match
                )
            )
        else:
            all_text = json.dumps(structured_content, default=str) + "\n" + text_content
            cves = list(
                dict.fromkeys(
                    match.group(0).upper()
                    for match in CVE_PATTERN.finditer(all_text)
                )
            )
        return sources, cves

    async def _call_server(
        self,
        query: str,
        analyst_output: AnalystOutput,
        verifier_output: VerifierOutput,
        consensus: ConsensusDecision,
    ) -> tuple[str, Any, str]:
        if Client is None:
            raise RuntimeError(
                "The MCP Python SDK is not installed. Install requirements-mcp.txt."
            )
        if not self.server_url:
            raise RuntimeError(
                "FRA_MCP_SERVER_URL is not configured; online evidence search was skipped."
            )

        async with Client(self.server_url) as client:
            tool_list = await client.list_tools()
            tool = self._select_tool(tool_list.tools)
            arguments = self._build_arguments(
                tool, query, analyst_output, verifier_output, consensus
            )
            result = await client.call_tool(tool.name, arguments)
            if getattr(result, "is_error", False):
                raise RuntimeError(self._text_content(result) or "MCP search tool returned an error")
            return tool.name, getattr(result, "structured_content", None), self._text_content(result)

    def search(
        self,
        analyst_output: AnalystOutput,
        verifier_output: VerifierOutput,
        consensus: ConsensusDecision,
        flow_summary: str,
        query_override: str = "",
    ) -> OnlineEvidenceResult:
        query = self.build_query(
            analyst_output, verifier_output, consensus, flow_summary
        )
        if query_override:
            # Analyst-selected FRA query keeps current packet-derived clues
            # needed by the server's product-discovery relevance filter.
            override = " ".join(query_override.split())[:160]
            clues = self._packet_signature_query_terms(flow_summary)
            query = override + (" packet clues: " + "; ".join(clues)
                                if clues else "")
        retrieved_at_utc = self._now()

        # A service/version alone is not a forensic finding.  Do not turn a
        # negative or inconclusive case into a list of generic related CVEs.
        attack_terms = [
            str(term).strip().casefold()
            for term in (
                analyst_output.attack.type,
                analyst_output.attack.technique,
            )
        ]
        unknown_attack_terms = {"", "unknown", "none", "not found"}
        has_attack = any(term not in unknown_attack_terms for term in attack_terms)
        has_candidate_cve = analyst_output.cve.candidate != NOT_FOUND
        has_packet_signature = bool(self._packet_signature_query_terms(flow_summary))
        # Mirror FRA's ability to research a product/version without inventing
        # an attack. No version, no lookup; no hidden benchmark labels.
        service = analyst_output.service.primary
        if not informative_service(service):
            service = analyst_output.service.application
        context_only = (
            informative_service(service)
            and bool(self._observed_version(service, flow_summary, analyst_output))
            and not has_attack and not has_candidate_cve and not has_packet_signature
        )
        if not has_attack and not has_candidate_cve and not has_packet_signature and not context_only:
            return OnlineEvidenceResult(
                status=ResultStatus.ABSTAIN.value,
                query=query,
                tool_name=self.tool_name,
                retrieved_at_utc=retrieved_at_utc,
                retrieval_errors=[
                    "Online evidence search skipped because no attack, CVE candidate, or packet-linked mechanism signature was identified."
                ],
            )

        try:
            async def call_server():
                return await self._call_server(
                    query,
                    analyst_output,
                    verifier_output,
                    consensus,
                )

            tool_name, structured_content, text_content = asyncio.run(call_server())
            sources, candidate_cves = self._parse_result(
                structured_content,
                text_content,
                retrieved_at_utc,
            )
            # Preserve partial-failure warnings so users can distinguish a
            # successful MCP call from full coverage of every source.
            raw_result = structured_content
            if (isinstance(raw_result, dict) and set(raw_result) == {"result"}
                    and isinstance(raw_result["result"], dict)):
                raw_result = raw_result["result"]
            warnings = raw_result.get("warnings", []) if isinstance(raw_result, dict) else []
            if not isinstance(warnings, list):
                warnings = []
            if context_only:
                warnings = [
                    "Context-only product/version research: CVE results are leads, "
                    "not proof of an observed attack.", *warnings
                ]
            return OnlineEvidenceResult(
                status="Valid",
                query=query,
                tool_name=tool_name,
                retrieved_at_utc=retrieved_at_utc,
                sources=sources,
                candidate_cves=candidate_cves,
                retrieval_errors=[str(item)[:500] for item in warnings[:20]],
            )
        except Exception as exc:
            return OnlineEvidenceResult(
                status="Abstain",
                query=query,
                tool_name=self.tool_name,
                retrieved_at_utc=retrieved_at_utc,
                retrieval_errors=[f"{type(exc).__name__}: {exc}"],
            )
