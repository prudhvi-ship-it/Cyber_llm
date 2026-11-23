"""MAFRA evidence-enrichment pipeline using an MCP online search tool.

This module is intentionally separate from ``mafra_agent.py``.  The original
NVD-based pipeline remains available as the baseline.
"""

import os
from agents.analyst_agent import AnalystAgent
from agents.consensus import ConsensusManager
from agents.mcp_reporter_agent import MCPReporterAgent
from agents.verifier_agent import VerifierAgent
from contracts import (ContractModel, ConsensusDecision, VerifierOutput, Decision, NOT_FOUND,
                       CVEValidationOutput, Confidence, ResultStatus)
from evidence_formatter import EvidenceFormatter
# Legacy policy import retained only for old test/patch compatibility.
# MAFRA-MCP no longer calls the separate online CVE validator.
from mcp_evidence_policy import derive_online_cve_validation
from cve_mechanism_matcher import rank_cve_mechanisms, CVEMechanismTriage
from mcp_online_search import MCPOnlineEvidenceSearch
from mcp_verifier_context import build_verifier_mcp_context
from binary_benchmark_policy import assess_binary_benchmark
from memory_manager import MemoryManager
from pipeline_errors import PipelineAbortError
from investigation_notebook import InvestigationNotebook
from erlang_cookie_evidence import VerifiedCookieRpcSequence


class MAFRAMCPAgent:
    """Run initial Analyzer → MCP research → revised Analyzer → Verifier → report."""

    def __init__(
        self,
        current_case_id: str | None = None,
        memory_mode: str | None = None,
        run_id: str | None = None,
        mcp_server_url: str | None = None,
        mcp_tool_name: str | None = None,
        investigation_notebook: str = "disabled",
        verified_cookie_rpc_sequences: tuple[VerifiedCookieRpcSequence, ...] = (),
    ):
        if investigation_notebook not in {"enabled", "disabled"}:
            raise ValueError("investigation_notebook must be enabled or disabled")
        self.notebook_mode = investigation_notebook
        self.verified_cookie_rpc_sequences = tuple(verified_cookie_rpc_sequences)
        self.last_notebook = None
        self.current_case_id = current_case_id or "anonymous_case"
        self.analyst = AnalystAgent()
        self.verifier = VerifierAgent()
        self.consensus = ConsensusManager()
        self.online_search = MCPOnlineEvidenceSearch(
            server_url=mcp_server_url,
            tool_name=mcp_tool_name,
        )
        self.evidence_formatter = EvidenceFormatter()
        self.reporter = MCPReporterAgent()
        self.last_online_result = None
        self.last_initial_analyst = None
        self.last_revised_analyst = None
        self.last_formatted_evidence = None
        self.last_cve_triage = CVEMechanismTriage()
        self.memory_manager = MemoryManager(
            system_name="MAFRA_MCP",
            current_case_id=current_case_id,
            mode=memory_mode,
            run_id=run_id,
        )

    @staticmethod
    def _show_status(stage: str, result: ContractModel) -> None:
        if result.validation_errors:
            print(
                f"Warning: {stage} returned {result.status} after validation "
                f"({len(result.validation_errors)} failed attempt(s))."
            )

    def run(self, flow_summary: str) -> str:
        print("\n=== Starting MAFRA MCP Evidence-Enrichment Analysis ===")
        # This notebook is strictly run-local. It never uses or stores ChromaDB
        # records, and the default disabled path preserves the old pipeline.
        notebook = (InvestigationNotebook(self.current_case_id, flow_summary)
                    if self.notebook_mode == "enabled" else None)
        self.last_notebook = notebook
        if notebook:
            print(f"Investigation notebook: ENABLED (current case only, "
                  f"packet observations={len(notebook.observations)})")

        # Read approved, independent training memory BEFORE reasoning. Do not
        # expose memories from the same evaluation run to the Analyst.
        early_context = ""
        rag_context = ""
        if self.memory_manager.mode == "read_only":
            print("\nStep 0: Approved training memory retrieval (before Analyst)...")
            rag_context = self.memory_manager.retrieve(
                flow_summary, require_approved_training=True
            )
            if self.memory_manager.last_retrievals:
                early_context = rag_context
            print(
                f"Pre-analysis RAG: mode={self.memory_manager.status()}, "
                f"approved_sources={len(self.memory_manager.last_retrievals)}"
            )

        print("\nStep 1: Analyzer Agent running...")
        if early_context:
            analyst_output = self.analyst.analyze(
                flow_summary, past_case_context=early_context
            )
        else:
            analyst_output = self.analyst.analyze(flow_summary)
        self._show_status("Analyzer", analyst_output)
        analyst_json = analyst_output.to_prompt_json()
        print(f"Analyzer done: {analyst_json[:200]}...")
        if analyst_output.status == "Abstain":
            raise PipelineAbortError("MAFRA MCP Analyzer", analyst_output.validation_errors)

        self.last_initial_analyst = analyst_output
        # Reset per-PCAP reasoner history; never carry another case forward.
        self.analyst._fra_reasoning_queue = ""
        if notebook:
            notebook.note_analyst("INITIAL ANALYST", analyst_output)
        print("\nStep 2: MCP online research running (before verification)...")
        # MCP's existing tool signature expects a verifier and consensus. At this
        # stage they are neutral placeholders, NEVER presented as verification.
        provisional_verifier = VerifierOutput()
        provisional_consensus = ConsensusDecision(
            service=analyst_output.service.primary,
            attack=analyst_output.attack.type,
            cve=analyst_output.cve.candidate,
        )
        planned_query = self.analyst.plan_fra_search_query(
            flow_summary, analyst_output
        )
        online_result = self.online_search.search(
            analyst_output=analyst_output,
            verifier_output=provisional_verifier,
            consensus=provisional_consensus,
            flow_summary=flow_summary,
            **({"query_override": planned_query} if planned_query else {}),
        )
        self.last_online_result = online_result
        if notebook:
            notebook.note_research(online_result)
        print(online_result.to_text()[:1600])
        # Step 5A candidate ranking is advisory only. It never reads PCAP
        # filenames/labels and it cannot set consensus or validated_cve.
        cve_triage = rank_cve_mechanisms(
            flow_summary, analyst_output, online_result,
            verified_cookie_rpc_sequences=self.verified_cookie_rpc_sequences,
        )
        self.last_cve_triage = cve_triage
        cve_hints = cve_triage.to_text() if cve_triage.candidates else ""
        print("\n" + cve_triage.to_text())

        # FRA keeps recent reasoning steps and tool observations available
        # throughout the investigation. Keep an in-run FIFO without writing
        # anything to ChromaDB or sending hidden benchmark labels to the LLM.
        fra_steps = [
            "Initial Analyst assessment: " + analyst_output.to_prompt_json()[:1800],
            "Search 1: " + str(planned_query if isinstance(planned_query, str) and planned_query else online_result.query)[:220],
            "Research 1: " + (", ".join(online_result.candidate_cves) or "no exact CVE lead"),
        ]
        self.analyst._fra_reasoning_queue = "\n".join(fra_steps)[-6500:]
        print("\nStep 3: Analyst reconsideration using MCP evidence...")
        if notebook:
            analyst_output = self.analyst.reconsider_with_online_evidence(
                flow_summary, analyst_output, online_result,
                past_case_context=early_context,
                investigation_notes=notebook.context(stage="revision"),
                **({"cve_mechanism_hints": cve_hints} if cve_hints else {}),
            )
        elif early_context:
            analyst_output = self.analyst.reconsider_with_online_evidence(
                flow_summary, analyst_output, online_result,
                past_case_context=early_context,
                **({"cve_mechanism_hints": cve_hints} if cve_hints else {}),
            )
        else:
            analyst_output = self.analyst.reconsider_with_online_evidence(
                flow_summary, analyst_output, online_result,
                **({"cve_mechanism_hints": cve_hints} if cve_hints else {}),
            )
        # The original FRA routes main_agent -> web tool -> main_agent as long
        # as the agent needs more observations. Keep the same *reasoning* loop
        # inside MAFRA's Analyst/MCP stage, with one search per turn, a hard
        # budget, and the existing Verifier/Consensus stages still afterward.
        # FRA has a larger step budget; MAFRA limits live expense explicitly.
        try:
            max_rounds = max(1, min(int(os.getenv("MAFRA_FRA_MAX_SEARCH_ROUNDS", "3")), 5))
        except ValueError:
            max_rounds = 3

        def normalized_query(value):
            import re
            return set(re.findall(r"[a-z0-9]+", str(value).casefold()))

        requested_queries = [planned_query if isinstance(planned_query, str) and planned_query else online_result.query]
        from mcp_evidence_contracts import OnlineEvidenceResult
        from itertools import zip_longest
        for next_round in range(2, max_rounds + 1):
            fra_steps.append(
                f"Analyst after search {next_round - 1}: "
                + analyst_output.to_prompt_json()[:1500]
            )
            # If the analyst has an application and a concrete CVE candidate,
            # do not spend extra queries. FRA ends when sufficient information
            # has been gathered; the independent Verifier will judge support.
            unknown_names = {"", "unknown", "web application", "http web application",
                             "http application", "custom web application"}
            missing_findings = (
                analyst_output.cve.candidate == NOT_FOUND
                or analyst_output.service.primary.strip().casefold() in unknown_names
            )
            if not missing_findings or not online_result.sources:
                break
            followup = self.analyst.plan_fra_search_query(
                flow_summary, analyst_output, online_result=online_result,
                reasoning_queue="\n".join(fra_steps)[-6500:]
            )
            if not isinstance(followup, str) or not followup.strip():
                break
            current = normalized_query(followup)
            if not current:
                break
            # FRA prohibits repeating the same or similar web search.
            if any(
                (current == prev or len(current & prev) / len(current | prev) >= 0.85)
                for prev in map(normalized_query, requested_queries)
                if prev
            ):
                break
            requested_queries.append(followup)
            print(f"FRA research: Analyst search turn {next_round}...")
            next_online = self.online_search.search(
                analyst_output=analyst_output,
                verifier_output=provisional_verifier,
                consensus=provisional_consensus,
                flow_summary=flow_summary,
                query_override=followup,
            )
            fra_steps.append(f"Search {next_round}: " + followup[:220])
            fra_steps.append(
                f"Research {next_round}: "
                + (", ".join(next_online.candidate_cves) or "no exact CVE lead")
            )
            if next_online.status != "Valid" or not next_online.sources:
                break
            # Preserve earlier authoritative results while adding new pages;
            # interleave results across searches instead of replacing them.
            merged_sources, seen_urls = [], set()
            for old_src, new_src in zip_longest(online_result.sources, next_online.sources):
                for src in (old_src, new_src):
                    if src is not None and src.url not in seen_urls:
                        merged_sources.append(src)
                        seen_urls.add(src.url)
            online_result = OnlineEvidenceResult(
                status="Valid",
                query=online_result.query + " | " + next_online.query,
                tool_name=online_result.tool_name,
                retrieved_at_utc=online_result.retrieved_at_utc,
                sources=merged_sources[:30],
                candidate_cves=list(dict.fromkeys(
                    [*online_result.candidate_cves, *next_online.candidate_cves]
                )),
                retrieval_errors=[*online_result.retrieval_errors,
                                  *next_online.retrieval_errors],
            )
            self.last_online_result = online_result
            cve_triage = rank_cve_mechanisms(
                flow_summary, analyst_output, online_result,
                verified_cookie_rpc_sequences=self.verified_cookie_rpc_sequences,
            )
            self.last_cve_triage = cve_triage
            cve_hints = cve_triage.to_text() if cve_triage.candidates else ""
            self.analyst._fra_reasoning_queue = "\n".join(fra_steps)[-6500:]
            analyst_output = self.analyst.reconsider_with_online_evidence(
                flow_summary, analyst_output, online_result,
                **({"past_case_context": early_context} if early_context else {}),
                **({"investigation_notes": notebook.context(stage="revision")}
                   if notebook else {}),
                **({"cve_mechanism_hints": cve_hints} if cve_hints else {}),
            )
        self._show_status("Revised Analyst", analyst_output)
        self.last_revised_analyst = analyst_output
        if notebook:
            notebook.note_analyst("REVISED ANALYST", analyst_output)
        analyst_json = analyst_output.to_prompt_json()
        print(f"Revised Analyst done: {analyst_json[:200]}...")
        print("FRA Analyst decision: "
              f"service={analyst_output.service.primary}; "
              f"CVE candidate={analyst_output.cve.candidate}; "
              f"CVE confidence={analyst_output.cve.confidence}")

        # The Analyst may revise its service/CVE without making another web
        # search. Always refresh mechanism triage from its FINAL findings
        # and the FINAL accumulated research before Verifier and binary policy.
        # This does not change the LLM answer or validate CVE applicability.
        cve_triage = rank_cve_mechanisms(
            flow_summary, analyst_output, online_result,
            verified_cookie_rpc_sequences=self.verified_cookie_rpc_sequences,
        )
        self.last_cve_triage = cve_triage
        cve_hints = cve_triage.to_text() if cve_triage.candidates else ""
        print("Final Analyst mechanism triage: "
              + (", ".join(item.cve_id for item in cve_triage.candidates)
                 or "no packet-backed candidate"))

        print("\nStep 4: Verifier running on revised Analyst output...")
        # Online evidence is context, not a verifier decision or packet proof.
        # This uses the FINAL accumulated MCP result and the FINAL Analyst CVE.
        mcp_verifier_context = build_verifier_mcp_context(
            flow_summary, analyst_output, online_result, cve_triage
        )
        verifier_research_kwargs = (
            {"mcp_evidence_context": mcp_verifier_context}
            if mcp_verifier_context else {}
        )
        if notebook:
            verifier_output = self.verifier.verify(
                flow_summary, analyst_output,
                investigation_notes=notebook.context(stage="verification"),
                **({"cve_mechanism_hints": cve_hints} if cve_hints else {}),
                **verifier_research_kwargs,
            )
        else:
            verifier_output = self.verifier.verify(
                flow_summary, analyst_output,
                **({"cve_mechanism_hints": cve_hints} if cve_hints else {}),
                **verifier_research_kwargs,
            )
        self._show_status("Verifier", verifier_output)
        verifier_json = verifier_output.to_prompt_json()
        print(f"Verifier done: {verifier_json[:200]}...")
        if verifier_output.status == "Abstain":
            raise PipelineAbortError("MAFRA MCP Verifier", verifier_output.validation_errors)

        if notebook:
            notebook.note_verifier(verifier_output)
        # FRA-aligned MAFRA: Analyst -> MCP -> Analyst -> Verifier -> Consensus.
        # No separate online CVE validation or post-consensus override.
        # The Reporter currently expects a CVEValidationOutput data contract;
        # populate that contract ONLY from existing Analyst+Verifier+Consensus
        # decisions rather than running another decision-making component.
        consensus = self.consensus.calculate(analyst_output, verifier_output)
        proposed_cve = analyst_output.cve.candidate
        verifier_supported = (verifier_output.cve_supported == Decision.YES.value)
        consensus_agrees = getattr(consensus, "cve", proposed_cve) == proposed_cve
        corroborated = (proposed_cve != NOT_FOUND and verifier_supported
                        and consensus_agrees)
        validated_cve = CVEValidationOutput(
            status=ResultStatus.VALID,
            validated_cve=proposed_cve if corroborated else NOT_FOUND,
            cve_supported=Decision.YES if corroborated else Decision.NO,
            confidence=(verifier_output.confidence if corroborated
                        else Confidence.LOW),
            reasons=[
                (f"Analyst proposed {proposed_cve}; independent Verifier "
                 f"CVE support: {verifier_output.cve_supported}. "
                 "No separate online CVE validator was run."),
            ],
        )
        # Benchmark-specific binary predictions, independently traceable to
        # packet observations. Do not modify raw Verifier/Consensus decisions.
        binary_assessment = assess_binary_benchmark(
            flow_summary, analyst_output, verifier_output, consensus,
            online_result, cve_triage,
        )
        consensus_text = self.consensus.format(consensus)
        print(consensus_text)

        print("\nStep 5: Evidence Formatting running...")
        formatted_evidence = self.evidence_formatter.format(
            flow_summary=flow_summary,
            analyst_output=analyst_output,
            verifier_output=verifier_output,
            consensus=consensus,
            online_result=online_result,
        )
        self.last_formatted_evidence = formatted_evidence
        print(formatted_evidence.to_prompt_text()[:1600])

        print("\nStep 6: RAG Memory context for report...")
        if self.memory_manager.mode != "read_only":
            # Isolated-memory behaviour remains report-only, avoiding use of
            # prior self-generated run outcomes in the Analyst's decisions.
            rag_context = self.memory_manager.retrieve(flow_summary)
        print(
            f"RAG: mode={self.memory_manager.status()}, "
            f"sources={len(self.memory_manager.last_retrievals)}"
        )

        print("\nStep 7: MCP Reporter Agent running...")
        final_report = self.reporter.generate(
            flow_summary=flow_summary,
            analyst_output=analyst_output,
            verifier_output=verifier_output,
            consensus=consensus,
            validated_cve=validated_cve,
            online_result=online_result,
            formatted_evidence=formatted_evidence,
            rag_context=rag_context,
            binary_assessment=binary_assessment,
            **({"investigation_notes": notebook.context(stage="report")}
               if notebook else {}),
            **({"cve_mechanism_hints": cve_hints} if cve_hints else {}),
        )
        self._show_status("MCP Reporter", final_report)
        if final_report.status == "Abstain":
            raise PipelineAbortError(
                "MAFRA MCP Reporter", final_report.validation_errors
            )
        final_report_text = final_report.to_text()

        print("\n=== MAFRA MCP Evidence-Enrichment Analysis Complete ===")

        return (
            "=== INITIAL ANALYZER OUTPUT ===\n"
            f"{self.last_initial_analyst.to_prompt_json()}\n\n"
            "=== REVISED ANALYZER OUTPUT ===\n"
            f"{analyst_json}\n\n"
            "=== VERIFIER OUTPUT ===\n"
            f"{verifier_json}\n\n"
            f"{consensus_text}\n\n"
            f"{online_result.to_text()}\n\n"
            f"{cve_triage.to_text()}\n\n"
            "=== FORMATTED EVIDENCE ===\n"
            f"{formatted_evidence.to_prompt_text()}\n\n"
            "=== ANALYST-VERIFIER CVE STATUS (NO SEPARATE VALIDATOR) ===\n"
            f"{validated_cve.to_prompt_json()}\n\n"
            "=== FINAL REPORT ===\n"
            f"{final_report_text}"
            + ("\n\n=== SINGLE-CASE INVESTIGATION NOTEBOOK (CONTEXT ONLY) ===\n"
               + notebook.context(stage="audit") if notebook else "")
        )
