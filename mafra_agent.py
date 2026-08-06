from agents.analyst_agent import AnalystAgent
from agents.consensus import ConsensusManager
from agents.cve_validator_agent import CVEValidatorAgent
from agents.reporter_agent import ReporterAgent
from agents.verifier_agent import VerifierAgent
from contracts import ContractModel
from memory_manager import MemoryManager
from pipeline_errors import PipelineAbortError
from web_search import WebSearch


class MAFRAAgent:
    def __init__(
        self,
        current_case_id: str | None = None,
        memory_mode: str | None = None,
        run_id: str | None = None,
    ):
        self.analyst = AnalystAgent()
        self.verifier = VerifierAgent()
        self.reporter = ReporterAgent()
        self.consensus = ConsensusManager()
        self.web_search = WebSearch()
        self.memory_manager = MemoryManager(
            system_name="MAFRA",
            current_case_id=current_case_id,
            mode=memory_mode,
            run_id=run_id,
        )
        self.cve_validator = CVEValidatorAgent()

    @staticmethod
    def _show_status(stage: str, result: ContractModel) -> None:
        if result.validation_errors:
            print(
                f"Warning: {stage} returned {result.status} after validation "
                f"({len(result.validation_errors)} failed attempt(s))."
            )

    def run(self, flow_summary: str) -> str:
        print("\n=== Starting MAFRA Multi-Agent Analysis ===")

        print("\nStep 1: Analyst Agent running...")
        analyst_output = self.analyst.analyze(flow_summary)
        self._show_status("Analyst", analyst_output)
        analyst_json = analyst_output.to_prompt_json()
        print(f"Analyst done: {analyst_json[:200]}...")
        if analyst_output.status == "Abstain":
            raise PipelineAbortError("MAFRA Analyst", analyst_output.validation_errors)

        print("\nStep 2: Verifier Agent running...")
        verifier_output = self.verifier.verify(flow_summary, analyst_output)
        self._show_status("Verifier", verifier_output)
        verifier_json = verifier_output.to_prompt_json()
        print(f"Verifier done: {verifier_json[:200]}...")
        if verifier_output.status == "Abstain":
            raise PipelineAbortError("MAFRA Verifier", verifier_output.validation_errors)

        print("\nStep 3: Consensus Manager running...")
        consensus = self.consensus.calculate(analyst_output, verifier_output)
        consensus_text = self.consensus.format(consensus)
        print(consensus_text)

        print("\nStep 4: CVE Search running...")
        cve_query = self.web_search.build_forensic_query(
            consensus.service,
            consensus.attack,
            analyst_output.to_prompt_json(),
            flow_summary,
        )
        print(f"Evidence-aware CVE query: {cve_query}")
        cve_results = self.web_search.run_structured(cve_query)
        cve_results_text = cve_results.to_text()
        print(f"CVE search done: {cve_results_text[:200]}...")

        print("\nStep 5: CVE Validator Agent running...")
        validated_cve = self.cve_validator.validate(
            flow_summary=flow_summary,
            analyst_output=analyst_output,
            verifier_output=verifier_output,
            cve_results=cve_results,
        )
        self._show_status("CVE Validator", validated_cve)
        validated_cve_json = validated_cve.to_prompt_json()
        print(f"CVE validation done: {validated_cve_json[:200]}...")
        if validated_cve.status == "Abstain":
            raise PipelineAbortError(
                "MAFRA CVE Validator", validated_cve.validation_errors
            )

        print("\nStep 6: RAG Memory retrieval...")
        rag_context = self.memory_manager.retrieve(flow_summary)
        print(
            f"RAG: mode={self.memory_manager.status()}, "
            f"sources={len(self.memory_manager.last_retrievals)}"
        )

        print("\nStep 7: Reporter Agent running...")
        final_report = self.reporter.generate(
            flow_summary=flow_summary,
            analyst_output=analyst_output,
            verifier_output=verifier_output,
            consensus=consensus,
            validated_cve=validated_cve,
            rag_context=rag_context,
        )
        self._show_status("Reporter", final_report)
        if final_report.status == "Abstain":
            raise PipelineAbortError("MAFRA Reporter", final_report.validation_errors)
        final_report_text = final_report.to_text()

        print("\n=== MAFRA Analysis Complete ===")

        # Preserve the existing human-readable report sections so current report
        # readers continue to work while all internal handoffs remain typed.
        return (
            "=== ANALYST OUTPUT ===\n"
            f"{analyst_json}\n\n"
            "=== VERIFIER OUTPUT ===\n"
            f"{verifier_json}\n\n"
            f"{consensus_text}\n\n"
            "=== CVE VALIDATION ===\n"
            f"{validated_cve_json}\n\n"
            "=== FINAL REPORT ===\n"
            f"{final_report_text}"
        )
