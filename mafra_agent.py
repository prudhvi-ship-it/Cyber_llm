from agents.cve_validator_agent import CVEValidatorAgent
from agents.analyst_agent import AnalystAgent
from agents.verifier_agent import VerifierAgent
from agents.reporter_agent import ReporterAgent
from agents.consensus import ConsensusManager
from web_search import WebSearch
from memory_manager import MemoryManager


class MAFRAAgent:
    def __init__(self):
        self.analyst = AnalystAgent()
        self.verifier = VerifierAgent()
        self.reporter = ReporterAgent()
        self.consensus = ConsensusManager()
        self.web_search = WebSearch()
        self.memory_manager = MemoryManager()
        self.cve_validator = CVEValidatorAgent()

    def run(self, flow_summary):
        print("\n=== Starting MAFRA Multi-Agent Analysis ===")

        print("\nStep 1: Analyst Agent running...")
        analyst_output = self.analyst.analyze(flow_summary)
        print(f"Analyst done: {analyst_output[:200]}...")

        print("\nStep 2: Verifier Agent running...")
        verifier_output = self.verifier.verify(flow_summary, analyst_output)
        print(f"Verifier done: {verifier_output[:200]}...")

        print("\nStep 3: Consensus Manager running...")
        consensus = self.consensus.calculate(analyst_output, verifier_output)
        consensus_text = self.consensus.format(consensus)
        print(consensus_text)

        print("\nStep 4: CVE Search running...")
        cve_query = f"{consensus['service']} {consensus['attack']}"
        cve_results = self.web_search.run(cve_query)
        print(f"CVE search done: {cve_results[:200]}...")

        print("\nStep 5: CVE Validator Agent running...")
        validated_cve = self.cve_validator.validate(
        flow_summary=flow_summary,
        analyst_output=analyst_output,
        verifier_output=verifier_output,
        cve_results=cve_results
)
        print(f"CVE validation done: {validated_cve[:200]}...")

        print("\nStep 6: RAG Memory retrieval...")
        rag_context = self.memory_manager.retrieve(flow_summary)
        print("RAG context retrieved.")

        print("\nStep 7: Reporter Agent running...")
        final_report = self.reporter.generate(
        flow_summary=flow_summary,
        analyst_output=analyst_output,
        verifier_output=verifier_output,
        validated_cve=validated_cve,
        rag_context=rag_context
)

        print("\n=== MAFRA Analysis Complete ===")

        return (
    "=== ANALYST OUTPUT ===\n"
    f"{analyst_output}\n\n"
    "=== VERIFIER OUTPUT ===\n"
    f"{verifier_output}\n\n"
    f"{consensus_text}\n\n"
    "=== CVE VALIDATION ===\n"
    f"{validated_cve}\n\n"
    "=== FINAL REPORT ===\n"
    f"{final_report}"
)