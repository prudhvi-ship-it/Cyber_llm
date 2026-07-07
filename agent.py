import os
import re
from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate
from prompts import MAIN_AGENT_PROMPT, FINAL_REPORT_PROMPT
from web_search import WebSearch
from memory_manager import MemoryManager
from dotenv import load_dotenv

load_dotenv()


class MainAgent:
    def __init__(self):
        self.llm = ChatOpenAI(
            model="gpt-4o",
            api_key=os.getenv("OPENAI_API_KEY")
        )
        self.web_search = WebSearch()
        self.memory = []
        self.memory_manager = MemoryManager()

    def think(self, flow_summary):
        """Analyse the flow summary."""
        try:
            prompt = PromptTemplate(
                input_variables=["flow_summary"],
                template=MAIN_AGENT_PROMPT
            )
            chain = prompt | self.llm
            response = chain.invoke({"flow_summary": flow_summary})
            return response.content
        except Exception as e:
            return f"Error in thinking: {e}"

    def identify_service(self, analysis):
        """Extract primary attacked service and attack type from analysis."""
        try:
            prompt = f"""From this analysis extract only the SINGLE most important service being attacked.

IMPORTANT RULES:
- If both a web application like phpMyAdmin or WordPress AND a database like MySQL are present, choose the WEB APPLICATION as the primary service.
- The web application is the attack entry point. The database is usually the backend.
- Focus on the service the attacker directly targeted.
- Look beyond simple login attempts and identify the actual exploitation technique when visible.
- Return ONLY the application name and version if visible.
- e.g. "Apache CouchDB" -> "CouchDB", "Apache HTTP Server" -> "Apache HTTP Server"
- Exception: keep "Apache" only when the service IS Apache HTTP Server.
- Attack Type must be the technical exploit method, not generic words like unauthorized access or default login.
- Prefer terms found in the flow such as preg_replace, RCE, path traversal, SQL injection, command execution, file upload.

Analysis:
{analysis}

Respond EXACTLY in this format with no markdown, no bold, no bullet points, no extra lines:
Service: [name and version only]
Attack Type: [specific technical exploit method in 2-5 words, e.g. preg_replace RCE, path traversal, SQL injection, command execution]

Only one service. Only one attack type. Nothing else."""
            response = self.llm.invoke(prompt)
            content = response.content.replace("**", "").replace("__", "")

            service_line = ""
            attack_line = ""

            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("Service:") and not service_line:
                    service_line = line
                elif line.startswith("Attack Type:") and not attack_line:
                    attack_line = line

            return f"{service_line}\n{attack_line}"

        except Exception as e:
            return f"Error identifying service: {e}"

    def search_cve(self, service_info, custom_query=None):
        """Search NVD for CVE. Accepts optional custom query for feedback rounds."""
        try:
            if custom_query:
                print(f"Searching CVE with refined query: {custom_query}")
                return self.web_search.run(custom_query)

            service_line = ""
            attack_line = ""

            for line in service_info.split("\n"):
                if line.startswith("Service:"):
                    service_line = line.replace("Service:", "").strip()
                elif line.startswith("Attack Type:"):
                    attack_line = line.replace("Attack Type:", "").strip()

            service_clean = re.split(r"[(\[,]", service_line)[0].strip()
            service_words = service_clean.split()[:2]
            service_short = " ".join(service_words)

            generic_terms = [
                "unauthorized", "access", "default", "credentials",
                "login", "attempt", "unknown", "successful", "failed",
                "exploitation", "exploit"
            ]

            attack_words = [
                word for word in attack_line.split()
                if word.lower() not in generic_terms
            ]

            attack_short = " ".join(attack_words[:4])

            if attack_short:
                query = f"{service_short} {attack_short}"
            else:
                query = service_short

            print(f"Searching CVE for: {query}")
            return self.web_search.run(query)

        except Exception as e:
            return f"Error searching CVE: {e}"

    def get_refined_query(self, cve_results, flow_summary, service_info):
        """Ask LLM for a better search query while staying on primary service."""
        try:
            prompt = f"""The CVE search returned no useful results.

Primary Service Information:
{service_info}

Flow Summary:
{flow_summary[:1200]}

Failed Search Results:
{cve_results[:500]}

Suggest a better NVD search query.

STRICT RULES:
- The query MUST stay focused on the Primary Service above.
- Do NOT switch to backend services like MySQL unless the Primary Service is MySQL.
- Use specific technical terms from the flow summary.
- Prefer exploit keywords such as preg_replace, RCE, command execution, authentication bypass, default credentials.
- Reply with 2-6 keywords ONLY.
- No sentences. No explanation.

Good examples:
phpMyAdmin preg_replace RCE
phpMyAdmin authentication bypass
CouchDB command execution
"""
            response = self.llm.invoke(prompt)
            query = response.content.strip()
            query = " ".join(query.split()[:8])
            return query if query else None

        except Exception:
            return None

    def generate_report(self, flow_summary, analysis, service_info, cve_results):
        """Generate final forensic report with RAG context."""
        try:
            past_cases = self.memory_manager.retrieve(flow_summary)
            print("\nRAG: Retrieved past cases for context")

            prompt = f"""You are a forensic analyst.
Based on all evidence below provide the final forensic report.

IMPORTANT:
Only report on the primary service identified below.
Do NOT replace it with backend technologies unless explicitly identified as the primary service.
Do NOT reference unrelated services from past cases.

Past Similar Cases (for reference only):
{past_cases}

Flow Summary:
{flow_summary[:1000]}

Initial Analysis:
{analysis[:500]}

Primary Identified Service (MUST USE):
{service_info}

CVE Search Results:
{cve_results[:3000]}

{FINAL_REPORT_PROMPT}
"""
            response = self.llm.invoke(prompt)
            return response.content

        except Exception as e:
            return f"Error generating report: {e}"

    def run(self, flow_summary):
        """Run complete forensic analysis with feedback loop."""
        print("\n=== Starting Main Agent Analysis ===")

        print("\nStep 1: Analysing flow summary...")
        analysis = self.think(flow_summary)
        self.memory.append(f"Analysis: {analysis[:200]}")
        print(f"Analysis done: {analysis[:100]}...")

        print("\nStep 2: Identifying service...")
        service_info = self.identify_service(analysis)
        self.memory.append(f"Service: {service_info}")
        print(f"Service identified: {service_info}")

        print("\nStep 3: Searching for CVE...")
        cve_results = self.search_cve(service_info)
        self.memory.append(f"CVE Results: {cve_results[:200]}")
        print(f"CVE search done: {cve_results[:100]}...")

        max_rounds = 3
        final_cve_results = cve_results

        for round_num in range(1, max_rounds + 1):
            print(f"\n--- Feedback Round {round_num}/{max_rounds} ---")

            most_likely = None

            for line in final_cve_results.split("\n"):
                if "Most Likely CVE:" in line:
                    match = re.search(r"CVE-\d{4}-\d+", line)
                    if match:
                        most_likely = match.group()
                    break

            print(f"Most Likely CVE detected: {most_likely}")

            if most_likely and most_likely != "CVE-NOT-FOUND":
                print(f"CVE found: {most_likely}. Stopping loop.")
                break

            print("CVE not found. Asking LLM for better query...")
            refined_query = self.get_refined_query(
                final_cve_results,
                flow_summary,
                service_info
            )

            if refined_query:
                print(f"Retrying with: {refined_query}")
                final_cve_results = self.search_cve(
                    service_info,
                    custom_query=refined_query
                )
            else:
                print("No refined query. Stopping loop.")
                break

        print("\nStep 4: Generating final report...")
        final_report = self.generate_report(
            flow_summary,
            analysis,
            service_info,
            final_cve_results
        )

        print("\n=== Analysis Complete ===")
        return final_report