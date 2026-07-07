from llm_client import get_llm


class CVEValidatorAgent:
    def __init__(self):
        self.llm = get_llm()

    def validate(self, flow_summary, analyst_output, verifier_output, cve_results):
        prompt = f"""
You are a defensive cybersecurity CVE validation agent.

Your job is to decide whether any CVE from the NVD search results is supported by the observed forensic evidence.

Important rules:
- Do NOT invent CVEs.
- Only choose a CVE that appears in the NVD search results.
- Prefer "Not Found" if the CVE is not clearly supported.
- Match the CVE against service, attack type, and specific evidence.
- Do NOT provide exploitation steps or offensive instructions.

Return ONLY in this format:

Validated CVE: [CVE number or Not Found]
CVE Supported: [Yes / No]
Confidence: [High / Medium / Low]
Reason:
- [reason 1]
- [reason 2]
- [reason 3]

Flow Summary:
{flow_summary[:1500]}

Analyst Output:
{analyst_output}

Verifier Output:
{verifier_output}

NVD Search Results:
{cve_results[:3500]}
"""
        response = self.llm.invoke(prompt)
        return response.content