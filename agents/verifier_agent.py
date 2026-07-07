from llm_client import get_llm


class VerifierAgent:
    def __init__(self):
        self.llm = get_llm()

    def verify(self, flow_summary, analyst_output):
        prompt = f"""
You are a cybersecurity forensic verifier.

Your job is NOT to redo the full analysis.
Your job is to check whether the analyst's conclusions are supported by the flow summary.

Check:
1. Is the service supported by evidence?
2. Is the attack type supported by evidence?
3. Is the CVE supported or unsupported?
4. Are there any hallucinations?
5. What is the verification confidence?

Return ONLY in this format:

Verification Result: [Supported / Partially Supported / Unsupported]
Service Supported: [Yes/No]
Attack Supported: [Yes/No]
CVE Supported: [Yes/No/Not Applicable]
Unsupported Claims:
- [claim 1 or None]
Evidence Check:
- [evidence 1]
- [evidence 2]
Confidence: [High/Medium/Low]

Flow Summary:
{flow_summary}

Analyst Output:
{analyst_output}
"""
        response = self.llm.invoke(prompt)
        return response.content