'''from llm_client import get_llm


class ReporterAgent:
    def __init__(self):
        self.llm = get_llm()

    def generate(self, flow_summary, analyst_output, verifier_output, cve_results, rag_context):
        prompt = f"""
You are a defensive cybersecurity forensic report writer.

Write a clear forensic report using ONLY the verified information below.
Do NOT provide exploitation steps or offensive instructions.
If the CVE is unsupported, write "Not Found".

Return ONLY in this format:

Affected Service: [service]
Identified CVE: [CVE or Not Found]
Attack: [Successful / Failed / Unknown]
Is Service Vulnerable: [Yes / No / Unknown]
Evidence:
- [evidence 1]
- [evidence 2]
- [evidence 3]

Verification Summary:
- [what was supported or unsupported]

Defensive Recommendation:
- [recommendation 1]
- [recommendation 2]
- [recommendation 3]

Flow Summary:
{flow_summary[:1200]}

Analyst Output:
{analyst_output}

Verifier Output:
{verifier_output}

CVE Search Results:
{cve_results[:2500]}

Past Similar Cases:
{rag_context}
"""
        response = self.llm.invoke(prompt)
        return response.content'''

from llm_client import get_llm


class ReporterAgent:
    def __init__(self):
        self.llm = get_llm()

    def generate(
        self,
        flow_summary,
        analyst_output,
        verifier_output,
        validated_cve,
        rag_context
    ):
        prompt = f"""
You are a defensive cybersecurity forensic report writer.

Write a clear forensic report using ONLY the verified information below.
Do NOT provide exploitation steps or offensive instructions.

IMPORTANT:
- Use the CVE decision from "Validated CVE Decision".
- If Validated CVE says "Validated CVE: CVE-XXXX-YYYY", use that CVE.
- If Validated CVE says "Not Found", write "Not Found".
- Do not override the CVE Validator.

Return ONLY in this format:

Affected Service: [service]
Identified CVE: [CVE or Not Found]
Attack: [Successful / Failed / Unknown]
Is Service Vulnerable: [Yes / No / Unknown]
Evidence:
- [evidence 1]
- [evidence 2]
- [evidence 3]

Verification Summary:
- [what was supported or unsupported]

Defensive Recommendation:
- [recommendation 1]
- [recommendation 2]
- [recommendation 3]

Flow Summary:
{flow_summary[:1200]}

Analyst Output:
{analyst_output}

Verifier Output:
{verifier_output}

Validated CVE Decision:
{validated_cve}

Past Similar Cases:
{rag_context}
"""
        response = self.llm.invoke(prompt)
        return response.content