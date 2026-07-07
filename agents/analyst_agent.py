from llm_client import get_llm


class AnalystAgent:
    def __init__(self):
        self.llm = get_llm()

    def analyze(self, flow_summary):
        prompt = f"""
You are a cybersecurity forensic analyst.

Analyze the flow summary and extract:

1. Primary attacked service
2. Attack type
3. Key evidence
4. Possible CVE or Not Found
5. Confidence level

Return ONLY in this format:

Service: [service]
Attack Type: [attack]
Possible CVE: [CVE or Not Found]
Confidence: [High/Medium/Low]
Evidence:
- [evidence 1]
- [evidence 2]
- [evidence 3]

Flow Summary:
{flow_summary}
"""
        response = self.llm.invoke(prompt)
        return response.content