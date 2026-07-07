import re
from urllib.parse import unquote_plus


class EvidenceExtractor:
    """Extract structured forensic evidence from raw TCP stream text."""

    def extract(self, flow_content):
        decoded = unquote_plus(flow_content)

        evidence = {
            "network": self.extract_network(decoded),
            "http": self.extract_http(decoded),
            "authentication": self.extract_authentication(decoded),
            "sql": self.extract_sql(decoded),
            "commands": self.extract_commands(decoded),
            "indicators": self.extract_indicators(decoded),
        }

        return evidence

    def extract_network(self, text):
        findings = []

        ip_port_pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}:\d+\b"
        findings.extend(re.findall(ip_port_pattern, text))

        ports = re.findall(r":(\d{2,5})\b", text)
        for port in ports:
            findings.append(f"Port {port}")

        return self.clean(findings)

    def extract_http(self, text):
        findings = []

        methods = re.findall(
            r"\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+([^\s]+)",
            text,
            re.IGNORECASE
        )

        for method, uri in methods:
            findings.append(f"{method.upper()} {uri}")

        status_codes = re.findall(r"HTTP/\d\.\d\s+(\d{3})", text)
        for code in status_codes:
            findings.append(f"HTTP Status {code}")

        hosts = re.findall(r"Host:\s*([^\r\n]+)", text, re.IGNORECASE)
        for host in hosts:
            findings.append(f"Host: {host.strip()}")

        user_agents = re.findall(r"User-Agent:\s*([^\r\n]+)", text, re.IGNORECASE)
        for ua in user_agents:
            findings.append(f"User-Agent: {ua.strip()}")

        return self.clean(findings)

    def extract_authentication(self, text):
        findings = []

        auth_patterns = [
            r"username=([^&\s]+)",
            r"user=([^&\s]+)",
            r"pma_username=([^&\s]+)",
            r"password=([^&\s]+)",
            r"pass=([^&\s]+)",
            r"pma_password=([^&\s]+)",
            r"token=([^&\s]+)",
            r"Cookie:\s*([^\r\n]+)",
            r"Set-Cookie:\s*([^\r\n]+)",
        ]

        for pattern in auth_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                findings.append(match.strip())

        if "root" in text.lower():
            findings.append("root user observed")

        if "admin" in text.lower():
            findings.append("admin keyword observed")

        return self.clean(findings)

    def extract_sql(self, text):
        findings = []

        sql_patterns = [
            r"\bCREATE\s+TABLE\b[^;\r\n]*",
            r"\bINSERT\s+INTO\b[^;\r\n]*",
            r"\bSELECT\b[^;\r\n]*",
            r"\bUPDATE\b[^;\r\n]*",
            r"\bDELETE\s+FROM\b[^;\r\n]*",
            r"\bDROP\s+TABLE\b[^;\r\n]*",
            r"\bSHOW\s+[A-Z\s]+\b[^;\r\n]*",
            r"\bUNHEX\s*\([^)]+\)",
            r"\bUNION\s+SELECT\b[^;\r\n]*",
        ]

        for pattern in sql_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            findings.extend(matches)

        return self.clean(findings)

    def extract_commands(self, text):
        findings = []

        command_patterns = [
            r"system\s*\([^)]+\)",
            r"exec\s*\([^)]+\)",
            r"shell_exec\s*\([^)]+\)",
            r"passthru\s*\([^)]+\)",
            r"popen\s*\([^)]+\)",
            r"proc_open\s*\([^)]+\)",
            r"\bwhoami\b",
            r"\bid\b",
            r"\buid=\d+",
            r"\bgid=\d+",
            r"/bin/sh",
            r"/bin/bash",
            r"cmd\.exe",
            r"powershell",
        ]

        for pattern in command_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            findings.extend(matches)

        return self.clean(findings)

    def extract_indicators(self, text):
        findings = []

        indicator_patterns = [
            r"preg_replace",
            r"useRegex=on",
            r"find=[^&\s]*?/e",
            r"/e\b",
            r"eval\s*\(",
            r"base64_decode\s*\(",
            r"[A-Za-z0-9+/]{40,}={0,2}",
            r"\.\./",
            r"UNHEX\s*\(",
            r"reverse shell",
            r"bind shell",
            r"phpMyAdmin",
            r"CouchDB",
            r"Erlang",
            r"epmd",
        ]

        for pattern in indicator_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            findings.extend(matches)

        return self.clean(findings)

    def clean(self, findings):
        cleaned = []

        for item in findings:
            if isinstance(item, tuple):
                item = " ".join(item)

            item = str(item).strip()

            if not item:
                continue

            if len(item) > 200:
                item = item[:200] + "..."

            cleaned.append(item)

        return sorted(set(cleaned))

    def format_for_prompt(self, evidence):
        sections = []

        for category, items in evidence.items():
            sections.append(f"{category.upper()}:")

            if items:
                for item in items:
                    sections.append(f"- {item}")
            else:
                sections.append("- None")

            sections.append("")

        return "\n".join(sections)