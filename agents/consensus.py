import re


class ConsensusManager:
    def extract_field(self, text, field_name):
        pattern = rf"{field_name}:\s*(.+)"
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return "Unknown"

    def calculate(self, analyst_output, verifier_output):
        service = self.extract_field(analyst_output, "Service")
        attack = self.extract_field(analyst_output, "Attack Type")
        cve = self.extract_field(analyst_output, "Possible CVE")

        verification_result = self.extract_field(
            verifier_output,
            "Verification Result"
        )
        service_supported = self.extract_field(
            verifier_output,
            "Service Supported"
        )
        attack_supported = self.extract_field(
            verifier_output,
            "Attack Supported"
        )
        cve_supported = self.extract_field(
            verifier_output,
            "CVE Supported"
        )
        verifier_confidence = self.extract_field(
            verifier_output,
            "Confidence"
        )

        score = 0

        if service_supported.lower().startswith("yes"):
            score += 1

        if attack_supported.lower().startswith("yes"):
            score += 1

        if cve_supported.lower().startswith("yes"):
            score += 1

        if verification_result.lower().startswith("supported"):
            score += 1

        if score >= 3:
            overall_confidence = "High"
        elif score == 2:
            overall_confidence = "Medium"
        else:
            overall_confidence = "Low"

        return {
            "service": service,
            "attack": attack,
            "cve": cve,
            "verification_result": verification_result,
            "service_supported": service_supported,
            "attack_supported": attack_supported,
            "cve_supported": cve_supported,
            "verifier_confidence": verifier_confidence,
            "overall_confidence": overall_confidence,
            "score": score
        }

    def format(self, consensus):
        return f"""
=== CONSENSUS SUMMARY ===
Service: {consensus["service"]}
Attack Type: {consensus["attack"]}
CVE: {consensus["cve"]}
Verification Result: {consensus["verification_result"]}
Service Supported: {consensus["service_supported"]}
Attack Supported: {consensus["attack_supported"]}
CVE Supported: {consensus["cve_supported"]}
Verifier Confidence: {consensus["verifier_confidence"]}
Overall Confidence: {consensus["overall_confidence"]}
Score: {consensus["score"]}/4
"""