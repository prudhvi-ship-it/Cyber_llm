"""Deterministic consensus calculation over validated agent outputs."""

from contracts import (
    AnalystOutput,
    Confidence,
    ConsensusDecision,
    Decision,
    NOT_FOUND,
    VerificationResult,
    VerifierOutput,
)


class ConsensusManager:
    def calculate(
        self,
        analyst_output: AnalystOutput,
        verifier_output: VerifierOutput,
    ) -> ConsensusDecision:
        score = 0

        if verifier_output.service_supported == Decision.YES.value:
            score += 1
        if verifier_output.attack_supported == Decision.YES.value:
            score += 1
        if verifier_output.success_supported == Decision.YES.value:
            score += 1
        max_score = 4
        if analyst_output.cve.candidate != NOT_FOUND:
            max_score += 1
            if verifier_output.cve_supported == Decision.YES.value:
                score += 1
        if verifier_output.verification_result == VerificationResult.SUPPORTED.value:
            score += 1

        ratio = score / max_score
        if ratio == 1.0:
            overall_confidence = Confidence.HIGH
        elif ratio >= 0.5:
            overall_confidence = Confidence.MEDIUM
        else:
            overall_confidence = Confidence.LOW

        return ConsensusDecision(
            service=analyst_output.service.primary,
            attack=analyst_output.attack.type,
            attack_success=analyst_output.attack.success,
            cve=analyst_output.cve.candidate,
            verification_result=verifier_output.verification_result,
            service_supported=verifier_output.service_supported,
            attack_supported=verifier_output.attack_supported,
            success_supported=verifier_output.success_supported,
            cve_supported=verifier_output.cve_supported,
            verifier_confidence=verifier_output.confidence,
            overall_confidence=overall_confidence,
            score=score,
            max_score=max_score,
        )

    def format(self, consensus: ConsensusDecision) -> str:
        return consensus.to_text()
