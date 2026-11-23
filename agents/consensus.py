"""Deterministic consensus calculation over validated agent outputs."""

from contracts import (
    AnalystOutput,
    AttackOutcome,
    Confidence,
    ConsensusDecision,
    Decision,
    NOT_FOUND,
    VerificationResult,
    ResultStatus,
    VerifierOutput,
)


class ConsensusManager:
    @staticmethod
    def _has_specific_attack(analyst_output: AnalystOutput) -> bool:
        unknown = {"", "unknown", "none", "not found", "not applicable", "n/a", "no attack"}
        return any(
            str(value or "").strip().casefold() not in unknown
            for value in (analyst_output.attack.type, analyst_output.attack.technique)
        )

    @staticmethod
    def _attack_outcome(
        analyst_output: AnalystOutput,
        verifier_output: VerifierOutput,
    ) -> AttackOutcome:
        """Return an outcome only when the packet-linked finding is verified.

        CVE support is evaluated independently. In particular, absence of
        observable success is not itself proof of a failed attack.
        """
        if (
            analyst_output.status != ResultStatus.VALID.value
            or verifier_output.status != ResultStatus.VALID.value
            or not ConsensusManager._has_specific_attack(analyst_output)
            or not analyst_output.attack.evidence
        ):
            return AttackOutcome.ABSTAIN

        # A partially supported result can still contain a verified attack
        # outcome when only the exact CVE is uncertain. But an explicitly
        # rejected or unresolved attack/outcome must remain Unknown.
        if verifier_output.verification_result in {
            VerificationResult.UNSUPPORTED.value,
            VerificationResult.ABSTAIN.value,
        }:
            return AttackOutcome.ABSTAIN
        if (
            verifier_output.attack_supported != Decision.YES.value
            or verifier_output.success_supported != Decision.YES.value
        ):
            return AttackOutcome.ABSTAIN

        if analyst_output.attack.success == AttackOutcome.SUCCESS.value:
            return AttackOutcome.SUCCESS
        if analyst_output.attack.success == AttackOutcome.FAILURE.value:
            return AttackOutcome.FAILURE
        return AttackOutcome.ABSTAIN

    def calculate(
        self,
        analyst_output: AnalystOutput,
        verifier_output: VerifierOutput,
    ) -> ConsensusDecision:
        score = 0
        specific_attack = self._has_specific_attack(analyst_output)
        attack_supported = (
            verifier_output.attack_supported if specific_attack else Decision.ABSTAIN.value
        )
        success_supported = (
            verifier_output.success_supported if specific_attack else Decision.ABSTAIN.value
        )
        effective_verification = (
            verifier_output.verification_result if specific_attack
            else VerificationResult.PARTIALLY_SUPPORTED.value
        )

        if verifier_output.service_supported == Decision.YES.value:
            score += 1
        if attack_supported == Decision.YES.value:
            score += 1
        if success_supported == Decision.YES.value:
            score += 1
        max_score = 4
        if analyst_output.cve.candidate != NOT_FOUND:
            max_score += 1
            if specific_attack and verifier_output.cve_supported == Decision.YES.value:
                score += 1
        if effective_verification == VerificationResult.SUPPORTED.value:
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
            attack_success=self._attack_outcome(analyst_output, verifier_output),
            cve=analyst_output.cve.candidate,
            verification_result=effective_verification,
            service_supported=verifier_output.service_supported,
            attack_supported=attack_supported,
            success_supported=success_supported,
            cve_supported=(verifier_output.cve_supported if specific_attack
                           else Decision.ABSTAIN.value),
            verifier_confidence=verifier_output.confidence,
            overall_confidence=overall_confidence,
            score=score,
            max_score=max_score,
        )

    def format(self, consensus: ConsensusDecision) -> str:
        return consensus.to_text()
