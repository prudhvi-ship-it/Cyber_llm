"""Offline regression checks for FRA and MAFRA decision contracts."""

import json

from agents.consensus import ConsensusManager
from contracts import (
    AnalystOutput,
    CVESelectionOutput,
    CVERetrievalResult,
    CVEValidationOutput,
    Decision,
    FinalReport,
    VerifierOutput,
    VerificationResult,
)
from decision_enforcement import enforce_fra_report, enforce_mafra_report


def main():
    analysis = AnalystOutput.model_validate({
        "service": {"primary": "Example Service"},
        "attack": {
            "type": "remote code execution",
            "success": "Success",
            "evidence": ["E-S0001-F000001-001"],
        },
        "cve": {"candidate": "Not Found"},
        "confidence": "High",
    })
    supported = VerifierOutput(
        verification_result=VerificationResult.SUPPORTED,
        service_supported=Decision.YES,
        attack_supported=Decision.YES,
        success_supported=Decision.YES,
        cve_supported=Decision.NOT_APPLICABLE,
        confidence="High",
    )
    unsupported_success = VerifierOutput(
        verification_result=VerificationResult.PARTIALLY_SUPPORTED,
        service_supported=Decision.YES,
        attack_supported=Decision.YES,
        success_supported=Decision.NO,
        cve_supported=Decision.NOT_APPLICABLE,
        confidence="Medium",
    )

    consensus = ConsensusManager().calculate(analysis, supported)
    weak_consensus = ConsensusManager().calculate(analysis, unsupported_success)
    validated_cve = CVEValidationOutput(
        validated_cve="CVE-2022-24706",
        cve_supported=Decision.YES,
        confidence="High",
    )

    mafra_draft = FinalReport(
        affected_service="Wrong Service",
        identified_cve="Not Found",
        attack="Fail",
        is_service_vulnerable="Unknown",
    )
    mafra_enforced = enforce_mafra_report(
        mafra_draft,
        analysis,
        unsupported_success,
        validated_cve,
    )

    retrieval = CVERetrievalResult(
        original_query="Example Service remote code execution",
        normalized_service="Example Service",
        retrieved_at_utc="2026-01-01T00:00:00+00:00",
        selection=CVESelectionOutput(
            selected_cve="CVE-2022-24706",
            confidence="High",
            reason="Test candidate",
        ),
    )
    fra_draft = FinalReport(
        affected_service="Wrong Service",
        identified_cve="Not Found",
        attack="Fail",
        is_service_vulnerable="Unknown",
    )
    fra_enforced = enforce_fra_report(fra_draft, analysis, retrieval)

    no_cve_validation = CVEValidationOutput(
        validated_cve="Not Found",
        cve_supported=Decision.NO,
        confidence="High",
    )
    successful_mafra_draft = FinalReport(
        affected_service="Example Service",
        identified_cve="Not Found",
        attack="Success",
        is_service_vulnerable="Unknown",
    )
    successful_mafra_enforced = enforce_mafra_report(
        successful_mafra_draft,
        analysis,
        supported,
        no_cve_validation,
    )

    successful_fra_retrieval = CVERetrievalResult(
        original_query="Example Service remote code execution",
        normalized_service="Example Service",
        retrieved_at_utc="2026-01-01T00:00:00+00:00",
        selection=CVESelectionOutput(
            selected_cve="Not Found",
            confidence="Low",
            reason="No exact CVE mapped",
        ),
    )
    successful_fra_draft = FinalReport(
        affected_service="Example Service",
        identified_cve="Not Found",
        attack="Success",
        is_service_vulnerable="Unknown",
    )
    successful_fra_enforced = enforce_fra_report(
        successful_fra_draft,
        analysis,
        successful_fra_retrieval,
    )

    checks = {
        "verifier_contract_contains_success_support": (
            supported.success_supported == Decision.YES.value
        ),
        "consensus_carries_attack_success": consensus.attack_success == "Success",
        "fully_supported_consensus_is_high": (
            consensus.overall_confidence == "High"
            and consensus.score == consensus.max_score == 4
        ),
        "unsupported_success_reduces_confidence": (
            weak_consensus.overall_confidence != "High"
        ),
        "mafra_reporter_cannot_claim_unverified_success": (
            mafra_enforced.attack == "Unknown"
        ),
        "mafra_reporter_cannot_replace_validated_cve": (
            mafra_enforced.identified_cve == "CVE-2022-24706"
        ),
        "mafra_final_service_cannot_drift": (
            mafra_enforced.affected_service == "Example Service"
        ),
        "validated_mafra_cve_marks_service_vulnerable": (
            mafra_enforced.is_service_vulnerable == "Yes"
        ),
        "verified_success_marks_mafra_service_vulnerable_without_cve": (
            successful_mafra_enforced.identified_cve == "Not Found"
            and successful_mafra_enforced.attack == "Success"
            and successful_mafra_enforced.is_service_vulnerable == "Yes"
        ),
        "fra_final_service_cannot_drift": (
            fra_enforced.affected_service == "Example Service"
        ),
        "fra_final_success_cannot_drift": fra_enforced.attack == "Success",
        "fra_final_cve_cannot_drift": (
            fra_enforced.identified_cve == "CVE-2022-24706"
        ),
        "validated_fra_cve_marks_service_vulnerable": (
            fra_enforced.is_service_vulnerable == "Yes"
        ),
        "observed_success_marks_fra_service_vulnerable_without_cve": (
            successful_fra_enforced.identified_cve == "Not Found"
            and successful_fra_enforced.attack == "Success"
            and successful_fra_enforced.is_service_vulnerable == "Yes"
        ),
    }

    status = "Valid" if all(checks.values()) else "Invalid"
    print(json.dumps({"status": status, "checks": checks}, indent=2))
    if status != "Valid":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
