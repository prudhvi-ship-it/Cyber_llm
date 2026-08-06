"""Deterministic CVE-validation consistency policy without LLM dependencies."""

from contracts import (
    AnalystOutput,
    CVECandidate,
    CVERetrievalResult,
    CVEValidationOutput,
    Confidence,
    Decision,
    NOT_FOUND,
    ResultStatus,
    UNKNOWN,
    VerifierOutput,
)


def candidate_by_id(
    cve_results: CVERetrievalResult,
    cve_id: str,
) -> CVECandidate | None:
    for candidate in cve_results.candidates:
        if candidate.cve_id == cve_id:
            return candidate
    return None


def strong_supported_candidate(
    analyst_output: AnalystOutput,
    verifier_output: VerifierOutput,
    cve_results: CVERetrievalResult,
) -> CVECandidate | None:
    """Return a candidate supported by analyst, verifier, product and version."""
    proposed = analyst_output.cve.candidate
    if proposed == NOT_FOUND:
        return None
    if verifier_output.cve_supported != Decision.YES.value:
        return None
    if cve_results.version == UNKNOWN:
        return None

    candidate = candidate_by_id(cve_results, proposed)
    if candidate is None or not candidate.product_match:
        return None

    version_supported = (
        candidate.version_match
        or candidate.version_status in {"Affected", "Mentioned"}
    )
    retrieval_support = (
        candidate.attack_match
        or cve_results.selection.selected_cve == candidate.cve_id
    )
    if not version_supported or not retrieval_support:
        return None
    return candidate


def enforce_consistent_cve_validation(
    validation: CVEValidationOutput,
    analyst_output: AnalystOutput,
    verifier_output: VerifierOutput,
    cve_results: CVERetrievalResult,
) -> CVEValidationOutput:
    """Keep a strongly supported allowed candidate from being erased."""
    supported = strong_supported_candidate(
        analyst_output,
        verifier_output,
        cve_results,
    )
    if supported is None:
        return validation

    if validation.cve_supported == Decision.YES.value:
        # A valid, allowed validator selection remains authoritative, including
        # when it identifies a different candidate than the analyst proposed.
        return validation

    return CVEValidationOutput(
        status=ResultStatus.VALID,
        validated_cve=supported.cve_id,
        cve_supported=Decision.YES,
        confidence=Confidence.MEDIUM,
        reasons=[
            "Deterministic consistency guard retained the analyst-proposed "
            "CVE because the verifier supported it and the allowed NVD "
            "candidate matched the product and observed version.",
            f"Observed version: {cve_results.version}; NVD version status: "
            f"{supported.version_status}.",
            "The validator may not replace structured observed-version "
            "evidence with an unsupported claim that the version is unknown.",
        ],
    )
