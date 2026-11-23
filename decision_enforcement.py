"""Deterministic final-decision rules shared by FRA and MAFRA."""

import re

from contracts import (
    AnalystOutput,
    AttackOutcome,
    ConsensusDecision,
    CVERetrievalResult,
    CVEValidationOutput,
    Decision,
    FinalReport,
    NOT_FOUND,
    UNKNOWN,
    VerificationResult,
    VerifierOutput,
)
from binary_benchmark_policy import BinaryBenchmarkAssessment


_EVIDENCE_PATTERN = re.compile(
    r"\[(E-[A-Za-z0-9-]+)(?:\s*\|\s*[^\]]+)?\]\s*(.+)"
)


def _build_evidence_catalog(flow_summary: str) -> dict[str, str]:
    """Map packet evidence IDs to their descriptions."""

    catalog: dict[str, str] = {}

    for line in flow_summary.splitlines():
        match = _EVIDENCE_PATTERN.search(line)
        if not match:
            continue

        evidence_id = match.group(1).strip()
        description = match.group(2).strip().strip("-").strip()

        if description and description.lower() != "none":
            catalog.setdefault(evidence_id, description)

    return catalog


def _build_readable_evidence(
    analysis: AnalystOutput,
    flow_summary: str,
) -> list[str]:
    """Convert bare evidence IDs into readable evidence statements."""

    catalog = _build_evidence_catalog(flow_summary)
    evidence_items: list[str] = []

    for evidence_id in analysis.attack.evidence:
        description = catalog.get(evidence_id)

        if description:
            cleaned = description.rstrip(".")
            evidence_items.append(
                f"PCAP [{evidence_id}]: {cleaned}."
            )
        else:
            evidence_items.append(
                f"PCAP [{evidence_id}]: Description unavailable in flow "
                "summary; verify this reference against the original capture."
            )

    return evidence_items


def _default_recommendations(
    service: str,
    attack_successful: bool,
    identified_cve: str,
) -> list[str]:
    """Generate safe minimum defensive recommendations."""

    service_label = (
        service if service and service != UNKNOWN else "the affected service"
    )

    recommendations = [
        (
            f"Upgrade {service_label} to the latest supported patched version "
            "and apply relevant vendor security advisories."
        ),
        (
            f"Restrict network access to {service_label} to trusted systems "
            "and dedicated management networks."
        ),
        (
            f"Run {service_label} with least privileges and review service, "
            "host, and network logs for related indicators of compromise."
        ),
    ]

    if identified_cve != NOT_FOUND:
        recommendations.append(
            f"Apply the vendor remediation specifically associated with "
            f"{identified_cve}."
        )

    if attack_successful:
        recommendations.append(
            "Investigate the affected host for unauthorized command execution "
            "and rotate potentially exposed credentials, tokens, and secrets."
        )

    return recommendations


def enforce_fra_report(
    report: FinalReport,
    analysis: AnalystOutput,
    cve_results: CVERetrievalResult,
) -> FinalReport:
    report.affected_service = analysis.service.primary
    report.attack = analysis.attack.success
    report.identified_cve = cve_results.selection.selected_cve

    # A validated CVE proves vulnerability. A successfully observed attack also
    # proves that the service was vulnerable in the captured state, even when
    # the exact CVE cannot be mapped from network evidence.
    if (
        report.identified_cve != NOT_FOUND
        or analysis.attack.success == AttackOutcome.SUCCESS.value
    ):
        report.is_service_vulnerable = Decision.YES.value

    return report


def enforce_mafra_report(
    report: FinalReport,
    analyst_output: AnalystOutput,
    verifier_output: VerifierOutput,
    validated_cve: CVEValidationOutput,
    consensus: ConsensusDecision | None = None,
    flow_summary: str = "",
    binary_assessment: BinaryBenchmarkAssessment | None = None,
) -> FinalReport:
    """Preserve raw decisions; show optional forced-choice predictions separately."""

    report.affected_service = (
        analyst_output.service.primary
        if verifier_output.service_supported == Decision.YES.value
        else UNKNOWN
    )

    report.identified_cve = validated_cve.validated_cve

    # Report context only. Verifier/Consensus/CVE validation stay unchanged.
    report._show_mafra_cve_context = True
    report._show_mafra_attack_uncertainty = True
    report._associated_cve_candidate = analyst_output.cve.candidate
    report._verifier_cve_support = verifier_output.cve_supported

    if consensus is not None:
        # Keep Consensus's three-way decision. Unknown is not a failed attack.
        report.attack = consensus.attack_success
    else:
        report.attack = (
            analyst_output.attack.success
            if (
                verifier_output.verification_result == VerificationResult.SUPPORTED.value
                and verifier_output.success_supported == Decision.YES.value
            )
            else AttackOutcome.ABSTAIN.value
        )

    if binary_assessment is not None:
        report._binary_benchmark = True
        report._binary_mechanism_match = binary_assessment.cve_mechanism_match
        report._binary_exact_applicability = binary_assessment.exact_applicability_established
        report._binary_attack_confidence = binary_assessment.attack_prediction_confidence
        report._binary_attack_verified = binary_assessment.attack_prediction_verified
        # The raw Consensus remains unchanged. The visible binary attack label
        # is a benchmark prediction and is explicitly qualified when unverified.
        report.attack = binary_assessment.attack_prediction

    # Only *verified* success can establish vulnerability; a forced binary
    # prediction is not proof.
    verified_success = (
        (consensus.attack_success == AttackOutcome.SUCCESS.value)
        if consensus is not None else
        (report.attack == AttackOutcome.SUCCESS.value)
    )

    # Preserve the distinction between CVE identification and vulnerability.
    # A failed or unobserved attempt is not proof that the service is safe.
    # The model may have output No; deterministically replace that unsupported
    # conclusion without altering the verified attack-outcome decision.
    if report.identified_cve != NOT_FOUND or verified_success:
        report.is_service_vulnerable = Decision.YES.value
    else:
        report.is_service_vulnerable = Decision.ABSTAIN.value

    # Replace bare evidence IDs with readable evidence descriptions.
    readable_evidence = _build_readable_evidence(
        analyst_output,
        flow_summary,
    )

    if readable_evidence:
        report.evidence = readable_evidence
    elif analyst_output.attack.evidence:
        report.evidence = [
            (
                f"PCAP [{evidence_id}]: Description unavailable in flow "
                "summary; verify this reference against the original capture."
            )
            for evidence_id in analyst_output.attack.evidence
        ]

    # Build a deterministic verification summary so validated information
    # cannot be omitted or contradicted by the Reporter model.
    verification_summary = [
        f"Affected service: {report.affected_service}.",
        f"Attack type: {analyst_output.attack.type}.",
        f"Attack technique: {analyst_output.attack.technique}.",
        (
            f"Service supported by Verifier: "
            f"{verifier_output.service_supported}."
        ),
        (
            f"Attack supported by Verifier: "
            f"{verifier_output.attack_supported}."
        ),
        (
            f"Attack success supported by Verifier: "
            f"{verifier_output.success_supported}."
        ),
        (
            f"Verification result: "
            f"{verifier_output.verification_result}."
        ),
        f"Verifier confidence: {verifier_output.confidence}.",
    ]

    if consensus is not None:
        verification_summary.extend(
            [
                f"Consensus confidence: {consensus.overall_confidence}.",
                f"Consensus score: {consensus.score}/{consensus.max_score}.",
                f"Consensus attack outcome: {consensus.attack_success}.",
            ]
        )

    if validated_cve.validated_cve == NOT_FOUND:
        verification_summary.append(
            "Exact CVE attribution was not confirmed from the available "
            "packet and version evidence."
        )
    else:
        verification_summary.append(
            f"Validated CVE: {validated_cve.validated_cve}."
        )

    for reason in validated_cve.reasons:
        verification_summary.append(f"CVE assessment: {reason}")

    for unsupported_claim in verifier_output.unsupported_claims:
        verification_summary.append(
            f"Unsupported claim: {unsupported_claim}"
        )

    if binary_assessment is not None:
        verification_summary.extend([
            f"Binary associated-CVE mechanism match: {binary_assessment.cve_mechanism_match}.",
            f"Exact CVE applicability established: {binary_assessment.exact_applicability_established}.",
            f"Binary attack prediction: {binary_assessment.attack_prediction} ({binary_assessment.attack_prediction_confidence} confidence).",
            f"Attack prediction supported by prior Consensus: {'Yes' if binary_assessment.attack_prediction_verified else 'No'}.",
            *[f"Binary decision limitation: {note}" for note in binary_assessment.notes],
        ])
    report.verification_summary = verification_summary

    # Prevent an empty recommendation section.
    if not any(
        recommendation.strip()
        for recommendation in report.defensive_recommendations
    ):
        report.defensive_recommendations = _default_recommendations(
            service=report.affected_service,
            attack_successful=verified_success,
            identified_cve=report.identified_cve,
        )

    return report
