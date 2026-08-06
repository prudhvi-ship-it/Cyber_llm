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
    VerifierOutput,
)


_EVIDENCE_PATTERN = re.compile(
    r"\[(E-[A-Za-z0-9-]+)\]\s*(.+)"
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
                f"PCAP [{evidence_id}]: Evidence cited by the "
                "validated Analyst and Verifier."
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
) -> FinalReport:
    """Preserve all validated MAFRA decisions and report details."""

    report.affected_service = (
        analyst_output.service.primary
        if verifier_output.service_supported == Decision.YES.value
        else UNKNOWN
    )

    report.identified_cve = validated_cve.validated_cve

    report.attack = (
        analyst_output.attack.success
        if verifier_output.success_supported == Decision.YES.value
        else AttackOutcome.ABSTAIN.value
    )

    verified_success = (
        verifier_output.success_supported == Decision.YES.value
        and analyst_output.attack.success == AttackOutcome.SUCCESS.value
    )

    # Preserve the distinction between CVE identification and vulnerability.
    if report.identified_cve != NOT_FOUND or verified_success:
        report.is_service_vulnerable = Decision.YES.value

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
                f"PCAP [{evidence_id}]: Evidence cited by the "
                "validated Analyst and Verifier."
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