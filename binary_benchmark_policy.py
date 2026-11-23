"""Evidence-bounded forced-choice predictions for MAFRA evaluation only.

Never reinterpret a missing fact as proof of the opposite fact. Raw Verifier and
Consensus evidence findings remain unchanged. Binary labels are predictions,
not verification, and retain an explicit confidence/limitation trail.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from contracts import AnalystOutput, AttackOutcome, ConsensusDecision, Decision, NOT_FOUND, VerifierOutput
from cve_mechanism_matcher import CVEMechanismTriage
from mcp_evidence_contracts import OnlineEvidenceResult


@dataclass(frozen=True)
class BinaryBenchmarkAssessment:
    cve_mechanism_match: str  # Yes / No; not an exact version assertion
    exact_applicability_established: str  # Yes / No (No = not proven)
    attack_prediction: str  # Success / Fail
    attack_prediction_confidence: str  # High / Medium / Low
    attack_prediction_verified: bool
    packet_ids: tuple[str, ...]
    notes: tuple[str, ...]


def _has_authoritative_cve_subject(online: OnlineEvidenceResult, cve: str) -> bool:
    """Require a CVE-specific advisory subject, never narrative cross-mentions."""
    for source in online.sources:
        host = (urlparse(source.url).hostname or "").lower()
        if host == 'nvd.nist.gov' and source.url.rstrip('/').upper().endswith('/' + cve):
            return True
        if host in {'www.cisa.gov', 'cisa.gov', 'docs.couchdb.org', 'lists.apache.org'}:
            if cve in (source.title + ' ' + source.url).upper():
                return True
    return False


def assess_binary_benchmark(
    flow_summary: str,
    analyst: AnalystOutput,
    verifier: VerifierOutput,
    consensus: ConsensusDecision,
    online: OnlineEvidenceResult,
    triage: CVEMechanismTriage,
) -> BinaryBenchmarkAssessment:
    """Make explicit binary *predictions*, without overwriting audit findings.

    A CVE is mechanism-matched only with independently observed packet-linked,
    distinctive mechanism features and a CVE-specific authoritative advisory.
    We deliberately do NOT count generic attack categories, web prose or mere
    CVE retrieval as a mechanism match.
    """
    notes: list[str] = []
    proposed = analyst.cve.candidate
    triage_item = next((c for c in triage.candidates if c.cve_id == proposed), None)
    packet_ids = tuple(triage_item.packet_ids) if triage_item else ()
    # The triage is derived from real packet-linked observations; revalidate
    # that every referenced ID is still present in this case's input.
    packet_ids = tuple(p for p in packet_ids if p in flow_summary)
    features = set(triage_item.mechanism_features) if triage_item else set()
    distinctive = (any(f.startswith('http_header:') for f in features)
                   or len(features) >= 2)
    supported_by_sources = (online.status == 'Valid'
                            and proposed in online.candidate_cves
                            and _has_authoritative_cve_subject(online, proposed))
    matched = bool(proposed != NOT_FOUND and packet_ids and distinctive
                   and supported_by_sources and analyst.attack.evidence)
    if not matched:
        notes.append('CVE mechanism match is not established; No means not supported, not disproven.')
    else:
        notes.append('CVE mechanism matches packet-linked features and a CVE-specific advisory; this does not prove target version.')

    missing = tuple(triage_item.missing_conditions) if triage_item else ()
    exact = bool(matched and verifier.cve_supported == Decision.YES.value
                 and not missing)
    if not exact:
        notes.append('Exact affected-version/configuration applicability has not been established; No does not mean patched or safe.')

    raw_consensus_outcome = getattr(consensus, 'attack_success', AttackOutcome.ABSTAIN.value)
    if raw_consensus_outcome in {AttackOutcome.SUCCESS.value, AttackOutcome.FAILURE.value}:
        outcome = raw_consensus_outcome
        confidence = getattr(consensus, 'overall_confidence', 'Low')
        if confidence not in {'High', 'Medium', 'Low'}:
            confidence = 'Medium'
        verified = True
    else:
        # An unverified prediction is allowed for benchmarking only, not as a
        # factual finding. Never silently transform Unknown into proven Fail.
        if analyst.attack.success in {AttackOutcome.SUCCESS.value, AttackOutcome.FAILURE.value}:
            outcome = analyst.attack.success
            notes.append('Attack result is a forced low-confidence Analyst prediction; Verifier/Consensus did not establish it.')
        else:
            outcome = AttackOutcome.FAILURE.value
            notes.append('No supported outcome prediction was available; forced-choice Fail is a low-confidence baseline, NOT evidence that the attempt was blocked.')
        confidence, verified = 'Low', False
    return BinaryBenchmarkAssessment(
        cve_mechanism_match='Yes' if matched else 'No',
        exact_applicability_established='Yes' if exact else 'No',
        attack_prediction=outcome,
        attack_prediction_confidence=confidence,
        attack_prediction_verified=verified,
        packet_ids=packet_ids if matched else (),
        notes=tuple(notes),
    )
