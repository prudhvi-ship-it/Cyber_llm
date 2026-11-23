"""Conservative policy for linking online sources to validated findings."""

from contracts import (
    AnalystOutput,
    CVEValidationOutput,
    Confidence,
    Decision,
    NOT_FOUND,
    ResultStatus,
    VerifierOutput,
)
from mcp_evidence_contracts import OnlineEvidenceResult
from cve_mechanism_matcher import CVEMechanismTriage, VENDOR_PROFILES
from erlang_cookie_evidence import VerifiedCookieRpcSequence


def derive_online_cve_validation(
    analyst_output: AnalystOutput,
    verifier_output: VerifierOutput,
    online_result: OnlineEvidenceResult,
    cve_triage: CVEMechanismTriage | None = None,
    verified_cookie_rpc_sequences: tuple[VerifiedCookieRpcSequence, ...] = (),
) -> CVEValidationOutput:
    """Validate an exact CVE only when agents and online evidence agree.

    The online search cannot create a new CVE finding by itself.  It can only
    corroborate the candidate already proposed by the Analyzer and supported
    by the Verifier.
    """

    proposed = analyst_output.cve.candidate
    reasons: list[str] = []

    if online_result.status != ResultStatus.VALID.value:
        reasons.append("MCP online evidence retrieval was unavailable or failed.")
    elif not online_result.sources:
        reasons.append("MCP returned no online sources for the investigation query.")
    else:
        reasons.append(
            f"MCP returned {len(online_result.sources)} online source(s) for the investigation query."
        )

    # Step 5B: independent *raw packet* corroboration of the CouchDB public
    # default cookie. A pair of matched MD5 digests, the vendor-identified
    # CouchDB node, and later command execution in the SAME stream support
    # high-confidence mechanism attribution despite an unreported version.
    # Never infer a CVE from summary text, filenames, an LLM opinion, or an
    # isolated digest. This path is limited to this vendor-reviewed profile.
    validated_profile = "CVE-2022-24706"
    if (
        verified_cookie_rpc_sequences
        and cve_triage is not None
        and any(x.cve_id == validated_profile for x in cve_triage.candidates)
        and validated_profile in online_result.candidate_cves
        and online_result.status == ResultStatus.VALID.value
        and verifier_output.status == ResultStatus.VALID.value
        and verifier_output.service_supported == Decision.YES.value
        and verifier_output.attack_supported == Decision.YES.value
        and verifier_output.success_supported == Decision.YES.value
        and "couchdb" in analyst_output.service.primary.lower()
        and any(s.handshake.server_node.startswith("couchdb@")
                and s.handshake.client_digest_matched
                and s.handshake.server_digest_matched
                for s in verified_cookie_rpc_sequences)
    ):
        reasons.append(
            "Raw TCP packets verify both Erlang challenge-response digests "
            "against Apache's publicly documented default cookie, followed by "
            "paired os:cmd('id') request/rex output in the same TCP stream. "
            "The official CVE-2022-24706 mechanism matches. Exact CouchDB "
            "version and the attacker's authorization are not observable; "
            "this is HIGH-CONFIDENCE mechanism attribution, not proof of intent."
        )
        reasons.append("Vendor advisory: https://docs.couchdb.org/en/stable/cve/2022-24706.html")
        return CVEValidationOutput(
            status=ResultStatus.VALID, validated_cve=validated_profile,
            cve_supported=Decision.YES, confidence=Confidence.HIGH,
            reasons=reasons,
        )

    # Mechanism-consistency is not proof of a specific vulnerable version or
    # default configuration. In the Step 5A path, avoid auto-confirming a
    # profiled CVE merely because both LLM agents repeat the same online lead.
    if (
        cve_triage is not None
        and proposed in VENDOR_PROFILES
        and any(item.cve_id == proposed for item in cve_triage.candidates)
    ):
        reasons.append(
            "A vulnerability-specific mechanism match exists, but the exact "
            "CVE prerequisites (including version and configuration) are "
            "unconfirmed. It remains a candidate, not validated attribution."
        )
        return CVEValidationOutput(
            status=ResultStatus.VALID,
            validated_cve=NOT_FOUND,
            cve_supported=Decision.NO,
            confidence=Confidence.LOW,
            reasons=reasons,
        )

    generic_mechanism_match = bool(
        cve_triage is not None
        and any(item.cve_id == proposed for item in cve_triage.candidates)
    )

    if (
        proposed != NOT_FOUND
        and verifier_output.cve_supported == Decision.YES.value
        and proposed in online_result.candidate_cves
        and generic_mechanism_match
    ):
        reasons.append(
            f"The Analyzer and Verifier supported {proposed}; MCP returned the "
            "same identifier; and packet observations matched a CVE-specific "
            "mechanism candidate from an authoritative source."
        )
        return CVEValidationOutput(
            status=ResultStatus.VALID,
            validated_cve=proposed,
            cve_supported=Decision.YES,
            confidence=Confidence.MEDIUM,
            reasons=reasons,
        )

    if proposed != NOT_FOUND and proposed not in online_result.candidate_cves:
        reasons.append(
            "The proposed CVE was not found in the MCP result set, so it was not confirmed."
        )
    elif proposed == NOT_FOUND:
        reasons.append("The Analyzer did not propose an exact CVE to corroborate.")
    elif not generic_mechanism_match:
        reasons.append(
            "The proposed CVE was not confirmed because packet observations did "
            "not produce a CVE-specific mechanism match from an authoritative source."
        )
    else:
        reasons.append("The Verifier did not support the proposed CVE.")

    return CVEValidationOutput(
        status=ResultStatus.VALID,
        validated_cve=NOT_FOUND,
        cve_supported=Decision.NO,
        confidence=Confidence.LOW,
        reasons=reasons,
    )
