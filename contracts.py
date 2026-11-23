"""Validated data contracts shared by the MAFRA agents.

LLM responses are untrusted input.  Every response must be converted to one of
these models before another component can use it.
"""

from __future__ import annotations

import json
import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator


UNKNOWN = "Unknown"
NOT_FOUND = "Not Found"
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
EVIDENCE_ID_PATTERN = re.compile(r"E-S\d{4}-F(?:\d{6}|UNKNOWN)-\d{3}")


class ResultStatus(str, Enum):
    VALID = "Valid"
    ABSTAIN = "Abstain"
    ERROR = "Error"


class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    UNKNOWN = UNKNOWN


class Decision(str, Enum):
    YES = "Yes"
    NO = "No"
    ABSTAIN = UNKNOWN
    NOT_APPLICABLE = "Not Applicable"


class AttackOutcome(str, Enum):
    SUCCESS = "Success"
    FAILURE = "Fail"
    ABSTAIN = UNKNOWN


class VerificationResult(str, Enum):
    SUPPORTED = "Supported"
    PARTIALLY_SUPPORTED = "Partially Supported"
    UNSUPPORTED = "Unsupported"
    ABSTAIN = UNKNOWN


class EvidenceCategory(str, Enum):
    NETWORK = "network"
    HTTP = "http"
    AUTHENTICATION = "authentication"
    SQL = "sql"
    COMMAND = "command"
    INDICATOR = "indicator"


class StrictModel(BaseModel):
    """Strict validation settings shared by nested and top-level models."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        validate_default=True,
    )


class ContractModel(StrictModel):
    """Base settings used by top-level inter-agent contracts."""

    status: ResultStatus = ResultStatus.VALID
    validation_errors: list[str] = Field(default_factory=list, exclude=True)

    def to_prompt_json(self) -> str:
        """Serialize safe model data for another agent's prompt."""
        return self.model_dump_json(indent=2, exclude={"validation_errors"})


class EvidenceItem(StrictModel):
    evidence_id: str = Field(pattern=r"^E-S\d{4}-F(?:\d{6}|UNKNOWN)-\d{3}$")
    category: EvidenceCategory
    observation: str = Field(min_length=1, max_length=500)
    stream_id: int = Field(ge=0)
    frame_number: int | None = Field(default=None, ge=1)
    timestamp_epoch: float | None = Field(default=None, ge=0)
    direction: str = UNKNOWN
    redacted: bool = True


def _unknown_if_blank(value: Any) -> str:
    if value is None or not str(value).strip():
        return UNKNOWN
    return str(value).strip()


'''def _normalise_cve(value: Any) -> str:
    value = _unknown_if_blank(value)
    if value.casefold() in {"unknown", "not found", "none", "n/a"}:
        return NOT_FOUND
    value = value.upper()
    if not CVE_PATTERN.fullmatch(value):
        raise ValueError("CVE must use the format CVE-YYYY-NNNN or be Not Found")
    return value'''
def _normalise_cve(value: Any) -> str:
    """Normalize CVE identifiers and common abstention values."""

    value = _unknown_if_blank(value)

    # Normalize common ways an LLM may express that no CVE was found.
    # Examples:
    #   Not Found
    #   CVE-NOT-FOUND
    #   cve_not_found
    #   N/A
    abstention_alias = re.sub(
        r"[^a-z0-9]+",
        "",
        value.casefold(),
    )

    if abstention_alias in {
        "unknown",
        "notfound",
        "cvenotfound",
        "none",
        "na",
        "null",
        "nil",
    }:
        return NOT_FOUND

    normalized_cve = value.upper()

    if not CVE_PATTERN.fullmatch(normalized_cve):
        raise ValueError(
            "CVE must use the format CVE-YYYY-NNNN or be Not Found"
        )

    return normalized_cve


class ServiceFinding(StrictModel):
    primary: str = UNKNOWN
    application: str = UNKNOWN
    framework: str = UNKNOWN
    web_server: str = UNKNOWN
    language: str = UNKNOWN
    database: str = UNKNOWN

    @field_validator(
        "primary", "application", "framework", "web_server", "language", "database",
        mode="before",
    )
    @classmethod
    def replace_blank_values(cls, value: Any) -> str:
        return _unknown_if_blank(value)


class AttackFinding(StrictModel):
    type: str = UNKNOWN
    technique: str = UNKNOWN
    success: AttackOutcome = AttackOutcome.ABSTAIN
    evidence: list[str] = Field(default_factory=list)

    @field_validator("type", "technique", mode="before")
    @classmethod
    def replace_blank_values(cls, value: Any) -> str:
        return _unknown_if_blank(value)

    @field_validator("evidence")
    @classmethod
    def require_packet_references(cls, values: list[str]) -> list[str]:
        for value in values:
            if not EVIDENCE_ID_PATTERN.search(str(value)):
                raise ValueError(
                    "each attack evidence claim must include a packet evidence ID"
                )
        return values


class CVEProposal(StrictModel):
    candidate: str = NOT_FOUND
    confidence: Confidence = Confidence.UNKNOWN
    reason: str = UNKNOWN

    @field_validator("candidate", mode="before")
    @classmethod
    def validate_cve(cls, value: Any) -> str:
        return _normalise_cve(value)

    @field_validator("reason", mode="before")
    @classmethod
    def replace_blank_reason(cls, value: Any) -> str:
        return _unknown_if_blank(value)


class AnalystOutput(ContractModel):
    service: ServiceFinding = Field(default_factory=ServiceFinding)
    attack: AttackFinding = Field(default_factory=AttackFinding)
    cve: CVEProposal = Field(default_factory=CVEProposal)
    confidence: Confidence = Confidence.UNKNOWN

    @classmethod
    def abstain(cls, errors: list[str] | None = None) -> "AnalystOutput":
        return cls(status=ResultStatus.ABSTAIN, validation_errors=errors or [])


class VerifierOutput(ContractModel):
    verification_result: VerificationResult = VerificationResult.ABSTAIN
    service_supported: Decision = Decision.ABSTAIN
    attack_supported: Decision = Decision.ABSTAIN
    success_supported: Decision = Decision.ABSTAIN
    cve_supported: Decision = Decision.NOT_APPLICABLE
    unsupported_claims: list[str] = Field(default_factory=list)
    evidence_check: list[str] = Field(default_factory=list)
    confidence: Confidence = Confidence.UNKNOWN

    @classmethod
    def abstain(cls, errors: list[str] | None = None) -> "VerifierOutput":
        return cls(status=ResultStatus.ABSTAIN, validation_errors=errors or [])


class ConsensusDecision(ContractModel):
    service: str = UNKNOWN
    attack: str = UNKNOWN
    attack_success: AttackOutcome = AttackOutcome.ABSTAIN
    cve: str = NOT_FOUND
    verification_result: VerificationResult = VerificationResult.ABSTAIN
    service_supported: Decision = Decision.ABSTAIN
    attack_supported: Decision = Decision.ABSTAIN
    success_supported: Decision = Decision.ABSTAIN
    cve_supported: Decision = Decision.NOT_APPLICABLE
    verifier_confidence: Confidence = Confidence.UNKNOWN
    overall_confidence: Confidence = Confidence.UNKNOWN
    score: int = Field(default=0, ge=0, le=5)
    max_score: int = Field(default=4, ge=1, le=5)

    def to_text(self) -> str:
        return (
            "=== CONSENSUS SUMMARY ===\n"
            f"Service: {self.service}\n"
            f"Attack Type: {self.attack}\n"
            f"Attack Success: {self.attack_success}\n"
            f"CVE: {self.cve}\n"
            f"Verification Result: {self.verification_result}\n"
            f"Service Supported: {self.service_supported}\n"
            f"Attack Supported: {self.attack_supported}\n"
            f"Success Supported: {self.success_supported}\n"
            f"CVE Supported: {self.cve_supported}\n"
            f"Verifier Confidence: {self.verifier_confidence}\n"
            f"Overall Confidence: {self.overall_confidence}\n"
            f"Score: {self.score}/{self.max_score}"
        )


class CVEValidationOutput(ContractModel):
    validated_cve: str = NOT_FOUND
    cve_supported: Decision = Decision.ABSTAIN
    confidence: Confidence = Confidence.UNKNOWN
    reasons: list[str] = Field(default_factory=list)

    @field_validator("validated_cve", mode="before")
    @classmethod
    def validate_cve(cls, value: Any) -> str:
        return _normalise_cve(value)

    @model_validator(mode="after")
    def validate_decision_consistency(self) -> "CVEValidationOutput":
        if self.cve_supported == Decision.YES.value and self.validated_cve == NOT_FOUND:
            raise ValueError("a supported CVE decision must include a CVE identifier")
        if self.cve_supported != Decision.YES.value and self.validated_cve != NOT_FOUND:
            raise ValueError("an unsupported or abstained CVE decision must use Not Found")
        return self

    @classmethod
    def abstain(cls, errors: list[str] | None = None) -> "CVEValidationOutput":
        return cls(status=ResultStatus.ABSTAIN, validation_errors=errors or [])


class CVECandidate(StrictModel):
    cve_id: str
    description: str = Field(min_length=1, max_length=4000)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    severity: str = UNKNOWN
    published: str = UNKNOWN
    source_url: str
    relevance_score: float
    relevance_reasons: list[str] = Field(default_factory=list)
    product_match: bool = False
    version_match: bool = False
    version_status: str = UNKNOWN
    attack_match: bool = False

    @field_validator("cve_id", mode="before")
    @classmethod
    def validate_candidate_id(cls, value: Any) -> str:
        cve_id = _normalise_cve(value)
        if cve_id == NOT_FOUND:
            raise ValueError("a CVE candidate must contain a CVE identifier")
        return cve_id


class CVESelectionOutput(ContractModel):
    selected_cve: str = NOT_FOUND
    confidence: Confidence = Confidence.UNKNOWN
    reason: str = UNKNOWN

    @field_validator("selected_cve", mode="before")
    @classmethod
    def validate_selected_cve(cls, value: Any) -> str:
        return _normalise_cve(value)

    @field_validator("reason", mode="before")
    @classmethod
    def replace_blank_reason(cls, value: Any) -> str:
        return _unknown_if_blank(value)

    @classmethod
    def abstain(cls, errors: list[str] | None = None) -> "CVESelectionOutput":
        return cls(status=ResultStatus.ABSTAIN, validation_errors=errors or [])


class CVERetrievalResult(ContractModel):
    original_query: str
    normalized_service: str
    version: str = UNKNOWN
    attack_terms: list[str] = Field(default_factory=list)
    search_queries: list[str] = Field(default_factory=list)
    retrieved_at_utc: str
    source: str = "NVD"
    candidates: list[CVECandidate] = Field(default_factory=list)
    selection: CVESelectionOutput = Field(default_factory=CVESelectionOutput)
    retrieval_errors: list[str] = Field(default_factory=list)

    @property
    def allowed_candidate_ids(self) -> set[str]:
        return {candidate.cve_id for candidate in self.candidates}

    def to_text(self, candidate_limit: int = 10) -> str:

        selected = self.selection.selected_cve
        selected_label = selected
        allowed = ", ".join(candidate.cve_id for candidate in self.candidates)
        sections = [
            "=== NVD CVE Search Results ===",
            f"Original Query: {self.original_query}",
            f"Normalized Service: {self.normalized_service}",
            f"Detected Version: {self.version}",
            f"Attack Terms: {', '.join(self.attack_terms) or 'None'}",
            f"Search Queries: {' | '.join(self.search_queries) or 'None'}",
            f"Retrieved At UTC: {self.retrieved_at_utc}",
            f"Total Valid Candidates: {len(self.candidates)}",
            f"Allowed Candidate IDs: {allowed or 'None'}",
            "",
            "=== Ranked CVE Candidates ===",
        ]
        if not self.candidates:
            sections.append("No product-matching CVEs found.")
        for rank, candidate in enumerate(self.candidates[:candidate_limit], start=1):
            sections.extend(
                [
                    f"Rank {rank}: {candidate.cve_id}",
                    f"Description: {candidate.description}",
                    f"CVSS: {candidate.cvss_score if candidate.cvss_score is not None else 'Unknown'}",
                    f"Severity: {candidate.severity}",
                    f"Published: {candidate.published}",
                    f"Relevance Score: {candidate.relevance_score}",
                    f"Relevance Reasons: {', '.join(candidate.relevance_reasons) or 'None'}",
                    f"Source: {candidate.source_url}",
                    "",
                ]
            )
        sections.extend(
            [
                "=== Validated Candidate Selection ===",
                f"Most Likely CVE: {selected_label}",
                f"Confidence: {self.selection.confidence}",
                f"Reason: {self.selection.reason}",
            ]
        )
        if self.retrieval_errors:
            sections.append(
                "Retrieval Warnings: " + " | ".join(self.retrieval_errors)
            )
        return "\n".join(sections)


class FinalReport(ContractModel):
    # Display-only MAFRA annotations, excluded from the LLM/report JSON schema.
    _show_mafra_cve_context: bool = PrivateAttr(default=False)
    _show_mafra_attack_uncertainty: bool = PrivateAttr(default=False)
    _associated_cve_candidate: str = PrivateAttr(default=NOT_FOUND)
    _verifier_cve_support: str = PrivateAttr(default=Decision.ABSTAIN.value)
    _binary_benchmark: bool = PrivateAttr(default=False)
    _binary_mechanism_match: str = PrivateAttr(default="No")
    _binary_exact_applicability: str = PrivateAttr(default="No")
    _binary_attack_confidence: str = PrivateAttr(default="Low")
    _binary_attack_verified: bool = PrivateAttr(default=False)

    affected_service: str = UNKNOWN
    identified_cve: str = NOT_FOUND
    attack: AttackOutcome = AttackOutcome.ABSTAIN
    is_service_vulnerable: Decision = Decision.ABSTAIN
    evidence: list[str] = Field(default_factory=list)
    verification_summary: list[str] = Field(default_factory=list)
    defensive_recommendations: list[str] = Field(default_factory=list)

    @field_validator("affected_service", mode="before")
    @classmethod
    def replace_blank_service(cls, value: Any) -> str:
        return _unknown_if_blank(value)

    @field_validator("identified_cve", mode="before")
    @classmethod
    def validate_cve(cls, value: Any) -> str:
        return _normalise_cve(value)

    @classmethod
    def abstain(cls, errors: list[str] | None = None) -> "FinalReport":
        return cls(status=ResultStatus.ABSTAIN, validation_errors=errors or [])

    def to_text(self) -> str:
        attack_label = {
            AttackOutcome.SUCCESS.value: "Successful",
            AttackOutcome.FAILURE.value: "Failed",
            # Preserve legacy FRA's binary rendering. MAFRA explicitly
            # displays unresolved outcomes as Unknown instead of Failed.
            AttackOutcome.ABSTAIN.value: (
                "Unknown" if self._show_mafra_attack_uncertainty else "Failed"
            ),
        }[self.attack]

        def lines(values: list[str]) -> str:
            return "\n".join(f"- {value}" for value in values) or "- None"

        # Preserve the existing identified-CVE line used for evaluation.
        if self._binary_benchmark:
            cve_context = (
                f"Associated CVE candidate (Analyst): {self._associated_cve_candidate}\n"
                f"Associated CVE mechanism match (binary): {self._binary_mechanism_match}\n"
                f"Exact CVE applicability established: {self._binary_exact_applicability}\n"
                f"Attack prediction confidence: {self._binary_attack_confidence}\n"
                f"Attack outcome evidence-verified: {'Yes' if self._binary_attack_verified else 'No'}\n"
            )
        else:
            cve_context = (
                f"Associated CVE candidate (Analyst): {self._associated_cve_candidate}\n"
                f"Verifier support for exact CVE: {self._verifier_cve_support}\n"
                if self._show_mafra_cve_context else ""
            )

        return (
            f"Affected Service: {self.affected_service}\n"
            f"{cve_context}"
            f"Identified CVE: {self.identified_cve}\n"
            f"Attack: {attack_label}\n"
            f"Is Service Vulnerable: {self.is_service_vulnerable}\n"
            "Evidence:\n"
            f"{lines(self.evidence)}\n\n"
            "Verification Summary:\n"
            f"{lines(self.verification_summary)}\n\n"
            "Defensive Recommendation:\n"
            f"{lines(self.defensive_recommendations)}"
        )


def contract_schema(model_type: type[ContractModel]) -> str:
    """Return the executable JSON Schema to include in an agent prompt."""
    schema = model_type.model_json_schema()
    # Internal parser diagnostics are not generated by the model.
    schema.get("properties", {}).pop("validation_errors", None)
    return json.dumps(schema, indent=2)


# Kept temporarily for older imports while the agents migrate to the models.
ANALYST_OUTPUT_CONTRACT = contract_schema(AnalystOutput)
