"""Central model configuration for fair and heterogeneous experiments."""

from __future__ import annotations

import os


EXPERIMENT_PROFILES = {"fair_same_model", "heterogeneous"}
DEFAULT_EXPERIMENT_PROFILE = "heterogeneous"
MODEL_ROLES = (
    "flow_summariser",
    "fra_reasoner",
    "cve_selector",
    "mafra_analyst",
    "mafra_verifier",
    "mafra_cve_validator",
    "mafra_reporter",
)

ROLE_ENVIRONMENT_VARIABLES = {
    role: "FRA_MODEL_" + role.upper() for role in MODEL_ROLES
}

HETEROGENEOUS_DEFAULTS = {
    "flow_summariser": "openai/gpt-5",
    # Match FRA's primary reasoner to MAFRA's analyst for a fairer baseline.
    "fra_reasoner": "openai/gpt-5",
    "cve_selector": "openai/gpt-5",
    "mafra_analyst": "openai/gpt-5",
    "mafra_verifier": "anthropic/claude-3-haiku",
    "mafra_cve_validator": "openai/gpt-5",
    "mafra_reporter": "google/gemini-2.5-flash",
}

LEGACY_ROLE_ALIASES = {
    "gpt": "openai/gpt-5",
    "claude": "anthropic/claude-3-haiku",
    "gemini": "google/gemini-2.5-flash",
}


def get_experiment_profile(profile: str | None = None) -> str:
    selected = (
        profile or os.getenv("FRA_EXPERIMENT_PROFILE", DEFAULT_EXPERIMENT_PROFILE)
    ).strip().lower()
    if selected not in EXPERIMENT_PROFILES:
        allowed = ", ".join(sorted(EXPERIMENT_PROFILES))
        raise ValueError(f"Unknown experiment profile '{selected}'. Use: {allowed}.")
    return selected


def resolve_model(role: str, profile: str | None = None) -> str:
    """Resolve one model role without exposing API credentials."""
    if role in LEGACY_ROLE_ALIASES:
        return LEGACY_ROLE_ALIASES[role]
    if role not in MODEL_ROLES:
        # Explicit OpenRouter model names remain supported by test utilities.
        if "/" in role:
            return role
        raise ValueError(f"Unknown LLM role: {role}")

    selected_profile = get_experiment_profile(profile)
    if selected_profile == "fair_same_model":
        return os.getenv("FRA_FAIR_MODEL", "openai/gpt-5").strip()
    environment_override = os.getenv(ROLE_ENVIRONMENT_VARIABLES[role])
    if environment_override:
        return environment_override.strip()
    return HETEROGENEOUS_DEFAULTS[role]


def experiment_manifest(profile: str | None = None) -> dict[str, object]:
    selected_profile = get_experiment_profile(profile)
    return {
        "profile": selected_profile,
        "provider_gateway": "OpenRouter",
        "temperature": float(os.getenv("FRA_LLM_TEMPERATURE", "0")),
        "timeout_seconds": float(os.getenv("FRA_LLM_TIMEOUT", "180")),
        "max_provider_retries": int(os.getenv("FRA_LLM_MAX_RETRIES", "2")),
        "memory_mode": os.getenv("FRA_MEMORY_MODE", "disabled"),
        "models": {
            role: resolve_model(role, selected_profile) for role in MODEL_ROLES
        },
    }
