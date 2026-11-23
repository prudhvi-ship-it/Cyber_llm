"""Single, auditable LLM factory used by every FRA and MAFRA role."""

import os

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

from experiment_config import get_experiment_profile, resolve_model
from llm_telemetry import TelemetryCallback

load_dotenv()


def get_llm(role: str = "flow_summariser", temperature: float | None = None):
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError("OPENROUTER_API_KEY is missing. Please check your .env file.")

    profile = get_experiment_profile()
    model_name = resolve_model(role, profile)
    selected_temperature = (
        float(os.getenv("FRA_LLM_TEMPERATURE", "0"))
        if temperature is None
        else float(temperature)
    )
    callback = TelemetryCallback(
        role=role,
        model=model_name,
        profile=profile,
    )

    return ChatOpenAI(
        model=model_name,
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1",
        
        temperature=None if model_name.startswith("openai/gpt-5") else selected_temperature,
        timeout=float(os.getenv("FRA_LLM_TIMEOUT", "180")),
        max_retries=int(os.getenv("FRA_LLM_MAX_RETRIES", "2")),
        max_tokens=int(os.getenv("OPENROUTER_MAX_TOKENS", "8192")),
        callbacks=[callback],
    )
