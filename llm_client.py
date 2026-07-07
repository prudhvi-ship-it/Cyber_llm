'''import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

load_dotenv()


DEFAULT_MODEL = os.getenv("LLM_MODEL", "gpt-4o")


def get_llm(model: str | None = None, temperature: float = 0):
    """Create and return the LLM used by the FRA project.

    Today this uses OpenAI through LangChain.
    Later, this file will be the only place we change for OpenRouter,
    Claude, Gemini, or multi-LLM support.
    """
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY is missing. Please check your .env file.")

    return ChatOpenAI(
        model=model or DEFAULT_MODEL,
        api_key=api_key,
        temperature=temperature,
    )'''

import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

load_dotenv()


MODEL_MAP = {
    "gpt": "openai/gpt-4o-mini",
    "claude": "anthropic/claude-3.5-haiku",
    "gemini": "google/gemini-2.0-flash-001",
}


def get_llm(role: str = "gpt", temperature: float = 0):
    api_key = os.getenv("OPENROUTER_API_KEY")

    if not api_key:
        raise ValueError("OPENROUTER_API_KEY is missing. Please check your .env file.")

    model_name = MODEL_MAP.get(role, role)

    return ChatOpenAI(
        model=model_name,
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1",
        temperature=temperature,
    )
