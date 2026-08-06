"""Helpers for safely validating JSON returned by an LLM."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import TypeVar

from pydantic import ValidationError

from contracts import ContractModel


T = TypeVar("T", bound=ContractModel)


def response_text(content: object) -> str:
    """Convert common LangChain response content shapes to plain text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return "".join(parts)
    return str(content)


def extract_json_object(text: str) -> dict:
    """Extract one JSON object without trusting markdown or surrounding prose."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()

    start = cleaned.find("{")
    if start < 0:
        raise ValueError("response did not contain a JSON object")

    value, _ = json.JSONDecoder().raw_decode(cleaned[start:])
    if not isinstance(value, dict):
        raise ValueError("top-level JSON value must be an object")
    return value


def invoke_validated(
    llm,
    prompt: str,
    model_type: type[T],
    fallback_factory: Callable[[list[str]], T],
    retries: int = 1,
) -> T:
    """Invoke an LLM, validate JSON, and abstain after bounded retries.

    Provider/network failures are already retried by the underlying client. They
    are not immediately invoked again here because doing so can amplify rate
    limits and duplicate paid calls. Schema/JSON failures still receive one
    bounded correction attempt.
    """
    errors: list[str] = []
    current_prompt = prompt

    for attempt in range(retries + 1):
        try:
            response = llm.invoke(current_prompt)
            payload = extract_json_object(response_text(response.content))
            return model_type.model_validate(payload)
        except (ValidationError, ValueError, TypeError, json.JSONDecodeError) as exc:
            errors.append(f"attempt {attempt + 1}: {str(exc)[:500]}")
        except Exception as exc:
            errors.append(
                f"attempt {attempt + 1}: provider error "
                f"{type(exc).__name__}: {str(exc)[:500]}"
            )
            break

        current_prompt = (
            prompt
            + "\n\nYour previous response failed validation. Return exactly one JSON object "
            "that follows the supplied schema. Do not use markdown or commentary."
        )

    return fallback_factory(errors)
