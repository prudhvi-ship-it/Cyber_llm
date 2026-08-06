"""JSONL telemetry for latency, tokens, provider cost, and failures."""

from __future__ import annotations

import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:
    class BaseCallbackHandler:  # type: ignore[no-redef]
        """Minimal fallback used only by dependency-free offline preflight."""

        pass


_MAX_ERROR_TEXT = 2000


def default_telemetry_path() -> Path:
    configured = os.getenv("FRA_TELEMETRY_PATH")
    if configured:
        return Path(configured)
    run_id = os.getenv("FRA_RUN_ID", "manual")
    return Path("evaluation_outputs") / "telemetry" / f"{run_id}.jsonl"


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _redact_error_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    text = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", text)
    text = re.sub(r"sk-[A-Za-z0-9_-]{12,}", "[REDACTED_API_KEY]", text)
    return text[:_MAX_ERROR_TEXT]


def _extract_usage(response: Any) -> dict[str, int | float | None]:
    sources: list[dict[str, Any]] = []
    llm_output = _as_dict(getattr(response, "llm_output", None))
    sources.extend([
        _as_dict(llm_output.get("token_usage")),
        _as_dict(llm_output.get("usage")),
        llm_output,
    ])
    try:
        message = response.generations[0][0].message
        response_metadata = _as_dict(
            getattr(message, "response_metadata", None)
        )
        sources.extend([
            _as_dict(getattr(message, "usage_metadata", None)),
            _as_dict(response_metadata.get("token_usage")),
            _as_dict(response_metadata.get("usage")),
            response_metadata,
        ])
    except (AttributeError, IndexError, TypeError):
        pass

    def first_number(keys: tuple[str, ...]):
        for source in sources:
            for key in keys:
                value = source.get(key)
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    return value
        return None

    input_tokens = first_number(("input_tokens", "prompt_tokens"))
    output_tokens = first_number(("output_tokens", "completion_tokens"))
    total_tokens = first_number(("total_tokens",))
    if total_tokens is None and input_tokens is not None and output_tokens is not None:
        total_tokens = input_tokens + output_tokens
    reported_cost = first_number(("cost", "total_cost", "cost_usd"))
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        "provider_reported_cost_usd": reported_cost,
    }


def _extract_error_details(error: Exception) -> dict[str, Any]:
    """Capture auditable provider diagnostics without leaking credentials."""
    response = getattr(error, "response", None)
    status_code = getattr(error, "status_code", None)
    if status_code is None and response is not None:
        status_code = getattr(response, "status_code", None)

    headers = getattr(response, "headers", None)
    if not isinstance(headers, dict):
        try:
            headers = dict(headers or {})
        except (TypeError, ValueError):
            headers = {}

    request_id = (
        headers.get("x-request-id")
        or headers.get("x-openrouter-request-id")
        or headers.get("cf-ray")
    )
    retry_after = headers.get("retry-after")

    body: Any = None
    if response is not None:
        try:
            body = response.json()
        except Exception:
            body = getattr(response, "text", None)
    if isinstance(body, (dict, list)):
        try:
            body = json.dumps(body, ensure_ascii=True)
        except (TypeError, ValueError):
            body = str(body)

    return {
        "error_type": type(error).__name__,
        "error_message": _redact_error_text(error),
        "http_status_code": status_code,
        "provider_request_id": _redact_error_text(request_id),
        "retry_after_seconds": _redact_error_text(retry_after),
        "provider_response_body": _redact_error_text(body),
    }


class TelemetryCallback(BaseCallbackHandler):
    """One callback instance is attached to each configured model role."""

    _write_lock = threading.Lock()

    def __init__(self, role: str, model: str, profile: str, path: str | Path | None = None):
        self.role = role
        self.model = model
        self.profile = profile
        self.path = Path(path) if path is not None else default_telemetry_path()
        self._starts: dict[str, tuple[float, int]] = {}

    @staticmethod
    def _prompt_size(values: Any) -> int:
        if isinstance(values, list):
            return sum(TelemetryCallback._prompt_size(value) for value in values)
        content = getattr(values, "content", values)
        return len(str(content))

    def _start(self, run_id: Any, prompt_values: Any) -> None:
        self._starts[str(run_id)] = (time.perf_counter(), self._prompt_size(prompt_values))

    def on_chat_model_start(self, serialized, messages, *, run_id, **kwargs):
        self._start(run_id, messages)

    def on_llm_start(self, serialized, prompts, *, run_id, **kwargs):
        self._start(run_id, prompts)

    def _base_record(self, run_id: Any, status: str) -> dict[str, Any]:
        start_time, prompt_chars = self._starts.pop(
            str(run_id), (time.perf_counter(), 0)
        )
        return {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "experiment_run_id": os.getenv("FRA_RUN_ID", "manual"),
            "case_id": os.getenv("FRA_CASE_ID", "unknown_case"),
            "system": os.getenv("FRA_SYSTEM_NAME", "UNKNOWN"),
            "profile": self.profile,
            "role": self.role,
            "provider_gateway": "OpenRouter",
            "model": self.model,
            "temperature": float(os.getenv("FRA_LLM_TEMPERATURE", "0")),
            "status": status,
            "latency_seconds": round(time.perf_counter() - start_time, 6),
            "prompt_characters": prompt_chars,
        }

    def _write(self, record: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._write_lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=True) + "\n")

    def on_llm_end(self, response, *, run_id, **kwargs):
        record = self._base_record(run_id, "success")
        record.update(_extract_usage(response))
        self._write(record)

    def on_llm_error(self, error, *, run_id, **kwargs):
        record = self._base_record(run_id, "error")
        record.update({
            "input_tokens": None,
            "output_tokens": None,
            "total_tokens": None,
            "provider_reported_cost_usd": None,
        })
        record.update(_extract_error_details(error))
        self._write(record)


def load_telemetry(path: str | Path) -> list[dict[str, Any]]:
    telemetry_path = Path(path)
    if not telemetry_path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in telemetry_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            records.append(value)
    return records
