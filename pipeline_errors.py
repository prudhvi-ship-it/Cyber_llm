"""Explicit pipeline-abort exceptions for invalid evaluation cases."""

from __future__ import annotations


class PipelineAbortError(RuntimeError):
    """Raised when a required LLM stage cannot produce a validated result."""

    def __init__(self, stage: str, errors: list[str] | None = None):
        self.stage = str(stage)
        self.errors = list(errors or [])
        detail = " | ".join(self.errors[:3]) if self.errors else "no validated output"
        super().__init__(f"{self.stage} failed: {detail}")
