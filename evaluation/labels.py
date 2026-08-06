"""Canonical label parsing for evaluation.

Predictions are intentionally tri-state: 1 (positive), 0 (negative), or None
(unknown/abstained). Unknown must never be silently converted to a negative.
"""

from __future__ import annotations

import math
import re
from typing import Any


def normalize_label(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and math.isnan(value):
        return ""
    return re.sub(
        r"\s+",
        " ",
        str(value)
        .lower()
        .replace("_", " ")
        .replace("`", "")
        .replace("*", "")
        .strip(),
    )


UNKNOWN_TOKENS = {
    "",
    "unknown",
    "not found",
    "none",
    "n/a",
    "na",
    "null",
    "abstain",
    "abstained",
    "undetermined",
    "inconclusive",
}

VULNERABLE_POSITIVE = {"true", "yes", "1", "vulnerable"}
VULNERABLE_NEGATIVE = {"false", "no", "0", "not vulnerable"}

SUCCESS_POSITIVE = {
    "true",
    "yes",
    "1",
    "success",
    "successful",
    "succeeded",
}
SUCCESS_NEGATIVE = {
    "false",
    "no",
    "0",
    "fail",
    "failed",
    "failure",
    "unsuccessful",
    "not successful",
}


def parse_binary_label(value: Any, task: str) -> int | None:
    """Parse one label without turning uncertainty into a negative answer."""
    normalized = normalize_label(value).strip(" .:;,")
    if normalized in UNKNOWN_TOKENS:
        return None

    task_name = task.strip().lower()
    if task_name in {"vulnerability", "vulnerable"}:
        positive, negative = VULNERABLE_POSITIVE, VULNERABLE_NEGATIVE
    elif task_name in {"success", "attack_success", "attack success"}:
        positive, negative = SUCCESS_POSITIVE, SUCCESS_NEGATIVE
    else:
        raise ValueError(f"Unsupported classification task: {task}")

    if normalized in positive:
        return 1
    if normalized in negative:
        return 0

    # Accept short explanations after a valid leading label, while checking
    # negative phrases first (for example, "Not vulnerable - patched").
    for token in sorted(negative, key=len, reverse=True):
        if re.match(rf"^{re.escape(token)}\b", normalized):
            return 0
    for token in sorted(positive, key=len, reverse=True):
        if re.match(rf"^{re.escape(token)}\b", normalized):
            return 1
    return None


def display_label(value: int | None, task: str) -> str:
    if value is None:
        return "Unknown/Abstain"
    if task == "vulnerability":
        return "Vulnerable" if value == 1 else "Not Vulnerable"
    return "Successful" if value == 1 else "Failed"
