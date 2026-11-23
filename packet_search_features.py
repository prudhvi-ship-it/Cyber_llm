"""Benchmark-independent, privacy-bounded search hints from packet-linked evidence.

These hints are NOT product, CVE, or exploitation verdicts. Only the names of
HTTP endpoints and non-standard headers are used; no header values, request
bodies, IP addresses, hosts, credentials, or raw paths are sent to research.
"""
from __future__ import annotations

import re

EVIDENCE_ID = re.compile(r"E-S\d{4}-F(?:\d{6}|UNKNOWN)-\d{3}")
METHOD_PATH = re.compile(r"\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(?:to\s+)?(/[^\s<>\"']{1,150})", re.I)
HEADER = re.compile(r"\b([A-Za-z][A-Za-z0-9-]{3,65})\s*:")
COMMON_SEGMENTS = {
    "api", "v1", "v2", "v3", "v4", "http", "https", "index", "html", "php",
    "home", "health", "status", "check", "login", "logout", "sign", "signin",
    "assets", "static", "public", "favicon", "robots", "www", "web", "app",
    "admin", "user", "users", "test", "default", "request", "response",
}
COMMON_HEADERS = {
    "host", "accept", "user-agent", "content-type", "content-length", "cookie",
    "authorization", "connection", "accept-encoding", "accept-language",
    "cache-control", "referer", "origin", "pragma", "x-forwarded-for",
    "x-forwarded-proto", "x-real-ip", "x-request-id", "traceparent", "date",
    "server", "location", "set-cookie", "transfer-encoding", "vary", "etag",
}
GENERIC_SERVICES = {
    "unknown", "none", "not found", "http", "https", "http api", "http json api",
    "rest api", "json api", "web server", "web service", "api server", "tcp",
    "unknown service", "application", "remote code execution", "python",
}


def informative_service(value: str) -> bool:
    """Require a product identity, not generic HTTP + address/port labels.

    Do not reject an actual application merely because the words 'web app'
    appear within its name. This guards unknown-product web discovery.
    """
    text = " ".join(str(value or "").casefold().split())
    if not text or text in GENERIC_SERVICES:
        return False
    stripped = re.sub(r"\s*\((?:port\s*)?\d{1,5}\)\s*$", "", text).strip()
    stripped = re.sub(r"\s+(?:on|at)\s+port\s+\d{1,5}$", "", stripped).strip()
    generic_prefixes = {
        "http web application", "https web application", "web application",
        "generic http application", "http application", "http web server",
        "web application server", "unknown web application", "web app",
        "generic web application", "http service", "http server", "http api",
        "web server", "web service", "http endpoint", "reverse proxy",
    }
    if re.match(r"^(?:web app|web application|http application|application)\s+with\b", stripped):
        return False  # A descriptive hypothesis, not a confirmed product.
    if stripped in generic_prefixes or stripped in GENERIC_SERVICES:
        return False
    # Never treat a generic application description as a software product.
    return not bool(re.fullmatch(
        r"(?:custom|generic|unknown|unidentified|unspecified|bespoke|internal|proprietary)"
        r"\s+(?:(?:http|https)\s+)?(?:web\s+)?(?:application|app|server|service|website)",
        stripped,
    ))


def _words(value: str) -> list[str]:
    # Split header/path segment names; ignore numeric/opaque path components.
    value = re.sub(r"([a-z])([A-Z])", r"\1 \2", value)
    parts = re.findall(r"[a-z][a-z0-9]{2,}", value.lower())
    return [x for x in parts if x not in COMMON_SEGMENTS and not x.isnumeric()]


def packet_clues(flow_summary: str, limit: int = 4) -> list[str]:
    """Return compact, generic clues only where a current packet ID exists."""
    clues: list[str] = []
    for line in flow_summary.splitlines():
        if not EVIDENCE_ID.search(line):
            continue
        for match in METHOD_PATH.finditer(line):
            path = match.group(1).split("?", 1)[0].split("#", 1)[0]
            words = list(dict.fromkeys(_words(path)))[:5]
            if len(words) >= 2 or (len(words) == 1 and len(words[0]) >= 10):
                clue = "endpoint " + " ".join(words)
                if clue not in clues:
                    clues.append(clue)
        for match in HEADER.finditer(line):
            name = match.group(1).casefold()
            if name in COMMON_HEADERS or not name.startswith("x-"):
                continue
            words = list(dict.fromkeys(_words(name[2:])))[:5]
            if len(words) >= 2 or (len(words) == 1 and len(words[0]) >= 10):
                clue = "header " + " ".join(words)
                if clue not in clues:
                    clues.append(clue)
        if len(clues) >= limit:
            break
    return clues[:limit]


def query_clue_words(query: str) -> list[str]:
    """Recognize only our own bounded 'packet clues:' query suffix."""
    marker = "packet clues:"
    if marker not in query.casefold():
        return []
    suffix = query.casefold().split(marker, 1)[1][:220]
    words = [x for x in _words(suffix) if x not in {"endpoint", "header", "clues", "packet"}]
    return list(dict.fromkeys(words))[:8]
