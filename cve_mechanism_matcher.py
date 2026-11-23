"""Conservative, evidence-linked triage of MCP CVE candidates (NOT CVE proof).

Step 5A: compare known vulnerability *mechanisms* with packet observations,
not the service name or generic RCE terms alone.  The tiny vendor-reviewed
profile is intentionally separate from benchmark ground truth: it represents
an official publicly documented advisory, not a PCAP label.

This module never assigns a validated CVE and never reads filenames/labels.
Any proposal must already have been retrieved by MCP from NVD or KEV.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import urlparse

from contracts import AnalystOutput
from mcp_evidence_contracts import OnlineEvidenceResult
from erlang_cookie_evidence import VerifiedCookieRpcSequence

_ID_LINE = re.compile(r"^\s*(?:-\s*)?\[(E-S\d{4}-F(?:\d{6}|UNKNOWN)-\d{3})(?:\s*\|\s*(?:client->server|server->client|peer->peer))?\]\s*(.*)$", re.I)
_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

# Distinctive features, not generic labels such as 'remote code execution'.
# The patterns must be matched in packet-linked observations, not web pages.
FEATURES = {
    "epmd_discovery": (r"\bepmd\b", r"\bnames\s+(?:query|enumeration)\b"),
    "erlang_rpc": (r"\bos\s*:\s*cmd\b", r"\berlang\b.{0,55}\b(?:rpc|rex)\b", r"\brex\s+(?:request|response)\b"),
    "erlang_distribution": (r"\berlang\s+distribution\b", r"\bcouchdb@(?:127|localhost)", r"\berlang\s+node\b"),
    "http_admin_config": (r"\bhttps?\b.{0,60}\b(?:config|admin|_config)\b", r"\b_config/\b", r"\bconfig(?:uration)?\b.{0,30}\bhttp\b"),
    "path_traversal": (r"\b(?:path|directory)\s+traversal\b", r"(?:\.\./){2,}", r"%2e%2e%2f"),
    "sql_injection": (r"\bsql\s+injection\b", r"\bunion\s+(?:all\s+)?select\b"),
    "deserialization": (r"\bdeserializ(?:e|ation)\b", r"\b(?:java|php)\s+serialized\b"),
    "log4j_lookup": (r"\$\{jndi:", r"\blog4shell\b"),
    "server_side_request_forgery": (r"\bssrf\b", r"\bserver.side request forgery\b"),
    "file_upload": (r"\bfile\s+upload\b", r"\bmultipart/form-data\b"),
    "authentication_bypass": (r"\bauth(?:entication|orization)?\s+bypass\b",),
}

# Reviewed against Apache's official CVE advisory, not a dataset label:
# https://docs.couchdb.org/en/stable/cve/2022-24706.html
# The cookie configuration and affected version are prerequisites that
# cannot be inferred merely from successful RPC command execution.
VENDOR_PROFILES = {
    "CVE-2022-24706": {
        "product": "couchdb",
        "features": ("epmd_discovery", "erlang_rpc", "erlang_distribution"),
        "min_distinct_features": 2,
        "advisory": "https://docs.couchdb.org/en/stable/cve/2022-24706.html",
        "mechanism": (
            "Apache's advisory describes externally reachable Erlang distribution "
            "ports advertised via EPMD plus an insecure default Erlang cookie; "
            "it does NOT require an HTTP API request."
        ),
        "unconfirmed_conditions": (
            "Default Erlang cookie was used (not established by network output alone)",
            "Affected CouchDB version/configuration (3.2.1 or below)",
            "Distribution port exposure was unauthorized, not just reachable within a trusted network",
        ),
    },
}


def _packet_observations(flow_summary: str) -> dict[str, str]:
    """Read only evidence-ID-prefixed lines; ignore free-form LLM prose."""
    observations: dict[str, str] = {}
    for line in flow_summary.splitlines():
        match = _ID_LINE.match(line)
        if match:
            detail = match.group(2)[:500]
            if re.search(r"\b(?:not observed|not present|no evidence|hypothetical|absent)\b", detail, re.I):
                continue
            observations.setdefault(match.group(1), detail)
    return observations


def _features(observations: dict[str, str]) -> dict[str, tuple[str, ...]]:
    found: dict[str, tuple[str, ...]] = {}
    for name, patterns in FEATURES.items():
        matched = tuple(
            evidence_id for evidence_id, text in observations.items()
            if any(re.search(pattern, text, re.I) for pattern in patterns)
        )
        if matched:
            found[name] = matched
    return found


def _source_for_cve(online: OnlineEvidenceResult, cve: str):
    """Tie descriptions to the exact record; ignore cross-CVE citations."""
    for source in online.sources:
        # A CVE in an arbitrary narrative is not necessarily the subject of it.
        host = (urlparse(source.url).hostname or "").lower()
        subject = f"{source.title} {source.url}"
        # NVD record subjects are identified by their own CVE URL/title. A
        # cross-reference inside another CVE description is not that CVE.
        if host == "nvd.nist.gov":
            if cve in {m.group(0).upper() for m in _CVE_ID.finditer(subject)}:
                return source
            continue
        if host in {"cisa.gov", "www.cisa.gov"} or host.endswith(".cisa.gov"):
            if cve in {m.group(0).upper() for m in _CVE_ID.finditer(
                f"{source.title} {' '.join(source.supports)}"
            )}:
                return source
            continue
        if host in {"docs.couchdb.org", "lists.apache.org"}:
            if cve in {m.group(0).upper() for m in _CVE_ID.finditer(subject)}:
                return source
    return None


def _service_identified(service: str, product: str) -> bool:
    """Compare real product tokens, allowing descriptive service suffixes.

    A label such as 'Next.js web application' still identifies Next.js; a
    generic 'HTTP web application' must never turn into an HTTP product match.
    No product name is inferred from the online advisory or a benchmark label.
    """
    service = " ".join(str(service or "").casefold().split())
    product = " ".join(str(product or "").casefold().split())
    if not service or not product or service in {"unknown", "not found"}:
        return False
    return bool(re.search(r"(?<![a-z0-9])" + re.escape(product) + r"(?![a-z0-9])", service))


def _service_identity_candidates(service) -> tuple[str, ...]:
    """Use Analyst-declared identities, not labels from retrieved webpages.

    Only remove a generic *suffix*. Never manufacture a software product from
    a generic 'HTTP web application on port 3000' description.
    """
    labels = []
    for field in ("primary", "framework", "application", "web_server", "database"):
        raw = getattr(service, field, "")
        label = " ".join(str(raw or "").casefold().split())
        label = re.sub(r"\s+(?:on|at)\s+port\s+\d{1,5}$", "", label).strip()
        if not label or label in {"unknown", "not found", "none", "n/a"}:
            continue
        if _generic_identity(label) or re.fullmatch(
            r"(?:http|https|generic|unknown|custom|unidentified)\s+(?:web\s+)?(?:application|app|server|service)", label
        ):
            continue
        labels.append(label)
        concise = re.sub(
            r"\s+(?:web\s+application|web\s+app|application|framework|database|service|web\s+server)$",
            "", label,
        ).strip()
        if concise and concise != label and not _generic_identity(concise):
            labels.append(concise)
    return tuple(dict.fromkeys(labels))


# Source and packet must mention the EXACT same nonstandard HTTP header.
# A name ending in '-id' is not the same header as its shorter prefix.
_CUSTOM_HEADER = re.compile(r"(?<![a-z0-9_-])(x-[a-z][a-z0-9-]{5,80})\s*:", re.I)
_COMMON_HEADERS = {"x-forwarded-for", "x-forwarded-proto", "x-real-ip", "x-request-id",
                   "x-frame-options", "x-content-type-options", "x-powered-by", "x-cache"}
_GENERIC_IDENTITIES = {"web application", "http web application", "http application",
                       "http web server", "http service", "http", "unknown", "web server",
                       "web service", "application", "http api"}


def _generic_identity(value: str) -> bool:
    label = re.sub(r"\s*\((?:port\s*)?\d+\)\s*$", "", value.strip().lower())
    return label in _GENERIC_IDENTITIES


def _exact_header_evidence(observations: dict[str, str], description: str) -> dict[str, tuple[str, ...]]:
    found: dict[str, set[str]] = {}
    for evidence_id, detail in observations.items():
        for match in _CUSTOM_HEADER.finditer(detail):
            name = match.group(1).lower()
            if name in _COMMON_HEADERS:
                continue
            # Hyphen is part of the token: don't match x-foo against x-foo-id.
            if re.search(r"(?<![a-z0-9_-])" + re.escape(name) + r"(?![a-z0-9_-])",
                         description, re.I):
                found.setdefault("http_header:" + name, set()).add(evidence_id)
    return {name: tuple(sorted(ids)) for name, ids in found.items()}


@dataclass(frozen=True)
class MechanismCandidate:
    cve_id: str
    level: str
    mechanism_features: tuple[str, ...]
    mechanism_explanation: str
    packet_ids: tuple[str, ...]
    reference: str
    missing_conditions: tuple[str, ...]


@dataclass(frozen=True)
class CVEMechanismTriage:
    candidates: tuple[MechanismCandidate, ...] = ()

    def to_text(self) -> str:
        lines = ["=== CVE MECHANISM CANDIDATES (NOT CONFIRMED CVEs) ==="]
        if not self.candidates:
            lines.append("No sufficiently discriminating mechanism match from available sources and packet observations.")
        for index, item in enumerate(self.candidates, 1):
            lines += [
                f"Rank {index}: {item.cve_id} — {item.level} (CANDIDATE ONLY)",
                "Matched packet mechanisms: " + ", ".join(item.mechanism_features),
                "CVE advisory mechanism: " + item.mechanism_explanation,
                "Packet evidence IDs: " + (", ".join(item.packet_ids) or "None"),
                "Advisory: " + item.reference,
                "Unconfirmed requirements: " + "; ".join(item.missing_conditions),
            ]
        lines.append("Do NOT equate this ranking with verified CVE exploitation or exact CVE attribution.")
        return "\n".join(lines)


def rank_cve_mechanisms(
    flow_summary: str, analyst_output: AnalystOutput, online: OnlineEvidenceResult,
    limit: int = 5,
    verified_cookie_rpc_sequences: tuple[VerifiedCookieRpcSequence, ...] = (),
) -> CVEMechanismTriage:
    """Rank distinct mechanism leads without changing CVE confirmation policy."""
    if online.status != "Valid" or not online.candidate_cves:
        return CVEMechanismTriage()
    evidence = _packet_observations(flow_summary)
    observed = _features(evidence)
    results: list[MechanismCandidate] = []
    for cve in online.candidate_cves:
        source = _source_for_cve(online, cve)
        if source is None:
            continue  # require NVD/KEV/vendor provenance for this specific ID
        profile = VENDOR_PROFILES.get(cve)
        if profile:
            if not _service_identified(analyst_output.service.primary, profile["product"]):
                continue
            matched = [feature for feature in profile["features"] if feature in observed]
            if (len(matched) < profile["min_distinct_features"]
                    or "erlang_rpc" not in matched
                    or not ({"epmd_discovery", "erlang_distribution"} & set(matched))):
                continue
            ids = tuple(sorted({identifier for feature in matched for identifier in observed[feature]}))
            cookie_proven = (
                cve == "CVE-2022-24706"
                and any(seq.handshake.server_node.startswith("couchdb@")
                        and seq.handshake.client_digest_matched
                        and seq.handshake.server_digest_matched
                        for seq in verified_cookie_rpc_sequences)
            )
            conditions = tuple(
                item for item in profile["unconfirmed_conditions"]
                if not (cookie_proven and item.startswith("Default Erlang cookie"))
            )
            results.append(MechanismCandidate(
                cve_id=cve, level=("Default cookie verified by packets"
                                   if cookie_proven else "Mechanism-consistent"),
                mechanism_features=tuple(matched),
                mechanism_explanation=profile["mechanism"], packet_ids=ids,
                reference=profile["advisory"],
                missing_conditions=conditions,
            ))
            continue
        # General fallback requires a CVE-specific NVD/vendor description and a
        # discriminating mechanism family (never product name + generic RCE).
        description = f"{source.title} {source.snippet}".lower()
        primary = analyst_output.service.primary.lower().strip()
        product_supported = any(
            _service_identified(description, identity)
            for identity in _service_identity_candidates(analyst_output.service)
        )
        header_matches = _exact_header_evidence(evidence, description)
        # If the Analyst knows only 'Web application', permit a *candidate*
        # only when an authoritative CVE subject describes an exact header
        # independently observed in packet-linked evidence. Never invent a
        # product identity from a generic attack label.
        if not product_supported and not (_generic_identity(primary) and header_matches):
            continue
        matches = [
            name for name in observed
            if name not in {"erlang_distribution", "epmd_discovery", "erlang_rpc"}
            and any(re.search(p, description, re.I) for p in FEATURES[name])
        ]
        matches.extend(header_matches)
        if not matches:
            continue
        ids = tuple(sorted({identifier for name in matches
                            for identifier in (header_matches[name] if name in header_matches
                                               else observed[name])}))
        results.append(MechanismCandidate(
            cve_id=cve, level="Preliminary mechanism overlap",
            mechanism_features=tuple(matches),
            mechanism_explanation="Mechanism keywords overlap a CVE-specific authoritative description; exact prerequisites unverified.",
            packet_ids=ids, reference=source.url,
            missing_conditions=(
                "Affected product version and CVE-specific prerequisites not independently established",
                "A packet header and advisory overlap alone cannot prove the server product or exact CVE",
            ),
        ))
    results.sort(key=lambda c: (
        0 if (c.level == "Mechanism-consistent" or c.level == "Default cookie verified by packets") else 1,
        -len(c.mechanism_features), c.cve_id,
    ))
    return CVEMechanismTriage(tuple(results[:max(0, limit)]))
