"""Local MCP server for online forensic evidence retrieval.

This server does not maintain a local vulnerability database.  Each search
queries public online security sources and returns structured supporting
evidence to the MAFRA MCP client.

Run from the project directory with:

    mcp run mcp_server.py --transport streamable-http
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.request
from urllib.parse import urlencode
from functools import lru_cache
from typing import Any

from mcp.server import MCPServer
from mcp_web_research import research_web
from packet_search_features import informative_service, query_clue_words


mcp = MCPServer(
    "MAFRA Online Forensic Evidence",
    instructions=(
        "Search authoritative online cybersecurity sources for supporting "
        "context. Do not treat online results as packet evidence."
    ),
)


CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
CISA_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
MITRE_ATTACK_URL_PAGE = "https://attack.mitre.org/"
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CVE_PAGE_URL = "https://nvd.nist.gov/vuln/detail/"
_NVD_RATE_LOCK = threading.Lock()
_NEXT_NVD_REQUEST_TIME = 0.0

# These are contextual mappings, not claims that ATT&CK proves what happened
# in the PCAP.  They prevent arbitrary query-word overlap from selecting an
# unrelated technique description.
ATTACK_TECHNIQUE_MAPPINGS = (
    (
        ("directory traversal", "path traversal", "remote code execution", "rce", "command injection", "ssrf"),
        "T1190",
        "Exploit Public-Facing Application",
    ),
    (("brute force", "password guessing", "credential stuffing"), "T1110", "Brute Force"),
    (("credential dumping", "password dumping", "credential theft"), "T1003", "OS Credential Dumping"),
    (("web shell", "server software component"), "T1505.003", "Web Shell"),
    (("valid account", "stolen credential"), "T1078", "Valid Accounts"),
    (("network service discovery", "service discovery", "port scan"), "T1046", "Network Service Scanning"),
)


def _tokens(value: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9][a-z0-9._/-]{1,}", value.casefold())
        if token not in {"unknown", "none", "not", "found"}
    }


def _first_cve(value: str) -> str:
    match = re.search(r"CVE-\d{4}-\d{4,}", value or "", re.IGNORECASE)
    return match.group(0).upper() if match else ""


def _service_matches(service: str, record_text: str) -> bool:
    service_terms = _tokens(service)
    if not service_terms:
        return True
    record_terms = _tokens(record_text)
    return service_terms.issubset(record_terms)


def _mitre_mapping(attack: str, query: str) -> tuple[str, str] | None:
    combined = f"{attack} {query}".casefold()
    for phrases, external_id, technique_name in ATTACK_TECHNIQUE_MAPPINGS:
        if any(phrase in combined for phrase in phrases):
            return external_id, technique_name
    return None


def _candidate_cves(
    sources: list[dict[str, Any]],
    requested_cve: str,
) -> list[str]:
    """Only take exact CVE IDs from actual NVD / KEV records, not ATT&CK prose."""
    # Preserve search/ranking order; alphabetic sorting obscures relevance.
    found = list(dict.fromkeys(
        match.group(0).upper()
        for source in sources
        if source.get("source_type") in {"nvd_cve_candidate", "cisa_kev"}
        for match in [re.fullmatch(
            r"CVE-\d{4}-\d{4,}", str(source.get("cve_id", "")), re.IGNORECASE
        )]
        if match
    ))
    if requested_cve in found:
        return [requested_cve] + [cve for cve in found if cve != requested_cve]
    return found


def _fetch_json(url: str) -> Any:
    headers = {"User-Agent": "MAFRA-MCP-Research/1.1"}
    is_nvd = url.startswith(NVD_CVE_API_URL)
    if is_nvd:
        api_key = os.getenv("NVD_API_KEY", "").strip()
        if api_key:
            headers["apiKey"] = api_key
        # NVD rate limits are commonly 5 requests / 30 seconds without a
        # key, 50 / 30 seconds with a key. Space our *server's* NVD calls.
        global _NEXT_NVD_REQUEST_TIME
        with _NVD_RATE_LOCK:
            delay = max(0.0, _NEXT_NVD_REQUEST_TIME - time.monotonic())
            if delay:
                time.sleep(delay)
            _NEXT_NVD_REQUEST_TIME = time.monotonic() + (0.7 if api_key else 6.2)
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


@lru_cache(maxsize=1)
def _load_kev() -> list[dict[str, Any]]:
    payload = _fetch_json(CISA_KEV_URL)
    return [
        item
        for item in payload.get("vulnerabilities", [])
        if isinstance(item, dict)
    ]


@lru_cache(maxsize=1)
def _load_attack_patterns() -> list[dict[str, Any]]:
    payload = _fetch_json(MITRE_ATTACK_URL)
    return [
        item
        for item in payload.get("objects", [])
        if isinstance(item, dict) and item.get("type") == "attack-pattern"
    ]


def _rank_score(text: str, terms: set[str], exact_terms: set[str]) -> int:
    record_tokens = _tokens(text)
    score = len(record_tokens.intersection(terms))
    score += 5 * len(record_tokens.intersection(exact_terms))
    return score


def _kev_sources(
    service: str,
    attack: str,
    version: str,
    cve: str,
    query: str,
    limit: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    if not informative_service(service):
        return [], ["KEV discovery skipped: no identified product; generic RCE is not a product match."]
    requested_cve = _first_cve(cve)
    terms = _tokens(" ".join((service, attack, version, cve, query)))
    exact_terms = _tokens(" ".join((service, cve)))
    matches: list[tuple[int, dict[str, Any]]] = []
    for item in _load_kev():
        text = " ".join(
            str(item.get(key, ""))
            for key in (
                "cveID",
                "vendorProject",
                "product",
                "vulnerabilityName",
                "shortDescription",
                "requiredAction",
            )
        )
        item_cve = _first_cve(str(item.get("cveID", "")))

        # When the validated agents provide a CVE, an exact catalog record is
        # the most useful supporting result.  Do not mix unrelated products
        # merely because they share a vendor or generic attack words.
        if requested_cve and item_cve != requested_cve:
            continue
        # Even an exact CVE-ID match cannot confirm the Analyst's claim if
        # the catalog record describes an unrelated product.
        if not _service_matches(service, text):
            continue

        score = _rank_score(text, terms, exact_terms)
        if requested_cve and item_cve == requested_cve:
            score = 1000
        if score <= 0:
            continue
        cve_id = item_cve or "Unknown"
        matches.append(
            (
                score,
                {
                    "source_name": "CISA KEV",
                    "title": str(item.get("vulnerabilityName", cve_id)),
                    "url": CISA_CATALOG_URL,
                    "snippet": (
                        f"{item.get('vendorProject', 'Unknown')} "
                        f"{item.get('product', 'Unknown')}: "
                        f"{item.get('shortDescription', 'Unknown')} "
                        f"Required action: {item.get('requiredAction', 'Unknown')}"
                    ),
                    "source_type": "cisa_kev",
                    "cve_id": cve_id,
                    "supports": [
                        f"CISA KEV identifies {cve_id} as exploited in the wild."
                    ],
                    "contradicts": [],
                    "match_reason": (
                        "Exact CVE match supplied by the validated investigation."
                        if requested_cve
                        else "Strict service and investigation-term match."
                    ),
                },
            )
        )
    matches.sort(key=lambda pair: pair[0], reverse=True)
    return [item for _, item in matches[:limit]], []



def _nvd_english_description(cve_record: dict[str, Any]) -> str:
    for description in cve_record.get("descriptions", []) or []:
        if isinstance(description, dict) and description.get("lang") == "en":
            return str(description.get("value") or "")
    return ""


def _nvd_product_text(cve_record: dict[str, Any]) -> str:
    """Use CPE product information only for relevance; not for proof of version."""
    matches: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if isinstance(value.get("criteria"), str):
                matches.append(value["criteria"].replace(":", " ").replace("_", " "))
            for key, item in value.items():
                if key not in {"criteria", "description", "references"}:
                    walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(cve_record.get("configurations", []))
    return " ".join(matches)


def _nvd_query_url(*, cve: str = "", keywords: str = "", results: int = 30) -> str:
    if cve:
        parameters = {"cveId": cve}
    else:
        parameters = {
            "keywordSearch": keywords,
            "resultsPerPage": str(max(1, min(int(results), 100))),
        }
    return f"{NVD_CVE_API_URL}?{urlencode(parameters)}&noRejected"


def _nvd_sources(
    service: str,
    attack: str,
    version: str,
    cve: str,
    limit: int,
    query: str = "",
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """Retrieve bounded NVD leads by product and packet-linked mechanism clues.

    Unknown products are never matched to random generic RCE records. With no
    product, the NVD description must contain two distinct packet-derived
    clue words. Product/version applicability remains unverified.
    """
    del version  # Independent version/CPE range checking is not implemented.
    service = " ".join(str(service or "").split())[:100]
    specific_product = informative_service(service)
    attack = " ".join(str(attack or "").split())[:80]
    if attack.casefold() in {"unknown", "none", "not found"}:
        attack = ""
    clues = query_clue_words(query)
    requested_cve = _first_cve(cve)
    urls: list[str] = []
    if specific_product:
        if requested_cve:
            urls.append(_nvd_query_url(cve=requested_cve))
        if len(clues) >= 2:
            urls.append(_nvd_query_url(keywords=f"{service} {' '.join(clues[:3])}", results=50))
        if attack:
            urls.append(_nvd_query_url(keywords=f"{service} {attack}", results=50))
        urls.append(_nvd_query_url(keywords=service, results=50))
    elif len(clues) >= 2:
        # Discovery requires packet-linked endpoint/header terms, not a generic
        # attack category. Keyword-only matches are low-confidence leads.
        urls.append(_nvd_query_url(keywords=" ".join(clues[:3]), results=50))
    else:
        return [], ["NVD lookup skipped: unknown product and no distinctive packet clues."], []

    results: list[tuple[int, dict[str, Any]]] = []
    warnings: list[str] = []
    fetched: list[str] = []
    seen_cves: set[str] = set()
    # Capped to three requests, regardless of how many leads are discovered.
    for url in list(dict.fromkeys(urls))[:3]:
        fetched.append(url)
        try:
            payload = _fetch_json(url)
            records = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
        except Exception as exc:
            warnings.append(f"NVD lookup failed: {type(exc).__name__}: {exc}")
            continue
        for wrapper in records if isinstance(records, list) else []:
            record = wrapper.get("cve", {}) if isinstance(wrapper, dict) else {}
            if not isinstance(record, dict) or record.get("vulnStatus") == "Rejected":
                continue
            cve_id = _first_cve(str(record.get("id", "")))
            if not cve_id or cve_id in seen_cves:
                continue
            description = _nvd_english_description(record)
            product_text = _nvd_product_text(record)
            if specific_product and not _service_matches(service, f"{description} {product_text}"):
                continue
            # Header names such as x-a-b must match packet-derived words
            # a and b, not be treated as a single indivisible NVD token.
            description_words = set(re.findall(r"[a-z0-9]{3,}", description.casefold()))
            clue_overlap = len(set(clues).intersection(description_words))
            if not specific_product and clue_overlap < 2:
                continue
            seen_cves.add(cve_id)
            score = 2 + 6 * clue_overlap + _rank_score(description, _tokens(attack), set())
            if specific_product and cve_id == requested_cve:
                score += 4  # Lead preference only; still not proof.
            match_note = (
                "Product matches NVD description/CPE; packet clue overlap is a search lead."
                if specific_product else
                "Unknown product; at least two independent packet-clue words match NVD text."
            )
            results.append((score, {
                "source_name": "NIST NVD",
                "title": f"{cve_id}: NVD vulnerability record",
                "url": f"{NVD_CVE_PAGE_URL}{cve_id}",
                "snippet": description[:2200] or "No English description in NVD record.",
                "source_type": "nvd_cve_candidate",
                "cve_id": cve_id,
                "supports": [
                    f"NVD lists {cve_id} as a research lead; "
                    "product identity, version applicability, and exploitation remain unverified."
                ],
                "contradicts": [],
                "match_reason": match_note,
            }))
    results.sort(key=lambda entry: (-entry[0], entry[1]["cve_id"]))
    return [source for _, source in results[:limit]], warnings, fetched


def _attack_sources(
    attack: str,
    query: str,
    limit: int,
) -> list[dict[str, Any]]:
    mapping = _mitre_mapping(attack, query)
    if mapping is None:
        return []

    external_id, mapped_name = mapping
    for item in _load_attack_patterns():
        name = str(item.get("name", ""))
        description = str(item.get("description", ""))
        external_url = MITRE_ATTACK_URL_PAGE
        item_external_id = ""
        for reference in item.get("external_references", []) or []:
            if reference.get("source_name") == "mitre-attack":
                item_external_id = str(reference.get("external_id", ""))
                external_url = reference.get("url") or external_url
                break
        if item_external_id != external_id:
            continue
        return [
            {
                "source_name": "MITRE ATT&CK",
                "title": name or mapped_name,
                "url": external_url,
                "snippet": description[:3500],
                "source_type": "mitre_attack_context",
                "supports": [
                    f"Contextual mapping: the investigation terms are consistent with ATT&CK {external_id} ({mapped_name})."
                ],
                "contradicts": [],
                "match_reason": "Controlled attack-class mapping; not proof of the PCAP event.",
            }
        ][:limit]
    return []


def _nvd_web_research_followups(
    sources: list[dict[str, Any]], query: str, service: str, limit: int = 2,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """FRA web research -> independently retrieve NVD records for cited leads.

    Links and snippets are UNTRUSTED. Exact CVE references in researched
    webpages may seed up to two authoritative NVD lookups, but candidates
    require product or *two distinct* packet clue words in NVD itself.
    Never use a filename, benchmark label, or webpage alone as attribution.
    """
    clues = set(query_clue_words(query))
    product_known = informative_service(service)
    if not product_known and len(clues) < 2:
        return [], [], []
    ids: list[str] = []
    for item in sources[:10]:
        if item.get("source_type") not in {"web_research_lead", "vendor_advisory_lead", "vendor_page_lead"}:
            continue
        # Only source title and bounded snippets: no implicit CVE candidates
        # from unrelated NVD/ATT&CK paragraphs elsewhere in the result.
        text = str(item.get("title", "")) + " " + str(item.get("snippet", ""))[:2000]
        for m in re.finditer(r"CVE-\d{4}-\d{4,}", text, re.I):
            cve_id = m.group(0).upper()
            if cve_id not in ids:
                ids.append(cve_id)
    retrieved: list[dict[str, Any]] = []
    warnings: list[str] = []
    urls: list[str] = []
    for cve_id in ids[:max(0, min(int(limit), 2))]:
        url = _nvd_query_url(cve=cve_id)
        urls.append(url)
        try:
            payload = _fetch_json(url)
        except Exception as exc:
            warnings.append(f"NVD web-candidate lookup failed: {type(exc).__name__}: {exc}")
            continue
        records = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
        for wrapped in records if isinstance(records, list) else []:
            rec = wrapped.get("cve", {}) if isinstance(wrapped, dict) else {}
            if not isinstance(rec, dict) or rec.get("vulnStatus") == "Rejected":
                continue
            if _first_cve(str(rec.get("id", ""))) != cve_id:
                continue
            description = _nvd_english_description(rec)
            product = _nvd_product_text(rec)
            # Hyphenated HTTP header names count as separate search words;
            # exactly the same clues must occur in the authoritative record.
            words = set(re.findall(r"[a-z0-9]{3,}", description.casefold()))
            overlap = clues.intersection(words)
            if product_known:
                if not _service_matches(service, description + " " + product):
                    continue
                if clues and not overlap:
                    continue
            elif len(overlap) < 2:
                continue
            retrieved.append({
                "source_name": "NIST NVD",
                "title": f"{cve_id}: NVD vulnerability record",
                "url": f"{NVD_CVE_PAGE_URL}{cve_id}",
                "snippet": description[:2200],
                "source_type": "nvd_cve_candidate",
                "cve_id": cve_id,
                "supports": [f"Web-cited {cve_id} was retrieved independently from NVD; applicability and exploitation are unverified."],
                "contradicts": [],
                "match_reason": ("Independent NVD record corroborates a web-research lead; "
                                 "matched packet clue words: " + ", ".join(sorted(overlap)) +
                                 "; NOT a confirmed case CVE."),
            })
    return retrieved, warnings, urls


@mcp.tool()
def search_forensic_evidence(
    query: str,
    service: str = "",
    attack: str = "",
    version: str = "",
    cve: str = "",
    evidence_keywords: list[str] | None = None,
    max_results: int = 8,
    include_contradictions: bool = True,
) -> dict[str, Any]:
    """Search NVD/KEV/ATT&CK plus web pages and official vendor advisories.

    Results from the open web are *research leads* only, not PCAP evidence.
    Returned candidate_cves come exclusively from NVD/KEV.
    """
    del evidence_keywords, include_contradictions
    limit = max(1, min(int(max_results), 20))
    sources: list[dict[str, Any]] = []
    warnings: list[str] = []
    queried_sources: list[str] = []

    try:
        queried_sources.append(CISA_KEV_URL)
        kev_sources, _ = _kev_sources(service, attack, version, cve, query, max(1, limit // 3))
        sources.extend(kev_sources)
    except Exception as exc:
        warnings.append(f"CISA KEV lookup failed: {type(exc).__name__}: {exc}")

    try:
        nvd_sources, nvd_warnings, nvd_queries = _nvd_sources(
            service, attack, version, cve, max(1, limit - len(sources) - 1), query=query
        )
        sources.extend(nvd_sources)
        warnings.extend(nvd_warnings)
        queried_sources.extend(nvd_queries)
    except Exception as exc:
        warnings.append(f"NVD lookup failed: {type(exc).__name__}: {exc}")

    try:
        queried_sources.append(MITRE_ATTACK_URL)
        sources.extend(_attack_sources(attack, query, 1))
    except Exception as exc:
        warnings.append(f"MITRE ATT&CK lookup failed: {type(exc).__name__}: {exc}")

    # Web research runs even if an individual vulnerability feed failed. With
    # no configured search API key it simply reports a warning and preserves
    # existing NVD/KEV/ATT&CK behavior. Do not call a general search engine
    # using raw packet payloads.
    try:
        web_sources, web_warnings, web_queries = research_web(
            service, attack, version, cve, query, 10
        )
        warnings.extend(web_warnings)
        queried_sources.extend(web_queries)
    except Exception as exc:
        web_sources = []
        warnings.append(f"Web research unavailable: {type(exc).__name__}: {exc}")

    # FRA-inspired research order: the web pages can expose a candidate
    # overlooked by the initial Analyst, but only NVD/KEV may nominate it.
    # This uses at most two EXTRA NVD requests and no additional LLM calls.
    if web_sources:
        try:
            discovered, discovered_warnings, discovered_urls = _nvd_web_research_followups(
                web_sources, query, service, limit=2
            )
            existing = {item.get("cve_id") for item in sources}
            # Prioritize independently confirmed web candidates over generic
            # NVD keyword hits, while never replacing vendor/packet checks.
            sources = [item for item in discovered if item["cve_id"] not in existing] + sources
            warnings.extend(discovered_warnings)
            queried_sources.extend(discovered_urls)
        except Exception as exc:
            warnings.append(f"Web lead verification unavailable: {type(exc).__name__}: {exc}")

    if web_sources:
        # Make room for web context without crowding out authoritative CVE
        # evidence and ATT&CK context. Original ordering is untouched if web
        # search is disabled/unavailable.
        web_slots = min(len(web_sources), max(1, limit // 2))
        base_slots = limit - web_slots
        cisa = [item for item in sources if item.get("source_type") == "cisa_kev"]
        mitre = [item for item in sources if item.get("source_type") == "mitre_attack_context"]
        nvd = [item for item in sources if item.get("source_type") == "nvd_cve_candidate"]
        # Preserve independently retrieved NVD leads before broad keyword
        # results, and keep the first KEV source for authoritative context.
        base_candidates = cisa[:1] + nvd + mitre[:1] + cisa[1:] + mitre[1:]
        sources = base_candidates[:base_slots] + web_sources[:web_slots]

    unique_sources: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for source in sources:
        key = (str(source.get("source_name")), str(source.get("cve_id") or source.get("title")))
        if key not in seen:
            seen.add(key)
            unique_sources.append(source)

    requested_cve = _first_cve(cve)

    return {
        "query": query,
        "sources": unique_sources[:limit],
        "candidate_cves": _candidate_cves(unique_sources[:limit], requested_cve),
        "sources_queried": queried_sources,
        "warnings": warnings,
    }
