"""Bounded, untrusted web evidence for MAFRA's MCP server (Step 2).

Online material supplies investigation leads only, never packet evidence or
proof of exploitation. Uses Serper (Google results) or Brave Search API.
All web content is treated as untrusted data; no downloaded code is executed.
"""
from __future__ import annotations

import html
from html.parser import HTMLParser
import ipaddress
import json
import os
import re
import socket
from typing import Any
from urllib import error, parse, request
from packet_search_features import informative_service, query_clue_words

# The standalone MCP server does not import llm_client; load its local .env
# if python-dotenv is available (keys are never placed in reports or ZIPs).
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

SERPER_URL = "https://google.serper.dev/search"
BRAVE_URL = "https://api.search.brave.com/res/v1/web/search"
GOOGLE_CSE_URL = "https://www.googleapis.com/customsearch/v1"
USER_AGENT = "MAFRA-MCP-Research/2.0 (forensic literature lookup)"

# Official domains where we can positively identify the vendor of a result.
# Unsupported vendors still get the general search; we don't mislabel their
# results as official advisories.
VENDOR_DOMAINS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("apache", "solr", "tomcat", "struts", "log4j", "httpd"), "apache.org"),
    (("microsoft", "exchange", "windows", "sharepoint", "iis"), "microsoft.com"),
    (("cisco",), "cisco.com"),
    (("grafana",), "grafana.com"),
    (("red hat", "rhel", "jboss"), "redhat.com"),
    (("ubuntu",), "ubuntu.com"),
    (("debian",), "debian.org"),
    (("oracle", "weblogic", "mysql"), "oracle.com"),
    (("wordpress",), "wordpress.org"),
    (("nginx",), "nginx.org"),
    (("phpmyadmin",), "phpmyadmin.net"),
    (("php",), "php.net"),
    (("fortinet", "fortigate"), "fortinet.com"),
    (("vmware", "vsphere", "vcenter", "broadcom"), "broadcom.com"),
    (("gitlab",), "gitlab.com"),
    (("jenkins",), "jenkins.io"),
)


def _bounded_int(env: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(env, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(value, maximum))


def _compact(text: Any, max_len: int) -> str:
    return " ".join(str(text or "").split())[:max_len]


def _service_terms(service: str) -> set[str]:
    stopwords = {"apache", "http", "https", "server", "the", "software", "application", "service", "web"}
    words = set(re.findall(r"[a-z0-9]{3,}", service.lower()))
    return {word for word in words if len(word) > 2 and word not in stopwords}


def _relevant(service: str, text: str) -> bool:
    terms = _service_terms(service)
    content = text.lower()
    if not terms:
        return bool(service.strip()) and service.lower() in content
    # More than one significant token should match for a multiword service.
    return all(re.search(r"(?<!\w)" + re.escape(term) + r"(?!\w)", content) for term in terms)


def _vendor_domain(service: str) -> str:
    value = service.casefold()
    for names, domain in VENDOR_DOMAINS:
        if any(re.search(r"(?<![a-z0-9])" + re.escape(name) + r"(?![a-z0-9])", value) for name in names):
            return domain
    return ""


def _hostname_in_domain(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def _public_https_url(url: str) -> str:
    """Reject non-public / malformed destinations prior to any page request.

    Hostname validation is defense-in-depth, not an egress firewall. Deployment
    environments should block private networks at the firewall as well.
    """
    candidate = str(url or "").strip()
    parsed = parse.urlsplit(candidate)
    if (parsed.scheme.lower() != "https" or not parsed.hostname or
            parsed.username or parsed.password or parsed.port not in (None, 443)):
        raise ValueError("Only standard public HTTPS URLs are permitted")
    hostname = parsed.hostname.lower().rstrip(".")
    if hostname == "localhost" or "." not in hostname or hostname.endswith((".local", ".internal", ".test", ".invalid")):
        raise ValueError("Internal or invalid hostname refused")
    try:
        ipaddress.ip_address(hostname)
        raise ValueError("Literal-IP webpage destinations are refused")
    except ValueError as exc:
        if "Literal-IP" in str(exc):
            raise
    if len(candidate) > 1600:
        raise ValueError("URL exceeds maximum length")
    return candidate


def _validate_dns_public(url: str) -> None:
    hostname = parse.urlsplit(_public_https_url(url)).hostname
    assert hostname
    addresses = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    if not addresses:
        raise ValueError("No DNS records")
    for item in addresses:
        ip = ipaddress.ip_address(item[4][0])
        if not ip.is_global:
            raise ValueError("Webpage destination resolves to a non-public IP")


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Avoid an unvalidated second destination.


class _TextOnlyParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hidden_tags: list[str] = []
        self.parts: list[str] = []
        self.skipped_tags = {"script", "style", "svg", "noscript", "nav", "footer", "header", "form", "head"}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in self.skipped_tags:
            self.hidden_tags.append(tag.lower())
        elif not self.hidden_tags and tag.lower() in {"p", "li", "h1", "h2", "h3", "td", "tr", "br", "div", "article", "section"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if self.hidden_tags and tag.lower() == self.hidden_tags[-1]:
            self.hidden_tags.pop()
        elif not self.hidden_tags and tag.lower() in {"p", "li", "h1", "h2", "h3", "div", "article", "section"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.hidden_tags:
            self.parts.append(data)


def _extract_relevant_text(page: str, service: str, attack: str, cve: str) -> str:
    parser = _TextOnlyParser()
    parser.feed(page[:150_000])
    lines = [_compact(line, 420) for line in "".join(parser.parts).splitlines()]
    lines = [line for line in lines if len(line) >= 25 or re.search(r"(?i)CVE-\d{4}-\d{4,}", line)]
    keywords = {word for word in _service_terms(service) if len(word) > 2}
    keywords.update(word for word in re.findall(r"[a-z0-9-]{4,}", attack.casefold()) if word not in {"attack", "service"})
    if cve and cve.lower().startswith("cve-"):
        keywords.add(cve.lower())
    # FRA extracts webpage text before asking the LLM to summarize it. Do not
    # throw away relevant pages because the Analyst still calls them 'Web App'.
    return _compact(" ".join(lines), 3400)


def _read_public_page(url: str, service: str, attack: str, cve: str) -> str:
    _validate_dns_public(url)
    opener = request.build_opener(_NoRedirect())
    req = request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,text/plain"})
    with opener.open(req, timeout=6) as response:
        mime = response.headers.get_content_type().lower()
        if mime not in {"text/html", "text/plain"}:
            raise ValueError("Only HTML/plaintext webpages are supported")
        # Avoid scripts, binary data, giant pages, and heavy page parsing.
        content = response.read(150_001)
        partial = len(content) > 150_000
        # Large vendor pages should not discard every usable clue. Read only a
        # bounded prefix and make its incomplete nature explicit downstream.
        # We never download or parse the remainder of the page.
        content = content[:150_000]
        encoding = response.headers.get_content_charset() or "utf-8"
        page = content.decode(encoding, errors="replace")
    if mime == "text/plain":
        # For generic HTTP applications, the packet-derived mechanism words
        # can establish excerpt relevance without guessing a framework.
        candidate_terms = set(re.findall(r"[a-z]{4,}", attack.casefold()))
        page_terms = set(re.findall(r"[a-z]{4,}", page.casefold()))
        extracted = _compact(page, 3400)
    else:
        extracted = _extract_relevant_text(page, service, attack, cve)
    if partial and extracted:
        return "[PARTIAL WEBPAGE: only first 150000 bytes examined] " + extracted
    return extracted


def _http_json(url: str, *, key: str, provider: str, query: str, count: int) -> dict[str, Any]:
    if provider == "serper":
        data = json.dumps({"q": query, "num": count, "gl": "us", "hl": "en"}).encode("utf-8")
        req = request.Request(
            url, data=data, method="POST",
            headers={"X-API-KEY": key, "Content-Type": "application/json", "Accept": "application/json", "User-Agent": USER_AGENT},
        )
    elif provider == "google":
        # Match FRA's Google Programmable Search / Custom Search JSON API.
        # The key and CSE id are local configuration, never search terms.
        cse_id = os.getenv("GOOGLE_CSE_ID", "").strip()
        if not cse_id:
            raise ValueError("GOOGLE_CSE_ID must be configured for Google search")
        params = parse.urlencode({"q": query, "key": key, "cx": cse_id, "num": min(10, count), "start": 1})
        req = request.Request(url + "?" + params,
                              headers={"Accept": "application/json", "User-Agent": USER_AGENT})
    else:
        params = parse.urlencode({"q": query, "count": count, "search_lang": "en", "safesearch": "moderate"})
        req = request.Request(
            url + "?" + params,
            headers={"X-Subscription-Token": key, "Accept": "application/json", "User-Agent": USER_AGENT},
        )
    with request.urlopen(req, timeout=12) as response:
        if response.headers.get_content_type().lower() != "application/json":
            raise ValueError("Search API did not return JSON")
        data = response.read(500_001)
        if len(data) > 500_000:
            raise ValueError("Search API response too large")
        payload = json.loads(data.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Invalid search API response")
        return payload


def _search_results(provider: str, key: str, query: str, count: int) -> list[dict[str, str]]:
    endpoint = (GOOGLE_CSE_URL if provider == "google" else
                SERPER_URL if provider == "serper" else BRAVE_URL)
    if provider == "google":
        # FRA rotates to another configured key when Google's quota is
        # exhausted. Never fallback to a different provider silently.
        from urllib.error import HTTPError
        keys = _google_keys()
        payload = None
        last_exc = None
        for candidate in keys:
            try:
                payload = _http_json(endpoint, key=candidate, provider=provider,
                                     query=query, count=count)
                break
            except HTTPError as exc:
                last_exc = exc
                if exc.code not in {403, 429}:
                    raise
        if payload is None:
            raise last_exc or ValueError("No Google CSE API keys configured")
        records = payload.get("items", [])
    else:
        payload = _http_json(endpoint, key=key, provider=provider, query=query, count=count)
        records = payload.get("organic", []) if provider == "serper" else payload.get("web", {}).get("results", [])
    result: list[dict[str, str]] = []
    for item in records if isinstance(records, list) else []:
        if not isinstance(item, dict):
            continue
        link = str(item.get("link" if provider in {"serper", "google"} else "url", ""))
        try:
            link = _public_https_url(link)
        except (ValueError, TypeError):
            continue
        result.append({
            "url": link,
            "title": _compact(html.unescape(item.get("title", "")), 160),
            "snippet": _compact(html.unescape(item.get("snippet" if provider in {"serper", "google"} else "description", "")), 600),
        })
    return result


def _google_keys() -> list[str]:
    """Use FRA's GOOGLE_API_KEY_N convention plus optional GOOGLE_API_KEY."""
    named = sorted((k, v.strip()) for k, v in os.environ.items()
                   if re.fullmatch(r"GOOGLE_API_KEY_\d+", k) and v.strip())
    keys = [value for _, value in sorted(named, key=lambda kv: int(kv[0].split("_")[-1]))]
    if os.getenv("GOOGLE_API_KEY", "").strip():
        keys.insert(0, os.getenv("GOOGLE_API_KEY", "").strip())
    return list(dict.fromkeys(keys))


def _config() -> tuple[str, str, str]:
    chosen = os.getenv("FRA_WEB_SEARCH_PROVIDER", "auto").strip().lower()
    if chosen == "off":
        return "off", "", ""
    if chosen == "auto":
        chosen = ("google" if os.getenv("GOOGLE_CSE_ID") and _google_keys() else
                  "serper" if os.getenv("SERPER_API_KEY") else
                  "brave" if os.getenv("BRAVE_SEARCH_API_KEY") else "off")
    if chosen not in {"google", "serper", "brave", "off"}:
        return "off", "", "Unknown FRA_WEB_SEARCH_PROVIDER (expected google, auto, serper, brave or off)."
    if chosen == "google":
        if not os.getenv("GOOGLE_CSE_ID") or not _google_keys():
            return "off", "", "Google Custom Search requires GOOGLE_CSE_ID and GOOGLE_API_KEY_1."
        return chosen, _google_keys()[0], ""
    key = (os.getenv("SERPER_API_KEY" if chosen == "serper" else "BRAVE_SEARCH_API_KEY", "").strip()
           if chosen != "off" else "")
    if chosen != "off" and not key:
        return "off", "", f"Web search requested with provider '{chosen}', but its API key is not set."
    return chosen, key, ""


def research_web(service: str, attack: str, version: str, cve: str, query: str, limit: int) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """FRA's query -> up to 10 webpages -> text, adapted for the MCP contract.

    The main Analyst chooses the query. Unlike the previous MAFRA search,
    we do not require product identification or suppress search results based
    on an assumed product. The original FRA tool similarly accepts the
    agent's query and tries to read each of the search results in order.

    Site content is untrusted and is not packet evidence. Page summaries and
    CVE conclusions remain the responsibility of the later Analyst stage.
    """
    provider, key, config_warning = _config()
    if provider == "off":
        return [], [config_warning or "Online search provider is not configured."], []

    # The client's 'packet clues:' suffix is structured local metadata, not
    # part of FRA's agent-chosen Google search query. Use the actual query.
    chosen = str(query or "").split(" packet clues:", 1)[0].strip()
    chosen = re.sub(r"(?i)CVE-\d{4}-\d{4,}", "", chosen)
    chosen = re.sub(r"https?://\S+|\b(?:\d{1,3}\.){3}\d{1,3}\b", "", chosen)
    chosen = _compact(chosen, 250)
    if not chosen or chosen.casefold() in {"unknown", "not found", "network forensic investigation"}:
        # The existing packet-clue suffix contains *only sanitized header and
        # endpoint names*, unlike raw packet values; use it only as fallback.
        clues = query_clue_words(query)
        chosen = _compact(" ".join([service if informative_service(service) else "",
                                    attack if attack.casefold() != "unknown" else "",
                                    " ".join(clues[:5])]), 250)
    if not chosen:
        return [], ["Web search skipped: no safe search query."], []

    total_hits = _bounded_int("FRA_WEB_SEARCH_RESULTS", 10, 1, 10)
    max_fetch = _bounded_int("FRA_WEB_FETCH_MAX_PAGES", 10, 0, 10)
    warnings: list[str] = []
    queried = [f"{provider} search: {chosen}"]
    try:
        hits = _search_results(provider, key, chosen, total_hits)
    except Exception as exc:
        return [], [f"{provider} search failed: {type(exc).__name__}: {exc}"], queried

    sources: list[dict[str, Any]] = []
    seen: set[str] = set()
    vendor = _vendor_domain(service) if informative_service(service) else ""
    for hit in hits:
        if len(sources) >= total_hits:
            break
        url = hit["url"]
        if url in seen:
            continue
        seen.add(url)
        host = parse.urlsplit(url).hostname or ""
        official = bool(vendor and _hostname_in_domain(host.lower(), vendor))
        advisory_clue = bool(re.search(r"(?i)advisory|security|vulnerab|cve-\d{4}",
                                        hit["title"] + " " + url))
        snippet = hit["snippet"]
        note = "Search snippet only (webpage unavailable or not fetched)."
        # Unlike the previous implementation, FRA attempts webpage retrieval
        # even when the target product name is unknown. Read text rather than
        # filtering pages out using the guessed product. SSRF/size protections
        # from MAFRA are retained.
        if len(sources) < max_fetch:
            try:
                excerpt = _read_public_page(url, "", "", "")
                if excerpt:
                    snippet = _compact(snippet + " | Webpage text: " + excerpt, 3400)
                    note = "Page text retrieved (bounded); requires Analyst summarization."
                    if excerpt.startswith("[PARTIAL WEBPAGE:"):
                        note = "Partial webpage text retrieved (size cap); requires Analyst summarization."
            except Exception as exc:
                warnings.append(f"Webpage read unavailable for {host}: {type(exc).__name__}: {exc}")
        sources.append({
            "source_name": "Official vendor webpage" if official else f"{provider.title()} web result",
            "title": hit["title"],
            "url": url,
            "snippet": "UNTRUSTED WEB RESEARCH (not PCAP evidence). " + _compact(snippet, 3600),
            "source_type": ("vendor_advisory_lead" if advisory_clue else "vendor_page_lead")
                           if official else "web_research_lead",
            "cve_id": "",  # FRA web content is a lead, not an NVD-confirmed CVE.
            "supports": [], "contradicts": [], "match_reason": note,
        })
    return sources[:max(1, min(int(limit), 10))], warnings, queried
