"""Optional live web-search smoke test. No API keys are stored or printed."""
from __future__ import annotations

import sys
from mcp_web_research import _config, research_web


def main() -> int:
    provider, _key, warning = _config()
    print(f"Web search provider: {provider}")
    if provider == "off":
        print(warning or "Web search provider or API key not configured.")
        print("Set FRA_WEB_SEARCH_PROVIDER and the selected provider's API key first.")
        return 2
    print("Querying for public Grafana path traversal references (no PCAP content)...")
    sources, warnings, queries = research_web(
        service="Grafana", attack="path traversal",
        version="", cve="CVE-2021-43798", query="", limit=10,
    )
    print(f"Search requests: {len(queries)}; relevant results: {len(sources)}")
    for item in sources[:5]:
        print(f"  - [{item['source_type']}] {item['title']} | {item['url']}")
    for warning in warnings[:6]:
        print("WARNING:", warning)
    if not sources:
        print("FAILED: no relevant web results. Check key, quota, network or query.")
        return 1
    print("PASS: Web search returned relevant URL-backed leads. This does not test PCAP accuracy.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
