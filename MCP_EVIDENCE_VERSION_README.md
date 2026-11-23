# MAFRA MCP Evidence-Enrichment Version

This is an isolated extension of the original project. The original
NVD-based pipeline remains available through `main_mafra.py`; the new workflow
uses `main_mafra_mcp.py`.

## Workflow

```text
PCAP / shared Flow Summary
  -> Analyzer Agent
  -> Verifier Agent
  -> Consensus
  -> MCP online evidence search
  -> deterministic Evidence Formatting
  -> MCP Reporter
```

The Analyzer and Verifier findings are retained. The MCP result is external
supporting context and does not replace packet evidence.

## MCP server contract

Configure a Streamable HTTP MCP server using:

```text
FRA_MCP_SERVER_URL=http://localhost:8000/mcp
FRA_MCP_SEARCH_TOOL=search_forensic_evidence
```

The configured tool should accept a `query` or `search_query` argument and
return either structured JSON or text. Structured results are preferred and
may contain:

```json
{
  "sources": [
    {
      "source_name": "MITRE ATT&CK",
      "title": "Relevant technique",
      "url": "https://example.org/source",
      "snippet": "Short source-supported explanation",
      "supports": ["..."],
      "contradicts": []
    }
  ]
}
```

The client inspects the advertised tool schema and only sends arguments that
the server declares. It never sends raw packet payloads to the online search;
it sends a compact investigation query derived from the validated agent
findings.

## Running

Install the original dependencies and then the MCP dependency:

```bash
python -m pip install -r requirements.txt -r requirements-mcp.txt
```

Run with a shared Flow Summary for a fair comparison:

```bash
python main_mafra_mcp.py \
  --pcap path/to/case.pcap \
  --flow-summary-file path/to/shared_summary.txt \
  --memory-mode disabled
```

The old implementation is not modified by this version and remains runnable
with `python main_mafra.py`.
