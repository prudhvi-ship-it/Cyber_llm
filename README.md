\# MAFRA: Multi-Agent Forensic Reasoning Assistant



MAFRA is a cybersecurity research project that uses multiple AI agents to analyze network evidence, validate CVE findings, and produce structured forensic reports.



The project compares:



\- FRA: the baseline forensic reasoning pipeline

\- MAFRA: the multi-agent forensic reasoning pipeline



\## Main Features



\- PCAP evidence extraction

\- Network-flow summarization

\- Multi-agent analysis and verification

\- CVE validation

\- Structured forensic reporting

\- LLM telemetry and audit records

\- Optional ChromaDB-based training memory

\- Automated evaluation and graph generation



\## Project Structure



```text

agents/                Multi-agent analysis components

evaluation/            Evaluation framework and metrics

evaluation\_outputs/    Final benchmark results and reports

MAFRA\_Eval30/          30-case heterogeneous evaluation dataset

chroma\_db/             Existing vector database

chroma\_db\_v2/          Updated vector database

docs/                  Additional project documentation

