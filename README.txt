# MAFRA-MCP: regenerate graphs from saved results (no PCAP runs)

This patch updates ONLY `evaluation/graphs.py` and `evaluation/run_eval.py`.
It adds `--graphs-only` which uses the original 30-case CSV and the original manifest.
The graph-only branch exits before any PCAP, MCP, GPT-5, or evaluation execution.
It writes seven report-ready PNGs in a NEW `graphs_report_ready/` folder.
It does NOT rewrite any saved results, old PNGs, forensic reports or manifests.

## Install in PowerShell (VS Code terminal)

1. Back up your existing `evaluation/graphs.py` and `evaluation/run_eval.py`.
2. Extract this ZIP. Copy the two new files inside its `evaluation` folder
   to your project's `evaluation` folder, replacing only those two.
3. In the project root, activate the existing virtual environment:

```powershell
cd "C:\Users\12486\Desktop\FRA_Project_V2_MCP"
.\.venv\Scripts\Activate.ps1
python -m py_compile evaluation\graphs.py evaluation\run_eval.py
python -m evaluation.run_eval --graphs-only --run-id gpt5_mcp_initial_30
```

## Output

`evaluation_outputs/runs/gpt5_mcp_initial_30/graphs_report_ready/`

Includes: 01 core accuracy, 03 runtime distribution, 06 benchmark comparison,
07 service accuracy, 08 CVE accuracy, 09 outcome accuracy, 11 case matrix.
Only service, CVE and attack-outcome accuracy appear in the report-ready
accuracy charts. Vulnerability-status accuracy remains in the original CSV.
Unknown attack outcomes still count as not matching ground-truth labels.

## Rollback

Restore your two backed-up Python files. The original saved CSV and graphs
will not have been changed by graph-only mode.
