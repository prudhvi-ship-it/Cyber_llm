# MAFRA

MAFRA analyzes packet captures to identify the attacked application, a possible
CVE, and the observed attack outcome. It uses separate Analyst and Verifier
agents, packet and frame evidence, and online vulnerability research through
MCP. The repository also contains the earlier FRA and MAFRA entry points and
saved evaluation results.

Use `main_mafra_mcp.py` for the current pipeline. The commands below use Windows
PowerShell and disable memory, as in the saved 30-case evaluations.

## Reproduction status

The source snapshot reviewed for these instructions is commit `4842db3`.
All 30 PCAPs referenced by `MAFRA_Eval30/ground_truth.csv` are present. A dataset
checksum manifest and an offline check are provided in `reproduction/`.

A clean installation and live end-to-end rerun have **not yet been verified**.
The recorded environment passes `pip check` and both command-line help commands,
but reports a Pydantic V1 compatibility warning on Python 3.14. See
[the verification record](docs/REPRODUCIBILITY.md) for checks completed and checks
still needed. A successful Git push alone does not establish reproducibility.

## Recorded environment

| Component | Reported version |
| --- | --- |
| Operating environment | Windows, PowerShell 5.1 |
| Python | 3.14.3 |
| TShark | 4.6.9 |
| MCP Python SDK | 2.2.0 |
| Python dependencies | `requirements.txt` and `requirements-mcp.txt` |

These are the reported versions, not a claim that every combination of Python,
Windows, and package versions has been tested. Do not suppress the compatibility
warning or change dependency versions to hide it. Check it during the fresh
installation test and record any version changes.

## 1. Clone and install

Install Git, Python, and Wireshark with TShark first. Make TShark available on
`PATH`, or set `TSHARK_PATH` in `.env` to its full executable path.

Use a new folder for the installation test:

```powershell
git clone https://github.com/prudhvi-ship-it/Cyber_llm.git MAFRA_Reproduction
cd MAFRA_Reproduction
git rev-parse HEAD
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-mcp.txt
.\.venv\Scripts\python.exe -m pip check
tshark --version
```

Record the full commit hash printed by Git. To test a particular revision,
check it out before installing. The historical snapshot `4842db3` predates this
documentation update; use the commit containing this README for the checks added
here. The direct executable paths below avoid the need to activate the venv.
If the `py` launcher is unavailable, use the full path to your Python 3.14
executable to create the venv.

MCP is pinned to the reported installed version. Its transitive dependencies are
not all locked by these two requirement files, so a full environment lock is
still pending. Initial setup may also need Internet access for tokenizer data.

## 2. Configure local credentials

```powershell
Copy-Item .env.example .env
notepad .env
```

Fill in `OPENROUTER_API_KEY`. The active model factory in `llm_client.py` uses
OpenRouter; an OpenAI API key alone does not configure this pipeline.

For the Serper web-search configuration, fill in `SERPER_API_KEY` too. Set
`FRA_WEB_SEARCH_PROVIDER=off` only when deliberately testing without general web
search; that changes the research configuration. `NVD_API_KEY` is optional.
NVD, CISA KEV, and MITRE ATT&CK retrieval also need Internet access.

The supplied template selects `fair_same_model`, `openai/gpt-5`, and disabled
memory explicitly. Verify that the selected model is available to your account.
Existing shell environment variables take precedence over `.env` because the
code uses the default `load_dotenv()` behavior. Use new terminals or clear stale
MAFRA configuration before testing.

Do not commit `.env`. The Chroma databases are not supplied or required for the
disabled-memory evaluation. Other memory modes require separate preparation.

## 3. Run the offline checks

From the repository root:

```powershell
.\.venv\Scripts\python.exe reproduction\check_dataset.py
.\.venv\Scripts\python.exe main_mafra_mcp.py --help
.\.venv\Scripts\python.exe -m evaluation.run_eval --help
.\.venv\Scripts\python.exe pcap_preflight.py --pcap MAFRA_Eval30\pcaps\CFA_event0_CVE-2022-24706.pcap
```

The dataset check needs only Python's standard library. It verifies the exact
ground-truth CSV and all 30 PCAP checksums. The PCAP preflight checks TShark and
packet access without an LLM call. It still imports project dependencies and may
need to initialize the tokenizer cache. A passing offline check does not confirm
model or MCP connectivity.

Selected offline regression tests:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_step6a_attack_flow_priority.py -v
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_eval_crash_flag_fix.py -v
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_fra_step5_cve_reporting.py -v
```

## 4. Start MCP in terminal 1

Open PowerShell in the cloned repository and run:

```powershell
.\.venv\Scripts\mcp.exe run mcp_server.py --transport streamable-http
```

Leave this terminal open. The client URL is `http://localhost:8000/mcp` and the
tool is `search_forensic_evidence`. This is the command documented by
`mcp_server.py`; its startup and tool connectivity must still be checked in the
fresh installation with SDK 2.2.0. An import or startup failure is a failed setup
check, not permission to continue without MCP.

## 5. Analyze one PCAP in terminal 2

Open another PowerShell terminal in the same repository:

```powershell
.\.venv\Scripts\python.exe main_mafra_mcp.py --pcap MAFRA_Eval30\pcaps\CFA_event0_CVE-2022-24706.pcap --memory-mode disabled --investigation-notebook disabled --mcp-url http://localhost:8000/mcp --report-output evaluation_outputs\reproduction_smoke\CFA-00_report.txt
```

This makes paid LLM calls and can use paid Serper requests. It writes a report,
an MCP evidence JSON file, and a terminal log under
`evaluation_outputs/reproduction_smoke/`. A generated flow summary is written
beside the PCAP. The capture itself is read, not rewritten.

Check that the report contains a consensus and final report, the MCP evidence
audit contains the expected source records without retrieval-failure warnings,
and the terminal log has no unhandled exception. Creating a report alone is not
proof that all online retrieval succeeded. A successful one-case run is needed
before launching the full evaluation.

## 6. Run the 30-case evaluation

Use a new run ID and keep the MCP server running:

```powershell
$mafraRunId = "repro_gpt5_" + (Get-Date -Format "yyyyMMdd_HHmmss")
.\.venv\Scripts\python.exe -m evaluation.run_eval --mafra-mcp-only --profile fair_same_model --memory-mode disabled --investigation-notebook disabled --mcp-url http://localhost:8000/mcp --run-id $mafraRunId
```

For an initial one-case evaluation, add `--limit 1` and use a separate run ID.
The default profile of the evaluator is `heterogeneous`, so keep the explicit
`--profile fair_same_model` flag when following these instructions. The
`--mafra-mcp-only` option runs the current MAFRA implementation, not the legacy
FRA/MAFRA comparison. Do not add a shared flow-summary input: this mode retains
in-process packet verification.

The run directory is `evaluation_outputs/runs/<run-id>/`. It contains
`evaluation_results.csv`, `experiment_manifest.json`, `evaluation_status.json`,
reports, raw outputs, graphs, and audit records. Check completeness and provider
errors in the status file, not only the number of CSV rows.

Resume an interrupted run using its original run ID and the same configuration,
with `--resume` added. Do not resume a one-case smoke run as a new benchmark.

## Saved model runs and results

The committed manifests record these same-model, disabled-memory runs:

| Model setting (`FRA_FAIR_MODEL`) | Saved run ID |
| --- | --- |
| `openai/gpt-5` | `gpt5_eval30_20261029_150628` |
| `openai/gpt-4o` | `gpt4o_after_gzip_30_20261025_183601` |
| `deepseek/deepseek-r1-0528` | `deepseek_r1_0528_30_20261025_202456` |

To rerun another model, change `FRA_FAIR_MODEL`, keep the same-model profile, and
use a new run ID. Do not substitute another model and call it the same experiment.
Model access and provider availability must be checked at execution time.

For example, regenerate plots from the saved GPT-5 result CSV without making LLM
calls:

```powershell
.\.venv\Scripts\python.exe -m evaluation.run_eval --graphs-only --run-id gpt5_eval30_20261029_150628
```

This writes `graphs_report_ready/` in that saved run directory. It reproduces
plots from stored predictions; it does not rerun packet analysis.

LLM responses, model aliases, search results, web pages, vulnerability feeds, and
provider errors can change. Fresh execution is not expected to produce identical
report text or necessarily the same scores. Compare each run's configuration,
saved evidence, completion status, and metrics. See
[reproducibility details](docs/REPRODUCIBILITY.md) for the known limitations.

## Repository layout

| Path | Contents |
| --- | --- |
| `main_mafra_mcp.py` | Current MAFRA entry point |
| `mcp_server.py` | MCP server for online forensic research |
| `agents/` | Analyst, Verifier, consensus, and reporting components |
| `evaluation/` | Dataset loading, evaluation, metrics, and plots |
| `MAFRA_Eval30/` | Ground-truth CSV and evaluation PCAPs |
| `evaluation_outputs/` | Saved results, manifests, and reports |
| `tests/` | Regression tests |
| `reproduction/` | Dataset checksums and offline integrity check |
| `docs/` | Reproduction notes and optional training-memory instructions |
