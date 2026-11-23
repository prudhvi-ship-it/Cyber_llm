# Reproduction review

Reviewed source: commit `4842db3`, supplied as `MAFRA_Repro_Review.zip`.
Review date: 2026-11-23.

Follow-up verification used a fresh clone at `01c7d10` and a newly created
Python 3.14 Windows virtual environment. The first installation attempt using
the committed requirements failed because `idna==3.11` conflicted with MCP's
`httpx2` dependency. Exporting the working environment's installed package
versions resolved the conflict. That snapshot installed successfully in the
fresh venv and passed `pip check`.

The corrected `requirements.txt` contains those versions, excluding `pip`,
`setuptools`, and `wheel`. No model or analysis code was changed by this fix.

## Checks completed

| Check | Result | Scope |
| --- | --- | --- |
| Existing environment `pip check` | Passed | User's installed Windows environment |
| Fresh environment installation | Passed using exported package versions | Fresh Windows Python 3.14 venv; original committed pins initially failed |
| Fresh environment `pip check` | Passed | No broken requirements reported |
| Fresh clone dataset checksums | All 30 PCAPs and ground-truth CSV matched | `MAFRA_Reproduction` clone |
| Fresh clone TShark preflight | Valid | CFA-00, 3,252 bytes, TCP streams 0 and 1 |
| Fresh clone pipeline/evaluator/MCP imports | Passed with Pydantic V1 warning | Includes `Client` and `MCPServer` imports |
| Current pipeline `--help` | Passed with Pydantic V1 warning | User's installed environment |
| Evaluator `--help` | Passed with the same warning | User's installed environment |
| Python source syntax | All 111 original scripts parsed | Review environment, Python 3.12.14; no imports required |
| Referenced dataset files | 30 of 30 PCAPs present | Uploaded source archive |
| Flow-ranking regression tests | 11 passed | Existing offline tests in review environment |
| Evaluation-reconciliation regression tests | 4 passed | Existing offline tests in review environment |
| CVE-reporting regression tests | 12 passed | Existing offline tests in review environment |
| Dataset integrity checker | Passed | Original inputs, Windows BOM/newlines, modified/missing PCAP, altered labels, and unsafe-path checks |

The review environment has different packages and Python from the user's
environment. These selected tests do not validate the full installed stack or
the MCP server. No real model requests or live vulnerability searches were made
during this review.

The initial PowerShell installer was subsequently run successfully in the
user's Windows project. It applied the six support files and created an external
backup before the documentation update was committed as `01c7d10`.

The supplied `reproduction/check_dataset.py` verifies the ground-truth CSV,
case IDs, PCAP paths, byte sizes, and SHA-256 hashes. Its manifest is tied to the
reviewed input files. The CSV hash ignores UTF-8 BOM and newline differences
that Git can introduce on Windows. PCAP hashes are over the original bytes.

## Changes supplied by this update

- Replace the incomplete README with setup, configuration, offline checks,
  MCP startup, one-case analysis, full evaluation, and saved-plot commands.
- Pin `requirements-mcp.txt` to the reported SDK version, `mcp==2.2.0`.
- Refresh `requirements.txt` from the installed package versions that succeeded
  in the fresh Windows venv, including `idna==3.20` and MCP dependencies.
- Extend `.env.example` with Serper, optional NVD, explicit same-model settings,
  disabled memory, and the MCP endpoint.
- Add a dataset manifest and a standard-library integrity check.

The installer copies only these documentation, template, requirement, and
dataset-check files. It preserves the existing `.env`, dependencies, analysis
code, prompts, scoring, PCAPs, and saved results. Its backup is stored outside
the Git repository. The two generated reports previously excluded after the
credential-pattern check remain excluded.

## Verification scope and remaining checks

Fresh environment installation, declared dependency consistency, dataset
integrity, TShark access to the sample PCAP, and application/MCP imports have
passed on Windows. These are the verified reproduction checks.

The following live checks were skipped at the user's request:

1. Start MCP in the fresh clone and confirm the expected tool is available at
   the configured URL.
2. Supply local credentials and finish a one-PCAP analysis. Inspect the report,
   evidence audit, and terminal log for retrieval or model errors.
3. Rerun all 30 cases under a new run ID and inspect completion and telemetry.

The project has a tested Windows installation snapshot and offline checks. A
fresh live end-to-end reproduction has not been established, and new benchmark
scores must not be claimed from these checks.

The separate Linux review environment could not access the package registry
(HTTP 403) and had no TShark executable. The Windows checks above were performed
later by the user and supersede the earlier pending installation status. The
selected regression test results remain scoped to the Linux review environment.

## Python warning and dependency locking

The reported environment uses Python 3.14.3 and emits:

```text
Core Pydantic V1 functionality isn't compatible with Python 3.14 or greater.
```

`pip check` tests declared package requirements; it does not establish that all
runtime code paths support the interpreter. The warning remains unresolved by
this documentation update. If the fresh test fails because of it, evaluate a
supported interpreter/package combination in another new environment and rerun
the checks. Do not describe that changed combination as the historical one.

The original requirements file was a stale package snapshot. The working
environment contained `mcp==2.2.0`, `httpx2==2.13.1`, and `idna==3.20`, while the
file still pinned `idna==3.11`. The new `requirements.txt` records the exported
Windows package versions that installed successfully in the fresh venv, with
bootstrap tools excluded. MCP is pinned to the same version in both requirement
files. The export includes platform-specific packages such as `pywin32`.

This snapshot does not include distribution hashes, downloaded wheels, or an
offline package mirror. It must not be described as a validated Linux/macOS
lock. The snapshot installation used pip 26.2.1; pip itself is not a runtime
dependency in the corrected requirements file. Record interpreter, OS, TShark,
commit, and installed package versions when repeating the procedure.

## Saved experiments and exact-result limits

The three documented run manifests select `fair_same_model`, disabled memory,
and a disabled investigation notebook. The evaluator defaults differ: its
profile defaults to `heterogeneous` and its notebook defaults to enabled. The
README therefore supplies both flags explicitly. A single manual invocation
also needs an explicit profile/model configuration in `.env` or the shell.

`experiment_config.py` currently defaults most heterogeneous roles to GPT-5 and
the reporter to Gemini 2.5 Flash. Some evaluator help text still mentions
GPT/Claude/Gemini. The actual resolved model map and the saved run manifest are
the relevant records, not that help-text description.

The GPT-5 saved run's status is `COMPLETE_WITH_PROVIDER_ERROR_WARNINGS`: all 30
rows are present, with four provider/LLM call errors recorded. Its status marks
`clean_run` and `provider_error_free` as false. It must not be described as an
error-free rerun. The raw outputs and telemetry are needed to interpret it.

Two DeepSeek CFA-11 generated report files were excluded from the pushed snapshot
after matching credential-like patterns. They remain available only in the
owner's local project. Do not promise a complete historical report archive or
remove the exclusions just to make the file count match. Saved CSV plotting is
separate from reading or rerunning those reports.

The source provides a rerunnable procedure, not a guarantee of identical LLM
predictions. Live model aliases, provider routing, search results, web pages,
NVD records, CISA KEV, and MITRE ATT&CK data can change. The run manifests do
not capture every environment setting, SDK version, provider route, or complete
snapshot of every remote resource. Keep a separate reproduction record with
those details, with credentials removed.

`--graphs-only` recalculates plots from a stored result CSV with the checked-out
metrics and graph code. It does not rerun the models or establish original
forensic accuracy. Scores from a fresh 30-case analysis should be compared with
the saved scores, and any differences and provider errors should be reported.
