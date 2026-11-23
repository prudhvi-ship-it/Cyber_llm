# Reproduction review

Reviewed source: commit `4842db3`, supplied as `MAFRA_Repro_Review.zip`.
Review date: 2026-11-23.

## Checks completed

| Check | Result | Scope |
| --- | --- | --- |
| Existing environment `pip check` | Passed | User's installed Windows environment |
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

The Windows PowerShell installer was reviewed but could not be executed in the
Linux review environment. It is restricted to the reviewed commit and a clean
working tree so an unexpected local revision is not overwritten.

The supplied `reproduction/check_dataset.py` verifies the ground-truth CSV,
case IDs, PCAP paths, byte sizes, and SHA-256 hashes. Its manifest is tied to the
reviewed input files. The CSV hash ignores UTF-8 BOM and newline differences
that Git can introduce on Windows. PCAP hashes are over the original bytes.

## Changes supplied by this update

- Replace the incomplete README with setup, configuration, offline checks,
  MCP startup, one-case analysis, full evaluation, and saved-plot commands.
- Pin `requirements-mcp.txt` to the reported SDK version, `mcp==2.2.0`.
- Extend `.env.example` with Serper, optional NVD, explicit same-model settings,
  disabled memory, and the MCP endpoint.
- Add a dataset manifest and a standard-library integrity check.

The installer copies only these documentation, template, requirement, and
dataset-check files. It preserves the existing `.env`, dependencies, analysis
code, prompts, scoring, PCAPs, and saved results. Its backup is stored outside
the Git repository. The two generated reports previously excluded after the
credential-pattern check remain excluded.

## Remaining checks before claiming a runnable reproduction

1. Apply and commit this update, then clone that commit into a new directory.
2. Create a new virtual environment without reusing the existing `.venv`.
3. Install both requirement files and run `pip check` there.
4. Run the dataset check, CLI help, and PCAP preflight from the README.
5. Start MCP and confirm the expected tool is available at the configured URL.
6. Supply local credentials and finish the one-PCAP analysis. Inspect the report,
   evidence audit, and terminal log for retrieval or model errors.
7. Run all 30 cases under a new run ID with the explicitly recorded model,
   profile, memory mode, and notebook setting. Check the status and telemetry.

The review attempted dependency resolution, but access to the Python package
registry was blocked with HTTP 403. It could not establish package availability,
install a fresh environment, or validate Windows MCP startup. No TShark
executable was available in the review environment. These checks must be
completed on a machine with the required software and network access.

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

The main requirements file pins listed packages, and MCP is pinned separately.
This is not a complete lock of MCP's transitive dependencies. After a successful
fresh installation and smoke test, record the interpreter, OS, TShark, commit,
and full installed package versions. For example, locally:

```powershell
.\.venv\Scripts\python.exe --version
tshark --version
git rev-parse HEAD
.\.venv\Scripts\python.exe -m pip list --format=freeze > requirements-resolved-windows.txt
```

That export records installed distributions and versions without source URLs.
Review it before publishing. Platform-specific dependencies mean it must not
be advertised as a verified Linux or macOS lock. Test installing the exported
versions in a second fresh Windows environment before treating it as a
validated environment lock.

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
