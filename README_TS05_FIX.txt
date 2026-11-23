MAFRA-MCP evaluation: TS-05 false-crash-flag fix
================================================
Purpose
- Correct the evaluator's mistake of labeling an inconclusive analysis as a subprocess crash.
- Keep TS-05's Unknown/Not Found predictions unchanged.
- Keep the JSONDecodeError telemetry record. An agent parsing error really occurred.
- Do not rerun 30 paid PCAP analyses to regenerate graphs.

1) Backup current run_eval.py (in the FRA_Project_V2_MCP root, PowerShell):
   Copy-Item .\evaluation\run_eval.py .\evaluation\run_eval.py.before_ts05_fix

2) Expand this patch ZIP from Downloads in project root:
   Expand-Archive "$env:USERPROFILE\Downloads\MAFRA_MCP_TS05_Crash_Flag_Fix.zip" -DestinationPath . -Force

3) Run offline tests:
   python -m unittest discover -s tests -p "test_eval_crash_flag_fix.py" -v

4) Reconcile TS-05's completed report without running an LLM:
   python -m evaluation.reconcile_completed_case --run-dir ".\evaluation_outputs\runs\gpt5_mcp_initial_30" --case-id TS-05
   This step requires 30/30 cases to already be recorded and checks the final report and console completion marker. It saves a timestamped copy of evaluation_results.csv first.

5) Refresh all metrics and graphs, with the same original profile, notebook and MCP URL:
   $env:FRA_EXPERIMENT_PROFILE = "fair_same_model"
   $env:FRA_FAIR_MODEL = "openai/gpt-5"
   python -m evaluation.run_eval `
       --mafra-mcp-only `
       --profile fair_same_model `
       --memory-mode disabled `
       --mcp-url "http://127.0.0.1:8000/mcp" `
       --investigation-notebook enabled `
       --run-id gpt5_mcp_initial_30 `
       --resume
   This will skip all 30 cases if all 30 have been recorded. Do not execute if your initial 30-case run is incomplete. A status of COMPLETE_WITH_PROVIDER_ERROR_WARNINGS is expected as long as the prior JSONDecodeError remains recorded.

Rollback
- Restore .\evaluation\run_eval.py from .\evaluation\run_eval.py.before_ts05_fix.
- Restore evaluation_results.csv from the timestamped backup created in step 4.
- Rerun the evaluation summary/graph generation with --resume (no paid reanalysis if all 30 are already recorded).

Limitations
- The API status 200 confirms only an HTTP response; it does not mean the analyst JSON parsing succeeded.
- This patch does not claim TS-05 attack identification was correct or that the LLM parsing issue disappeared.
- Future actual model failures are still recorded in llm_telemetry.jsonl, separately from process crashes.
