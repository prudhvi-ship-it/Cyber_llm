import pandas as pd
from pathlib import Path

from evaluation.config import OUTPUT_DIR


METRIC_DEFINITIONS = pd.DataFrame([
    {
        "Term": "Strict Accuracy",
        "Definition": "Correct predictions divided by all cases; Unknown/Not Found counts as incorrect.",
    },
    {
        "Term": "Coverage",
        "Definition": "Cases with a positive or negative answer divided by all cases.",
    },
    {
        "Term": "Answered Only",
        "Definition": "F1, MCC, precision, and recall calculated only where the system gave a class answer.",
    },
    {
        "Term": "Positive Vulnerability Class",
        "Definition": "Vulnerable/Yes.",
    },
    {
        "Term": "Positive Attack-Success Class",
        "Definition": "Successful/Success.",
    },
    {
        "Term": "Unknown/Abstain",
        "Definition": "A separate prediction state; never silently treated as No or Failed.",
    },
    {
        "Term": "Confusion Matrix",
        "Definition": "Uses the model's actual final prediction with Negative, Positive, and Unknown columns.",
    },
])


def save_reports(
    results_df,
    summary_df,
    stats_df,
    telemetry_df=None,
    telemetry_summary_df=None,
    manifest_df=None,
    output_dir=None,
):
    destination = Path(output_dir) if output_dir is not None else OUTPUT_DIR
    destination.mkdir(parents=True, exist_ok=True)
    results_csv = destination / "evaluation_results.csv"
    results_xlsx = destination / "MAFRA_Evaluation_Results.xlsx"

    results_df.to_csv(results_csv, index=False)

    with pd.ExcelWriter(results_xlsx, engine="openpyxl") as writer:
        results_df.to_excel(writer, index=False, sheet_name="Results")
        summary_df.to_excel(writer, index=False, sheet_name="Summary")
        stats_df.to_excel(writer, index=False, sheet_name="F1_MCC_Precision_Recall")
        METRIC_DEFINITIONS.to_excel(
            writer,
            index=False,
            sheet_name="Metric_Definitions",
        )
        if telemetry_df is not None:
            telemetry_df.to_excel(writer, index=False, sheet_name="LLM_Calls")
        if telemetry_summary_df is not None:
            telemetry_summary_df.to_excel(
                writer,
                index=False,
                sheet_name="LLM_Summary",
            )
        if manifest_df is not None:
            manifest_df.to_excel(writer, index=False, sheet_name="Experiment_Config")
