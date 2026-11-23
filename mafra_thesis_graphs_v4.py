from __future__ import annotations

import argparse
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from matplotlib.ticker import PercentFormatter
import numpy as np
import pandas as pd


# ============================================================
# FILE PATHS
# ============================================================

ROOT = Path(__file__).resolve().parent
RUNS = ROOT / "evaluation_outputs" / "runs"
OUT = ROOT / "thesis_graphs"

CSV_PATHS = {
    "GPT-5": (
        RUNS
        / "gpt5_eval30_20261029_150628"
        / "evaluation_results.csv"
    ),
    "GPT-4o": (
        RUNS
        / "gpt4o_after_gzip_30_20261025_183601"
        / "evaluation_results.csv"
    ),
    "DeepSeek-R1-0528": (
        RUNS
        / "deepseek_r1_0528_30_20261025_202456"
        / "evaluation_results.csv"
    ),
}

OLLAMA_ZIP = ROOT / "MAFRA_V1_V3_Results.zip"

ZIP_FILES = {
    "Ollama V1": (
        "MAFRA_MCP_Updated_Pair/evaluation_outputs/runs/"
        "updated_mcp_v1_30/evaluation_results.csv"
    ),
    "Ollama V3": (
        "MAFRA_MCP_Updated_Pair/evaluation_outputs/runs/"
        "updated_mcp_v3_30/evaluation_results.csv"
    ),
}

METRICS = {
    "Service": "mafra_service_match",
    "CVE": "mafra_cve_match",
    "Attack outcome": "mafra_success_match",
}

COLORS = {
    "GPT-5": "tab:blue",
    "GPT-4o": "tab:orange",
    "DeepSeek-R1-0528": "tab:green",
    "Ollama V1": "tab:blue",
    "Ollama V3": "tab:orange",
}


# ============================================================
# READ EVALUATION RESULTS
# ============================================================

def read_csv(path: Path) -> pd.DataFrame:

    if not path.is_file():
        raise FileNotFoundError(
            f"Missing evaluation file: {path}"
        )

    return pd.read_csv(
        path,
        encoding="utf-8-sig",
        dtype=str,
        keep_default_na=False,
    )


def read_zip_csv(path: Path, member: str) -> pd.DataFrame:

    if not path.is_file():
        raise FileNotFoundError(
            f"Missing Ollama ZIP: {path}"
        )

    with ZipFile(path) as archive:

        if member not in archive.namelist():
            raise FileNotFoundError(
                f"ZIP does not contain: {member}"
            )

        data = archive.read(member)

    return pd.read_csv(
        BytesIO(data),
        encoding="utf-8-sig",
        dtype=str,
        keep_default_na=False,
    )


# ============================================================
# CALCULATE ACCURACY
# ============================================================

def score(name: str, df: pd.DataFrame):

    df.columns = df.columns.str.strip()

    missing = {"id", *METRICS.values()} - set(df.columns)

    if missing:
        raise ValueError(
            f"{name}: missing columns: {sorted(missing)}"
        )

    ids = df["id"].str.strip()

    if (
        len(df) != 30
        or ids.nunique() != 30
        or ids.eq("").any()
    ):
        raise ValueError(
            f"{name}: expected 30 unique cases, "
            f"found {len(df)} rows"
        )

    result = {
        "Model": name,
        "ids": set(ids),
    }

    for label, column in METRICS.items():

        values = (
            df[column]
            .str.strip()
            .str.lower()
        )

        if not values.isin(["true", "false"]).all():
            raise ValueError(
                f"{name}: unexpected values in {column}"
            )

        result[label] = int(
            values.eq("true").sum()
        )

    return result


# ============================================================
# BASIC GRAPH STYLE
# ============================================================

def chart(title: str):

    fig, ax = plt.subplots(
        figsize=(10, 6)
    )

    # One title only
    ax.set_title(
        title,
        fontsize=12
    )

    # Y axis
    ax.set_ylabel("Accuracy (%)")
    ax.set_ylim(0, 100)

    ax.yaxis.set_major_formatter(
        PercentFormatter(xmax=100)
    )

    # Plain appearance
    ax.grid(False)

    # Space reserved for legend on right
    fig.subplots_adjust(
        left=0.11,
        right=0.75,
        top=0.90,
        bottom=0.24
    )

    return fig, ax


# ============================================================
# COLOR LEGEND ON RIGHT
# ============================================================

def add_legend(fig, names):

    patches = [
        Patch(
            facecolor=COLORS[name],
            label=name
        )
        for name in names
    ]

    fig.legend(
        handles=patches,
        loc="upper left",
        bbox_to_anchor=(0.78, 0.87),
        frameon=True,
        fontsize=10
    )


# ============================================================
# SAVE GRAPH
# ============================================================

def save(fig, filename):

    OUT.mkdir(
        parents=True,
        exist_ok=True
    )

    for extension in ("png", "svg"):

        fig.savefig(
            OUT / f"{filename}.{extension}",
            dpi=300,
            bbox_inches="tight"
        )

    plt.close(fig)


# ============================================================
# FIGURES 1, 2 AND 3
# ============================================================

def graph_model_accuracy(
    runs,
    metric,
    title,
    filename
):

    fig, ax = chart(title)

    names = [
        run["Model"]
        for run in runs
    ]

    counts = [
        run[metric]
        for run in runs
    ]

    percentages = [
        100 * count / 30
        for count in counts
    ]

    x = np.arange(len(runs))

    bars = ax.bar(
        x,
        percentages,
        color=[
            COLORS[name]
            for name in names
        ],
        width=0.55
    )

    ax.set_xticks(
        x,
        names,
        rotation=22,
        ha="right"
    )

    ax.set_xlabel("Model")

    # Percentages above bars
    for bar, percentage in zip(
        bars,
        percentages
    ):

        ax.text(
            bar.get_x() + bar.get_width() / 2,
            percentage + 1.5,
            f"{percentage:.1f}%",
            ha="center",
            va="bottom",
            fontsize=10
        )

    add_legend(fig, names)

    save(fig, filename)


# ============================================================
# FIGURE 4 - OLLAMA V1 VS V3
# ============================================================

def graph_ollama(runs):

    fig, ax = chart(
        "Ollama V1 vs V3 Accuracy"
    )

    metrics = list(METRICS)

    x = np.arange(len(metrics))

    width = 0.32

    for index, run in enumerate(runs):

        percentages = [
            100 * run[metric] / 30
            for metric in metrics
        ]

        bars = ax.bar(
            x + (index - 0.5) * width,
            percentages,
            width=width,
            color=COLORS[run["Model"]]
        )

        for bar, percentage in zip(
            bars,
            percentages
        ):

            ax.text(
                bar.get_x() + bar.get_width() / 2,
                percentage + 1.5,
                f"{percentage:.1f}%",
                ha="center",
                va="bottom",
                fontsize=10
            )

    ax.set_xticks(
        x,
        metrics
    )

    ax.set_xlabel("Metric")

    add_legend(
        fig,
        [run["Model"] for run in runs]
    )

    save(
        fig,
        "figure4_ollama_v1_v3"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--check-only",
        action="store_true"
    )

    parser.add_argument(
        "--gpt5",
        type=Path,
        default=CSV_PATHS["GPT-5"]
    )

    parser.add_argument(
        "--gpt4o",
        type=Path,
        default=CSV_PATHS["GPT-4o"]
    )

    parser.add_argument(
        "--deepseek",
        type=Path,
        default=CSV_PATHS["DeepSeek-R1-0528"]
    )

    parser.add_argument(
        "--ollama-zip",
        type=Path,
        default=OLLAMA_ZIP
    )

    parser.add_argument(
        "--ollama-v1-csv",
        type=Path
    )

    parser.add_argument(
        "--ollama-v3-csv",
        type=Path
    )

    args = parser.parse_args()

    # GPT-5, GPT-4o and DeepSeek
    cloud = [
        score(
            "GPT-5",
            read_csv(args.gpt5)
        ),
        score(
            "GPT-4o",
            read_csv(args.gpt4o)
        ),
        score(
            "DeepSeek-R1-0528",
            read_csv(args.deepseek)
        ),
    ]

    # Ollama V1 and V3
    ollama = []

    for name, override in [
        ("Ollama V1", args.ollama_v1_csv),
        ("Ollama V3", args.ollama_v3_csv)
    ]:

        if override:
            df = read_csv(override)
        else:
            df = read_zip_csv(
                args.ollama_zip,
                ZIP_FILES[name]
            )

        ollama.append(
            score(name, df)
        )

    all_runs = cloud + ollama

    # Verify matching evaluation cases
    for run in all_runs[1:]:

        if run["ids"] != cloud[0]["ids"]:
            raise ValueError(
                f"{run['Model']}: case IDs "
                "differ from GPT-5"
            )

    # Print source results
    print(
        "\nVerified results from source files "
        "(30 cases per model):"
    )

    print(
        f"{'Model':22} "
        f"{'Service':>9} "
        f"{'CVE':>8} "
        f"{'Outcome':>9}"
    )

    for run in all_runs:

        print(
            f"{run['Model']:22} "
            f"{run['Service']:>9} "
            f"{run['CVE']:>8} "
            f"{run['Attack outcome']:>9}"
        )

    if args.check_only:

        print(
            "\nCHECK ONLY: no graphs created."
        )

        return

    # Figure 1: Service
    graph_model_accuracy(
        cloud,
        "Service",
        "Service Identification Accuracy",
        "figure1_services"
    )

    # Figure 2: CVE
    graph_model_accuracy(
        cloud,
        "CVE",
        "CVE Identification Accuracy",
        "figure2_cve"
    )

    # Figure 3: Attack outcome
    graph_model_accuracy(
        cloud,
        "Attack outcome",
        "Attack Outcome Accuracy",
        "figure3_attack_outcomes"
    )

    # Figure 4: Ollama V1 vs V3
    graph_ollama(ollama)

    # Save exact values used in the graphs
    pd.DataFrame([
        {
            "Model": run["Model"],
            "Service correct": run["Service"],
            "CVE correct": run["CVE"],
            "Attack outcome correct": run["Attack outcome"],
            "Cases": 30,
        }
        for run in all_runs
    ]).to_csv(
        OUT / "scores_used.csv",
        index=False
    )

    print(
        f"\nSaved the four graphs to: {OUT}"
    )


if __name__ == "__main__":
    main()