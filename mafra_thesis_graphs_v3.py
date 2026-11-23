"""Make four thesis charts from saved MAFRA-MCP and Ollama evaluations.

Figure 1 - GPT-5 / GPT-4o / DeepSeek service accuracy.
Figure 2 - GPT-5 / GPT-4o / DeepSeek exact CVE accuracy.
Figure 3 - GPT-5 / GPT-4o / DeepSeek attack outcomes (correct/wrong/unknown).
Figure 4 - Ollama V1 vs V3 on service, CVE and attack outcome.

The evaluation files and the original evaluation/graphs.py are never modified.

Run from the FRA_Project_V2_MCP folder:
    python -m pip install pandas matplotlib
    python mafra_thesis_graphs_v2.py --check-only
    python mafra_thesis_graphs_v2.py

Optional PRESENTATION-ONLY preview (NOT measured research results):
    python mafra_thesis_graphs_v2.py --draft-illustrative

In preview mode only, GPT-5's CVE and attack outcome scores are presented at
DeepSeek's level as a clearly labeled HYPOTHETICAL SCENARIO. Its service score
stays measured and unchanged. The attack outcome scenario supposes that 11 of
GPT-5's previously Unknown decisions are correct rather than abstentions.
GPT-5's REAL scores are unchanged in source CSV and included alongside plotted
values in plotted_values_and_sources.csv. Illustrative figures are prominently
marked NOT MEASURED and saved to a DIFFERENT folder.
"""

from __future__ import annotations

import argparse
import zipfile
from dataclasses import dataclass
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.patches import Patch
from matplotlib.ticker import PercentFormatter

ROOT = Path(__file__).resolve().parent
RUNS = ROOT / "evaluation_outputs" / "runs"
DEFAULT_FILES = {
    "GPT-5": RUNS / "gpt5_mcp_initial_30" / "evaluation_results.csv",
    "GPT-4o": RUNS / "gpt4o_after_gzip_30_20261025_183601" / "evaluation_results.csv",
    "DeepSeek-R1-0528": RUNS / "deepseek_r1_0528_30_20261025_202456" / "evaluation_results.csv",
}
DEFAULT_OLLAMA_ZIP = ROOT / "MAFRA_V1_V3_Results.zip"
ZIP_MEMBERS = {
    "Ollama V1": (
        "MAFRA_MCP_Updated_Pair/evaluation_outputs/runs/"
        "updated_mcp_v1_30/evaluation_results.csv"
    ),
    "Ollama V3": (
        "MAFRA_MCP_Updated_Pair/evaluation_outputs/runs/"
        "updated_mcp_v3_30/evaluation_results.csv"
    ),
}
EXPECTED_RUN_ID = {
    "Ollama V1": "updated_mcp_v1_30",
    "Ollama V3": "updated_mcp_v3_30",
}

N = 30
MATCH_FIELDS = {
    "Service": "mafra_service_match",
    "CVE": "mafra_cve_match",
    "Attack outcome": "mafra_success_match",
}
MODEL_COLORS = {
    "GPT-5": "#294B70",
    "GPT-4o": "#8EA0B3",
    "DeepSeek-R1-0528": "#15857B",
    "Ollama V1": "#446A94",
    "Ollama V3": "#16917F",
}
OUTCOME_COLORS = {
    "Correct": "#15857B",
    "Incorrect": "#BD7D5E",
    "Unknown": "#B9C2CC",
    "No report": "#806997",
}
UNKNOWN_VALUES = {"", "unknown", "not found", "not_found", "none", "nan", "abstain", "skipped"}
POSITIVE_OUTCOMES = {"success", "successful"}
NEGATIVE_OUTCOMES = {"fail", "failed", "failure"}


@dataclass
class Run:
    name: str
    source: str
    run_id: str
    dataframe: pd.DataFrame
    service: int
    cve: int
    outcome: int
    incorrect: int
    unknown: int
    crashed: int


def read_csv(path: Path) -> pd.DataFrame:
    if not path.is_file():
        raise FileNotFoundError(f"Missing evaluation CSV: {path}")
    return pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8-sig")


def read_from_zip(path: Path, member: str) -> pd.DataFrame:
    if not path.is_file():
        raise FileNotFoundError(f"Missing Ollama ZIP: {path}")
    with zipfile.ZipFile(path, "r") as archive:
        if member not in archive.namelist():
            raise ValueError(f"Ollama ZIP does not contain: {member}")
        with archive.open(member) as stream:
            return pd.read_csv(stream, dtype=str, keep_default_na=False,
                               encoding="utf-8-sig")


def evaluate(name: str, frame: pd.DataFrame, source: str) -> Run:
    """Calculate scores from evaluator's recorded Consensus match flags."""
    df = frame.copy()
    df.columns = df.columns.str.strip()
    required = {"id", "run_id", "mafra_attack_success", "mafra_crashed", *MATCH_FIELDS.values()}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"{name}: missing columns {sorted(missing)}")
    if (len(df) != N or df["id"].str.strip().nunique() != N
            or df["id"].str.strip().eq("").any()):
        raise ValueError(f"{name}: expected {N} rows with unique case IDs")
    run_ids = set(df["run_id"].str.strip())
    if len(run_ids) != 1 or "" in run_ids:
        raise ValueError(f"{name}: invalid run IDs: {run_ids}")
    for col in [*MATCH_FIELDS.values(), "mafra_crashed"]:
        values = df[col].str.strip().str.lower()
        invalid = set(values) - {"true", "false"}
        if invalid:
            raise ValueError(f"{name}: unexpected values in {col}: {sorted(invalid)}")
        df[col] = values.eq("true")
    outcomes = df["mafra_attack_success"].str.strip().str.lower()
    allowed = UNKNOWN_VALUES | POSITIVE_OUTCOMES | NEGATIVE_OUTCOMES
    if set(outcomes) - allowed:
        raise ValueError(f"{name}: unexpected attack outcomes: {sorted(set(outcomes)-allowed)}")
    if df.loc[df["mafra_crashed"], list(MATCH_FIELDS.values())].any().any():
        raise ValueError(f"{name}: crashed case incorrectly marked as correct")
    crashed = int(df["mafra_crashed"].sum())
    correct = int(df[MATCH_FIELDS["Attack outcome"]].sum())
    unknown = int(((~df["mafra_crashed"]) & outcomes.isin(UNKNOWN_VALUES)).sum())
    incorrect = N - correct - unknown - crashed
    if incorrect < 0:
        raise ValueError(f"{name}: negative incorrect outcome count")
    return Run(name, source, next(iter(run_ids)), df,
               int(df[MATCH_FIELDS["Service"]].sum()),
               int(df[MATCH_FIELDS["CVE"]].sum()),
               correct, incorrect, unknown, crashed)


def validate_same_cases(runs: list[Run]) -> None:
    baseline = runs[0].dataframe.set_index("id").sort_index()
    for run in runs[1:]:
        other = run.dataframe.set_index("id").sort_index()
        if set(other.index) != set(baseline.index):
            raise ValueError(f"{run.name}: cases differ from GPT-5 evaluation")
        for col in ("expected_service", "expected_cve", "expected_success"):
            if col in baseline and col in other:
                a = baseline[col].str.strip().str.lower()
                b = other[col].str.strip().str.lower()
                if (a != b).any():
                    raise ValueError(f"{run.name}: different ground-truth values for {col}")


def setup_figure(title: str, subtitle: str, draft: bool, horizontal: bool = False):
    fig, ax = plt.subplots(figsize=(11.4, 5.7), dpi=120)
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")
    fig.suptitle(title, x=0.10, ha="left", y=0.96,
                 fontsize=16, fontweight="bold", color="#23364C")
    ax.set_title(subtitle, loc="left", pad=16, fontsize=10, color="#536476")
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.tick_params(axis="both", length=0)
    ax.set_axisbelow(True)
    ax.grid(axis="x" if horizontal else "y", alpha=0.17)
    if not horizontal:
        ax.set_ylim(0, 100)
        ax.set_ylabel("Accuracy (%)")
        ax.yaxis.set_major_formatter(PercentFormatter(xmax=100))
    # Reserve the entire right side for legends. NEVER place over plot bars.
    fig.subplots_adjust(left=0.10 if not horizontal else 0.23,
                        right=0.73, top=0.79, bottom=0.20)
    if draft:
        fig.text(0.10, 0.058,
                 "ILLUSTRATIVE PREVIEW - NOT MEASURED EVALUATION RESULTS",
                 fontsize=10.2, color="#A03930", weight="bold")
    return fig, ax


def add_right_legend(fig, colors: dict[str, str], title: str):
    handles = [Patch(facecolor=color, edgecolor="none", label=label)
               for label, color in colors.items()]
    fig.legend(handles=handles, title=title, loc="upper left",
               bbox_to_anchor=(0.77, 0.77), frameon=False, fontsize=10,
               title_fontsize=10, labelspacing=1.1, borderaxespad=0)


def write_note(fig, note: str, draft: bool):
    fig.text(0.10, 0.09 if draft else 0.07,
             note, ha="left", fontsize=8.5, color="#556678")


def save(fig, folder: Path, filename: str):
    for suffix in ("png", "svg"):
        fig.savefig(folder / f"{filename}.{suffix}",
                    dpi=300 if suffix == "png" else None,
                    facecolor="white", bbox_inches="tight")
    plt.close(fig)


def figure_accuracy(runs: list[Run], metric: str, number: int,
                    folder: Path, display: dict[str, dict[str, int]], draft: bool):
    title = "Service identification accuracy" if metric == "service" else "Exact CVE identification accuracy"
    fig, ax = setup_figure(f"Figure {number}. {title}",
                            "MAFRA-MCP | 30 PCAPs per model | benchmark exact-match scoring",
                            draft)
    names = [r.name for r in runs]
    counts = [display[r.name][metric] for r in runs]
    bars = ax.bar(names, [100 * x / N for x in counts], width=0.58,
                  color=[MODEL_COLORS[name] for name in names])
    for bar, count, name in zip(bars, counts, names):
        value = 100 * count / N
        is_demo = draft and name == "GPT-5" and metric == "cve"
        if is_demo:
            bar.set_hatch("///")
            bar.set_edgecolor("white")
        ax.text(bar.get_x() + bar.get_width()/2, value + 2.1,
                f"{count}/{N} ({value:.1f}%)" + ("*" if is_demo else ""),
                ha="center", va="bottom", fontsize=10, fontweight="bold")
    add_right_legend(fig, {name: MODEL_COLORS[name] for name in names}, "Model / bar color")
    if draft:
        note = ("GPT-5 service uses its actual measured score; only GPT-5 CVE (*) is "
                "hypothetical." if metric == "service" else
                "* GPT-5 CVE is an illustrative scenario, not a measured result.")
    else:
        note = "GPT-5 used an earlier pipeline; differences are not exclusively model effects."
    write_note(fig, note, draft)
    save(fig, folder, f"figure{number}_{'services' if metric == 'service' else 'cve'}")


def figure_outcomes(runs: list[Run], folder: Path, display: dict[str, dict[str, int]], draft: bool):
    fig, ax = setup_figure("Figure 3. Attack outcome classification",
                            "Correct, incorrect, Unknown and unavailable predictions (30 cases per model)",
                            draft, horizontal=True)
    categories = ("Correct", "Incorrect", "Unknown", "No report")
    for i, run in enumerate(runs):
        left = 0
        shown_correct = display[run.name]["outcome"]
        extra_correct = shown_correct - run.outcome
        if extra_correct < 0 or extra_correct > run.unknown:
            raise ValueError(f"{run.name}: illustrative outcome scenario cannot be formed from Unknown decisions")
        shown_unknown = run.unknown - extra_correct
        counts = (shown_correct, run.incorrect, shown_unknown, run.crashed)
        if sum(counts) != N:
            raise ValueError(f"{run.name}: outcome chart does not total {N} cases")
        for cat, count in zip(categories, counts):
            if count:
                bar = ax.barh(i, count, left=left, height=0.57, color=OUTCOME_COLORS[cat])
                if draft and run.name == "GPT-5" and cat == "Correct":
                    bar[0].set_hatch("///")
                    bar[0].set_edgecolor("white")
                if count >= 2:
                    ax.text(left+count/2, i, str(count), ha="center", va="center",
                            fontsize=11, fontweight="bold",
                            color="#263644" if cat == "Unknown" else "white")
                left += count
    ax.set_yticks(range(len(runs)), [r.name for r in runs])
    ax.invert_yaxis()
    ax.set_xlim(0, N)
    ax.set_xlabel("PCAP cases")
    shown = categories if any(r.crashed for r in runs) else categories[:3]
    add_right_legend(fig, {k: OUTCOME_COLORS[k] for k in shown}, "Prediction result")
    write_note(fig, ("Hypothetical GPT-5 scenario: 11 of its 22 Unknown outcomes "
                     "are assumed correct; not measured." if draft else
                     "Unknown is not counted as correct. GPT-5 is an earlier pipeline run."), draft)
    save(fig, folder, "figure3_attack_outcomes")


def figure_ollama(runs: list[Run], folder: Path, draft: bool):
    fig, ax = setup_figure("Figure 4. Ollama V1 vs V3: three evaluation metrics",
                            "Exploratory local-model evaluation | 30 PCAPs per version | crashes included",
                            draft)
    metrics = ("Service", "CVE", "Attack outcome")
    xs = range(len(metrics))
    width = 0.33
    for idx, run in enumerate(runs):
        counts = (run.service, run.cve, run.outcome)
        offsets = [x + (idx-0.5)*width for x in xs]
        bars = ax.bar(offsets, [100*x/N for x in counts], width=width,
                      color=MODEL_COLORS[run.name])
        for bar, count in zip(bars, counts):
            pct = 100 * count / N
            ax.text(bar.get_x()+bar.get_width()/2, pct+1.8,
                    f"{pct:.1f}%", ha="center", va="bottom", fontsize=9.5,
                    fontweight="bold")
    ax.set_xticks(list(xs), metrics)
    add_right_legend(fig, {r.name: MODEL_COLORS[r.name] for r in runs}, "Ollama version")
    write_note(fig, "Preliminary results: V1 has 5 crashed cases; V3 has 3. All 30 are counted.", draft)
    save(fig, folder, "figure4_ollama_v1_v3")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--gpt5", type=Path, default=DEFAULT_FILES["GPT-5"])
    parser.add_argument("--gpt4o", type=Path, default=DEFAULT_FILES["GPT-4o"])
    parser.add_argument("--deepseek", type=Path, default=DEFAULT_FILES["DeepSeek-R1-0528"])
    parser.add_argument("--ollama-zip", type=Path, default=DEFAULT_OLLAMA_ZIP)
    parser.add_argument("--ollama-v1-csv", type=Path, default=None)
    parser.add_argument("--ollama-v3-csv", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--check-only", action="store_true",
                        help="Read/validate all results and print scores; generate no figures")
    parser.add_argument("--draft-illustrative", action="store_true",
                        help="Preview only: show hypothetical GPT-5 CVE/outcome equal to DeepSeek; measured service unchanged")
    args = parser.parse_args()

    paths = {"GPT-5": args.gpt5, "GPT-4o": args.gpt4o, "DeepSeek-R1-0528": args.deepseek}
    cloud = [evaluate(name, read_csv(path), str(path)) for name, path in paths.items()]
    ollama = []
    for name, csv_override in [("Ollama V1", args.ollama_v1_csv),
                               ("Ollama V3", args.ollama_v3_csv)]:
        if csv_override is not None:
            run = evaluate(name, read_csv(csv_override), str(csv_override))
        else:
            member = ZIP_MEMBERS[name]
            run = evaluate(name, read_from_zip(args.ollama_zip, member),
                           f"{args.ollama_zip}::{member}")
        if run.run_id != EXPECTED_RUN_ID[name]:
            raise ValueError(f"{name}: expected run ID {EXPECTED_RUN_ID[name]}, got {run.run_id}")
        ollama.append(run)
    validate_same_cases(cloud + ollama)

    display = {r.name: {"service": r.service, "cve": r.cve, "outcome": r.outcome}
               for r in cloud + ollama}
    if args.draft_illustrative:
        # Intentionally NOT the measurements. Keep actual scores in Run objects.
        display["GPT-5"]["cve"] = display["DeepSeek-R1-0528"]["cve"]
        display["GPT-5"]["outcome"] = display["DeepSeek-R1-0528"]["outcome"]

    print("\nVerified results from source files (each run has 30 cases):")
    print(f"{'Model':21} {'Service':>9} {'CVE':>9} {'Outcome':>9} {'Unknown':>9} {'Crashes':>9}")
    for r in cloud + ollama:
        print(f"{r.name:21} {r.service:>9} {r.cve:>9} {r.outcome:>9} {r.unknown:>9} {r.crashed:>9}")
    if args.draft_illustrative:
        print("\nILLUSTRATIVE PREVIEW (not real results):")
        print(f"  GPT-5 service: {cloud[0].service}/30 measured -> unchanged")
        print(f"  GPT-5 CVE:     {cloud[0].cve}/30 measured -> {display['GPT-5']['cve']}/30 hypothetical")
        print(f"  GPT-5 outcome: {cloud[0].outcome}/30 measured -> {display['GPT-5']['outcome']}/30 hypothetical")
        print("  Outcome preview assumes previously Unknown outcomes are correct; NOT observed.")
    if args.check_only:
        print("\nCHECK ONLY: no graphs were created.")
        return

    destination = args.output or ROOT / ("thesis_graphs_illustrative" if args.draft_illustrative
                                         else "thesis_graphs")
    destination.mkdir(parents=True, exist_ok=True)
    figure_accuracy(cloud, "service", 1, destination, display, args.draft_illustrative)
    figure_accuracy(cloud, "cve", 2, destination, display, args.draft_illustrative)
    figure_outcomes(cloud, destination, display, args.draft_illustrative)
    figure_ollama(ollama, destination, args.draft_illustrative)

    rows = []
    for r in cloud + ollama:
        dp = display[r.name]
        rows.append({
            "model": r.name, "run_id": r.run_id, "source": r.source, "cases": N,
            "measured_service_correct": r.service, "measured_cve_correct": r.cve,
            "measured_outcome_correct": r.outcome,
            "plotted_service_correct": dp["service"], "plotted_cve_correct": dp["cve"],
            "plotted_outcome_correct": dp["outcome"],
            "plotted_service_pct": round(dp["service"]*100/N, 1),
            "plotted_cve_pct": round(dp["cve"]*100/N, 1),
            "plotted_outcome_pct": round(dp["outcome"]*100/N, 1),
            "measured_outcome_incorrect": r.incorrect, "measured_outcome_unknown": r.unknown,
            "plotted_outcome_incorrect": r.incorrect,
            "plotted_outcome_unknown": r.unknown - (dp["outcome"] - r.outcome),
            "crashes": r.crashed,
            "illustrative_cve_override": bool(args.draft_illustrative and r.name == "GPT-5"),
            "illustrative_outcome_override": bool(args.draft_illustrative and r.name == "GPT-5"),
            "illustrative_assumption": ("11 Unknown -> Correct (unverified scenario)"
                                       if args.draft_illustrative and r.name == "GPT-5" else ""),
        })
    pd.DataFrame(rows).to_csv(destination / "plotted_values_and_sources.csv", index=False)
    print(f"\nSaved PNG and SVG charts in: {destination}")
    if args.draft_illustrative:
        print("ILLUSTRATIVE graphics are not suitable as empirical thesis results.")


if __name__ == "__main__":
    main()
