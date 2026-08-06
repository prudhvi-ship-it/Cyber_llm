from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATASET_DIR = PROJECT_ROOT / "MAFRA_Eval30"
GROUND_TRUTH_CSV = DATASET_DIR / "ground_truth.csv"
PCAP_DIR = DATASET_DIR / "pcaps"

OUTPUT_DIR = PROJECT_ROOT / "evaluation_outputs"
RAW_OUTPUT_DIR = OUTPUT_DIR / "raw_outputs"
GRAPH_DIR = OUTPUT_DIR / "graphs"

RESULTS_CSV = OUTPUT_DIR / "evaluation_results.csv"
RESULTS_XLSX = OUTPUT_DIR / "MAFRA_Evaluation_Results.xlsx"