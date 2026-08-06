import pandas as pd
from evaluation.config import GROUND_TRUTH_CSV
from evaluation.labels import parse_binary_label


REQUIRED_COLUMNS = {
    "ID",
    "Benchmark",
    "PCAP File",
    "PCAP Path",
    "Expected Service",
    "Expected CVE",
    "Expected Success",
    "Expected Vulnerable",
}


def validate_ground_truth(df):
    missing = sorted(REQUIRED_COLUMNS - set(df.columns))
    if missing:
        raise ValueError(f"Ground truth is missing columns: {', '.join(missing)}")
    if df["ID"].isna().any() or df["ID"].astype(str).str.strip().eq("").any():
        raise ValueError("Ground truth contains an empty case ID.")
    if df["ID"].astype(str).duplicated().any():
        duplicates = df.loc[df["ID"].astype(str).duplicated(), "ID"].tolist()
        raise ValueError(f"Ground truth contains duplicate IDs: {duplicates}")

    invalid_success = df[
        df["Expected Success"].map(
            lambda value: parse_binary_label(value, "success") is None
        )
    ]
    invalid_vulnerable = df[
        df["Expected Vulnerable"].map(
            lambda value: parse_binary_label(value, "vulnerability") is None
        )
    ]
    if not invalid_success.empty:
        raise ValueError(
            "Unrecognized Expected Success labels for IDs: "
            + ", ".join(invalid_success["ID"].astype(str))
        )
    if not invalid_vulnerable.empty:
        raise ValueError(
            "Unrecognized Expected Vulnerable labels for IDs: "
            + ", ".join(invalid_vulnerable["ID"].astype(str))
        )


def load_ground_truth(limit=None):
    df = pd.read_csv(GROUND_TRUTH_CSV)
    validate_ground_truth(df)

    if limit is not None:
        df = df.head(limit)

    return df
