"""Check the published evaluation inputs without third-party packages or APIs."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = Path(__file__).with_name("dataset_manifest.json")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def project_file(root: Path, relative: str) -> Path:
    parts = PurePosixPath(relative)
    if parts.is_absolute() or ".." in parts.parts or "\\" in relative:
        raise ValueError(f"Invalid manifest path: {relative}")
    path = root.joinpath(*parts.parts).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError(f"Manifest path escapes the project: {relative}")
    return path


def check(root: Path, manifest: dict) -> list[str]:
    errors: list[str] = []
    truth = manifest["ground_truth"]
    truth_path = project_file(root, truth["path"])
    if not truth_path.is_file():
        return [f"Missing ground truth: {truth['path']}"]
    # Git may convert CSV line endings on Windows. Keep values and row order
    # fixed while ignoring UTF-8 BOM and platform newline differences.
    truth_text = truth_path.read_text(encoding="utf-8-sig")
    if hashlib.sha256(truth_text.encode("utf-8")).hexdigest() != truth["sha256"]:
        errors.append(f"Ground-truth checksum differs: {truth['path']}")

    with truth_path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != manifest["case_count"]:
        errors.append(f"Expected {manifest['case_count']} ground-truth rows; found {len(rows)}")
    if any("ID" not in row or "PCAP Path" not in row for row in rows):
        return errors + ["Ground truth is missing ID or PCAP Path columns"]

    entries = manifest["cases"]
    expected = {item["id"]: item for item in entries}
    if len(expected) != manifest["case_count"] or len(expected) != len(entries):
        errors.append("Manifest case IDs are duplicated or the case count differs")
    observed = [row["ID"] for row in rows]
    if len(set(observed)) != len(observed) or set(observed) != set(expected):
        errors.append("Ground-truth case IDs differ from the manifest")
    for row in rows:
        entry = expected.get(row["ID"])
        if entry is None:
            continue
        relative = "MAFRA_Eval30/" + row["PCAP Path"].replace("\\", "/")
        if relative != entry["path"]:
            errors.append(f"PCAP path differs for {row['ID']}")
    for entry in entries:
        path = project_file(root, entry["path"])
        if not path.is_file():
            errors.append(f"Missing PCAP: {entry['path']}")
        elif path.stat().st_size != entry["size_bytes"] or sha256(path) != entry["sha256"]:
            errors.append(f"PCAP checksum or size differs: {entry['path']}")
    return errors


def main() -> int:
    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        errors = check(PROJECT_ROOT, manifest)
    except (OSError, ValueError, KeyError, TypeError, csv.Error) as exc:
        print(f"FAIL: Cannot validate dataset: {exc}", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"PASS: ground-truth CSV and all {manifest['case_count']} PCAP checksums match.")
    print(f"Reference source commit: {manifest['source_commit']}")
    print("No TShark, model, MCP, or network calls were made.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
