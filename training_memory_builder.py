"""Build an approved, training-only ChromaDB collection for FRA/MAFRA.

This utility intentionally refuses benchmark/evaluation folders. It never reads
MAFRA_Eval30 or evaluation_outputs, and every input record must explicitly be
marked approved and training-only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


FORBIDDEN_PATH_PARTS = {"mafra_eval30", "evaluation_outputs"}
REQUIRED_SPLIT = "training"


def _safe_collection_name(value: str) -> str:
    import re

    cleaned = re.sub(r"[^a-zA-Z0-9_-]+", "_", value).strip("_-").lower()
    if len(cleaned) < 3:
        raise ValueError("Collection name must contain at least three safe characters.")
    return cleaned[:80]


def _reject_evaluation_path(path: Path) -> None:
    lowered = {part.casefold() for part in path.resolve().parts}
    forbidden = sorted(FORBIDDEN_PATH_PARTS & lowered)
    if forbidden:
        raise ValueError(
            "Training memory input must be independent of the evaluation set; "
            f"forbidden path component(s): {', '.join(forbidden)}"
        )


def _normalise_record(raw: dict[str, Any], line_number: int) -> dict[str, str]:
    approved = raw.get("approved") is True
    split = str(raw.get("split", "")).strip().casefold()
    if not approved:
        raise ValueError(f"Line {line_number}: approved must be true.")
    if split != REQUIRED_SPLIT:
        raise ValueError(f"Line {line_number}: split must be 'training'.")

    source_id = str(raw.get("source_id") or raw.get("case_id") or "").strip()
    flow_summary = str(raw.get("flow_summary") or "").strip()
    report = str(raw.get("report") or "").strip()
    provenance = str(raw.get("provenance") or "").strip()
    if not source_id:
        raise ValueError(f"Line {line_number}: source_id is required.")
    if not flow_summary:
        raise ValueError(f"Line {line_number}: flow_summary is required.")
    if not report:
        raise ValueError(f"Line {line_number}: report is required.")
    if not provenance:
        raise ValueError(f"Line {line_number}: provenance is required.")

    return {
        "source_id": source_id,
        "flow_summary": flow_summary,
        "report": report,
        "provenance": provenance,
    }


def load_approved_records(input_path: str | os.PathLike[str]) -> list[dict[str, str]]:
    path = Path(input_path)
    if not path.is_file():
        raise FileNotFoundError(f"Training JSONL file not found: {path}")
    _reject_evaluation_path(path)

    records: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Line {line_number}: invalid JSON: {exc.msg}") from exc
        if not isinstance(raw, dict):
            raise ValueError(f"Line {line_number}: each JSONL row must be an object.")
        record = _normalise_record(raw, line_number)
        if record["source_id"] in seen_ids:
            raise ValueError(
                f"Line {line_number}: duplicate source_id {record['source_id']!r}."
            )
        seen_ids.add(record["source_id"])
        records.append(record)

    if not records:
        raise ValueError("No approved training records were found.")
    return records


def build_collection(
    records: list[dict[str, str]],
    *,
    db_path: str,
    collection_name: str,
    replace: bool = False,
) -> dict[str, Any]:
    import chromadb
    from chromadb.utils import embedding_functions

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "OPENAI_API_KEY is required to create text embeddings for training RAG."
        )

    safe_name = _safe_collection_name(collection_name)
    client = chromadb.PersistentClient(path=db_path)
    existing_names = {
        item if isinstance(item, str) else item.name
        for item in client.list_collections()
    }
    if safe_name in existing_names:
        if not replace:
            raise FileExistsError(
                f"Collection [{safe_name}] already exists. Use --replace only after "
                "reviewing the approved training input."
            )
        client.delete_collection(safe_name)

    embed_fn = embedding_functions.OpenAIEmbeddingFunction(
        api_key=api_key,
        model_name="text-embedding-3-small",
    )
    collection = client.get_or_create_collection(
        name=safe_name,
        embedding_function=embed_fn,
        metadata={
            "hnsw:space": "cosine",
            "dataset_split": "training",
            "approved_only": True,
        },
    )

    ids: list[str] = []
    documents: list[str] = []
    metadatas: list[dict[str, Any]] = []
    for record in records:
        source_hash = hashlib.sha256(record["source_id"].encode("utf-8")).hexdigest()
        document = (
            "APPROVED TRAINING-ONLY FORENSIC CASE\n"
            f"FLOW SUMMARY:\n{record['flow_summary'][:3000]}\n\n"
            f"REPORT:\n{record['report'][:4000]}"
        )
        content_hash = hashlib.sha256(document.encode("utf-8")).hexdigest()
        ids.append(f"training_{source_hash[:24]}")
        documents.append(document)
        metadatas.append(
            {
                "case_id": f"training_{source_hash[:20]}",
                "source_id_hash": source_hash,
                "content_sha256": content_hash,
                "provenance": record["provenance"][:500],
                "split": REQUIRED_SPLIT,
                "approved": True,
                "type": "forensic_analysis",
            }
        )

    batch_size = 50
    for start in range(0, len(ids), batch_size):
        end = start + batch_size
        collection.upsert(
            ids=ids[start:end],
            documents=documents[start:end],
            metadatas=metadatas[start:end],
        )

    return {
        "status": "Valid",
        "db_path": str(Path(db_path).resolve()),
        "collection": safe_name,
        "record_count": int(collection.count()),
        "embedding_model": "text-embedding-3-small",
        "split": REQUIRED_SPLIT,
        "approved_only": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build an approved training-only RAG collection."
    )
    parser.add_argument("--input", required=True, help="Approved training JSONL file")
    parser.add_argument(
        "--db-path",
        default=os.getenv("FRA_MEMORY_DB_PATH", "./chroma_db_v2"),
    )
    parser.add_argument(
        "--collection",
        default=os.getenv("FRA_TRAINING_COLLECTION", "fra_training_memory"),
    )
    parser.add_argument("--replace", action="store_true")
    parser.add_argument(
        "--manifest-output",
        default="training_memory_manifest.json",
        help="Audit manifest path; raw training text is not copied into it.",
    )
    args = parser.parse_args()

    records = load_approved_records(args.input)
    result = build_collection(
        records,
        db_path=args.db_path,
        collection_name=args.collection,
        replace=args.replace,
    )
    result["input_file_sha256"] = hashlib.sha256(
        Path(args.input).read_bytes()
    ).hexdigest()
    result["input_record_count"] = len(records)
    destination = Path(args.manifest_output)
    destination.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    print(f"Manifest saved: {destination.resolve()}")


if __name__ == "__main__":
    main()
