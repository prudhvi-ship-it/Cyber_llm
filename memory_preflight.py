"""Offline validation for leakage-safe memory behavior."""

import json

from memory_manager import MemoryManager


class FakeCollection:
    """Small in-memory Chroma stand-in; no API key or network required."""

    def __init__(self):
        self.records = [
            {
                "id": "memory_current",
                "document": "CURRENT CASE SECRET ANSWER",
                "metadata": {"case_id": "case_current"},
                "distance": 0.01,
            },
            {
                "id": "memory_approved",
                "document": "Approved similar defensive case",
                "metadata": {"case_id": "case_training"},
                "distance": 0.18,
            },
            {
                "id": "memory_unrelated",
                "document": "Unrelated distant case",
                "metadata": {"case_id": "case_other"},
                "distance": 0.91,
            },
        ]

    def count(self):
        return len(self.records)

    def query(self, **_kwargs):
        return {
            "ids": [[item["id"] for item in self.records]],
            "documents": [[item["document"] for item in self.records]],
            "metadatas": [[item["metadata"] for item in self.records]],
            "distances": [[item["distance"] for item in self.records]],
        }

    def upsert(self, ids, documents, metadatas):
        self.records.append({
            "id": ids[0],
            "document": documents[0],
            "metadata": metadatas[0],
            "distance": 0.0,
        })


def main():
    checks = {}

    disabled = MemoryManager(
        mode="disabled",
        system_name="FRA",
        current_case_id="case_current",
        audit_path="",
    )
    checks["evaluation_memory_disabled"] = (
        disabled.retrieve("test") == "RAG memory disabled for this run."
        and not disabled.store("case_current", "flow", "report")
        and disabled.count() == 0
    )

    fake_collection = FakeCollection()
    isolated = MemoryManager(
        mode="isolated",
        system_name="FRA",
        run_id="preflight",
        current_case_id="case_current",
        max_distance=0.35,
        collection=fake_collection,
        audit_path="",
    )
    context = isolated.retrieve("similar flow", n_results=2)
    checks["current_case_excluded"] = "CURRENT CASE SECRET ANSWER" not in context
    checks["similar_case_allowed"] = "Approved similar defensive case" in context
    checks["distant_case_rejected"] = "Unrelated distant case" not in context
    checks["retrieval_source_auditable"] = (
        isolated.last_retrievals
        == [{"source_id": "memory_approved", "distance": 0.18}]
    )
    checks["system_collection_isolated"] = (
        isolated.collection_name == "fra_fra_preflight"
    )

    before = fake_collection.count()
    read_only = MemoryManager(
        mode="read_only",
        system_name="MAFRA",
        current_case_id="case_new",
        collection_name="approved_training",
        collection=fake_collection,
        audit_path="",
    )
    blocked = not read_only.store("case_new", "flow", "report")
    checks["read_only_write_blocked"] = blocked and fake_collection.count() == before

    status = "Valid" if all(checks.values()) else "Invalid"
    print(json.dumps({"status": status, "checks": checks}, indent=2))
    if status != "Valid":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
