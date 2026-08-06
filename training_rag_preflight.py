"""Check whether the approved read-only training RAG is ready for evaluation."""

import json

from memory_manager import MemoryManager


def main():
    manager = MemoryManager(
        system_name="EVALUATION_PREFLIGHT",
        current_case_id="training_rag_preflight",
        mode="read_only",
        run_id="training_rag_preflight",
        audit_path="",
    )
    health = manager.health()
    valid = health["status"] == "read_only" and int(health["count"]) > 0
    result = {
        "status": "Valid" if valid else "Invalid",
        "checks": {
            "training_collection_exists": health["status"] != "unavailable",
            "training_collection_non_empty": int(health["count"]) > 0,
            "training_collection_is_read_only": health["status"] == "read_only",
        },
        "memory": health,
    }
    print(json.dumps(result, indent=2))
    if not valid:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
