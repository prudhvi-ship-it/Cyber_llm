"""NVD retrieval preflight that performs no LLM calls."""

import argparse
import json

from web_search import WebSearch


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Test NVD product/version retrieval without invoking an LLM."
    )
    parser.add_argument("--query", required=True, help="Service, version, and attack")
    parser.add_argument("--max-candidates", type=int, default=10)
    args = parser.parse_args()

    search = WebSearch(use_llm=False)
    result = search.run_structured(
        args.query,
        max_candidates=max(1, min(args.max_candidates, 20)),
    )
    output = {
        "status": result.status,
        "normalized_service": result.normalized_service,
        "version": result.version,
        "attack_terms": result.attack_terms,
        "search_queries": result.search_queries,
        "retrieved_at_utc": result.retrieved_at_utc,
        "candidate_count": len(result.candidates),
        "candidates": [
            {
                "cve_id": candidate.cve_id,
                "relevance_score": candidate.relevance_score,
                "version_status": candidate.version_status,
                "relevance_reasons": candidate.relevance_reasons,
                "source_url": candidate.source_url,
            }
            for candidate in result.candidates
        ],
        "retrieval_errors": result.retrieval_errors,
        "llm_called": False,
    }
    print(json.dumps(output, indent=2))
    return 1 if result.status == "Error" else 0


if __name__ == "__main__":
    raise SystemExit(main())
