FRA/MAFRA APPROVED TRAINING RAG SETUP
=====================================

Why the smoke test stopped being a full proposed-system test
-------------------------------------------------------------
The read-only collection fra_training_memory did not exist. The corrected
runner now checks that this collection exists and contains at least one approved
training case before any paid evaluation calls begin.

Important research rule
-----------------------
Do not build this collection from MAFRA_Eval30, its PCAPs, its generated reports,
or evaluation_outputs. That would leak benchmark answers into evaluation.

Input format
------------
Create a JSONL file outside the project evaluation folders. Every line must be a
JSON object with:
- source_id: stable identifier for the independent training case
- split: "training"
- approved: true
- provenance: where the case came from and why it is allowed
- flow_summary: sanitized training-only flow evidence
- report: reviewed defensive report for that training case

The formal schema is approved_training_cases.schema.json.

Build command
-------------
python training_memory_builder.py --input C:\path\approved_training_cases.jsonl --replace

The command creates fra_training_memory in chroma_db_v2 and writes
training_memory_manifest.json. It requires OPENAI_API_KEY for embeddings.

Verify before evaluation
------------------------
python training_rag_preflight.py

Then run the 3-case proposed-system smoke test:
python -m evaluation.run_eval --limit 3 --skip-fra --profile heterogeneous --memory-mode read_only --run-id smoke_proposed_3_fixed

No-memory smoke test
--------------------
Until an independent approved training corpus is available, use:
python -m evaluation.run_eval --limit 3 --skip-fra --profile heterogeneous --memory-mode disabled --run-id smoke_mafra_no_memory_fixed

That run is correctly labeled a no-memory ablation, not the full proposed system.
