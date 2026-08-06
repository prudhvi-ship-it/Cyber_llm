"""Compatibility entry point for the modular evaluation package.

The previous duplicate evaluator contained the old F1/MCC bug. Keeping one
implementation prevents the two scripts from producing contradictory results.
"""

from evaluation.run_eval import main


if __name__ == "__main__":
    main()
