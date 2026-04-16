"""Run the full RAGAS evaluation benchmark.

Usage:
    python -m scripts.05_run_eval
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(name)s  %(message)s")

from crtkb.eval.benchmark import load_questions, print_results_table, run_benchmark
from crtkb.utils.neo4j_client import close_driver


def main() -> None:
    try:
        questions = load_questions()
        print(f"Loaded {len(questions)} benchmark questions.")

        summary = run_benchmark(questions)
        print_results_table(summary)

        # Save results to JSON
        output_path = Path("eval_results.json")
        with open(output_path, "w") as f:
            json.dump(summary, f, indent=2, default=str)
        print(f"\nDetailed results saved to {output_path}")

    except Exception as exc:
        logging.error("Evaluation failed: %s", exc, exc_info=True)
        sys.exit(1)
    finally:
        close_driver()


if __name__ == "__main__":
    main()
