"""Run the LLM extraction pipeline on specified source documents.

Usage:
    python -m scripts.03_run_pipeline <source_path> [--type markdown|text]
    python -m scripts.03_run_pipeline path/to/document.md
"""

from __future__ import annotations

import argparse
import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(name)s  %(message)s")

from crtkb.pipeline.runner import run_pipeline
from crtkb.utils.neo4j_client import close_driver


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the LLM extraction pipeline.")
    parser.add_argument("source_path", help="Path to the source document.")
    parser.add_argument(
        "--type",
        dest="source_type",
        default="markdown",
        choices=["markdown", "text"],
        help="Source document type (default: markdown).",
    )
    args = parser.parse_args()

    try:
        summary = run_pipeline(args.source_path, args.source_type)
        print(f"\nPipeline complete:")
        for k, v in summary.items():
            print(f"  {k}: {v}")
    except Exception as exc:
        logging.error("Pipeline failed: %s", exc, exc_info=True)
        sys.exit(1)
    finally:
        close_driver()


if __name__ == "__main__":
    main()
