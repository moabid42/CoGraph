"""Apply schema constraints and indexes to the Neo4j database.

Usage:
    python -m scripts.01_init_schema
"""

from __future__ import annotations

import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(name)s  %(message)s")

from cograph.utils.neo4j_client import init_schema, close_driver


def main() -> None:
    try:
        init_schema()
        print("Schema initialised successfully.")
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        close_driver()


if __name__ == "__main__":
    main()
