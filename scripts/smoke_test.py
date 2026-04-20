"""Smoke-test queries to verify graph integrity after loading.

Usage:
    python -m scripts.smoke_test
"""

from __future__ import annotations

import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(name)s  %(message)s")

from cograph.config import settings
from cograph.utils.neo4j_client import close_driver, get_driver

logger = logging.getLogger(__name__)

CHECKS = [
    (
        "Technique → Tactic (exit criterion, expect ~691)",
        "MATCH (t:Technique)-[:PART_OF_TACTIC]->(ta:Tactic) RETURN count(DISTINCT t) AS cnt",
    ),
    (
        "Node cardinalities",
        "MATCH (n) RETURN labels(n)[0] AS label, count(n) AS cnt ORDER BY cnt DESC",
    ),
    (
        "Orphan check (should be 0 for structured sources)",
        "MATCH (n) WHERE NOT (n)--() RETURN labels(n)[0] AS label, count(n) AS cnt",
    ),
    (
        "Procedure → Technique (expect ~1774)",
        "MATCH (p:Procedure)-[:IMPLEMENTS]->(t:Technique) RETURN count(p) AS cnt",
    ),
    (
        "LOLBin → Technique (expect ~232)",
        "MATCH (l:LOLBin)-[:EXECUTES_VIA]->(t:Technique) RETURN count(DISTINCT l) AS cnt",
    ),
    (
        "Total relationship count",
        "MATCH ()-[r]->() RETURN count(r) AS cnt",
    ),
]


def main() -> None:
    driver = get_driver()
    passed = True

    try:
        with driver.session(database=settings.neo4j_database) as session:
            for description, query in CHECKS:
                print(f"\n── {description}")
                result = session.run(query)
                records = list(result)
                if not records:
                    print("  (no results)")
                    continue
                for rec in records:
                    line = "  " + "  ".join(f"{k}={rec[k]}" for k in rec.keys())
                    print(line)
    except Exception as exc:
        logger.error("Smoke test failed: %s", exc, exc_info=True)
        passed = False
    finally:
        close_driver()

    if not passed:
        sys.exit(1)
    print("\n✓ Smoke tests completed.")


if __name__ == "__main__":
    main()
