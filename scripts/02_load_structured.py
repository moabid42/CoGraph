"""Run all deterministic parsers and MERGE the structured backbone into Neo4j.

Usage:
    python -m scripts.02_load_structured
"""

from __future__ import annotations

import logging
import sys
import time

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(name)s  %(message)s")

from crtkb.config import settings
from crtkb.parsers.attack_stix import AttackStixParser
from crtkb.parsers.atomic_red_team import AtomicRedTeamParser
from crtkb.parsers.lolbas import LolbasParser
from crtkb.utils.neo4j_client import close_driver, merge_nodes, merge_relationships

logger = logging.getLogger(__name__)


def main() -> None:
    batch_size = settings.merge_batch_size
    total_nodes = 0
    total_rels = 0
    t0 = time.perf_counter()

    # Order matters: ATT&CK first (creates Technique nodes others depend on)
    parsers = [
        ("MITRE ATT&CK", AttackStixParser()),
        ("Atomic Red Team", AtomicRedTeamParser()),
        ("LOLBAS", LolbasParser()),
    ]

    try:
        for name, parser in parsers:
            logger.info("─── Parsing %s ───", name)
            nodes, rels = parser.parse()

            logger.info("Merging %d nodes …", len(nodes))
            n = merge_nodes(nodes, batch_size=batch_size)
            total_nodes += n

            logger.info("Merging %d relationships …", len(rels))
            r = merge_relationships(rels, batch_size=batch_size)
            total_rels += r

        elapsed = time.perf_counter() - t0
        print(
            f"\nStructured backbone loaded: {total_nodes} nodes, "
            f"{total_rels} relationships in {elapsed:.1f}s."
        )
    except Exception as exc:
        logger.error("Load failed: %s", exc, exc_info=True)
        sys.exit(1)
    finally:
        close_driver()


if __name__ == "__main__":
    main()
