"""Create vector indexes for entity embeddings and compute embeddings in batch.

Usage:
    python -m scripts.04_build_indexes
"""

from __future__ import annotations

import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(name)s  %(message)s")

from crtkb.config import settings
from crtkb.utils.embedder import embed_text
from crtkb.utils.neo4j_client import close_driver, get_driver

logger = logging.getLogger(__name__)

# Labels that get vector indexes (those with description text + embedding property)
INDEXED_LABELS = [
    "Technique",
    "Malware",
    "Tool",
    "IntrusionSet",
    "Procedure",
    "LOLBin",
    "Defense",
    "Mitigation",
    "Campaign",
]


def create_vector_indexes() -> None:
    """Create a vector index per label for embedding-based search."""
    driver = get_driver()
    with driver.session(database=settings.neo4j_database) as session:
        for label in INDEXED_LABELS:
            index_name = f"{label.lower()}_embedding_idx"
            try:
                session.run(
                    f"CREATE VECTOR INDEX {index_name} IF NOT EXISTS "
                    f"FOR (n:{label}) ON (n.embedding) "
                    f"OPTIONS {{indexConfig: {{"
                    f"  `vector.dimensions`: {settings.embedding_dimensions},"
                    f"  `vector.similarity_function`: 'cosine'"
                    f"}}}}"
                )
                logger.info("Created vector index: %s", index_name)
            except Exception:
                logger.warning("Could not create index %s", index_name, exc_info=True)


def compute_embeddings(label: str, batch_size: int = 100) -> int:
    """Compute and store embeddings for all nodes of a given label that lack one."""
    driver = get_driver()
    count = 0

    with driver.session(database=settings.neo4j_database) as session:
        # Fetch nodes without embeddings
        result = session.run(
            f"MATCH (n:{label}) WHERE n.embedding IS NULL "
            f"RETURN elementId(n) AS eid, n.name AS name, n.description AS desc"
        )
        records = list(result)

    logger.info("%s: %d nodes need embeddings.", label, len(records))

    # Batch embed and write back
    driver = get_driver()
    for i in range(0, len(records), batch_size):
        batch = records[i : i + batch_size]
        updates = []
        for rec in batch:
            emb = embed_text(rec["name"] or "", rec["desc"] or "")
            updates.append({"eid": rec["eid"], "embedding": emb})

        with driver.session(database=settings.neo4j_database) as session:
            session.execute_write(
                lambda tx, upd=updates: tx.run(
                    "UNWIND $updates AS row "
                    "MATCH (n) WHERE elementId(n) = row.eid "
                    "SET n.embedding = row.embedding",
                    updates=upd,
                )
            )
        count += len(batch)
        logger.info("%s: embedded %d / %d", label, count, len(records))

    return count


def main() -> None:
    try:
        logger.info("Creating vector indexes …")
        create_vector_indexes()

        logger.info("Computing embeddings …")
        total = 0
        for label in INDEXED_LABELS:
            total += compute_embeddings(label)

        print(f"\nVector indexes created. Computed {total} embeddings.")
    except Exception as exc:
        logger.error("Failed: %s", exc, exc_info=True)
        sys.exit(1)
    finally:
        close_driver()


if __name__ == "__main__":
    main()
