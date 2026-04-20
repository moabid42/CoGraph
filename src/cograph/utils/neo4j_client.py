"""Neo4j driver singleton, schema initialisation, and batch helpers."""

from __future__ import annotations

import logging
from pathlib import Path

from neo4j import GraphDatabase, Driver

from cograph.config import settings
from cograph.models.nodes import NodeRecord
from cograph.models.relationships import RelRecord
from cograph.ontology.schema import NODE_TYPES

logger = logging.getLogger(__name__)

_SCHEMA_FILE = Path(__file__).resolve().parents[1] / "ontology" / "schema_init.cypher"

# ── Singleton driver ─────────────────────────────────────────────────────

_driver: Driver | None = None


def get_driver() -> Driver:
    """Return (and cache) a Neo4j driver."""
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )
        _driver.verify_connectivity()
        logger.info("Neo4j driver connected to %s", settings.neo4j_uri)
    return _driver


def close_driver() -> None:
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None


# ── Schema initialisation ───────────────────────────────────────────────

def init_schema() -> None:
    """Execute every statement in ``schema_init.cypher`` against the database."""
    driver = get_driver()
    text = _SCHEMA_FILE.read_text()
    # Split on semicolons, skip blank / comment-only fragments
    statements = [
        s.strip()
        for s in text.split(";")
        if s.strip() and not s.strip().startswith("//")
    ]
    with driver.session(database=settings.neo4j_database) as session:
        for stmt in statements:
            session.run(stmt)
            logger.debug("Executed: %s", stmt[:80])
    logger.info("Schema initialised — %d statements executed.", len(statements))


# ── Batch MERGE helpers ─────────────────────────────────────────────────

def merge_nodes(records: list[NodeRecord], batch_size: int = 500) -> int:
    """MERGE a list of NodeRecords into Neo4j in batches.  Returns count."""
    if not records:
        return 0

    driver = get_driver()
    total = 0
    # Group by label for efficient UNWIND
    by_label: dict[str, list[dict]] = {}
    for r in records:
        by_label.setdefault(r.label, []).append(r.properties)

    with driver.session(database=settings.neo4j_database) as session:
        for label, props_list in by_label.items():
            ukey = NODE_TYPES[label]["unique_key"]
            query = (
                f"UNWIND $batch AS row "
                f"MERGE (n:{label} {{{ukey}: row.{ukey}}}) "
                f"ON CREATE SET n += row "
                f"ON MATCH SET n += row"
            )
            for i in range(0, len(props_list), batch_size):
                batch = props_list[i : i + batch_size]
                session.execute_write(lambda tx, q=query, b=batch: tx.run(q, batch=b))
                total += len(batch)
            logger.info("Merged %d %s nodes.", len(props_list), label)
    return total


def merge_relationships(records: list[RelRecord], batch_size: int = 500) -> int:
    """MERGE a list of RelRecords into Neo4j in batches.  Returns count."""
    if not records:
        return 0

    driver = get_driver()
    total = 0

    # Group by (src_label, rel_type, tgt_label) for efficient UNWIND
    groups: dict[tuple[str, str, str], list[dict]] = {}
    for r in records:
        key = (r.source_label, r.rel_type, r.target_label)
        row = {
            "src_key": r.source_key,
            "tgt_key": r.target_key,
            **r.provenance.to_props(),
            **r.extra_props,
        }
        groups.setdefault(key, []).append(row)

    with driver.session(database=settings.neo4j_database) as session:
        for (sl, rt, tl), rows in groups.items():
            src_ukey = NODE_TYPES[sl]["unique_key"]
            tgt_ukey = NODE_TYPES[tl]["unique_key"]
            query = (
                f"UNWIND $batch AS row "
                f"MATCH (src:{sl} {{{src_ukey}: row.src_key}}) "
                f"MATCH (tgt:{tl} {{{tgt_ukey}: row.tgt_key}}) "
                f"MERGE (src)-[r:{rt}]->(tgt) "
                f"ON CREATE SET r += row "
                f"ON MATCH SET r += row"
            )
            for i in range(0, len(rows), batch_size):
                batch = rows[i : i + batch_size]
                session.execute_write(lambda tx, q=query, b=batch: tx.run(q, batch=b))
                total += len(batch)
            logger.info("Merged %d %s edges (%s)->(%s).", len(rows), rt, sl, tl)
    return total
