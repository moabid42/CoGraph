"""Stage 1: Source Registration — create a Source node in Neo4j for traceability."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from cograph.config import settings
from cograph.utils.neo4j_client import get_driver

logger = logging.getLogger(__name__)


def register_source(
    source_path: str,
    source_type: str,
    metadata: dict | None = None,
) -> str:
    """Create a ``(:Source)`` node and return a unique ``batch_id``."""
    batch_id = str(uuid.uuid4())
    driver = get_driver()
    props = {
        "batch_id": batch_id,
        "path": source_path,
        "type": source_type,
        "ingested_at": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        **(metadata or {}),
    }
    with driver.session(database=settings.neo4j_database) as session:
        session.run(
            "MERGE (s:Source {batch_id: $batch_id}) SET s += $props",
            batch_id=batch_id,
            props=props,
        )
    logger.info("Registered source %s (batch %s).", source_path, batch_id)
    return batch_id


def mark_source_done(batch_id: str, status: str = "completed") -> None:
    """Update the Source node status after ingestion."""
    driver = get_driver()
    with driver.session(database=settings.neo4j_database) as session:
        session.run(
            "MATCH (s:Source {batch_id: $batch_id}) SET s.status = $status",
            batch_id=batch_id,
            status=status,
        )
