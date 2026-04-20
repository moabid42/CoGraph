"""Stage 7: Provenance Tagging — attach source metadata to every extracted entity and relationship."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from cograph.models.provenance import Provenance

logger = logging.getLogger(__name__)


def tag_entities(entities: list[dict], batch_id: str) -> list[dict]:
    """Add provenance fields to each entity dict."""
    now = datetime.now(timezone.utc).isoformat()
    for ent in entities:
        ent.setdefault("provenance", {})
        ent["provenance"].update({
            "source_name": "llm-extracted",
            "source_url": ent.get("source_path", ""),
            "confidence": ent.get("confidence", 0.7),
            "batch_id": batch_id,
            "extracted_at": now,
        })
    return entities


def tag_relations(relations: list[dict], batch_id: str) -> list[dict]:
    """Add provenance fields to each relation dict."""
    now = datetime.now(timezone.utc).isoformat()
    for rel in relations:
        rel.setdefault("provenance", {})
        rel["provenance"].update({
            "source_name": "llm-extracted",
            "source_url": rel.get("source_path", ""),
            "confidence": rel.get("confidence", 0.7),
            "batch_id": batch_id,
            "extracted_at": now,
        })
    return relations


def make_provenance(
    source_name: str = "llm-extracted",
    source_url: str = "",
    confidence: float = 0.7,
    batch_id: str = "",
) -> Provenance:
    """Create a Provenance instance for LLM-extracted data."""
    return Provenance(
        source_name=source_name,
        source_url=source_url,
        confidence=confidence,
        batch_id=batch_id,
    )
