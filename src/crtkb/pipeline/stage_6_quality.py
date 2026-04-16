"""Stage 6: Quality Filtering — drop low-confidence entities and invalid relationships."""

from __future__ import annotations

import logging

from crtkb.config import settings
from crtkb.ontology.schema import NODE_TYPES, PATTERNS

logger = logging.getLogger(__name__)

# Generic words that should not be standalone entity names
_GENERIC_NAMES = frozenset({
    "attack", "system", "network", "data", "file", "process", "user",
    "command", "server", "client", "service", "access", "target",
    "payload", "script", "code", "tool", "technique",
})


def filter_entities(entities: list[dict], threshold: float | None = None) -> list[dict]:
    """Drop entities below confidence threshold or with invalid labels."""
    threshold = threshold or settings.quality_confidence_threshold
    valid_labels = set(NODE_TYPES.keys())
    filtered = []

    for ent in entities:
        label = ent.get("label", "")
        name = ent.get("name", "").strip()
        confidence = ent.get("confidence", 0.7)

        if label not in valid_labels:
            logger.debug("Dropping entity with unknown label: %s", label)
            continue
        if confidence < threshold:
            logger.debug("Dropping low-confidence entity: %s (%.2f)", name, confidence)
            continue
        if not name or name.lower() in _GENERIC_NAMES:
            logger.debug("Dropping generic entity name: %s", name)
            continue

        filtered.append(ent)

    dropped = len(entities) - len(filtered)
    if dropped:
        logger.info("Quality filter: dropped %d / %d entities.", dropped, len(entities))
    return filtered


def filter_relations(relations: list[dict]) -> list[dict]:
    """Drop relations that violate the ontology pattern constraints."""
    valid_patterns = {(s, r, t) for s, r, t in PATTERNS}
    filtered = []

    for rel in relations:
        pattern = (rel.get("source_label", ""), rel.get("rel_type", ""), rel.get("target_label", ""))
        if pattern not in valid_patterns:
            logger.debug("Dropping invalid relation pattern: %s", pattern)
            continue
        # Self-loop check
        if (
            rel.get("source_name", "") == rel.get("target_name", "")
            and rel.get("source_label") == rel.get("target_label")
        ):
            logger.debug("Dropping self-loop: %s", rel.get("source_name"))
            continue
        filtered.append(rel)

    dropped = len(relations) - len(filtered)
    if dropped:
        logger.info("Quality filter: dropped %d / %d relations.", dropped, len(relations))
    return filtered
