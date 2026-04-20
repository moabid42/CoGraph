"""Stage 5: Three-Tier Entity Resolution.

Tier 1 — Canonical ID lookup (deterministic, zero cost)
Tier 2 — Embedding similarity (BGE-large-en-v1.5, threshold 0.88)
Tier 3 — LLM verdict (borderline cases between 0.80 and 0.88)
"""

from __future__ import annotations

import logging
import re

from cograph.config import settings
from cograph.utils.embedder import embed_text
from cograph.utils.neo4j_client import get_driver

logger = logging.getLogger(__name__)

ATTACK_ID_PATTERN = re.compile(r"[TSGCM]\d{4}(?:\.\d{3})?")


def tier1_canonical_lookup(entity_name: str, entity_label: str) -> str | None:
    """Extract a canonical ATT&CK ID from the entity text and look it up in the graph."""
    match = ATTACK_ID_PATTERN.search(entity_name)
    if not match:
        return None

    candidate_id = match.group(0)
    driver = get_driver()
    with driver.session(database=settings.neo4j_database) as session:
        result = session.run(
            f"MATCH (n:{entity_label}) WHERE n.attack_id = $aid RETURN n.attack_id AS aid",
            aid=candidate_id,
        )
        record = result.single()
        if record:
            logger.debug("Tier 1 match: %s → %s", entity_name, candidate_id)
            return record["aid"]

    # Also try exact name match
    from cograph.ontology.schema import NODE_TYPES

    ukey = NODE_TYPES[entity_label]["unique_key"]
    with driver.session(database=settings.neo4j_database) as session:
        result = session.run(
            f"MATCH (n:{entity_label}) WHERE n.name = $name RETURN n.{ukey} AS uid",
            name=entity_name,
        )
        record = result.single()
        if record:
            logger.debug("Tier 1 name match: %s → %s", entity_name, record["uid"])
            return record["uid"]

    return None


def tier2_embedding_match(
    entity_name: str,
    entity_description: str,
    entity_label: str,
    threshold: float | None = None,
) -> tuple[str | None, float]:
    """Find the closest existing node by embedding similarity.

    Returns (unique_key_value, score) or (None, 0.0).
    """
    threshold = threshold or settings.er_embedding_threshold
    embedding = embed_text(entity_name, entity_description)

    from cograph.ontology.schema import NODE_TYPES

    ukey = NODE_TYPES[entity_label]["unique_key"]
    index_name = f"{entity_label.lower()}_embedding_idx"

    driver = get_driver()
    with driver.session(database=settings.neo4j_database) as session:
        try:
            result = session.run(
                "CALL db.index.vector.queryNodes($index, 5, $embedding) "
                "YIELD node, score "
                f"WHERE score >= $threshold AND $label IN labels(node) "
                f"RETURN node.{ukey} AS uid, score "
                "ORDER BY score DESC LIMIT 1",
                index=index_name,
                embedding=embedding,
                threshold=settings.er_borderline_low,  # Use lower bound first
                label=entity_label,
            )
            record = result.single()
            if record:
                score = record["score"]
                uid = record["uid"]
                if score >= threshold:
                    logger.debug("Tier 2 match: %s → %s (score=%.3f)", entity_name, uid, score)
                    return uid, score
                else:
                    # Borderline — return for Tier 3
                    return uid, score
        except Exception:
            logger.debug("Vector index %s not found, skipping Tier 2.", index_name)

    return None, 0.0


def tier3_llm_verdict(entity_a: dict, entity_b: dict) -> bool:
    """Ask the LLM whether two entities should be merged."""
    from cograph.utils.llm_client import get_llm

    llm = get_llm()
    prompt = (
        "Are these two entities the same concept in offensive security?\n"
        f"Entity A: {entity_a.get('name', '')} — {entity_a.get('description', '')[:200]}\n"
        f"Entity B: {entity_b.get('name', '')} — {entity_b.get('description', '')[:200]}\n"
        "Answer YES or NO with a one-sentence reason."
    )
    try:
        response = llm.invoke(prompt)
        answer = response.content.strip().upper()
        is_match = answer.startswith("YES")
        logger.debug("Tier 3 verdict: %s vs %s → %s", entity_a["name"], entity_b["name"], is_match)
        return is_match
    except Exception:
        logger.warning("Tier 3 LLM call failed.", exc_info=True)
        return False


def resolve_entity(
    entity_name: str,
    entity_description: str,
    entity_label: str,
) -> str | None:
    """Run the three-tier resolution cascade. Returns the existing node's
    unique key if a match is found, or None if the entity is new."""

    # Tier 1: canonical ID
    uid = tier1_canonical_lookup(entity_name, entity_label)
    if uid:
        return uid

    # Tier 2: embedding similarity
    uid, score = tier2_embedding_match(entity_name, entity_description, entity_label)
    if uid and score >= settings.er_embedding_threshold:
        return uid

    # Tier 3: LLM verdict for borderline cases
    if uid and score >= settings.er_borderline_low:
        from cograph.ontology.schema import NODE_TYPES

        ukey = NODE_TYPES[entity_label]["unique_key"]
        driver = get_driver()
        with driver.session(database=settings.neo4j_database) as session:
            result = session.run(
                f"MATCH (n:{entity_label} {{{ukey}: $uid}}) "
                "RETURN n.name AS name, n.description AS description",
                uid=uid,
            )
            record = result.single()
            if record:
                existing = {"name": record["name"], "description": record["description"] or ""}
                candidate = {"name": entity_name, "description": entity_description}
                if tier3_llm_verdict(existing, candidate):
                    return uid

    return None
