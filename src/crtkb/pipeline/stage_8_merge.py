"""Stage 8: Graph Merge — MERGE LLM-extracted entities and relations into Neo4j."""

from __future__ import annotations

import logging

from crtkb.config import settings
from crtkb.models.nodes import NodeRecord
from crtkb.models.provenance import Provenance
from crtkb.models.relationships import RelRecord
from crtkb.ontology.schema import NODE_TYPES
from crtkb.pipeline.stage_5_entity_res import resolve_entity
from crtkb.utils.neo4j_client import merge_nodes, merge_relationships

logger = logging.getLogger(__name__)

# Source reliability tiers (higher = more authoritative)
_RELIABILITY = {
    "mitre-attack": 3,
    "atomic-red-team": 3,
    "lolbas": 3,
    "d3fend": 3,
    "llm-extracted": 1,
}


def merge_extracted_entities(
    entities: list[dict],
    batch_id: str,
) -> dict[str, str]:
    """Merge LLM-extracted entities into Neo4j after entity resolution.

    Returns a mapping of ``entity_name → resolved_unique_key`` so that
    relationships can reference the correct node.
    """
    name_to_key: dict[str, str] = {}
    new_nodes: list[NodeRecord] = []

    for ent in entities:
        label = ent["label"]
        name = ent["name"]
        description = ent.get("description", "")

        # Try to resolve to an existing node
        existing_key = resolve_entity(name, description, label)

        if existing_key:
            name_to_key[name] = existing_key
            logger.debug("Resolved '%s' → existing %s:%s", name, label, existing_key)
        else:
            # Create a new node
            ukey = NODE_TYPES[label]["unique_key"]
            # Generate an ID for new entities
            attack_id = ent.get("attack_id", "")
            if ukey == "attack_id" and attack_id:
                key_value = attack_id
            elif ukey == "name":
                key_value = name
            elif ukey == "proc_id":
                key_value = f"llm:::{name}"
            elif ukey == "defense_id":
                key_value = f"llm:::{name}"
            else:
                key_value = f"llm:::{name}"

            props = {ukey: key_value, "name": name, "description": description}
            new_nodes.append(NodeRecord(label=label, properties=props))
            name_to_key[name] = key_value
            logger.debug("New entity: %s:%s = %s", label, ukey, key_value)

    if new_nodes:
        merge_nodes(new_nodes, batch_size=settings.merge_batch_size)
        logger.info("Merged %d new LLM-extracted nodes.", len(new_nodes))

    return name_to_key


def merge_extracted_relations(
    relations: list[dict],
    name_to_key: dict[str, str],
    batch_id: str,
) -> int:
    """Merge LLM-extracted relationships into Neo4j."""
    rel_records: list[RelRecord] = []

    for rel in relations:
        src_name = rel.get("source_name", "")
        tgt_name = rel.get("target_name", "")
        src_key = name_to_key.get(src_name)
        tgt_key = name_to_key.get(tgt_name)

        if not src_key or not tgt_key:
            logger.debug(
                "Skipping relation: unresolved entities (%s → %s)", src_name, tgt_name
            )
            continue

        prov_data = rel.get("provenance", {})
        prov = Provenance(
            source_name=prov_data.get("source_name", "llm-extracted"),
            source_url=prov_data.get("source_url", ""),
            confidence=prov_data.get("confidence", 0.7),
            batch_id=batch_id,
        )

        rel_records.append(RelRecord(
            source_label=rel["source_label"],
            source_key=src_key,
            rel_type=rel["rel_type"],
            target_label=rel["target_label"],
            target_key=tgt_key,
            provenance=prov,
        ))

    count = merge_relationships(rel_records, batch_size=settings.merge_batch_size)
    logger.info("Merged %d LLM-extracted relationships.", count)
    return count
