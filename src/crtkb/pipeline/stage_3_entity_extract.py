"""Stage 3: Entity Extraction — LLM pass 1 to extract ontology-conformant entities."""

from __future__ import annotations

import json
import logging

from crtkb.ontology.schema import NODE_TYPES
from crtkb.pipeline.stage_2_chunking import Chunk
from crtkb.utils.llm_client import get_llm

logger = logging.getLogger(__name__)

_ENTITY_PROMPT = """You are an expert in offensive security and the MITRE ATT&CK framework.
Given the following text chunk, extract all named entities that match the allowed entity types.

Allowed entity types:
{entity_types}

For each entity, output a JSON object with:
- "label": one of the allowed entity types
- "name": the entity name
- "attack_id": the ATT&CK ID if applicable (e.g. T1558.003), otherwise ""
- "description": a brief description from the text

Output a JSON array of entity objects. If no entities are found, output [].

TEXT:
{text}

ENTITIES (JSON array):"""


def _build_entity_types_desc() -> str:
    lines = []
    for label, info in NODE_TYPES.items():
        lines.append(f"- {label}: {info['description']}")
    return "\n".join(lines)


def extract_entities(chunks: list[Chunk]) -> list[dict]:
    """Run LLM entity extraction on each chunk. Returns raw entity dicts."""
    llm = get_llm()
    entity_types_desc = _build_entity_types_desc()
    all_entities: list[dict] = []

    for chunk in chunks:
        prompt = _ENTITY_PROMPT.format(
            entity_types=entity_types_desc,
            text=chunk.text[:3000],  # Truncate to fit context
        )

        try:
            response = llm.invoke(prompt)
            text = response.content.strip()
            # Extract JSON array from response
            start = text.find("[")
            end = text.rfind("]") + 1
            if start >= 0 and end > start:
                entities = json.loads(text[start:end])
                for ent in entities:
                    ent["chunk_id"] = chunk.chunk_id
                    ent["source_path"] = chunk.source_path
                all_entities.extend(entities)
        except Exception:
            logger.warning("Entity extraction failed for chunk %s", chunk.chunk_id, exc_info=True)

    logger.info("Extracted %d raw entities from %d chunks.", len(all_entities), len(chunks))
    return all_entities
