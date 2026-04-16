"""Stage 4: Relation Extraction — LLM pass 2 to find relationships between extracted entities."""

from __future__ import annotations

import json
import logging

from crtkb.ontology.schema import PATTERNS, REL_TYPES
from crtkb.pipeline.stage_2_chunking import Chunk
from crtkb.utils.llm_client import get_llm

logger = logging.getLogger(__name__)

_REL_PROMPT = """You are an expert in offensive security and the MITRE ATT&CK framework.
Given the following text chunk and a list of entities already extracted from it,
identify relationships between these entities.

Allowed relationship types:
{rel_types}

Allowed patterns (source_label, rel_type, target_label):
{patterns}

Entities found in this chunk:
{entities}

TEXT:
{text}

For each relationship, output a JSON object with:
- "source_name": name of the source entity
- "source_label": label of the source entity
- "rel_type": one of the allowed relationship types
- "target_name": name of the target entity
- "target_label": label of the target entity
- "description": brief justification from the text

Output a JSON array. If no relationships found, output [].

RELATIONSHIPS (JSON array):"""


def _build_rel_types_desc() -> str:
    lines = []
    for rt, desc in REL_TYPES.items():
        lines.append(f"- {rt}: {desc}")
    return "\n".join(lines)


def _build_patterns_desc() -> str:
    lines = []
    for src, rel, tgt in PATTERNS:
        lines.append(f"  ({src})-[{rel}]->({tgt})")
    return "\n".join(lines)


def extract_relations(
    chunks: list[Chunk],
    entities_by_chunk: dict[str, list[dict]],
) -> list[dict]:
    """Run LLM relation extraction on each chunk with its entities as context."""
    llm = get_llm()
    rel_types_desc = _build_rel_types_desc()
    patterns_desc = _build_patterns_desc()
    all_relations: list[dict] = []

    for chunk in chunks:
        chunk_entities = entities_by_chunk.get(chunk.chunk_id, [])
        if len(chunk_entities) < 2:
            continue  # Need at least 2 entities for a relationship

        entities_str = json.dumps(
            [{"label": e["label"], "name": e["name"]} for e in chunk_entities],
            indent=2,
        )

        prompt = _REL_PROMPT.format(
            rel_types=rel_types_desc,
            patterns=patterns_desc,
            entities=entities_str,
            text=chunk.text[:3000],
        )

        try:
            response = llm.invoke(prompt)
            text = response.content.strip()
            start = text.find("[")
            end = text.rfind("]") + 1
            if start >= 0 and end > start:
                relations = json.loads(text[start:end])
                for rel in relations:
                    rel["chunk_id"] = chunk.chunk_id
                    rel["source_path"] = chunk.source_path
                all_relations.extend(relations)
        except Exception:
            logger.warning(
                "Relation extraction failed for chunk %s", chunk.chunk_id, exc_info=True
            )

    logger.info("Extracted %d raw relations from %d chunks.", len(all_relations), len(chunks))
    return all_relations
