"""Pipeline Runner — orchestrates the 8-stage LLM extraction pipeline end-to-end."""

from __future__ import annotations

import logging
from pathlib import Path

from crtkb.pipeline.stage_1_source_reg import mark_source_done, register_source
from crtkb.pipeline.stage_2_chunking import Chunk, chunk_markdown, chunk_text
from crtkb.pipeline.stage_3_entity_extract import extract_entities
from crtkb.pipeline.stage_4_rel_extract import extract_relations
from crtkb.pipeline.stage_5_entity_res import resolve_entity
from crtkb.pipeline.stage_6_quality import filter_entities, filter_relations
from crtkb.pipeline.stage_7_provenance import tag_entities, tag_relations
from crtkb.pipeline.stage_8_merge import merge_extracted_entities, merge_extracted_relations

logger = logging.getLogger(__name__)


def run_pipeline(
    source_path: str,
    source_type: str = "markdown",
    text: str | None = None,
) -> dict:
    """Run the full 8-stage pipeline on a single source document.

    Args:
        source_path: Path or URL of the source document.
        source_type: One of "markdown", "text".
        text: The raw text content.  If None, reads from source_path.

    Returns:
        A summary dict with counts and the batch_id.
    """
    # Stage 1: Source Registration
    batch_id = register_source(source_path, source_type)
    logger.info("[1/8] Source registered: batch_id=%s", batch_id)

    # Read text if not provided
    if text is None:
        text = Path(source_path).read_text(encoding="utf-8")

    # Stage 2: Chunking
    if source_type == "markdown":
        chunks = chunk_markdown(text, source_path)
    else:
        chunks = chunk_text(text, source_path)
    logger.info("[2/8] Chunked into %d chunks.", len(chunks))

    # Stage 3: Entity Extraction
    raw_entities = extract_entities(chunks)
    logger.info("[3/8] Extracted %d raw entities.", len(raw_entities))

    # Stage 4: Relation Extraction
    entities_by_chunk: dict[str, list[dict]] = {}
    for ent in raw_entities:
        cid = ent.get("chunk_id", "")
        entities_by_chunk.setdefault(cid, []).append(ent)
    raw_relations = extract_relations(chunks, entities_by_chunk)
    logger.info("[4/8] Extracted %d raw relations.", len(raw_relations))

    # Stage 5 is invoked during Stage 8 (merge)

    # Stage 6: Quality Filtering
    filtered_entities = filter_entities(raw_entities)
    filtered_relations = filter_relations(raw_relations)
    logger.info("[6/8] After filtering: %d entities, %d relations.",
                len(filtered_entities), len(filtered_relations))

    # Stage 7: Provenance Tagging
    tagged_entities = tag_entities(filtered_entities, batch_id)
    tagged_relations = tag_relations(filtered_relations, batch_id)
    logger.info("[7/8] Provenance tagged.")

    # Stage 8: Graph Merge (includes Stage 5 entity resolution)
    name_to_key = merge_extracted_entities(tagged_entities, batch_id)
    rel_count = merge_extracted_relations(tagged_relations, name_to_key, batch_id)
    logger.info("[8/8] Merged: %d entity mappings, %d relationships.", len(name_to_key), rel_count)

    mark_source_done(batch_id)

    summary = {
        "batch_id": batch_id,
        "chunks": len(chunks),
        "raw_entities": len(raw_entities),
        "raw_relations": len(raw_relations),
        "filtered_entities": len(filtered_entities),
        "filtered_relations": len(filtered_relations),
        "merged_entities": len(name_to_key),
        "merged_relations": rel_count,
    }
    logger.info("Pipeline complete: %s", summary)
    return summary
