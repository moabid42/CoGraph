"""Hybrid retriever: vector search top-K → 2-hop Cypher fan-out."""

from __future__ import annotations

import logging

from neo4j_graphrag.retrievers import VectorCypherRetriever

from crtkb.config import settings
from crtkb.utils.embedder import get_embedder
from crtkb.utils.neo4j_client import get_driver

logger = logging.getLogger(__name__)

# 2-hop fan-out query appended to vector search results
RETRIEVAL_QUERY_2HOP = """
WITH node, score

// 1-hop: direct relationships
OPTIONAL MATCH (node)-[r1]-(n1)
WHERE NOT n1:Source

// 2-hop: relationships of neighbours
OPTIONAL MATCH (n1)-[r2]-(n2)
WHERE NOT n2:Source
  AND id(n2) <> id(node)

WITH node, score,
     collect(DISTINCT {
       name: n1.name,
       label: labels(n1)[0],
       rel_type: type(r1),
       direction: CASE WHEN startNode(r1) = node THEN 'outgoing' ELSE 'incoming' END,
       source_name: r1.source_name,
       description: coalesce(n1.description, '')[..200]
     })[..30] AS hop1,
     collect(DISTINCT {
       name: n2.name,
       label: labels(n2)[0],
       via: n1.name,
       rel_type: type(r2),
       source_name: r2.source_name
     })[..20] AS hop2

RETURN
  node {
    .name,
    .attack_id,
    .description,
    labels: labels(node)
  } AS matched_entity,
  score,
  hop1,
  hop2
"""


def get_vector_cypher_retriever(
    index_name: str = "technique_embedding_idx",
    top_k: int = 5,
) -> VectorCypherRetriever:
    """Build a VectorCypherRetriever with 2-hop fan-out."""
    return VectorCypherRetriever(
        driver=get_driver(),
        index_name=index_name,
        retrieval_query=RETRIEVAL_QUERY_2HOP,
        embedder=get_embedder(),
        neo4j_database=settings.neo4j_database,
    )
