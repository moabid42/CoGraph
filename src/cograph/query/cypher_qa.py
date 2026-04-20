"""Text-to-Cypher retriever for structural / quantitative queries."""

from __future__ import annotations

import logging

from neo4j_graphrag.retrievers import Text2CypherRetriever

from cograph.config import settings
from cograph.query.prompts import CYPHER_SYSTEM_PROMPT
from cograph.utils.llm_client import get_llm
from cograph.utils.neo4j_client import get_driver

logger = logging.getLogger(__name__)

NEO4J_SCHEMA_DESCRIPTION = """
Node labels: Technique, Tactic, Malware, Tool, IntrusionSet, Campaign, Mitigation,
             DataComponent, DetectionStrategy, Procedure, LOLBin, Platform, Defense
Relationship types: SUBTECHNIQUE_OF, PART_OF_TACTIC, USES_TECHNIQUE, USES_TOOL,
                    USES_MALWARE, ATTRIBUTED_TO, MITIGATES, DETECTS, IMPLEMENTS,
                    EXECUTES_VIA, RUNS_ON, DEFENDS_AGAINST, REQUIRES, CONTRADICTS
Key properties: attack_id (unique per entity), name, description, aliases, proc_id
Provenance on relationships: source_name, confidence, batch_id, stix_description
"""


def get_cypher_retriever() -> Text2CypherRetriever:
    """Build a Text2CypherRetriever for structural queries."""
    return Text2CypherRetriever(
        driver=get_driver(),
        llm=get_llm(),
        neo4j_schema=NEO4J_SCHEMA_DESCRIPTION,
        neo4j_database=settings.neo4j_database,
    )
