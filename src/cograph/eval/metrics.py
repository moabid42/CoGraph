"""Custom RAGAS metrics: CitationAccuracy and GraphCoverage."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CitationAccuracyResult:
    """Result of citation accuracy evaluation for a single answer."""

    total_citations: int = 0
    verified_citations: int = 0
    score: float = 0.0


def compute_citation_accuracy(
    answer: str,
    contexts: list[str],
    source_names: list[str] | None = None,
) -> CitationAccuracyResult:
    """Extract [source_name] citations from the answer and verify each
    cited fact appears in the context from that source.

    Score = verified_citations / total_citations (or 1.0 if no citations).
    """
    # Extract citations like [mitre-attack] or [atomic-red-team]
    citation_pattern = re.compile(r"\[([^\]]+)\]")
    citations = citation_pattern.findall(answer)

    if not citations:
        return CitationAccuracyResult(total_citations=0, verified_citations=0, score=1.0)

    # Simple verification: check if the cited source name appears in the contexts
    context_text = " ".join(contexts).lower()
    available_sources = {s.lower() for s in (source_names or [])}

    verified = 0
    for cite in citations:
        cite_lower = cite.lower()
        # A citation is verified if:
        # 1) The source name was in the retrieved contexts, OR
        # 2) The cited text appears in the context
        if cite_lower in context_text or cite_lower in available_sources:
            verified += 1

    score = verified / len(citations) if citations else 1.0
    return CitationAccuracyResult(
        total_citations=len(citations),
        verified_citations=verified,
        score=score,
    )


@dataclass
class GraphCoverageResult:
    """Result of graph coverage evaluation for a single query."""

    gold_entities: list[str] = field(default_factory=list)
    found_entities: list[str] = field(default_factory=list)
    score: float = 0.0


def compute_graph_coverage(
    retrieved_context: str,
    gold_entity_ids: list[str],
) -> GraphCoverageResult:
    """Check how many gold-standard entity IDs appear in the retrieved context.

    Score = found_gold_entities / total_gold_entities (or 1.0 if no gold entities).
    """
    if not gold_entity_ids:
        return GraphCoverageResult(score=1.0)

    context_upper = retrieved_context.upper()
    found = [eid for eid in gold_entity_ids if eid.upper() in context_upper]

    score = len(found) / len(gold_entity_ids)
    return GraphCoverageResult(
        gold_entities=gold_entity_ids,
        found_entities=found,
        score=score,
    )
