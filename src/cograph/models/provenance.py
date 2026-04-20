"""Provenance metadata attached to every relationship in the graph."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class Provenance(BaseModel):
    """Tracks *where* a piece of graph data came from."""

    source_name: str = Field(
        ...,
        description="Origin dataset, e.g. 'mitre-attack', 'atomic-red-team', 'lolbas', 'llm-extracted'",
    )
    source_url: str = Field(default="", description="URL or file path of the source document")
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="1.0 for deterministic parsers, 0–1 for LLM-extracted",
    )
    batch_id: str = Field(default="", description="Langfuse batch ID for traceability")
    extracted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    stix_description: str = Field(
        default="",
        description="STIX relationship description field (CTI context)",
    )

    def to_props(self) -> dict:
        """Flatten to a dict suitable for Cypher SET clauses."""
        return {
            "source_name": self.source_name,
            "source_url": self.source_url,
            "confidence": self.confidence,
            "batch_id": self.batch_id,
            "extracted_at": self.extracted_at.isoformat(),
            "stix_description": self.stix_description,
        }
