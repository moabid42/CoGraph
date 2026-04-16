"""Pydantic model for relationship records ready for Neo4j MERGE."""

from __future__ import annotations

from pydantic import BaseModel

from crtkb.models.provenance import Provenance


class RelRecord(BaseModel):
    """A typed, directed edge between two nodes, with provenance."""

    source_label: str
    source_key: str          # value of the unique-key property on the source node
    rel_type: str            # e.g. "USES_TECHNIQUE"
    target_label: str
    target_key: str          # value of the unique-key property on the target node
    provenance: Provenance
    extra_props: dict = {}   # additional edge properties (e.g. LOLBAS command details)
