"""Stub parser for D3FEND (RDF).

D3FEND data is not yet present in the data/ directory.  This stub follows
the SourceParser protocol so it can be wired into the load script.  When
the D3FEND RDF turtle file is obtained, implement the body using rdflib.
"""

from __future__ import annotations

import logging

from cograph.models.nodes import NodeRecord
from cograph.models.relationships import RelRecord

logger = logging.getLogger(__name__)


class D3fendParser:
    """Parse D3FEND RDF data (stub — not yet implemented)."""

    source_name = "d3fend"

    def parse(self) -> tuple[list[NodeRecord], list[RelRecord]]:
        logger.warning("D3FEND parser is a stub — no data available yet.")
        return [], []
