"""Base protocol for all deterministic source parsers."""

from __future__ import annotations

from typing import Protocol

from crtkb.models.nodes import NodeRecord
from crtkb.models.relationships import RelRecord


class SourceParser(Protocol):
    """Every parser implements this interface."""

    source_name: str

    def parse(self) -> tuple[list[NodeRecord], list[RelRecord]]:
        """Return all nodes and relationships extracted from this source."""
        ...
