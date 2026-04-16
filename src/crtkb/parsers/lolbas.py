"""Deterministic parser for the LOLBAS (Living off the Land Binaries) JSON catalogue.

Reads ``lolbas.json`` and produces LOLBin nodes linked to Techniques via
EXECUTES_VIA edges (one per MitreID in each command entry).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from crtkb.config import settings
from crtkb.models.nodes import LOLBin, NodeRecord
from crtkb.models.provenance import Provenance
from crtkb.models.relationships import RelRecord

logger = logging.getLogger(__name__)


def _make_prov(url: str) -> Provenance:
    return Provenance(
        source_name="lolbas",
        source_url=url,
        confidence=1.0,
    )


class LolbasParser:
    """Parse the LOLBAS JSON catalogue."""

    source_name = "lolbas"

    def __init__(self, path: Path | None = None):
        self.path = path or settings.lolbas_path

    def parse(self) -> tuple[list[NodeRecord], list[RelRecord]]:
        logger.info("Loading LOLBAS catalogue from %s …", self.path)
        with open(self.path) as f:
            entries = json.load(f)

        logger.info("LOLBAS: %d entries.", len(entries))

        nodes: list[NodeRecord] = []
        rels: list[RelRecord] = []

        for entry in entries:
            name = entry.get("Name", "")
            if not name:
                continue

            # Collect categories, sigma rules, full paths
            commands = entry.get("Commands", [])
            categories = sorted({c.get("Category", "") for c in commands if c.get("Category")})
            sigma_rules = [
                d.get("Sigma", "")
                for d in (entry.get("Detection") or [])
                if d and d.get("Sigma")
            ]
            full_paths = [
                p.get("Path", "")
                for p in (entry.get("Full_Path") or [])
                if p and p.get("Path")
            ]
            lolbas_url = entry.get("url", "")

            lolbin = LOLBin(
                name=name,
                description=entry.get("Description", ""),
                full_paths=full_paths,
                categories=categories,
                sigma_rules=sigma_rules,
            )
            nodes.append(lolbin.to_record())

            prov = _make_prov(lolbas_url)

            # One EXECUTES_VIA edge per unique (binary, MitreID) pair
            seen_mitre_ids: set[str] = set()
            for cmd in commands:
                mitre_id = cmd.get("MitreID", "")
                if not mitre_id or mitre_id in seen_mitre_ids:
                    continue
                seen_mitre_ids.add(mitre_id)

                rels.append(RelRecord(
                    source_label="LOLBin",
                    source_key=name,
                    rel_type="EXECUTES_VIA",
                    target_label="Technique",
                    target_key=mitre_id,
                    provenance=prov,
                    extra_props={
                        "command": cmd.get("Command", ""),
                        "category": cmd.get("Category", ""),
                        "privileges": cmd.get("Privileges", ""),
                        "usecase": cmd.get("Usecase", ""),
                        "operating_system": cmd.get("OperatingSystem", ""),
                    },
                ))

        logger.info(
            "LOLBAS: parsed %d nodes, %d relationships.",
            len(nodes),
            len(rels),
        )
        return nodes, rels
