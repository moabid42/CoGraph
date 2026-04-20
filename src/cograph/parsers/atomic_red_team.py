"""Deterministic parser for Atomic Red Team YAML test definitions.

Reads all ``T*/T*.yaml`` files under the atomics directory and produces
Procedure nodes linked to their parent Technique via IMPLEMENTS edges.
"""

from __future__ import annotations

import glob
import logging
from pathlib import Path

import yaml

from cograph.config import settings
from cograph.models.nodes import NodeRecord, Platform, Procedure
from cograph.models.provenance import Provenance
from cograph.models.relationships import RelRecord

logger = logging.getLogger(__name__)


def _make_prov(yaml_path: str) -> Provenance:
    return Provenance(
        source_name="atomic-red-team",
        source_url=yaml_path,
        confidence=1.0,
    )


class AtomicRedTeamParser:
    """Parse Atomic Red Team YAML test definitions."""

    source_name = "atomic-red-team"

    def __init__(self, glob_pattern: str | None = None):
        self.glob_pattern = glob_pattern or str(
            settings.data_dir / "atomic-red-team" / "atomics" / "T*" / "T*.yaml"
        )

    def parse(self) -> tuple[list[NodeRecord], list[RelRecord]]:
        yaml_files = sorted(glob.glob(self.glob_pattern))
        logger.info("Found %d Atomic Red Team YAML files.", len(yaml_files))

        nodes: list[NodeRecord] = []
        rels: list[RelRecord] = []
        platforms_seen: set[str] = set()

        for fpath in yaml_files:
            try:
                with open(fpath) as f:
                    data = yaml.safe_load(f)
            except Exception:
                logger.warning("Failed to parse %s, skipping.", fpath)
                continue

            if not data or "atomic_tests" not in data:
                continue

            technique_id: str = data.get("attack_technique", "")
            if not technique_id:
                continue

            prov = _make_prov(fpath)

            for test in data["atomic_tests"]:
                guid = test.get("auto_generated_guid", "")
                if not guid:
                    continue

                proc_id = f"{technique_id}:::{guid}"
                executor = test.get("executor", {})
                supported = test.get("supported_platforms", [])

                proc = Procedure(
                    proc_id=proc_id,
                    guid=guid,
                    name=test.get("name", ""),
                    description=test.get("description", ""),
                    executor_type=executor.get("name", ""),
                    command=executor.get("command", ""),
                    elevation_required=executor.get("elevation_required", False),
                    platforms=supported,
                )
                nodes.append(proc.to_record())

                # IMPLEMENTS → Technique
                rels.append(RelRecord(
                    source_label="Procedure",
                    source_key=proc_id,
                    rel_type="IMPLEMENTS",
                    target_label="Technique",
                    target_key=technique_id,
                    provenance=prov,
                ))

                # RUNS_ON → Platform
                for plat in supported:
                    if plat not in platforms_seen:
                        nodes.append(Platform(name=plat).to_record())
                        platforms_seen.add(plat)
                    rels.append(RelRecord(
                        source_label="Procedure",
                        source_key=proc_id,
                        rel_type="RUNS_ON",
                        target_label="Platform",
                        target_key=plat,
                        provenance=prov,
                    ))

        logger.info(
            "Atomic Red Team: parsed %d nodes, %d relationships.",
            len(nodes),
            len(rels),
        )
        return nodes, rels
