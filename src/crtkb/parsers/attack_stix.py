"""Deterministic parser for the MITRE ATT&CK STIX 2.1 bundle.

Reads ``enterprise-attack.json`` and produces NodeRecords for Technique,
Tactic, Malware, Tool, IntrusionSet, Campaign, Mitigation, DataComponent,
and DetectionStrategy — plus RelRecords for all STIX relationships.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from crtkb.config import settings
from crtkb.models.nodes import (
    Campaign,
    DataComponent,
    DetectionStrategy,
    IntrusionSet,
    Malware,
    Mitigation,
    NodeRecord,
    Platform,
    Tactic,
    Technique,
    Tool,
)
from crtkb.models.provenance import Provenance
from crtkb.models.relationships import RelRecord

logger = logging.getLogger(__name__)


# ── Helpers ──────────────────────────────────────────────────────────────

def _get_attack_id(obj: dict) -> str | None:
    """Extract the ATT&CK external_id (e.g. T1003.001) from external_references."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and "external_id" in ref:
            return ref["external_id"]
    return None


def _is_active(obj: dict) -> bool:
    """Return True if the object is neither revoked nor deprecated."""
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _make_prov(stix_desc: str = "") -> Provenance:
    return Provenance(
        source_name="mitre-attack",
        source_url="https://attack.mitre.org",
        confidence=1.0,
        stix_description=stix_desc,
    )


# ── STIX type → graph label mapping ─────────────────────────────────────

_STIX_TO_LABEL = {
    "attack-pattern": "Technique",
    "malware": "Malware",
    "tool": "Tool",
    "intrusion-set": "IntrusionSet",
    "campaign": "Campaign",
    "course-of-action": "Mitigation",
    "x-mitre-tactic": "Tactic",
    "x-mitre-data-component": "DataComponent",
    "x-mitre-detection-strategy": "DetectionStrategy",
}

# Dispatch table for STIX "uses" relationships:
# (source_stix_type, target_stix_type) → graph rel_type
_USES_DISPATCH: dict[tuple[str, str], str] = {
    ("malware", "attack-pattern"): "USES_TECHNIQUE",
    ("tool", "attack-pattern"): "USES_TECHNIQUE",
    ("intrusion-set", "attack-pattern"): "USES_TECHNIQUE",
    ("campaign", "attack-pattern"): "USES_TECHNIQUE",
    ("intrusion-set", "tool"): "USES_TOOL",
    ("intrusion-set", "malware"): "USES_MALWARE",
    ("campaign", "tool"): "USES_TOOL",
    ("campaign", "malware"): "USES_MALWARE",
}

_STIX_REL_MAP: dict[str, str] = {
    "subtechnique-of": "SUBTECHNIQUE_OF",
    "mitigates": "MITIGATES",
    "detects": "DETECTS",
    "attributed-to": "ATTRIBUTED_TO",
}


class AttackStixParser:
    """Parse the MITRE ATT&CK enterprise STIX bundle."""

    source_name = "mitre-attack"

    def __init__(self, path: Path | None = None):
        self.path = path or settings.attack_stix_path

    def parse(self) -> tuple[list[NodeRecord], list[RelRecord]]:
        logger.info("Loading STIX bundle from %s …", self.path)
        with open(self.path) as f:
            bundle = json.load(f)

        objects = bundle["objects"]
        logger.info("Bundle contains %d objects.", len(objects))

        # Build lookup: stix_id → object
        lookup: dict[str, dict] = {}
        for obj in objects:
            lookup[obj["id"]] = obj

        nodes: list[NodeRecord] = []
        rels: list[RelRecord] = []
        platforms_seen: set[str] = set()
        tactic_shortnames: dict[str, str] = {}  # shortname → attack_id

        # ── Pass 1: create nodes ────────────────────────────────────────
        for obj in objects:
            if not _is_active(obj):
                continue

            stix_type = obj["type"]
            attack_id = _get_attack_id(obj)

            if stix_type == "attack-pattern" and attack_id:
                tech = Technique(
                    attack_id=attack_id,
                    stix_id=obj["id"],
                    name=obj.get("name", ""),
                    description=obj.get("description", ""),
                    platforms=obj.get("x_mitre_platforms", []),
                    is_subtechnique=obj.get("x_mitre_is_subtechnique", False),
                    created=_parse_dt(obj.get("created")),
                    modified=_parse_dt(obj.get("modified")),
                )
                nodes.append(tech.to_record())

                # RUNS_ON edges
                for plat in obj.get("x_mitre_platforms", []):
                    if plat not in platforms_seen:
                        nodes.append(Platform(name=plat).to_record())
                        platforms_seen.add(plat)
                    rels.append(RelRecord(
                        source_label="Technique",
                        source_key=attack_id,
                        rel_type="RUNS_ON",
                        target_label="Platform",
                        target_key=plat,
                        provenance=_make_prov(),
                    ))

                # PART_OF_TACTIC edges (deferred until tactics are loaded)
                for phase in obj.get("kill_chain_phases", []):
                    if phase.get("kill_chain_name") == "mitre-attack":
                        # Store for second pass after tactics are created
                        rels.append(RelRecord(
                            source_label="Technique",
                            source_key=attack_id,
                            rel_type="PART_OF_TACTIC",
                            target_label="Tactic",
                            target_key=f"__shortname__{phase['phase_name']}",
                            provenance=_make_prov(),
                        ))

            elif stix_type == "x-mitre-tactic" and attack_id:
                shortname = obj.get("x_mitre_shortname", "")
                tac = Tactic(
                    attack_id=attack_id,
                    name=obj.get("name", ""),
                    shortname=shortname,
                    description=obj.get("description", ""),
                )
                nodes.append(tac.to_record())
                tactic_shortnames[shortname] = attack_id

            elif stix_type == "malware" and attack_id:
                nodes.append(Malware(
                    attack_id=attack_id,
                    stix_id=obj["id"],
                    name=obj.get("name", ""),
                    aliases=obj.get("x_mitre_aliases", []),
                    platforms=obj.get("x_mitre_platforms", []),
                    description=obj.get("description", ""),
                ).to_record())

            elif stix_type == "tool" and attack_id:
                nodes.append(Tool(
                    attack_id=attack_id,
                    stix_id=obj["id"],
                    name=obj.get("name", ""),
                    aliases=obj.get("x_mitre_aliases", []),
                    platforms=obj.get("x_mitre_platforms", []),
                    description=obj.get("description", ""),
                ).to_record())

            elif stix_type == "intrusion-set" and attack_id:
                nodes.append(IntrusionSet(
                    attack_id=attack_id,
                    stix_id=obj["id"],
                    name=obj.get("name", ""),
                    aliases=obj.get("aliases", []),
                    description=obj.get("description", ""),
                ).to_record())

            elif stix_type == "campaign" and attack_id:
                nodes.append(Campaign(
                    attack_id=attack_id,
                    stix_id=obj["id"],
                    name=obj.get("name", ""),
                    description=obj.get("description", ""),
                    first_seen=_parse_dt(obj.get("first_seen")),
                    last_seen=_parse_dt(obj.get("last_seen")),
                ).to_record())

            elif stix_type == "course-of-action" and attack_id:
                nodes.append(Mitigation(
                    attack_id=attack_id,
                    stix_id=obj["id"],
                    name=obj.get("name", ""),
                    description=obj.get("description", ""),
                ).to_record())

            elif stix_type == "x-mitre-data-component" and attack_id:
                nodes.append(DataComponent(
                    attack_id=attack_id,
                    stix_id=obj["id"],
                    name=obj.get("name", ""),
                    description=obj.get("description", ""),
                ).to_record())

            elif stix_type == "x-mitre-detection-strategy" and attack_id:
                nodes.append(DetectionStrategy(
                    attack_id=attack_id,
                    stix_id=obj["id"],
                    name=obj.get("name", ""),
                    description=obj.get("description", ""),
                    platforms=obj.get("x_mitre_platforms", []),
                ).to_record())

        # ── Resolve tactic shortname placeholders ───────────────────────
        resolved_rels: list[RelRecord] = []
        for r in rels:
            if r.target_key.startswith("__shortname__"):
                shortname = r.target_key.removeprefix("__shortname__")
                tactic_id = tactic_shortnames.get(shortname)
                if tactic_id:
                    r.target_key = tactic_id
                    resolved_rels.append(r)
                else:
                    logger.warning("Unknown tactic shortname: %s", shortname)
            else:
                resolved_rels.append(r)
        rels = resolved_rels

        # ── Pass 2: STIX relationship objects ───────────────────────────
        for obj in objects:
            if obj["type"] != "relationship" or not _is_active(obj):
                continue

            rel_type_stix = obj["relationship_type"]
            src_obj = lookup.get(obj["source_ref"])
            tgt_obj = lookup.get(obj["target_ref"])
            if not src_obj or not tgt_obj:
                continue
            if not _is_active(src_obj) or not _is_active(tgt_obj):
                continue

            src_id = _get_attack_id(src_obj)
            tgt_id = _get_attack_id(tgt_obj)
            if not src_id or not tgt_id:
                continue

            src_label = _STIX_TO_LABEL.get(src_obj["type"])
            tgt_label = _STIX_TO_LABEL.get(tgt_obj["type"])
            if not src_label or not tgt_label:
                continue

            stix_desc = obj.get("description", "")

            if rel_type_stix == "uses":
                key = (src_obj["type"], tgt_obj["type"])
                graph_rel = _USES_DISPATCH.get(key)
                if not graph_rel:
                    continue
            elif rel_type_stix in _STIX_REL_MAP:
                graph_rel = _STIX_REL_MAP[rel_type_stix]
            else:
                continue  # skip revoked-by and unknown types

            rels.append(RelRecord(
                source_label=src_label,
                source_key=src_id,
                rel_type=graph_rel,
                target_label=tgt_label,
                target_key=tgt_id,
                provenance=_make_prov(stix_desc),
            ))

        logger.info(
            "ATT&CK STIX: parsed %d nodes, %d relationships.",
            len(nodes),
            len(rels),
        )
        return nodes, rels
