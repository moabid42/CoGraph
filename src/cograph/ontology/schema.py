"""Ontology constants: entity types, relationship types, and valid patterns.

These drive both the Cypher schema constraints and the LLM extraction schema
so the ontology is defined in exactly one place.
"""

from __future__ import annotations

# ── Entity (node) types ──────────────────────────────────────────────────

NODE_TYPES: dict[str, dict] = {
    "Technique": {
        "description": "An ATT&CK attack technique or sub-technique",
        "unique_key": "attack_id",
        "properties": {
            "attack_id": "STRING",
            "stix_id": "STRING",
            "name": "STRING",
            "description": "STRING",
            "platforms": "LIST<STRING>",
            "is_subtechnique": "BOOLEAN",
            "created": "DATETIME",
            "modified": "DATETIME",
            "embedding": "LIST<FLOAT>",
        },
    },
    "Tactic": {
        "description": "An ATT&CK tactic (kill-chain phase)",
        "unique_key": "attack_id",
        "properties": {
            "attack_id": "STRING",
            "name": "STRING",
            "shortname": "STRING",
            "description": "STRING",
            "embedding": "LIST<FLOAT>",
        },
    },
    "Malware": {
        "description": "Adversary-authored malicious software",
        "unique_key": "attack_id",
        "properties": {
            "attack_id": "STRING",
            "stix_id": "STRING",
            "name": "STRING",
            "aliases": "LIST<STRING>",
            "platforms": "LIST<STRING>",
            "description": "STRING",
            "embedding": "LIST<FLOAT>",
        },
    },
    "Tool": {
        "description": "A legitimate dual-use software tool used in attacks",
        "unique_key": "attack_id",
        "properties": {
            "attack_id": "STRING",
            "stix_id": "STRING",
            "name": "STRING",
            "aliases": "LIST<STRING>",
            "platforms": "LIST<STRING>",
            "description": "STRING",
            "embedding": "LIST<FLOAT>",
        },
    },
    "IntrusionSet": {
        "description": "A threat actor group / intrusion set",
        "unique_key": "attack_id",
        "properties": {
            "attack_id": "STRING",
            "stix_id": "STRING",
            "name": "STRING",
            "aliases": "LIST<STRING>",
            "description": "STRING",
            "embedding": "LIST<FLOAT>",
        },
    },
    "Campaign": {
        "description": "A named campaign attributed to a threat actor",
        "unique_key": "attack_id",
        "properties": {
            "attack_id": "STRING",
            "stix_id": "STRING",
            "name": "STRING",
            "description": "STRING",
            "first_seen": "DATETIME",
            "last_seen": "DATETIME",
            "embedding": "LIST<FLOAT>",
        },
    },
    "Mitigation": {
        "description": "A defensive mitigation / course of action",
        "unique_key": "attack_id",
        "properties": {
            "attack_id": "STRING",
            "stix_id": "STRING",
            "name": "STRING",
            "description": "STRING",
            "embedding": "LIST<FLOAT>",
        },
    },
    "DataComponent": {
        "description": "A data component used for detection",
        "unique_key": "attack_id",
        "properties": {
            "attack_id": "STRING",
            "stix_id": "STRING",
            "name": "STRING",
            "description": "STRING",
        },
    },
    "DetectionStrategy": {
        "description": "A detection strategy (ATT&CK v18+)",
        "unique_key": "attack_id",
        "properties": {
            "attack_id": "STRING",
            "stix_id": "STRING",
            "name": "STRING",
            "description": "STRING",
            "platforms": "LIST<STRING>",
        },
    },
    "Procedure": {
        "description": "A concrete, executable test of a technique (Atomic Red Team)",
        "unique_key": "proc_id",
        "properties": {
            "proc_id": "STRING",
            "guid": "STRING",
            "name": "STRING",
            "description": "STRING",
            "executor_type": "STRING",
            "command": "STRING",
            "elevation_required": "BOOLEAN",
            "platforms": "LIST<STRING>",
            "embedding": "LIST<FLOAT>",
        },
    },
    "LOLBin": {
        "description": "A living-off-the-land binary that can be abused",
        "unique_key": "name",
        "properties": {
            "name": "STRING",
            "description": "STRING",
            "full_paths": "LIST<STRING>",
            "categories": "LIST<STRING>",
            "sigma_rules": "LIST<STRING>",
            "embedding": "LIST<FLOAT>",
        },
    },
    "Platform": {
        "description": "An operating system or environment (Windows, Linux, macOS, …)",
        "unique_key": "name",
        "properties": {
            "name": "STRING",
        },
    },
    "Defense": {
        "description": "A defensive countermeasure (D3FEND or LLM-extracted)",
        "unique_key": "defense_id",
        "properties": {
            "defense_id": "STRING",
            "name": "STRING",
            "description": "STRING",
            "embedding": "LIST<FLOAT>",
        },
    },
}

# ── Relationship types ───────────────────────────────────────────────────

REL_TYPES: dict[str, str] = {
    "SUBTECHNIQUE_OF": "A sub-technique of a parent technique",
    "PART_OF_TACTIC": "Technique belongs to a tactic (kill-chain phase)",
    "USES_TECHNIQUE": "Entity uses/employs an attack technique",
    "USES_TOOL": "Entity uses a dual-use tool",
    "USES_MALWARE": "Entity uses malware",
    "ATTRIBUTED_TO": "Campaign is attributed to an intrusion set",
    "MITIGATES": "Mitigation addresses a technique",
    "DETECTS": "Detection strategy detects a technique",
    "IMPLEMENTS": "Procedure implements / tests a technique",
    "EXECUTES_VIA": "LOLBin can execute via a technique",
    "RUNS_ON": "Technique or procedure runs on a platform",
    "DEFENDS_AGAINST": "Defense counters a technique",
    "REQUIRES": "Procedure requires another as prerequisite",
    "CONTRADICTS": "Two assertions contradict each other",
}

# ── Valid (source_label, rel_type, target_label) patterns ────────────────

PATTERNS: list[tuple[str, str, str]] = [
    # ATT&CK structure
    ("Technique", "SUBTECHNIQUE_OF", "Technique"),
    ("Technique", "PART_OF_TACTIC", "Tactic"),
    # Uses — technique
    ("Malware", "USES_TECHNIQUE", "Technique"),
    ("Tool", "USES_TECHNIQUE", "Technique"),
    ("IntrusionSet", "USES_TECHNIQUE", "Technique"),
    ("Campaign", "USES_TECHNIQUE", "Technique"),
    # Uses — tool / malware
    ("IntrusionSet", "USES_TOOL", "Tool"),
    ("IntrusionSet", "USES_MALWARE", "Malware"),
    ("Campaign", "USES_TOOL", "Tool"),
    ("Campaign", "USES_MALWARE", "Malware"),
    # Attribution
    ("Campaign", "ATTRIBUTED_TO", "IntrusionSet"),
    # Defensive
    ("Mitigation", "MITIGATES", "Technique"),
    ("DetectionStrategy", "DETECTS", "Technique"),
    ("Defense", "DEFENDS_AGAINST", "Technique"),
    # Procedures / LOLBins
    ("Procedure", "IMPLEMENTS", "Technique"),
    ("LOLBin", "EXECUTES_VIA", "Technique"),
    # Platform
    ("Technique", "RUNS_ON", "Platform"),
    ("Procedure", "RUNS_ON", "Platform"),
    # LLM-extracted
    ("Procedure", "REQUIRES", "Procedure"),
]

# ── Provenance properties attached to every relationship ─────────────────

PROVENANCE_PROPS: list[str] = [
    "source_name",
    "source_url",
    "confidence",
    "batch_id",
    "extracted_at",
    "stix_description",
]
