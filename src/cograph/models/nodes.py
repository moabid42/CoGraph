"""Pydantic models for every node (entity) type in the CoGraph ontology."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


# ── Generic record used by parsers to feed the load script ───────────────

class NodeRecord(BaseModel):
    """A label + property dict ready for ``MERGE`` into Neo4j."""

    label: str
    properties: dict

    @property
    def unique_key(self) -> str:
        """Return the canonical unique-key field name for this label."""
        from cograph.ontology.schema import NODE_TYPES  # noqa: avoid circular

        return NODE_TYPES[self.label]["unique_key"]

    @property
    def unique_value(self):
        return self.properties[self.unique_key]


# ── Typed models for each entity (used for validation / IDE support) ─────

class Technique(BaseModel):
    attack_id: str
    stix_id: str = ""
    name: str = ""
    description: str = ""
    platforms: list[str] = Field(default_factory=list)
    is_subtechnique: bool = False
    created: datetime | None = None
    modified: datetime | None = None

    def to_record(self) -> NodeRecord:
        props = self.model_dump(exclude_none=True)
        if self.created:
            props["created"] = self.created.isoformat()
        if self.modified:
            props["modified"] = self.modified.isoformat()
        return NodeRecord(label="Technique", properties=props)


class Tactic(BaseModel):
    attack_id: str
    name: str = ""
    shortname: str = ""
    description: str = ""

    def to_record(self) -> NodeRecord:
        return NodeRecord(label="Tactic", properties=self.model_dump(exclude_none=True))


class Malware(BaseModel):
    attack_id: str
    stix_id: str = ""
    name: str = ""
    aliases: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    description: str = ""

    def to_record(self) -> NodeRecord:
        return NodeRecord(label="Malware", properties=self.model_dump(exclude_none=True))


class Tool(BaseModel):
    attack_id: str
    stix_id: str = ""
    name: str = ""
    aliases: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    description: str = ""

    def to_record(self) -> NodeRecord:
        return NodeRecord(label="Tool", properties=self.model_dump(exclude_none=True))


class IntrusionSet(BaseModel):
    attack_id: str
    stix_id: str = ""
    name: str = ""
    aliases: list[str] = Field(default_factory=list)
    description: str = ""

    def to_record(self) -> NodeRecord:
        return NodeRecord(label="IntrusionSet", properties=self.model_dump(exclude_none=True))


class Campaign(BaseModel):
    attack_id: str
    stix_id: str = ""
    name: str = ""
    description: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def to_record(self) -> NodeRecord:
        props = self.model_dump(exclude_none=True)
        if self.first_seen:
            props["first_seen"] = self.first_seen.isoformat()
        if self.last_seen:
            props["last_seen"] = self.last_seen.isoformat()
        return NodeRecord(label="Campaign", properties=props)


class Mitigation(BaseModel):
    attack_id: str
    stix_id: str = ""
    name: str = ""
    description: str = ""

    def to_record(self) -> NodeRecord:
        return NodeRecord(label="Mitigation", properties=self.model_dump(exclude_none=True))


class DataComponent(BaseModel):
    attack_id: str
    stix_id: str = ""
    name: str = ""
    description: str = ""

    def to_record(self) -> NodeRecord:
        return NodeRecord(label="DataComponent", properties=self.model_dump(exclude_none=True))


class DetectionStrategy(BaseModel):
    attack_id: str
    stix_id: str = ""
    name: str = ""
    description: str = ""
    platforms: list[str] = Field(default_factory=list)

    def to_record(self) -> NodeRecord:
        return NodeRecord(
            label="DetectionStrategy", properties=self.model_dump(exclude_none=True)
        )


class Procedure(BaseModel):
    proc_id: str
    guid: str = ""
    name: str = ""
    description: str = ""
    executor_type: str = ""
    command: str = ""
    elevation_required: bool = False
    platforms: list[str] = Field(default_factory=list)

    def to_record(self) -> NodeRecord:
        return NodeRecord(label="Procedure", properties=self.model_dump(exclude_none=True))


class LOLBin(BaseModel):
    name: str
    description: str = ""
    full_paths: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    sigma_rules: list[str] = Field(default_factory=list)

    def to_record(self) -> NodeRecord:
        return NodeRecord(label="LOLBin", properties=self.model_dump(exclude_none=True))


class Platform(BaseModel):
    name: str

    def to_record(self) -> NodeRecord:
        return NodeRecord(label="Platform", properties=self.model_dump())


class Defense(BaseModel):
    defense_id: str
    name: str = ""
    description: str = ""

    def to_record(self) -> NodeRecord:
        return NodeRecord(label="Defense", properties=self.model_dump(exclude_none=True))
