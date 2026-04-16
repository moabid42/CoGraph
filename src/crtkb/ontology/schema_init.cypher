// ===== CRTKB Schema Constraints and Indexes =====
// Run once after Neo4j is up to enforce ontology invariants.

// ── Uniqueness constraints (one per entity type) ────────────────────────
CREATE CONSTRAINT technique_attack_id IF NOT EXISTS
  FOR (t:Technique) REQUIRE t.attack_id IS UNIQUE;

CREATE CONSTRAINT tactic_attack_id IF NOT EXISTS
  FOR (t:Tactic) REQUIRE t.attack_id IS UNIQUE;

CREATE CONSTRAINT malware_attack_id IF NOT EXISTS
  FOR (m:Malware) REQUIRE m.attack_id IS UNIQUE;

CREATE CONSTRAINT tool_attack_id IF NOT EXISTS
  FOR (t:Tool) REQUIRE t.attack_id IS UNIQUE;

CREATE CONSTRAINT intrusion_set_attack_id IF NOT EXISTS
  FOR (i:IntrusionSet) REQUIRE i.attack_id IS UNIQUE;

CREATE CONSTRAINT campaign_attack_id IF NOT EXISTS
  FOR (c:Campaign) REQUIRE c.attack_id IS UNIQUE;

CREATE CONSTRAINT mitigation_attack_id IF NOT EXISTS
  FOR (m:Mitigation) REQUIRE m.attack_id IS UNIQUE;

CREATE CONSTRAINT data_component_attack_id IF NOT EXISTS
  FOR (d:DataComponent) REQUIRE d.attack_id IS UNIQUE;

CREATE CONSTRAINT detection_strategy_attack_id IF NOT EXISTS
  FOR (d:DetectionStrategy) REQUIRE d.attack_id IS UNIQUE;

CREATE CONSTRAINT procedure_proc_id IF NOT EXISTS
  FOR (p:Procedure) REQUIRE p.proc_id IS UNIQUE;

CREATE CONSTRAINT lolbin_name IF NOT EXISTS
  FOR (l:LOLBin) REQUIRE l.name IS UNIQUE;

CREATE CONSTRAINT platform_name IF NOT EXISTS
  FOR (p:Platform) REQUIRE p.name IS UNIQUE;

CREATE CONSTRAINT defense_id IF NOT EXISTS
  FOR (d:Defense) REQUIRE d.defense_id IS UNIQUE;

// ── STIX ID lookup indexes ──────────────────────────────────────────────
CREATE INDEX technique_stix_id IF NOT EXISTS FOR (t:Technique) ON (t.stix_id);
CREATE INDEX malware_stix_id IF NOT EXISTS FOR (m:Malware) ON (m.stix_id);
CREATE INDEX tool_stix_id IF NOT EXISTS FOR (t:Tool) ON (t.stix_id);
CREATE INDEX intrusion_set_stix_id IF NOT EXISTS FOR (i:IntrusionSet) ON (i.stix_id);
CREATE INDEX campaign_stix_id IF NOT EXISTS FOR (c:Campaign) ON (c.stix_id);

// ── Fulltext indexes ────────────────────────────────────────────────────
CREATE FULLTEXT INDEX entity_name_fulltext IF NOT EXISTS
  FOR (n:Technique|Tactic|Malware|Tool|IntrusionSet|Campaign|Mitigation|LOLBin|Defense)
  ON EACH [n.name];

CREATE FULLTEXT INDEX alias_fulltext IF NOT EXISTS
  FOR (n:Malware|Tool|IntrusionSet)
  ON EACH [n.aliases];
