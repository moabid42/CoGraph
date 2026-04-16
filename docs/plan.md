# CRTKB Architecture & Implementation Plan

## Context

CRTKB (Cognitive Red Teaming Knowledge Base) is a bachelor thesis project that builds a Neo4j-backed knowledge graph unifying offensive security tradecraft. The goal is a queryable, fully-cited representation of attack techniques, procedures, tools, and defenses — initially scoped to Windows/Active Directory. An LLM-powered ingestion pipeline extracts entities from heterogeneous sources, resolves duplicates, and merges them into the graph with mandatory provenance. A hybrid query layer combines vector search with graph traversal for citation-backed answers. The system is evaluated against a 30-question benchmark using RAGAS metrics.

**Current state**: Only raw data sources exist (ATT&CK STIX, Atomic Red Team, LOLBAS). No application code, no Docker setup, no schema — everything needs to be built.

---

## Project Structure

```
CoGraph/
├── .env.example
├── pyproject.toml
├── docker-compose.yml
├── Makefile                              # up, ingest, query, eval targets
│
├── data/                                 # Already exists
│   ├── attack-stix-data/
│   ├── atomic-red-team/
│   ├── lolbas/
│   └── d3fend/                           # To be obtained later (RDF)
│
├── docker/
│   └── neo4j/
│       └── neo4j.conf
│
├── src/crtkb/
│   ├── __init__.py
│   ├── config.py                         # Pydantic Settings (env vars, paths, thresholds)
│   │
│   ├── ontology/
│   │   ├── __init__.py
│   │   ├── schema.py                     # NODE_TYPES, REL_TYPES, PATTERNS as Python constants
│   │   └── schema_init.cypher            # Constraint DDL
│   │
│   ├── parsers/                          # Week 1
│   │   ├── __init__.py
│   │   ├── base.py                       # SourceParser protocol
│   │   ├── attack_stix.py               # MITRE ATT&CK STIX 2.1
│   │   ├── atomic_red_team.py           # Atomic Red Team YAML
│   │   ├── lolbas.py                    # LOLBAS JSON
│   │   └── d3fend.py                    # D3FEND RDF (stub)
│   │
│   ├── pipeline/                         # Week 2
│   │   ├── __init__.py
│   │   ├── runner.py                    # Orchestrates 8 stages
│   │   ├── stage_1_source_reg.py
│   │   ├── stage_2_chunking.py
│   │   ├── stage_3_entity_extract.py    # LLM pass 1
│   │   ├── stage_4_rel_extract.py       # LLM pass 2
│   │   ├── stage_5_entity_res.py        # Three-tier resolver
│   │   ├── stage_6_quality.py
│   │   ├── stage_7_provenance.py
│   │   └── stage_8_merge.py
│   │
│   ├── query/                            # Week 3
│   │   ├── __init__.py
│   │   ├── retriever.py                 # VectorCypherRetriever + 2-hop fan-out
│   │   ├── cypher_qa.py                 # Text2CypherRetriever for structural queries
│   │   ├── rag.py                       # GraphRAG orchestrator with citations
│   │   └── prompts.py                   # System prompts, citation templates
│   │
│   ├── eval/                             # Week 4
│   │   ├── __init__.py
│   │   ├── benchmark.py                 # Load questions, run eval loop
│   │   ├── metrics.py                   # Custom RAGAS metrics (CitationAccuracy, GraphCoverage)
│   │   ├── judge.py                     # LLM-as-judge calibration
│   │   └── questions.yaml               # 30 questions, 3 tiers, gold answers
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── nodes.py                     # Pydantic models: Technique, Tactic, Procedure, etc.
│   │   ├── relationships.py             # Relationship models with provenance
│   │   └── provenance.py               # Provenance metadata model
│   │
│   └── utils/
│       ├── __init__.py
│       ├── neo4j_client.py              # Driver singleton, schema init, health check
│       ├── llm_client.py               # OpenAILLM wrapper for vLLM
│       ├── embedder.py                 # SentenceTransformerEmbeddings (BGE-large)
│       └── langfuse_client.py          # Langfuse tracer setup
│
├── scripts/
│   ├── 01_init_schema.py                # Run schema_init.cypher
│   ├── 02_load_structured.py            # Run all deterministic parsers
│   ├── 03_run_pipeline.py               # Run LLM pipeline on specified sources
│   ├── 04_build_indexes.py              # Create vector + fulltext indexes
│   ├── 05_run_eval.py                   # Run RAGAS evaluation
│   └── smoke_test.py                    # Verify graph integrity
│
├── tests/
│   ├── conftest.py
│   ├── test_parsers/
│   ├── test_pipeline/
│   └── test_query/
│
└── notebooks/
    ├── 01_explore_stix.ipynb
    ├── 02_graph_statistics.ipynb
    └── 03_query_demo.ipynb
```

---

## Ontology

### 13 Entity Types

| # | Label | Unique Key | Source | Est. Count |
|---|-------|-----------|--------|------------|
| 1 | `Technique` | `attack_id` (T1558.003) | ATT&CK STIX `attack-pattern` | ~835 |
| 2 | `Tactic` | `attack_id` (TA0006) | ATT&CK STIX `x-mitre-tactic` | 14 |
| 3 | `Malware` | `attack_id` (S0386) | ATT&CK STIX `malware` | ~696 |
| 4 | `Tool` | `attack_id` (S0039) | ATT&CK STIX `tool` | 91 |
| 5 | `IntrusionSet` | `attack_id` (G0119) | ATT&CK STIX `intrusion-set` | 187 |
| 6 | `Campaign` | `attack_id` (C0027) | ATT&CK STIX `campaign` | 52 |
| 7 | `Mitigation` | `attack_id` (M1031) | ATT&CK STIX `course-of-action` | ~268 |
| 8 | `DataComponent` | `attack_id` (DC0084) | ATT&CK STIX `x-mitre-data-component` | 109 |
| 9 | `DetectionStrategy` | `attack_id` (DET0237) | ATT&CK STIX `x-mitre-detection-strategy` | 691 |
| 10 | `Procedure` | `proc_id` (T1003.001:::guid) | Atomic Red Team YAML | ~1,756 |
| 11 | `LOLBin` | `name` (Bash.exe) | LOLBAS JSON | 232 |
| 12 | `Platform` | `name` (Windows) | ATT&CK + Atomic RT | ~11 |
| 13 | `Defense` | `defense_id` | D3FEND / LLM pipeline | TBD |

**Key design decisions**:
- `Technique` covers both parents (T1003) and sub-techniques (T1003.001) under one label, linked by `SUBTECHNIQUE_OF` edges
- `Malware` vs `Tool` stay separate (ATT&CK semantics: malware is adversary-authored, tools are legitimate dual-use)
- `LOLBin` is distinct from `Tool` — different granularity (specific Windows binaries with command-line variants)
- `Platform` as first-class nodes avoids duplicating platform strings on every Technique/Procedure
- `DetectionStrategy` is the v18 ATT&CK object type that replaces the older data-source detection model

### Node Properties (representative examples)

**Technique**: `attack_id`, `stix_id`, `name`, `description`, `platforms` (list), `is_subtechnique`, `created`, `modified`, `embedding` (1024-dim BGE-large-en-v1.5)

**Procedure**: `proc_id`, `guid`, `name`, `description`, `executor_type`, `command`, `elevation_required`, `platforms`, `embedding`

**LOLBin**: `name`, `description`, `full_paths` (list), `categories` (list), `sigma_rules` (list), `embedding`

All entity types with text descriptions get an `embedding` property (BGE-large-en-v1.5, 1024 dims) for vector search.

### 20 Relationship Types

| # | Type | Source -> Target | Origin | Est. Count |
|---|------|-----------------|--------|------------|
| 1 | `SUBTECHNIQUE_OF` | Technique -> Technique | STIX `subtechnique-of` | ~477 |
| 2 | `PART_OF_TACTIC` | Technique -> Tactic | STIX `kill_chain_phases` | ~1,200 |
| 3 | `USES_TECHNIQUE` | Malware -> Technique | STIX `uses` | ~9,836 |
| 4 | `USES_TECHNIQUE` | IntrusionSet -> Technique | STIX `uses` | ~4,362 |
| 5 | `USES_TECHNIQUE` | Campaign -> Technique | STIX `uses` | ~1,019 |
| 6 | `USES_TECHNIQUE` | Tool -> Technique | STIX `uses` | ~800 |
| 7 | `USES_TOOL` | IntrusionSet -> Tool | STIX `uses` | ~457 |
| 8 | `USES_MALWARE` | IntrusionSet -> Malware | STIX `uses` | ~647 |
| 9 | `USES_MALWARE` | Campaign -> Malware | STIX `uses` | ~84 |
| 10 | `USES_TOOL` | Campaign -> Tool | STIX `uses` | ~65 |
| 11 | `ATTRIBUTED_TO` | Campaign -> IntrusionSet | STIX `attributed-to` | ~25 |
| 12 | `MITIGATES` | Mitigation -> Technique | STIX `mitigates` | ~1,445 |
| 13 | `DETECTS` | DetectionStrategy -> Technique | STIX `detects` | ~691 |
| 14 | `IMPLEMENTS` | Procedure -> Technique | Atomic RT `attack_technique` | ~1,756 |
| 15 | `EXECUTES_VIA` | LOLBin -> Technique | LOLBAS `MitreID` | ~460 |
| 16 | `RUNS_ON` | Technique -> Platform | STIX `x_mitre_platforms` | ~2,300 |
| 17 | `RUNS_ON` | Procedure -> Platform | Atomic RT `supported_platforms` | ~1,756 |
| 18 | `DEFENDS_AGAINST` | Defense -> Technique | D3FEND / LLM-extracted | TBD |
| 19 | `REQUIRES` | Procedure -> Procedure | LLM-extracted prerequisites | TBD |
| 20 | `CONTRADICTS` | Any -> Any | LLM-detected conflicts | TBD |

### Provenance on Every Relationship

```
source_name: STRING      # "mitre-attack", "atomic-red-team", "lolbas", "llm-extracted"
source_url: STRING       # URL or file path
confidence: FLOAT        # 1.0 for deterministic, 0.0-1.0 for LLM-extracted
batch_id: STRING         # Langfuse batch ID for traceability
extracted_at: DATETIME
stix_description: STRING # STIX relationship description field (CTI context)
```

### schema_init.cypher

```cypher
-- Uniqueness constraints (13 entity types)
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

-- STIX ID lookup indexes
CREATE INDEX technique_stix_id IF NOT EXISTS FOR (t:Technique) ON (t.stix_id);
CREATE INDEX malware_stix_id IF NOT EXISTS FOR (m:Malware) ON (m.stix_id);
CREATE INDEX tool_stix_id IF NOT EXISTS FOR (t:Tool) ON (t.stix_id);
CREATE INDEX intrusion_set_stix_id IF NOT EXISTS FOR (i:IntrusionSet) ON (i.stix_id);
CREATE INDEX campaign_stix_id IF NOT EXISTS FOR (c:Campaign) ON (c.stix_id);

-- Fulltext indexes for name-based search
CREATE FULLTEXT INDEX entity_name_fulltext IF NOT EXISTS
  FOR (n:Technique|Tactic|Malware|Tool|IntrusionSet|Campaign|Mitigation|LOLBin|Defense)
  ON EACH [n.name];
CREATE FULLTEXT INDEX alias_fulltext IF NOT EXISTS
  FOR (n:Malware|Tool|IntrusionSet)
  ON EACH [n.aliases];
```

---

## Week 1 — Deterministic Parsers & Structured Backbone

### Parser Protocol

```python
# src/crtkb/parsers/base.py
class SourceParser(Protocol):
    source_name: str
    def parse(self) -> tuple[list[NodeRecord], list[RelRecord]]: ...
```

Every parser returns flat lists of Pydantic `NodeRecord` / `RelRecord`. The load script batches these into `UNWIND ... MERGE` Cypher statements (batch size 500).

### ATT&CK STIX Parser (`src/crtkb/parsers/attack_stix.py`)

**Input**: `data/attack-stix-data/enterprise-attack/enterprise-attack.json` (50MB, 24,772 objects)

**Algorithm**:
1. Load bundle, build `stix_id -> object` lookup dict
2. Filter out `revoked == True` or `x_mitre_deprecated == True` objects
3. For each STIX type, create the corresponding graph node:
   - `attack-pattern` -> `Technique` (extract ATT&CK ID from `external_references` where `source_name == "mitre-attack"`)
   - `x-mitre-tactic` -> `Tactic` (store `x_mitre_shortname` — this is the join key for `kill_chain_phases`)
   - `malware` -> `Malware`, `tool` -> `Tool`, `intrusion-set` -> `IntrusionSet`, etc.
4. For each `relationship` object, dispatch on `(source_stix_type, target_stix_type)` to produce the correct graph edge — the STIX `uses` type is overloaded for 6 different semantic patterns
5. Build `PART_OF_TACTIC` edges by joining `kill_chain_phases[*].phase_name` to `Tactic.shortname`
6. Build `RUNS_ON` edges from `x_mitre_platforms`
7. Store STIX relationship `description` field in provenance (contains CTI context)

**Expected output**: ~1,863 nodes + ~19,848 relationships

### Atomic Red Team Parser (`src/crtkb/parsers/atomic_red_team.py`)

**Input**: `data/atomic-red-team/atomics/T*/T*.yaml` (330 directories, skip `Indexes/`)

**Algorithm**:
1. Glob YAML files, `yaml.safe_load()` each
2. For each test in `atomic_tests`: create `Procedure` node with `proc_id = "{attack_technique}:::{auto_generated_guid}"`
3. Create `IMPLEMENTS` edge to the `Technique` matching `attack_technique`
4. Create `RUNS_ON` edges from `supported_platforms`

**Expected output**: ~1,756 Procedure nodes, ~1,756 IMPLEMENTS edges, ~1,756 RUNS_ON edges

### LOLBAS Parser (`src/crtkb/parsers/lolbas.py`)

**Input**: `data/lolbas/lolbas.json` (232 entries)

**Algorithm**:
1. Load JSON array
2. For each entry: create `LOLBin` node with `name`, `description`, `full_paths`, `categories`, `sigma_rules`
3. For each command, create `EXECUTES_VIA` edge to `Technique` matching `MitreID`, carrying `command`, `category`, `privileges`, `usecase` as edge properties

**Expected output**: 232 LOLBin nodes, ~460 EXECUTES_VIA edges

### Load Order

ATT&CK first (creates all Technique nodes others depend on) -> Atomic Red Team -> LOLBAS.

### Smoke Tests (`scripts/smoke_test.py`)

```cypher
-- Exit criterion from project description
MATCH (t:Technique)-[:PART_OF_TACTIC]->(ta:Tactic) RETURN count(t)  -- expect ~691

-- Cardinality check
MATCH (n) RETURN labels(n)[0] AS label, count(n) ORDER BY count DESC

-- Orphan check (should be 0 for structured sources)
MATCH (n) WHERE NOT (n)--() RETURN labels(n)[0], count(n)

-- Cross-source joins
MATCH (p:Procedure)-[:IMPLEMENTS]->(t:Technique) RETURN count(p)  -- ~1,756
MATCH (l:LOLBin)-[:EXECUTES_VIA]->(t:Technique) RETURN count(l)   -- ~232
```

---

## Week 2 — LLM Extraction Pipeline

### 8-Stage Architecture

```
Source Document
      │
[1. Source Registration]  ─── Create Source node in Neo4j, get batch_id (UUID)
      │
[2. Chunking]             ─── Markdown: split on ## headers, then 1500-token chunks with 200 overlap
      │                        Prepend section header to sub-chunks for context
[3. Entity Extraction]    ─── SimpleKGPipeline LLM pass 1 (entities only)
      │
[4. Relation Extraction]  ─── SimpleKGPipeline LLM pass 2 (relations given entities from pass 1)
      │
[5. Entity Resolution]    ─── Three-tier: canonical ID -> embedding similarity -> LLM verdict
      │
[6. Quality Filtering]    ─── Drop confidence < 0.5, validate schema constraints, flag generics
      │
[7. Provenance Tagging]   ─── Attach source_name, source_url, chunk_id, confidence, batch_id
      │
[8. Graph Merge]          ─── MERGE with ON CREATE/ON MATCH, reliability-tier conflict resolution
```

### SimpleKGPipeline Integration

Use `neo4j-graphrag-python`'s `SimpleKGPipeline` for stages 3-4 with strict schema constraints:

```python
schema = {
    "node_types": [all 13 entity types with descriptions and properties],
    "relationship_types": [all 20 relationship types with descriptions],
    "patterns": [all valid (source_label, rel_type, target_label) triples],
    "additional_node_types": False,      # Strict: ontology types only
    "additional_relationship_types": False,
    "additional_patterns": False,
}
```

LLM: `OpenAILLM` pointed at vLLM endpoint (`http://localhost:8000/v1`), model `Qwen/Qwen2.5-72B-Instruct`, temperature 0.0.

### Three-Tier Entity Resolution (`src/crtkb/pipeline/stage_5_entity_res.py`)

**Tier 1 — Canonical ID Lookup** (deterministic, zero cost):
Regex `[TSGCM]\d{4}(?:\.\d{3})?` extracts ATT&CK IDs from LLM-extracted entity text. Direct graph lookup.

**Tier 2 — Embedding Similarity** (one embedding + one vector query):
BGE-large-en-v1.5 embedding of entity name+description, cosine similarity against same-label nodes. Threshold: 0.88.

**Tier 3 — LLM Verdict** (one LLM call, borderline cases only):
For similarity between 0.80 and 0.88, ask the LLM "Are these the same entity?" with both descriptions. YES/NO answer.

**Execution order**: Always Tier 1 first. If no match, Tier 2. If borderline, Tier 3.

### End-to-End Validation Target

Ingest Kerberoasting section from InternalAllTheThings. Verify LLM-extracted entities merge correctly with ATT&CK T1558.003 and provenance edges trace back to source chunks.

---

## Week 3 — Query Layer

### Hybrid Retrieval (`src/crtkb/query/retriever.py`)

**Flow**: User question -> BGE-large embedding -> vector search top-K (K=5) -> 2-hop Cypher fan-out per hit -> aggregate context -> LLM answer generation with citations

**2-hop Cypher fan-out** (runs after vector search):
```cypher
WITH node, score
OPTIONAL MATCH (node)-[r1]-(n1) WHERE NOT n1:Source
OPTIONAL MATCH (n1)-[r2]-(n2) WHERE NOT n2:Source AND id(n2) <> id(node)
RETURN node, score,
  collect(DISTINCT {entity: n1, rel: type(r1), prov: r1.source_name}) AS hop1,
  collect(DISTINCT {entity: n2, via: n1.name, rel: type(r2)})[0..20] AS hop2
```

2-hop limit is deliberate — the ATT&CK graph is highly connected, 3 hops would retrieve thousands of nodes.

### Query Router

Keyword-based router (no LLM needed):
- "how many", "count", "list all", "which groups" -> `Text2CypherRetriever` (structural queries)
- Everything else -> `VectorCypherRetriever` (semantic queries)

### Answer Generation (`src/crtkb/query/rag.py`)

```python
rag = GraphRAG(
    retriever=retriever,
    llm=llm,
    prompt_template="Answer using ONLY the graph context. "
                    "Cite every claim as [source_name]. "
                    "If context is insufficient, say so."
)
```

### Vector Index Setup (`scripts/04_build_indexes.py`)

Create per-label vector indexes (BGE-large, 1024 dims, cosine similarity) for: Technique, Malware, Tool, IntrusionSet, Procedure, LOLBin, Defense.

Embed `name + first 500 chars of description` as a batch post-processing step after structured load.

---

## Week 4 — Evaluation

### 30-Question Benchmark (`src/crtkb/eval/questions.yaml`)

- **Easy (10)**: Single-hop lookups. "What tactic does T1558 belong to?" / "List sub-techniques of T1003."
- **Medium (10)**: Multi-hop reasoning. "What tools does APT29 use for credential access?" / "Which mitigations apply to Kerberoasting?"
- **Hard (10)**: Attack chain synthesis. "Design a credential theft chain from initial access to domain admin." / "Compare detection strategies for DCSync vs Kerberoasting."

### 6 RAGAS Metrics

| Metric | Implementation | Target |
|--------|---------------|--------|
| Citation Accuracy | Custom `SingleTurnMetric` — verify cited facts appear in context from that source | >= 85% |
| Factual Correctness | RAGAS `FactualCorrectness` | >= 80% |
| Graph Coverage | Custom — gold-standard entities found in retrieved subgraph | >= 75% |
| Retrieval Relevance | RAGAS `ContextPrecision` | measured |
| Answer Completeness | RAGAS `AnswerCorrectness` | measured |
| Faithfulness | RAGAS `Faithfulness` | measured |

### LLM-as-Judge Calibration

Human-label 50 question-answer pairs -> run LLM judge on same pairs -> compute Cohen's kappa -> target 85% agreement (kappa >= 0.7).

---

## Technology Stack

```toml
# pyproject.toml core dependencies
neo4j-graphrag = ">=1.4.0"          # Core KG framework (SimpleKGPipeline, retrievers, GraphRAG)
neo4j = ">=5.17.0"                   # Python driver
pydantic = ">=2.6.3"                 # Data models
pydantic-settings = ">=2.2.0"       # Config from env vars
pyyaml = ">=6.0.1"                   # YAML parsing (Atomic RT)
rdflib = ">=7.0.0"                   # D3FEND RDF (stub, future)
sentence-transformers = ">=3.0.0"    # BGE-large-en-v1.5 embeddings
ragas = ">=0.2.0"                    # Evaluation framework
langfuse = ">=2.40.0"               # Observability
tqdm = ">=4.66.0"                    # Progress bars
python-dotenv = ">=1.0.0"           # .env loading
```

### Docker Compose Services

| Service | Image | Ports | Purpose |
|---------|-------|-------|---------|
| `neo4j` | `neo4j:5.26-community` | 7474, 7687 | Graph database (4G heap, 2G pagecache, APOC) |
| `vllm` | `vllm/vllm-openai:latest` | 8000 | LLM serving (Qwen2.5-72B, tensor-parallel 2) |
| `langfuse` | `langfuse/langfuse:latest` | 3000 | Observability UI |
| `langfuse-db` | `postgres:16-alpine` | — | Langfuse backend |

---

## Implementation Order

1. **`pyproject.toml`**, **`docker-compose.yml`**, **`.env.example`**, **`Makefile`**
2. **`src/crtkb/config.py`** — Pydantic Settings with all env vars
3. **`src/crtkb/ontology/`** — `schema.py` constants + `schema_init.cypher`
4. **`src/crtkb/models/`** — Pydantic models for nodes, relationships, provenance
5. **`src/crtkb/utils/neo4j_client.py`** — Driver singleton, schema init
6. **`src/crtkb/parsers/`** — ATT&CK STIX, Atomic RT, LOLBAS, D3FEND stub
7. **`scripts/01_init_schema.py`**, **`scripts/02_load_structured.py`**, **`scripts/smoke_test.py`**
8. **`src/crtkb/utils/llm_client.py`**, **`embedder.py`**, **`langfuse_client.py`**
9. **`src/crtkb/pipeline/`** — All 8 stages
10. **`scripts/03_run_pipeline.py`**
11. **`scripts/04_build_indexes.py`**
12. **`src/crtkb/query/`** — Retriever, Cypher QA, RAG, prompts
13. **`src/crtkb/eval/`** — Benchmark, metrics, judge, questions.yaml
14. **`scripts/05_run_eval.py`**

## Verification

- After step 7: run `smoke_test.py` — check cardinalities, zero orphans, exit criterion (`count(t) ~ 691`)
- After step 10: ingest Kerberoasting section, verify T1558.003 merge + provenance
- After step 12: interactive query testing via notebook (`notebooks/03_query_demo.ipynb`)
- After step 14: full RAGAS benchmark, produce results table with per-tier breakdown

## Open Question

- **D3FEND data**: Not present in `data/` yet. When/how will it be obtained? The parser is stubbed — does it need to be implemented in Week 1 or can it wait?
