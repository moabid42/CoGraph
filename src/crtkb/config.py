"""Centralised configuration loaded from environment variables / .env file."""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings


_PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """All tunables for CRTKB, read from env vars prefixed ``CRTKB_``."""

    # ── Neo4j ────────────────────────────────────────────────────────────
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "changeme"
    neo4j_database: str = "neo4j"

    # ── LLM ──────────────────────────────────────────────────────────────
    llm_provider: str = "google"  # "google" (Gemini), "openai", or "vllm"
    llm_model_name: str = "gemini-2.5-flash"
    llm_api_key: str = ""
    llm_base_url: str = ""  # only needed for vllm / custom OpenAI endpoints

    # ── Embeddings ───────────────────────────────────────────────────────
    embedding_model: str = "BAAI/bge-large-en-v1.5"
    embedding_dimensions: int = 1024

    # ── Entity resolution ────────────────────────────────────────────────
    er_embedding_threshold: float = 0.88
    er_borderline_low: float = 0.80

    # ── Pipeline ─────────────────────────────────────────────────────────
    chunk_size: int = 1500
    chunk_overlap: int = 200
    merge_batch_size: int = 500
    quality_confidence_threshold: float = 0.5

    # ── Langfuse ─────────────────────────────────────────────────────────
    langfuse_secret_key: str = ""
    langfuse_public_key: str = ""
    langfuse_base_url: str = "http://localhost:3000"

    # ── Data paths (relative to project root) ────────────────────────────
    data_dir: Path = _PROJECT_ROOT / "data"
    attack_stix_path: Path = _PROJECT_ROOT / "data" / "attack-stix-data" / "enterprise-attack" / "enterprise-attack.json"
    atomic_rt_glob: str = "data/atomic-red-team/atomics/T*/T*.yaml"
    lolbas_path: Path = _PROJECT_ROOT / "data" / "lolbas" / "lolbas.json"

    model_config = {
        "env_prefix": "CRTKB_",
        "env_file": str(_PROJECT_ROOT / ".env"),
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


# Module-level singleton — import this everywhere.
settings = Settings()
