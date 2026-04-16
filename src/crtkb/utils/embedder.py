"""BGE-large-en-v1.5 embedding wrapper using sentence-transformers."""

from __future__ import annotations

from neo4j_graphrag.embeddings.sentence_transformers import SentenceTransformerEmbeddings

from crtkb.config import settings

_embedder: SentenceTransformerEmbeddings | None = None


def get_embedder() -> SentenceTransformerEmbeddings:
    """Return a cached SentenceTransformerEmbeddings instance."""
    global _embedder
    if _embedder is None:
        _embedder = SentenceTransformerEmbeddings(model=settings.embedding_model)
    return _embedder


def embed_text(name: str, description: str, max_desc_chars: int = 500) -> list[float]:
    """Embed ``name + description[:max_desc_chars]`` for vector indexing."""
    text = f"{name}. {description[:max_desc_chars]}" if description else name
    return get_embedder().embed_query(text)
