"""Thin wrapper around the vLLM-served LLM via an OpenAI-compatible client."""

from __future__ import annotations

from neo4j_graphrag.llm.openai_llm import OpenAILLM

from crtkb.config import settings

_llm: OpenAILLM | None = None


def get_llm() -> OpenAILLM:
    """Return a cached OpenAILLM instance pointed at the vLLM endpoint."""
    global _llm
    if _llm is None:
        _llm = OpenAILLM(
            model_name=settings.vllm_model_name,
            model_params={
                "base_url": settings.vllm_base_url,
                "api_key": settings.vllm_api_key,
                "temperature": 0.0,
                "max_tokens": 4096,
            },
        )
    return _llm
