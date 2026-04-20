"""LLM client factory — supports Google Gemini, OpenAI, and vLLM backends."""

from __future__ import annotations

import logging

from cograph.config import settings

logger = logging.getLogger(__name__)

_llm = None


def get_llm():
    """Return a cached LLM instance based on ``settings.llm_provider``."""
    global _llm
    if _llm is not None:
        return _llm

    provider = settings.llm_provider.lower()

    if provider == "google":
        from neo4j_graphrag.llm import OpenAILLM

        # Gemini exposes an OpenAI-compatible endpoint
        _llm = OpenAILLM(
            model_name=settings.llm_model_name,
            model_params={
                "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
                "api_key": settings.llm_api_key,
                "temperature": 0.0,
                "max_tokens": 4096,
            },
        )
        logger.info("LLM: Google Gemini (%s) via OpenAI-compat endpoint", settings.llm_model_name)

    elif provider == "openai":
        from neo4j_graphrag.llm import OpenAILLM

        _llm = OpenAILLM(
            model_name=settings.llm_model_name,
            model_params={
                "api_key": settings.llm_api_key,
                "temperature": 0.0,
                "max_tokens": 4096,
            },
        )
        logger.info("LLM: OpenAI (%s)", settings.llm_model_name)

    elif provider == "vllm":
        from neo4j_graphrag.llm import OpenAILLM

        _llm = OpenAILLM(
            model_name=settings.llm_model_name,
            model_params={
                "base_url": settings.llm_base_url or "http://localhost:8000/v1",
                "api_key": settings.llm_api_key or "not-needed",
                "temperature": 0.0,
                "max_tokens": 4096,
            },
        )
        logger.info("LLM: vLLM (%s) at %s", settings.llm_model_name, settings.llm_base_url)

    else:
        raise ValueError(f"Unknown LLM provider: {provider!r}. Use 'google', 'openai', or 'vllm'.")

    return _llm
