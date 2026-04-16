"""Optional Langfuse observability integration."""

from __future__ import annotations

import logging

from crtkb.config import settings

logger = logging.getLogger(__name__)

_langfuse = None


def get_langfuse():
    """Return a Langfuse client (or None if keys are not configured)."""
    global _langfuse
    if _langfuse is not None:
        return _langfuse

    if not settings.langfuse_secret_key or not settings.langfuse_public_key:
        logger.info("Langfuse keys not configured — tracing disabled.")
        return None

    from langfuse import Langfuse

    _langfuse = Langfuse(
        secret_key=settings.langfuse_secret_key,
        public_key=settings.langfuse_public_key,
        host=settings.langfuse_base_url,
    )
    logger.info("Langfuse client initialised at %s", settings.langfuse_base_url)
    return _langfuse
