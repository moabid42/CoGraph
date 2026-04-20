"""Stage 2: Adaptive Chunking — split source documents into LLM-sized chunks."""

from __future__ import annotations

import logging
import re

from pydantic import BaseModel, Field

from cograph.config import settings

logger = logging.getLogger(__name__)


class Chunk(BaseModel):
    """A text chunk with metadata for provenance."""

    chunk_id: str
    text: str
    source_path: str
    section_header: str = ""
    index: int = 0


def chunk_markdown(
    text: str,
    source_path: str,
    chunk_size: int | None = None,
    chunk_overlap: int | None = None,
) -> list[Chunk]:
    """Split Markdown text on ``##`` headers, then sub-split large sections.

    Each sub-chunk is prefixed with the section header for context.
    """
    chunk_size = chunk_size or settings.chunk_size
    chunk_overlap = chunk_overlap or settings.chunk_overlap

    # Split on ## headers (keep the header line attached to its section)
    sections = re.split(r"(?=^## )", text, flags=re.MULTILINE)
    sections = [s.strip() for s in sections if s.strip()]

    chunks: list[Chunk] = []
    idx = 0
    for section in sections:
        lines = section.split("\n")
        header = lines[0] if lines[0].startswith("#") else ""
        body = "\n".join(lines[1:]).strip() if header else section

        # Sub-split if section exceeds chunk_size characters
        if len(body) <= chunk_size:
            chunks.append(Chunk(
                chunk_id=f"{source_path}::chunk_{idx}",
                text=f"{header}\n\n{body}" if header else body,
                source_path=source_path,
                section_header=header,
                index=idx,
            ))
            idx += 1
        else:
            # Token-approximate splitting by characters
            start = 0
            while start < len(body):
                end = start + chunk_size
                fragment = body[start:end]
                prefix = f"{header}\n\n" if header else ""
                chunks.append(Chunk(
                    chunk_id=f"{source_path}::chunk_{idx}",
                    text=prefix + fragment,
                    source_path=source_path,
                    section_header=header,
                    index=idx,
                ))
                idx += 1
                start = end - chunk_overlap

    logger.info("Chunked %s into %d chunks.", source_path, len(chunks))
    return chunks


def chunk_text(
    text: str,
    source_path: str,
    chunk_size: int | None = None,
    chunk_overlap: int | None = None,
) -> list[Chunk]:
    """Fixed-size splitting for non-Markdown text."""
    chunk_size = chunk_size or settings.chunk_size
    chunk_overlap = chunk_overlap or settings.chunk_overlap

    chunks: list[Chunk] = []
    idx = 0
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunks.append(Chunk(
            chunk_id=f"{source_path}::chunk_{idx}",
            text=text[start:end],
            source_path=source_path,
            index=idx,
        ))
        idx += 1
        start = end - chunk_overlap

    logger.info("Chunked %s into %d chunks.", source_path, len(chunks))
    return chunks
