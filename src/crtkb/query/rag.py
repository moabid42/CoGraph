"""GraphRAG orchestrator — routes queries and generates cited answers."""

from __future__ import annotations

import logging
import re

from neo4j_graphrag.generation import GraphRAG

from crtkb.query.cypher_qa import get_cypher_retriever
from crtkb.query.prompts import RAG_PROMPT_TEMPLATE, RAG_SYSTEM_PROMPT
from crtkb.query.retriever import get_vector_cypher_retriever
from crtkb.utils.llm_client import get_llm

logger = logging.getLogger(__name__)

# Keywords that signal a structural query
_STRUCTURAL_KEYWORDS = re.compile(
    r"\b(how many|count|list all|which groups|which actors|"
    r"number of|enumerate|show all|total)\b",
    re.IGNORECASE,
)


def _is_structural_query(question: str) -> bool:
    """Heuristic: does the question need a Cypher query rather than RAG?"""
    return bool(_STRUCTURAL_KEYWORDS.search(question))


def build_rag(index_name: str = "technique_embedding_idx") -> GraphRAG:
    """Build the GraphRAG pipeline with vector retriever + LLM."""
    retriever = get_vector_cypher_retriever(index_name=index_name)
    return GraphRAG(
        retriever=retriever,
        llm=get_llm(),
    )


def query(question: str) -> str:
    """Route a question to the appropriate retriever and return the answer."""
    if _is_structural_query(question):
        logger.info("Routing to Text2Cypher: %s", question[:80])
        retriever = get_cypher_retriever()
        try:
            result = retriever.search(query_text=question)
            return f"[Cypher result]\n{result.items}"
        except Exception:
            logger.warning("Cypher retriever failed, falling back to RAG.", exc_info=True)

    logger.info("Routing to GraphRAG: %s", question[:80])
    rag = build_rag()
    result = rag.search(query_text=question)
    return result.answer


def interactive() -> None:
    """Simple interactive REPL for testing queries."""
    print("CRTKB Query Layer — type 'quit' to exit.\n")
    while True:
        try:
            q = input("Question: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if q.lower() in ("quit", "exit", "q"):
            break
        if not q:
            continue
        try:
            answer = query(q)
            print(f"\n{answer}\n")
        except Exception as exc:
            print(f"Error: {exc}\n")
