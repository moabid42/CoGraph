"""LLM-as-judge for answer quality evaluation and calibration."""

from __future__ import annotations

import json
import logging

from cograph.utils.llm_client import get_llm

logger = logging.getLogger(__name__)

_JUDGE_PROMPT = """You are an expert evaluator for a red teaming knowledge base.
Rate the following generated answer compared to the reference answer.

Question: {question}
Reference Answer: {reference}
Generated Answer: {answer}

Rate on each criterion (1-5 scale):
1. Factual Correctness: Are the facts in the generated answer correct?
2. Completeness: Does the generated answer cover the key points?
3. Citation Quality: Are claims properly attributed with source citations?
4. Relevance: Is the answer focused on what was asked?

Output a JSON object with keys: factual_correctness, completeness, citation_quality, relevance, overall (average), reasoning (brief explanation).

JSON:"""


def judge_answer(
    question: str,
    answer: str,
    reference: str,
) -> dict:
    """Ask the LLM to judge an answer against a reference.

    Returns a dict with scores and reasoning.
    """
    llm = get_llm()
    prompt = _JUDGE_PROMPT.format(
        question=question,
        reference=reference,
        answer=answer,
    )

    try:
        response = llm.invoke(prompt)
        text = response.content.strip()
        # Parse JSON from response
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            result = json.loads(text[start:end])
            # Ensure all expected keys exist
            for key in ["factual_correctness", "completeness", "citation_quality", "relevance"]:
                result.setdefault(key, 0)
            scores = [result[k] for k in ["factual_correctness", "completeness", "citation_quality", "relevance"]]
            result["overall"] = sum(scores) / len(scores)
            return result
    except Exception:
        logger.warning("Judge evaluation failed.", exc_info=True)

    return {
        "factual_correctness": 0,
        "completeness": 0,
        "citation_quality": 0,
        "relevance": 0,
        "overall": 0,
        "reasoning": "Evaluation failed.",
    }


def calibrate_judge(
    human_labels: list[dict],
) -> dict:
    """Compare LLM judge scores against human labels to compute agreement.

    Args:
        human_labels: list of dicts with keys: question, answer, reference,
                      human_score (1-5).

    Returns:
        Agreement statistics.
    """
    agreements = 0
    total = 0
    diffs = []

    for item in human_labels:
        result = judge_answer(item["question"], item["answer"], item["reference"])
        llm_score = round(result.get("overall", 0))
        human_score = item["human_score"]
        diff = abs(llm_score - human_score)
        diffs.append(diff)
        if diff <= 1:  # Within 1 point = agreement
            agreements += 1
        total += 1

    agreement_rate = agreements / total if total else 0
    avg_diff = sum(diffs) / len(diffs) if diffs else 0

    return {
        "total_samples": total,
        "agreements_within_1": agreements,
        "agreement_rate": agreement_rate,
        "avg_score_diff": avg_diff,
    }
