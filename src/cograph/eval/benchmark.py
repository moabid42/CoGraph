"""Benchmark runner — loads questions.yaml, runs the query layer, and evaluates."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from cograph.eval.judge import judge_answer
from cograph.eval.metrics import compute_citation_accuracy, compute_graph_coverage
from cograph.query.rag import query

logger = logging.getLogger(__name__)

_QUESTIONS_FILE = Path(__file__).parent / "questions.yaml"


def load_questions(path: Path | None = None) -> list[dict]:
    """Load the benchmark questions from YAML."""
    path = path or _QUESTIONS_FILE
    with open(path) as f:
        return yaml.safe_load(f)


def run_benchmark(questions: list[dict] | None = None) -> dict:
    """Run the full evaluation benchmark.

    Returns a results dict with per-question scores and tier summaries.
    """
    if questions is None:
        questions = load_questions()

    results = []
    tier_scores: dict[str, list[float]] = {"easy": [], "medium": [], "hard": []}

    for i, q in enumerate(questions):
        question_text = q["question"]
        gold_answer = q["gold_answer"]
        gold_entities = q.get("gold_entities", [])
        difficulty = q.get("difficulty", "medium")

        logger.info("[%d/%d] %s — %s", i + 1, len(questions), difficulty, question_text[:60])

        try:
            answer = query(question_text)
        except Exception:
            logger.warning("Query failed for question %d", i + 1, exc_info=True)
            answer = "Error: query failed."

        # Citation accuracy
        citation = compute_citation_accuracy(answer, [gold_answer])

        # Graph coverage
        coverage = compute_graph_coverage(answer, gold_entities)

        # LLM judge
        judge = judge_answer(question_text, answer, gold_answer)

        result = {
            "index": i + 1,
            "difficulty": difficulty,
            "question": question_text,
            "generated_answer": answer,
            "gold_answer": gold_answer,
            "citation_accuracy": citation.score,
            "graph_coverage": coverage.score,
            "judge_overall": judge.get("overall", 0),
            "judge_factual": judge.get("factual_correctness", 0),
            "judge_completeness": judge.get("completeness", 0),
            "judge_citation": judge.get("citation_quality", 0),
            "judge_relevance": judge.get("relevance", 0),
            "judge_reasoning": judge.get("reasoning", ""),
        }
        results.append(result)
        tier_scores[difficulty].append(judge.get("overall", 0))

    # Compute tier summaries
    tier_summary = {}
    for tier, scores in tier_scores.items():
        if scores:
            tier_summary[tier] = {
                "count": len(scores),
                "avg_score": sum(scores) / len(scores),
                "min_score": min(scores),
                "max_score": max(scores),
            }

    # Overall metrics
    all_citation = [r["citation_accuracy"] for r in results]
    all_coverage = [r["graph_coverage"] for r in results]
    all_overall = [r["judge_overall"] for r in results]

    summary = {
        "total_questions": len(results),
        "citation_accuracy_avg": sum(all_citation) / len(all_citation) if all_citation else 0,
        "graph_coverage_avg": sum(all_coverage) / len(all_coverage) if all_coverage else 0,
        "judge_overall_avg": sum(all_overall) / len(all_overall) if all_overall else 0,
        "tier_breakdown": tier_summary,
        "results": results,
    }

    return summary


def print_results_table(summary: dict) -> None:
    """Print a formatted results table."""
    print("\n" + "=" * 80)
    print("CoGraph EVALUATION RESULTS")
    print("=" * 80)

    print(f"\nOverall ({summary['total_questions']} questions):")
    print(f"  Citation Accuracy:  {summary['citation_accuracy_avg']:.2%}")
    print(f"  Graph Coverage:     {summary['graph_coverage_avg']:.2%}")
    print(f"  Judge Overall:      {summary['judge_overall_avg']:.2f} / 5.0")

    print("\nTier Breakdown:")
    for tier, stats in summary.get("tier_breakdown", {}).items():
        print(f"  {tier.upper()} ({stats['count']}): avg={stats['avg_score']:.2f}, "
              f"min={stats['min_score']:.2f}, max={stats['max_score']:.2f}")

    print("\nPer-Question Results:")
    print(f"{'#':>3} {'Tier':>6} {'Cite':>6} {'Covg':>6} {'Judge':>6}  Question")
    print("-" * 80)
    for r in summary.get("results", []):
        print(
            f"{r['index']:>3} {r['difficulty']:>6} "
            f"{r['citation_accuracy']:>6.2%} {r['graph_coverage']:>6.2%} "
            f"{r['judge_overall']:>6.2f}  {r['question'][:40]}"
        )
    print("=" * 80)
