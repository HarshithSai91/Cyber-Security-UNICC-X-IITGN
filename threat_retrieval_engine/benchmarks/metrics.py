"""
threat_retrieval_engine/benchmarks/metrics.py
=============================================
Comprehensive RAG and IR Evaluation Metrics Suite:
  1. Retrieval Accuracy (R):
     - Hit@K, MRR@K, NDCG@K, MAP@K
  2. Context Quality:
     - Context Precision (signal-to-noise ratio in top chunks)
     - Context Recall (ground-truth facts covered in context)
  3. Generation Fidelity (G):
     - Faithfulness / Groundedness (hallucination rate = 1 - faithfulness)
     - Answer Relevance (query alignment of generated attribution)
  4. Citation Attribution:
     - Provenance Accuracy (doc_id, chunk_id, source_org verification)
     - Span Overlap (character offset span overlap precision/recall)
  5. Classification & Confidence:
     - Macro F1 across 5 tiers
     - Confusion Matrix
  6. Latency SLA Distribution:
     - P50, P90, P95, P99 percentiles
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from typing import Any, Sequence


# ============================================================================
# 1. Retrieval Accuracy Metrics (IR Standards)
# ============================================================================

def hit_at_k(actual: Sequence[str], predicted: Sequence[str], k: int) -> int:
    """Returns 1 if any actual document ID is in the top K predicted items, else 0."""
    if not actual or not predicted:
        return 0
    top_k = set(predicted[:k])
    for item in actual:
        if item in top_k:
            return 1
    return 0


def mrr_at_k(actual: Sequence[str], predicted: Sequence[str], k: int) -> float:
    """Calculates Reciprocal Rank at cutoff K for a single query."""
    if not actual or not predicted:
        return 0.0
    actual_set = set(actual)
    for i, item in enumerate(predicted[:k]):
        if item in actual_set:
            return 1.0 / (i + 1.0)
    return 0.0


def ndcg_at_k(actual: Sequence[str], predicted: Sequence[str], k: int) -> float:
    """
    Calculates Normalized Discounted Cumulative Gain at cutoff K.
    Uses binary relevance (1 if document is in actual set, 0 otherwise).
    """
    if not actual or not predicted:
        return 0.0

    actual_set = set(actual)
    seen: set[str] = set()
    dcg = 0.0
    for i, item in enumerate(predicted[:k]):
        if item in actual_set and item not in seen:
            dcg += 1.0 / math.log2(i + 2.0)
            seen.add(item)

    idcg = 0.0
    num_ideal = min(len(actual_set), k)
    for i in range(num_ideal):
        idcg += 1.0 / math.log2(i + 2.0)

    if idcg == 0.0:
        return 0.0
    return dcg / idcg


def average_precision_at_k(actual: Sequence[str], predicted: Sequence[str], k: int) -> float:
    """
    Calculates Average Precision at cutoff K:
      AP@K = (1 / min(|actual|, K)) * sum_{i=1}^K [P(i) * rel(i)]
    """
    if not actual or not predicted:
        return 0.0

    actual_set = {a.upper() for a in actual}
    seen: set[str] = set()
    hits = 0
    sum_precisions = 0.0

    for i, item in enumerate(predicted[:k]):
        item_upper = item.upper()
        if item_upper in actual_set and item_upper not in seen:
            seen.add(item_upper)
            hits += 1
            sum_precisions += hits / (i + 1.0)

    denom = min(len(actual_set), k)
    return min(1.0, (sum_precisions / denom) if denom > 0 else 0.0)


def map_at_k(
    actual_lists: Sequence[Sequence[str]],
    predicted_lists: Sequence[Sequence[str]],
    k: int = 10,
) -> float:
    """Calculates Mean Average Precision across all queries."""
    if not actual_lists or not predicted_lists or len(actual_lists) != len(predicted_lists):
        return 0.0
    aps = [
        average_precision_at_k(actual, pred, k)
        for actual, pred in zip(actual_lists, predicted_lists)
    ]
    return sum(aps) / len(aps) if aps else 0.0


def precision_recall(
    actual: Sequence[str], predicted: Sequence[str]
) -> tuple[float, float]:
    """Calculates set-based Precision and Recall."""
    if not actual and not predicted:
        return 1.0, 1.0
    if not actual or not predicted:
        return 0.0, 0.0

    actual_set = set(actual)
    predicted_set = set(predicted)
    true_positives = len(actual_set & predicted_set)

    precision = true_positives / len(predicted_set) if predicted_set else 0.0
    recall = true_positives / len(actual_set) if actual_set else 0.0
    return precision, recall


# ============================================================================
# 2. Context Quality Metrics (RAGAS Framework)
# ============================================================================

def context_precision(
    ground_truth_entities: Sequence[str],
    retrieved_chunk_texts: Sequence[str],
) -> float:
    """
    Evaluates signal-to-noise ratio in top retrieved context chunks:
      Ratio of retrieved chunks that contain at least one ground-truth entity/signal.
    """
    if not ground_truth_entities or not retrieved_chunk_texts:
        return 0.0

    targets = [e.lower() for e in ground_truth_entities if e]
    if not targets:
        return 0.0

    relevant_chunks = 0
    for text in retrieved_chunk_texts:
        text_lower = text.lower()
        if any(t in text_lower for t in targets):
            relevant_chunks += 1

    return relevant_chunks / len(retrieved_chunk_texts)


def context_recall(
    ground_truth_entities: Sequence[str],
    retrieved_chunk_texts: Sequence[str],
) -> float:
    """
    Evaluates whether all ground-truth threat facts/entities are captured across
    the combined retrieved context.
    """
    if not ground_truth_entities:
        return 1.0
    if not retrieved_chunk_texts:
        return 0.0

    combined_text = " ".join(retrieved_chunk_texts).lower()
    targets = [e.lower() for e in ground_truth_entities if e]
    if not targets:
        return 1.0

    found = sum(1 for t in targets if t in combined_text)
    return found / len(targets)


# ============================================================================
# 3. Generation Fidelity & Groundedness Metrics
# ============================================================================

def faithfulness(
    generated_attribution: dict[str, list[str]],
    retrieved_chunk_texts: Sequence[str],
) -> float:
    """
    Measures absence of hallucination:
      Ensures every entity claimed in the generated attribution (CVEs, IOCs, TTPs,
      malware) actually exists in the retrieved chunk context.
      Score = Grounded Claims / Total Claims. Score 1.0 = 0% Hallucination.
    """
    if not retrieved_chunk_texts:
        return 0.0

    combined_text = " ".join(retrieved_chunk_texts).lower()
    all_claims: list[str] = []

    for key in ("matching_cves", "matching_iocs", "matching_mitre_techniques", "shared_malware"):
        vals = generated_attribution.get(key) or []
        all_claims.extend(v.lower() for v in vals if v)

    if not all_claims:
        # No claims made -> perfectly unhallucinated
        return 1.0

    grounded = sum(1 for claim in all_claims if claim in combined_text)
    return grounded / len(all_claims)


def answer_relevance(
    query: str,
    generated_response_text: str,
    query_entities: Sequence[str] | None = None,
) -> float:
    """
    Evaluates semantic alignment between analyst's query and the generated attribution.
    Uses token overlap and entity preservation scoring.
    """
    if not generated_response_text:
        return 0.0

    q_words = set(re.findall(r"\b\w{3,}\b", query.lower()))
    r_words = set(re.findall(r"\b\w{3,}\b", generated_response_text.lower()))

    if not q_words:
        return 1.0

    word_overlap = len(q_words & r_words) / len(q_words)

    # Entity preservation bonus
    entity_score = 1.0
    if query_entities:
        q_ent = [e.lower() for e in query_entities if e]
        if q_ent:
            preserved = sum(1 for e in q_ent if e in generated_response_text.lower())
            entity_score = preserved / len(q_ent)

    return 0.6 * word_overlap + 0.4 * entity_score


# ============================================================================
# 4. Citation Attribution & Span Overlap Metrics
# ============================================================================

def citation_provenance_accuracy(
    citations: Sequence[dict[str, Any]],
    expected_doc_ids: Sequence[str],
) -> dict[str, float]:
    """
    Evaluates citation quality:
      - doc_id_accuracy: cited doc_id matches expected threat document ID
      - provenance_completeness: checks chunk_id, source_org, and published_date are non-empty
    """
    if not citations or not expected_doc_ids:
        return {"doc_id_accuracy": 0.0, "provenance_completeness": 0.0}

    exp_set = {d.upper() for d in expected_doc_ids}
    doc_hits = 0
    prov_complete = 0

    for cit in citations:
        doc = str(cit.get("doc_id", "")).upper()
        # Substring or exact match
        if any(e in doc or doc in e for e in exp_set):
            doc_hits += 1

        has_org = bool(cit.get("source_org"))
        has_date = bool(cit.get("published_date"))
        has_snip = bool(cit.get("text_snippet"))
        if has_org and has_date and has_snip:
            prov_complete += 1

    return {
        "doc_id_accuracy": doc_hits / len(citations) if citations else 0.0,
        "provenance_completeness": prov_complete / len(citations) if citations else 0.0,
    }


def span_overlap_f1(
    extracted_snippet: str,
    full_chunk_text: str,
) -> float:
    """
    Measures character span overlap accuracy between the cited evidence snippet
    and the source chunk text.
    """
    if not extracted_snippet or not full_chunk_text:
        return 0.0

    snip = extracted_snippet.strip().lower()
    full = full_chunk_text.strip().lower()

    if snip in full:
        return 1.0

    # Overlap via token intersection
    s_tokens = set(snip.split())
    f_tokens = set(full.split())
    if not s_tokens:
        return 0.0

    prec = len(s_tokens & f_tokens) / len(s_tokens)
    return prec


# ============================================================================
# 5. Classification & Confusion Matrix
# ============================================================================

def macro_f1(
    actual_labels: Sequence[str],
    predicted_labels: Sequence[str],
    classes: Sequence[str],
) -> float:
    """Calculates unweighted Macro F1 score across all specified classes."""
    if not actual_labels or not predicted_labels or len(actual_labels) != len(predicted_labels):
        return 0.0

    f1_scores: list[float] = []
    for cls in classes:
        tp = sum(1 for a, p in zip(actual_labels, predicted_labels) if a == cls and p == cls)
        fp = sum(1 for a, p in zip(actual_labels, predicted_labels) if a != cls and p == cls)
        fn = sum(1 for a, p in zip(actual_labels, predicted_labels) if a == cls and p != cls)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        if precision + recall > 0:
            f1_scores.append(2 * precision * recall / (precision + recall))
        else:
            f1_scores.append(0.0)

    if not f1_scores:
        return 0.0
    return sum(f1_scores) / len(f1_scores)


def confusion_matrix(
    actual_labels: Sequence[str],
    predicted_labels: Sequence[str],
    classes: Sequence[str],
) -> dict[str, dict[str, int]]:
    """Generates an NxN confusion matrix dictionary: matrix[actual][predicted] = count."""
    matrix: dict[str, dict[str, int]] = {
        actual_cls: {pred_cls: 0 for pred_cls in classes}
        for actual_cls in classes
    }
    for a, p in zip(actual_labels, predicted_labels):
        if a in matrix and p in matrix[a]:
            matrix[a][p] += 1
        elif a in matrix:
            matrix[a][p] = 1
    return matrix


# ============================================================================
# 6. Latency Distribution & Stress SLA Metrics
# ============================================================================

def latency_percentiles(latencies_ms: Sequence[float]) -> dict[str, float]:
    """
    Computes full latency distribution: P50, P90, P95, P99, mean, min, max.
    """
    if not latencies_ms:
        return {
            "p50_ms": 0.0,
            "p90_ms": 0.0,
            "p95_ms": 0.0,
            "p99_ms": 0.0,
            "mean_ms": 0.0,
            "min_ms": 0.0,
            "max_ms": 0.0,
        }

    sorted_l = sorted(latencies_ms)
    n = len(sorted_l)

    def _perc(p: float) -> float:
        idx = min(int(n * p), n - 1)
        return round(sorted_l[idx], 2)

    return {
        "p50_ms": _perc(0.50),
        "p90_ms": _perc(0.90),
        "p95_ms": _perc(0.95),
        "p99_ms": _perc(0.99),
        "mean_ms": round(sum(sorted_l) / n, 2),
        "min_ms": round(sorted_l[0], 2),
        "max_ms": round(sorted_l[-1], 2),
    }
