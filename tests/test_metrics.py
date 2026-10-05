"""
tests/test_metrics.py
=====================
Unit tests for benchmark metrics: Hit@K, MRR@K, NDCG@K, Macro F1,
Confusion Matrix, and Precision/Recall.
"""

from __future__ import annotations

import math

try:
    import pytest
except ImportError:
    class _PytestStub:
        @staticmethod
        def approx(expected, abs=1e-4):
            class _ApproxVal:
                def __init__(self, val: float, tol: float):
                    self.val = val
                    self.tol = tol
                def __repr__(self) -> str:
                    return f"{self.val} +/- {self.tol}"
                def __eq__(self, actual: object) -> bool:
                    if not isinstance(actual, (int, float)):
                        return False
                    return math.isclose(float(actual), self.val, abs_tol=self.tol)
            return _ApproxVal(expected, abs)
    pytest = _PytestStub()
from threat_retrieval_engine.benchmarks.metrics import (
    confusion_matrix,
    hit_at_k,
    macro_f1,
    mrr_at_k,
    ndcg_at_k,
    precision_recall,
)


def test_hit_at_k() -> None:
    actual = ["doc_a", "doc_b"]
    predicted = ["doc_c", "doc_a", "doc_d"]

    assert hit_at_k(actual, predicted, k=1) == 0
    assert hit_at_k(actual, predicted, k=2) == 1
    assert hit_at_k(actual, predicted, k=3) == 1
    assert hit_at_k([], predicted, k=3) == 0
    assert hit_at_k(actual, [], k=3) == 0


def test_mrr_at_k() -> None:
    actual = ["target_doc"]
    assert mrr_at_k(actual, ["target_doc", "other"], k=5) == 1.0
    assert mrr_at_k(actual, ["other", "target_doc"], k=5) == 0.5
    assert mrr_at_k(actual, ["other1", "other2", "target_doc"], k=5) == pytest.approx(1.0 / 3.0)
    assert mrr_at_k(actual, ["other1", "other2"], k=2) == 0.0


def test_ndcg_at_k() -> None:
    actual = ["doc_1", "doc_2"]
    # Perfect ranking: both docs at top
    assert ndcg_at_k(actual, ["doc_1", "doc_2", "doc_3"], k=3) == pytest.approx(1.0)

    # Empty inputs
    assert ndcg_at_k([], ["doc_1"], k=3) == 0.0
    assert ndcg_at_k(["doc_1"], [], k=3) == 0.0


def test_precision_recall() -> None:
    actual = ["a", "b", "c"]
    predicted = ["b", "c", "d"]
    # Overlap = {b, c} -> 2
    # Precision = 2/3, Recall = 2/3
    p, r = precision_recall(actual, predicted)
    assert p == pytest.approx(2.0 / 3.0)
    assert r == pytest.approx(2.0 / 3.0)


def test_macro_f1_and_confusion_matrix() -> None:
    classes = ["EXACT", "STRONG", "PARTIAL", "WEAK", "UNSUPPORTED"]
    actual = ["EXACT", "STRONG", "WEAK", "UNSUPPORTED"]
    predicted = ["EXACT", "STRONG", "WEAK", "UNSUPPORTED"]

    # Perfect prediction -> F1 = 1.0 for predicted, 0 for unrepresented
    f1 = macro_f1(actual, predicted, classes)
    assert f1 > 0.7

    cm = confusion_matrix(actual, predicted, classes)
    assert cm["EXACT"]["EXACT"] == 1
    assert cm["STRONG"]["STRONG"] == 1
    assert cm["WEAK"]["WEAK"] == 1
    assert cm["UNSUPPORTED"]["UNSUPPORTED"] == 1
    assert cm["PARTIAL"]["PARTIAL"] == 0
