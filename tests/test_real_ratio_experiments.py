"""
tests/test_real_ratio_experiments.py
====================================
Automated test suite verifying the empirical superiority, separability,
and ablation characteristics of 4-factor composite scoring ratios on
the 1,000 realistic benchmark scenarios (data/benchmark_dataset_1000.json).
"""

from __future__ import annotations

import pytest
from pathlib import Path
import sys

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.test_composite_score_ratios import (
    load_real_scenarios,
    evaluate_ratio,
    run_ablation_experiments,
    BENCHMARK_1000_PATH,
)
from threat_retrieval_engine.api.helpers import (
    CALIBRATED_SCORING_WEIGHTS,
    CALIBRATED_CONFIDENCE_THRESHOLDS,
)


@pytest.fixture(scope="module")
def real_1000_samples():
    assert BENCHMARK_1000_PATH.exists(), f"1,000 benchmark dataset missing at {BENCHMARK_1000_PATH}"
    samples = load_real_scenarios(BENCHMARK_1000_PATH)
    assert len(samples) == 1000, f"Expected 1,000 scenarios, got {len(samples)}"
    return samples


def test_real_1000_canonical_accuracy_and_f1(real_1000_samples):
    """Calibrated ratio (0.40, 0.20, 0.20, 0.20) must achieve >= 98% accuracy and macro F1."""
    res = evaluate_ratio(
        real_1000_samples,
        CALIBRATED_SCORING_WEIGHTS,
        thresholds=CALIBRATED_CONFIDENCE_THRESHOLDS,
    )
    assert res["is_monotonic"], "Tier ordering must be strictly monotonic"
    assert res["accuracy"] >= 0.98, f"Expected >= 98% accuracy, got {res['accuracy']:.2%}"
    assert res["macro_f1"] >= 0.98, f"Expected >= 98% Macro F1, got {res['macro_f1']:.2%}"
    assert res["min_mean_margin"] >= 0.15, f"Expected margin >= 0.15, got {res['min_mean_margin']}"


def test_real_1000_uniform_baseline_failure(real_1000_samples):
    """Uniform weights (0.25, 0.25, 0.25, 0.25) must fail with negative margin and low accuracy."""
    res_canonical = evaluate_ratio(
        real_1000_samples,
        CALIBRATED_SCORING_WEIGHTS,
        thresholds=CALIBRATED_CONFIDENCE_THRESHOLDS,
    )
    res_uniform = evaluate_ratio(
        real_1000_samples,
        (0.25, 0.25, 0.25, 0.25),
    )

    # Uniform baseline has a negative margin between PARTIAL and STRONG
    assert res_uniform["min_mean_margin"] < 0.0, "Uniform weights must yield negative margin due to tier collision"
    assert res_canonical["accuracy"] - res_uniform["accuracy"] > 0.20, "Canonical must beat uniform by > 20% accuracy"
    assert res_canonical["macro_f1"] - res_uniform["macro_f1"] > 0.25, "Canonical must beat uniform by > 25% F1"


def test_real_1000_factor_ablation_collapse(real_1000_samples):
    """Ablation of IOC or TTP must cause severe degradation or tier inversion."""
    ablations = run_ablation_experiments(real_1000_samples)

    # 1. Ablating IOC causes tier inversion (negative margin)
    ioc_abl = ablations["Ablate IOC (w_ioc = 0)"]
    assert ioc_abl["min_mean_margin"] < 0.0, "Removing IOC must cause negative margin"
    assert ioc_abl["macro_f1"] < 0.50, "Removing IOC must drop Macro F1 below 50%"

    # 2. Ablating TTP causes severe F1 collapse
    ttp_abl = ablations["Ablate TTP (w_ttp = 0)"]
    assert ttp_abl["min_mean_margin"] < 0.05, "Removing TTP must compress safety margin to near zero"
    assert ttp_abl["macro_f1"] < 0.85, "Removing TTP must drop Macro F1 below 85%"

    # 3. Ablating CVE degrades margin significantly
    cve_abl = ablations["Ablate CVE (w_cve = 0)"]
    assert cve_abl["min_mean_margin"] < 0.12, "Removing CVE must degrade margin below 0.12"
