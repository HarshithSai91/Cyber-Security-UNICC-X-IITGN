"""
tests/test_benchmarks.py
========================
Verification of benchmark dataset structure, metric evaluation, and output generation.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from threat_retrieval_engine.benchmarks.evaluate import (
    DEFAULT_DATASET,
    evaluate_engine,
)
from threat_retrieval_engine.api.pipeline import ThreatRetrieverEngine


def test_benchmark_dataset_integrity() -> None:
    assert DEFAULT_DATASET.exists(), f"Benchmark dataset missing at {DEFAULT_DATASET}"

    with open(DEFAULT_DATASET, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert isinstance(data, list)
    assert len(data) >= 10

    for item in data:
        assert "query" in item
        assert "expected_tier" in item
        assert item["expected_tier"] in ["EXACT", "STRONG", "PARTIAL", "WEAK", "UNSUPPORTED"]


@pytest.mark.asyncio
async def test_evaluate_engine_dry_run(test_engine: ThreatRetrieverEngine, tmp_path: Path) -> None:
    mini_dataset = [
        {
            "query_id": "test_cve_01",
            "query": "Attacker exploited CVE-2017-0144 using T1021.002",
            "expected_tier": "STRONG",
            "relevant_documents": ["CVE-2017-0144"],
            "expected_top_chunk": "chunk_eb_01",
        },
        {
            "query_id": "test_benign_02",
            "query": "Routine printer paper maintenance",
            "expected_tier": "UNSUPPORTED",
            "relevant_documents": [],
            "expected_top_chunk": "",
        },
    ]

    out_file = tmp_path / "test_benchmark_results.json"
    passed = await evaluate_engine(
        engine=test_engine,
        engine_name="TestEngine",
        dataset=mini_dataset,
        output_path=out_file,
    )

    assert out_file.exists()
    with open(out_file, "r", encoding="utf-8") as f:
        res = json.load(f)

    assert res["benchmark_dataset_scale"]["total_queries"] == 2
    assert "retrieval_accuracy" in res
    assert "hit_at_3" in res["retrieval_accuracy"]
    assert "macro_f1" in res["classification_fidelity"]
    assert "per_query_results" in res
