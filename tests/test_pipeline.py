"""
tests/test_pipeline.py
======================
Integration tests for the ThreatRetrieverEngine pipeline orchestrator.
"""

from __future__ import annotations

import pytest
from threat_retrieval_engine.api.pipeline import ThreatRetrieverEngine


def test_threat_retriever_engine_run_query(test_engine: ThreatRetrieverEngine) -> None:
    query = "Attacker exploited CVE-2017-0144 using T1021.002 from host 198.51.100.24"
    response = test_engine.run_query(query=query, top_k=3, alpha=0.5)

    assert response.query_threat_id.startswith("query_")
    assert len(response.top_matches) > 0

    top_match = response.top_matches[0]
    assert top_match.rank == 1
    assert top_match.chunk_id == "chunk_eb_01"
    assert top_match.confidence_tier in ["EXACT", "STRONG"]
    assert top_match.composite_score >= 0.70

    # Evidence breakdown
    assert top_match.evidence_breakdown.cve_similarity > 0.0
    assert top_match.evidence_breakdown.ioc_similarity > 0.0

    # Citations
    assert len(top_match.citations) > 0
    assert top_match.citations[0].doc_id == "CVE-2017-0144"

    # Pipeline profile timings
    assert response.pipeline_profile.total_ms > 0.0


def test_threat_retriever_engine_unsupported_query(test_engine: ThreatRetrieverEngine) -> None:
    query = "Routine maintenance on office printer setup and paper tray refill"
    response = test_engine.run_query(query=query, top_k=3, alpha=0.5)

    if response.top_matches:
        top_match = response.top_matches[0]
        assert top_match.confidence_tier in ["WEAK", "UNSUPPORTED"]
        assert top_match.composite_score < 0.50
