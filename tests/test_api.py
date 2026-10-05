"""
tests/test_api.py
=================
FastAPI endpoint tests for the Threat Retrieval & Matching Subsystem.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from threat_retrieval_engine.api.schemas import (
    AttributionSchema,
    CitationSchema,
    EvidenceBreakdownSchema,
    MatchResponse,
    PipelineProfileSchema,
    TopMatchSchema,
)


def _mock_match_response() -> MatchResponse:
    return MatchResponse(
        query_threat_id="test_query_001",
        top_matches=[
            TopMatchSchema(
                rank=1,
                chunk_id="chunk_test_01",
                composite_score=0.92,
                confidence_tier="EXACT",
                evidence_breakdown=EvidenceBreakdownSchema(
                    ioc_similarity=1.0,
                    cve_similarity=1.0,
                    ttp_similarity=0.8,
                    semantic_similarity=0.85,
                ),
                attribution=AttributionSchema(
                    cves=["CVE-2017-0144"],
                    mitre_ttps=["T1021.002"],
                    iocs={"ipv4": ["198.51.100.24"]},
                ),
                stix_relationships=[],
                citations=[
                    CitationSchema(
                        chunk_id="chunk_test_01",
                        doc_id="CVE-2017-0144",
                        doc_title="EternalBlue",
                        source_org="NVD",
                        published_date="2017-03-14",
                        text_snippet="Exploit details...",
                    )
                ],
            )
        ],
        pipeline_profile=PipelineProfileSchema(
            exact_match_ms=0.5,
            vector_database_ms=45.0,
            knowledge_graph_ms=10.0,
            scoring_ms=1.5,
            citation_ms=0.5,
            total_ms=57.5,
        ),
    )


def test_api_match_endpoint(test_client: TestClient) -> None:
    mock_engine = MagicMock()
    mock_engine.run_query.return_value = _mock_match_response()

    with patch("threat_retrieval_engine.api.main.get_orchestrator", return_value=mock_engine):
        response = test_client.post(
            "/match",
            json={"query": "Attacker exploited CVE-2017-0144", "top_k": 5, "alpha": 0.5},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["query_threat_id"] == "test_query_001"
        assert len(data["top_matches"]) == 1
        assert data["top_matches"][0]["confidence_tier"] == "EXACT"


def test_api_query_alias_endpoint(test_client: TestClient) -> None:
    mock_engine = MagicMock()
    mock_engine.run_query.return_value = _mock_match_response()

    with patch("threat_retrieval_engine.api.main.get_orchestrator", return_value=mock_engine):
        response = test_client.post(
            "/query",
            json={"query": "Apache Log4j CVE-2021-44228", "top_k": 3},
        )
        assert response.status_code == 200
        data = response.json()
        assert "top_matches" in data


def test_api_validation_error_on_empty_body(test_client: TestClient) -> None:
    response = test_client.post("/match", json={})
    assert response.status_code == 422
