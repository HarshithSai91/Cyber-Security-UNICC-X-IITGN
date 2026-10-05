from __future__ import annotations

try:
    from pydantic import BaseModel, Field
except ImportError:
    from dataclasses import dataclass, field as _field

    class BaseModel:
        def __init__(self, **kwargs: Any) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

        def dict(self) -> dict[str, Any]:
            return self.__dict__

        def model_dump(self) -> dict[str, Any]:
            return self.__dict__

    def Field(default: Any = ..., **kwargs: Any) -> Any:
        if default is ...:
            if "default_factory" in kwargs:
                return _field(default_factory=kwargs["default_factory"])
            return _field()
        return _field(default=default)


class MatchRequest(BaseModel):
    query: str = Field(..., description="Threat query string or incident report text")
    top_k: int = Field(5, ge=1, le=50, description="Number of top threat matches to return")
    alpha: float = Field(0.5, ge=0.0, le=1.0, description="Weighting parameter between dense vector and sparse lexical search")


class EvidenceBreakdownSchema(BaseModel):
    ioc_similarity: float = 0.0
    cve_similarity: float = 0.0
    ttp_similarity: float = 0.0
    semantic_similarity: float = 0.0


class AttributionSchema(BaseModel):
    matching_iocs: list[str] = Field(default_factory=list)
    matching_cves: list[str] = Field(default_factory=list)
    shared_malware: list[str] = Field(default_factory=list)
    matching_mitre_techniques: list[str] = Field(default_factory=list)


class CitationSchema(BaseModel):
    doc_id: str
    doc_title: str
    source_org: str
    published_date: str
    page_number: int | None = None
    text_snippet: str


class TopMatchSchema(BaseModel):
    rank: int
    chunk_id: str
    composite_score: float
    confidence_tier: str
    evidence_breakdown: EvidenceBreakdownSchema
    attribution: AttributionSchema
    stix_relationships: list[str] = Field(default_factory=list)
    citations: list[CitationSchema]


class PipelineProfileSchema(BaseModel):
    exact_match_ms: float = 0.0
    vector_database_ms: float = 0.0
    knowledge_graph_ms: float = 0.0
    scoring_ms: float = 0.0
    citation_ms: float = 0.0
    total_ms: float = 0.0


class MatchResponse(BaseModel):
    query_threat_id: str
    top_matches: list[TopMatchSchema]
    pipeline_profile: PipelineProfileSchema
