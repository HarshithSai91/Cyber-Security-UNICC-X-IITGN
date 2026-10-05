"""
reranker.py
===========
Cross-encoder reranking to sharpen the top of the hybrid result list.

Hybrid RRF gives a strong *candidate set* but its ordering still rests on
bi-encoder similarity + lexical overlap, neither of which reads the query and
passage jointly. A cross-encoder does: it feeds ``[query, passage]`` through one
transformer with full cross-attention and emits a single relevance logit. It is
far more accurate but far more expensive, so the standard pattern is:

    hybrid retrieve top-50  ->  cross-encoder rerank  ->  keep top-5

We use ``BAAI/bge-reranker-v2-m3`` (the reranker sibling of the BGE-M3 embedder)
via FlagEmbedding's ``FlagReranker``. The model is lazy-loaded so importing this
module stays cheap, and callers can inject any object exposing
``compute_score(pairs)`` (used by the tests to avoid a model download).
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Protocol

try:
    from threat_retrieval_engine.search_engine.vector_database import fetch_chunk_metadata
except ImportError:
    from vector_database import fetch_chunk_metadata

logger = logging.getLogger(__name__)

DEFAULT_RERANKER_MODEL = "BAAI/bge-reranker-v2-m3"


@dataclass
class RerankedResult:
    chunk_id: str
    rerank_score: float
    text: str
    metadata: dict[str, Any] = field(default_factory=dict)


class ScorerProtocol(Protocol):
    """Anything exposing FlagReranker's compute_score(pairs) -> list[float]."""

    def compute_score(self, sentence_pairs: list[list[str]], **kwargs: Any) -> Any: ...


class CrossEncoderReranker:
    """
    Wraps a cross-encoder scorer. In production it loads ``BAAI/bge-reranker-v2-m3``;
    in tests a stub scorer can be injected via ``scorer=``.
    """

    def __init__(
        self,
        model_name: str = DEFAULT_RERANKER_MODEL,
        use_fp16: bool = True,
        scorer: ScorerProtocol | None = None,
    ) -> None:
        self.model_name = model_name
        self._use_fp16 = use_fp16
        self._scorer: ScorerProtocol | None = scorer  # if injected, skip lazy load

    def _load(self) -> ScorerProtocol:
        if self._scorer is not None:
            return self._scorer
        try:
            from FlagEmbedding import FlagReranker  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "FlagEmbedding is not installed. Run: pip install FlagEmbedding>=1.2.10"
            ) from exc
        logger.info("Loading cross-encoder reranker %s …", self.model_name)
        self._scorer = FlagReranker(self.model_name, use_fp16=self._use_fp16)
        logger.info("Reranker loaded.")
        return self._scorer

    def rerank(
        self,
        query: str,
        candidates: list[tuple[str, str]],
        top_k: int = 5,
    ) -> list[RerankedResult]:
        """
        Score and reorder candidates.

        Parameters
        ----------
        query : str
            The user query (no BGE prefix — cross-encoders take raw text).
        candidates : list[(chunk_id, passage_text)]
            The passages to score. Fetch texts from SQLite up-front (see
            :func:`rerank_hybrid_results`).
        top_k : int
            Number of results to keep.
        """
        if not candidates:
            return []

        scorer = self._load()
        pairs = [[query, text] for _, text in candidates]
        raw_scores = scorer.compute_score(pairs, normalize=True)
        # compute_score returns a float for a single pair, else a list
        if not isinstance(raw_scores, (list, tuple)):
            raw_scores = [raw_scores]

        scored = [
            RerankedResult(chunk_id=cid, rerank_score=float(score), text=text)
            for (cid, text), score in zip(candidates, raw_scores)
        ]
        scored.sort(key=lambda r: r.rerank_score, reverse=True)
        return scored[:top_k]


def rerank_hybrid_results(
    reranker: CrossEncoderReranker,
    query: str,
    hybrid_results: list[Any],
    sqlite: sqlite3.Connection,
    top_k: int = 5,
    hydrate_metadata: bool = True,
) -> list[RerankedResult]:
    """
    Convenience bridge: take :class:`hybrid_search.HybridResult` objects, pull
    their passage text from SQLite, rerank, and attach full metadata.
    """
    candidates: list[tuple[str, str]] = []
    meta_cache: dict[str, dict[str, Any]] = {}
    for hr in hybrid_results:
        meta = fetch_chunk_metadata(hr.chunk_id, sqlite)
        if not meta:
            continue
        meta_cache[hr.chunk_id] = meta
        # Rerank on the enriched context so identifiers/TTPs are visible to the model.
        candidates.append((hr.chunk_id, meta.get("enriched_text") or meta.get("text", "")))

    reranked = reranker.rerank(query, candidates, top_k=top_k)
    if hydrate_metadata:
        for r in reranked:
            r.metadata = meta_cache.get(r.chunk_id, {})
    return reranked
