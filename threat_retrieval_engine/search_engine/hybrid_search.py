"""
hybrid_search.py
================
Hybrid retrieval: fuse lexical (BM25) and dense (BGE-M3) candidate lists with
Reciprocal Rank Fusion, honouring search-time metadata filters.

Why RRF
-------
Dense and lexical scores live on incompatible scales (cosine ~[0,1] vs. an
unbounded BM25 sum), so you cannot simply add them. Reciprocal Rank Fusion
sidesteps calibration entirely by combining *ranks*:

    RRF(d) = Σ_lists  1 / (k + rank_list(d))          (k = 60 by convention)

A document ranked #1 by either retriever gets 1/(k+1); agreement across both
retrievers compounds. It is parameter-light, robust, and the same fusion Qdrant
uses internally.

Metadata filtering
------------------
Filters (``source_org``, ``severity``, date ranges, a specific CVE, …) are
applied at search time, before fusion:

* the **dense** side passes the filter straight to Qdrant's payload index;
* the **lexical** side is constrained to the same candidate set by resolving the
  filter to an allow-list of chunk_ids (a Qdrant payload scroll) and passing it
  into :meth:`BM25Index.search`.

This avoids the classic "post-filter recall collapse" where you filter *after*
top-k and end up with far fewer than k results.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Callable

try:
    from qdrant_client import QdrantClient
    from qdrant_client.models import (
        DatetimeRange,
        FieldCondition,
        Filter,
        MatchAny,
        MatchValue,
    )
except ImportError:
    QdrantClient = Any  # type: ignore
    DatetimeRange = Any  # type: ignore
    FieldCondition = Any  # type: ignore
    Filter = Any  # type: ignore
    MatchAny = Any  # type: ignore
    MatchValue = Any  # type: ignore

try:
    from threat_retrieval_engine.search_engine.bm25_index import BM25Index
    from threat_retrieval_engine.search_engine.vector_database import COLLECTION_NAME, search_vectors
except ImportError:
    from bm25_index import BM25Index
    from vector_database import COLLECTION_NAME, search_vectors

logger = logging.getLogger(__name__)

DEFAULT_RRF_K = 60
DEFAULT_CANDIDATE_K = 50   # how many to pull from each retriever before fusion


@dataclass
class HybridResult:
    chunk_id: str
    rrf_score: float
    dense_rank: int | None = None     # 1-based rank in the dense list (None if absent)
    lexical_rank: int | None = None   # 1-based rank in the BM25 list
    dense_score: float | None = None
    payload: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Metadata filter construction
# ---------------------------------------------------------------------------


def build_qdrant_filter(filters: dict[str, Any] | None) -> Filter | None:
    """
    Translate a plain filter dict into a Qdrant ``Filter``.

    Supported forms per key:
      * scalar            -> MatchValue           {"source_org": "CISA"}
      * list              -> MatchAny (OR)        {"cves": ["CVE-2017-0144", ...]}
      * {"gte":.., "lte":..} on published_date -> DatetimeRange
    """
    if not filters:
        return None

    conditions: list[FieldCondition] = []
    for key, value in filters.items():
        if key == "published_date" and isinstance(value, dict):
            conditions.append(
                FieldCondition(
                    key=key,
                    range=DatetimeRange(gte=value.get("gte"), lte=value.get("lte")),
                )
            )
        elif isinstance(value, (list, tuple, set)):
            conditions.append(
                FieldCondition(key=key, match=MatchAny(any=list(value)))
            )
        else:
            conditions.append(
                FieldCondition(key=key, match=MatchValue(value=value))
            )
    return Filter(must=conditions) if conditions else None


def resolve_filter_to_ids(
    qdrant: QdrantClient,
    qfilter: Filter | None,
    limit: int = 10_000,
) -> set[str] | None:
    """
    Scroll Qdrant for every chunk_id satisfying ``qfilter``.
    Returns None when there is no filter (meaning "no restriction").
    """
    if qfilter is None or qdrant is None or qdrant is Any:
        return None
    allowed: set[str] = set()
    next_page = None
    while True:
        points, next_page = qdrant.scroll(
            collection_name=COLLECTION_NAME,
            scroll_filter=qfilter,
            limit=1024,
            offset=next_page,
            with_payload=True,
            with_vectors=False,
        )
        for p in points:
            cid = (p.payload or {}).get("chunk_id")
            if cid:
                allowed.add(cid)
        if next_page is None or len(allowed) >= limit:
            break
    return allowed


# ---------------------------------------------------------------------------
# Reciprocal Rank Fusion
# ---------------------------------------------------------------------------


def reciprocal_rank_fusion(
    ranked_lists: list[list[str]],
    k: int = DEFAULT_RRF_K,
) -> dict[str, float]:
    """
    Fuse several ranked lists of chunk_ids into one score map.
    ``ranked_lists`` is a list of lists, each already ordered best-first.
    """
    scores: dict[str, float] = {}
    for ranked in ranked_lists:
        for rank, chunk_id in enumerate(ranked, start=1):
            scores[chunk_id] = scores.get(chunk_id, 0.0) + 1.0 / (k + rank)
    return scores


# ---------------------------------------------------------------------------
# Hybrid searcher
# ---------------------------------------------------------------------------


class HybridSearcher:
    """
    Ties together the BM25 lexical index and the Qdrant dense index.

    Parameters
    ----------
    qdrant, sqlite : the shared storage handles from ``vector_database.setup_databases``.
    bm25 : a built :class:`BM25Index` (see ``bm25_index.build_from_sqlite``).
    query_encoder : callable(query_text) -> dense vector (list[float]).
        Injected so tests can stub it; use :func:`default_query_encoder` in prod.
    """

    def __init__(
        self,
        qdrant: QdrantClient,
        sqlite: sqlite3.Connection,
        bm25: BM25Index,
        query_encoder: Callable[[str], list[float]],
        rrf_k: int = DEFAULT_RRF_K,
    ) -> None:
        self.qdrant = qdrant
        self.sqlite = sqlite
        self.bm25 = bm25
        self.query_encoder = query_encoder
        self.rrf_k = rrf_k

    def search(
        self,
        query: str,
        top_k: int = 10,
        filters: dict[str, Any] | None = None,
        candidate_k: int = DEFAULT_CANDIDATE_K,
    ) -> list[HybridResult]:
        """
        Run lexical + dense retrieval, fuse with RRF, return the top_k.
        """
        qfilter = build_qdrant_filter(filters)
        allowed_ids = resolve_filter_to_ids(self.qdrant, qfilter)
        if allowed_ids is not None and not allowed_ids:
            logger.info("Filter matched zero documents — empty result set.")
            return []

        # --- dense side (Qdrant) ---
        if self.qdrant is not None and self.qdrant is not Any and self.query_encoder is not None:
            try:
                dense_vec = self.query_encoder(query)
                dense_hits = search_vectors(
                    self.qdrant,
                    query_dense_vector=dense_vec,
                    top_k=candidate_k,
                    filter_dict=None,          # richer filter already applied via qfilter below
                ) if qfilter is None else self._dense_search_filtered(dense_vec, candidate_k, qfilter)
                dense_ranked = [h["chunk_id"] for h in dense_hits if h.get("chunk_id")]
                dense_meta = {h["chunk_id"]: h for h in dense_hits if h.get("chunk_id")}
            except Exception as exc:
                logger.warning("Dense search failed (%s); continuing with lexical only.", exc)
                dense_ranked = []
                dense_meta = {}
        else:
            dense_ranked = []
            dense_meta = {}

        # --- lexical side (BM25) ---
        lexical_hits = self.bm25.search(query, top_k=candidate_k, allowed_ids=allowed_ids)
        lexical_ranked = [h.chunk_id for h in lexical_hits]

        # --- fuse ---
        fused = reciprocal_rank_fusion([dense_ranked, lexical_ranked], k=self.rrf_k)

        dense_pos = {cid: i + 1 for i, cid in enumerate(dense_ranked)}
        lex_pos = {cid: i + 1 for i, cid in enumerate(lexical_ranked)}

        results = [
            HybridResult(
                chunk_id=cid,
                rrf_score=score,
                dense_rank=dense_pos.get(cid),
                lexical_rank=lex_pos.get(cid),
                dense_score=dense_meta.get(cid, {}).get("score"),
                payload=dense_meta.get(cid, {}).get("payload") or {},
            )
            for cid, score in sorted(fused.items(), key=lambda kv: kv[1], reverse=True)
        ]
        return results[:top_k]

    def _dense_search_filtered(
        self, dense_vec: list[float], candidate_k: int, qfilter: Filter
    ) -> list[dict[str, Any]]:
        """Dense search using the full Qdrant Filter object (not the simple dict path)."""
        res = self.qdrant.query_points(
            collection_name=COLLECTION_NAME,
            query=dense_vec,
            using="dense",
            query_filter=qfilter,
            limit=candidate_k,
        )
        return [
            {
                "id": hit.id,
                "chunk_id": (hit.payload or {}).get("chunk_id"),
                "score": hit.score,
                "payload": hit.payload,
            }
            for hit in res.points
        ]


# ---------------------------------------------------------------------------
# Default production query encoder
# ---------------------------------------------------------------------------


def default_query_encoder(vectorizer: Any) -> Callable[[str], list[float]]:
    """
    Build a query-encoder closure over a ``BGEVectorizer`` instance.
    Applies the asymmetric BGE-M3 query prefix at query time.
    """
    from validator import add_query_prefix

    def _encode(query: str) -> list[float]:
        prefixed = add_query_prefix(query)
        result = vectorizer.encode([("__query__", prefixed)])[0]
        return result.dense_vector

    return _encode
