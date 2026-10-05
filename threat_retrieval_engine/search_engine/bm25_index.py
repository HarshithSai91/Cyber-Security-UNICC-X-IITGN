"""
bm25_index.py
=============
In-memory Okapi BM25 lexical search index over the CTI corpus.

This is the *keyword* half of hybrid retrieval. It complements the dense
BGE-M3 vector index: dense search captures paraphrase / semantic similarity,
BM25 nails exact technical tokens (CVE ids, hashes, IPs, product names) that
embeddings routinely blur.

Design notes
------------
* Pure Python, zero extra dependencies — the ranking math is ~40 lines.
* Uses the cyber-aware :func:`tokenizer.tokenize`, so ``CVE-2017-0144`` and
  ``198.51.100.24`` are single terms.
* Built directly from the SQLite corpus store (see :func:`build_from_sqlite`),
  so it always mirrors what was actually indexed into Qdrant.
* Search accepts an optional ``allowed_ids`` allow-list, which is how
  search-time metadata filtering is enforced (the caller resolves the filter to
  a set of chunk_ids, e.g. via a Qdrant payload scroll, and passes it in).

Okapi BM25 score for query Q against document D:

    score(D, Q) = Σ_t IDF(t) * ( f(t,D) * (k1 + 1) )
                              / ( f(t,D) + k1 * (1 - b + b * |D| / avgdl) )

    IDF(t) = ln( 1 + (N - n(t) + 0.5) / (n(t) + 0.5) )
"""

from __future__ import annotations

import logging
import math
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field

try:
    from threat_retrieval_engine.search_engine.tokenizer import tokenize
except ImportError:
    from tokenizer import tokenize

logger = logging.getLogger(__name__)

# Standard Okapi BM25 hyper-parameters
DEFAULT_K1 = 1.5
DEFAULT_B = 0.75


@dataclass
class BM25Result:
    chunk_id: str
    score: float


@dataclass
class BM25Index:
    """
    A lightweight inverted-index BM25 ranker.

    Usage
    -----
        idx = BM25Index()
        idx.add("chunk_1", "text about CVE-2017-0144 ...")
        idx.add("chunk_2", "...")
        idx.finalize()
        hits = idx.search("psexec lateral movement", top_k=50)
    """

    k1: float = DEFAULT_K1
    b: float = DEFAULT_B

    # Internal state
    _doc_len: dict[str, int] = field(default_factory=dict)
    _term_freqs: dict[str, dict[str, int]] = field(default_factory=dict)  # chunk_id -> {term: tf}
    _postings: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))  # term -> chunk_ids
    _avgdl: float = 0.0
    _finalized: bool = False

    # -- indexing ----------------------------------------------------------

    def add(self, chunk_id: str, text: str) -> None:
        """Add or replace one document in the index."""
        tokens = tokenize(text)
        tf: dict[str, int] = defaultdict(int)
        for tok in tokens:
            tf[tok] += 1

        # If replacing an existing doc, retract its old postings first
        if chunk_id in self._term_freqs:
            for old_term in self._term_freqs[chunk_id]:
                self._postings[old_term].discard(chunk_id)

        self._term_freqs[chunk_id] = dict(tf)
        self._doc_len[chunk_id] = len(tokens)
        for term in tf:
            self._postings[term].add(chunk_id)
        self._finalized = False

    def finalize(self) -> None:
        """Compute the average document length. Call once after all adds."""
        if self._doc_len:
            self._avgdl = sum(self._doc_len.values()) / len(self._doc_len)
        else:
            self._avgdl = 0.0
        self._finalized = True
        logger.info(
            "BM25 index finalized — docs=%d unique_terms=%d avgdl=%.1f",
            len(self._doc_len), len(self._postings), self._avgdl,
        )

    @property
    def size(self) -> int:
        return len(self._doc_len)

    # -- search ------------------------------------------------------------

    def _idf(self, term: str, n_docs: int) -> float:
        n_t = len(self._postings.get(term, ()))
        if n_t == 0:
            return 0.0
        return math.log(1 + (n_docs - n_t + 0.5) / (n_t + 0.5))

    def search(
        self,
        query: str,
        top_k: int = 50,
        allowed_ids: set[str] | None = None,
    ) -> list[BM25Result]:
        """
        Rank documents against ``query``.

        Parameters
        ----------
        query : str
            Raw query text (tokenized with the same cyber-aware tokenizer).
        top_k : int
            Number of results to return.
        allowed_ids : set[str] | None
            If given, only these chunk_ids are considered — this is the
            search-time metadata filter hook. An empty set yields no results.
        """
        if not self._finalized:
            self.finalize()

        n_docs = len(self._doc_len)
        if n_docs == 0:
            return []

        query_terms = tokenize(query)
        if not query_terms:
            return []

        scores: dict[str, float] = defaultdict(float)
        for term in query_terms:
            postings = self._postings.get(term, ())
            # Skip stop words / ultra-high-frequency terms present in >20% of docs
            if not postings or (n_docs > 500 and len(postings) > n_docs * 0.20):
                continue
            idf = self._idf(term, n_docs)
            if idf <= 0.0:
                continue
            for chunk_id in postings:  # only docs containing the term
                if allowed_ids is not None and chunk_id not in allowed_ids:
                    continue
                tf = self._term_freqs[chunk_id][term]
                dl = self._doc_len[chunk_id]
                denom = tf + self.k1 * (1 - self.b + self.b * dl / self._avgdl)
                scores[chunk_id] += idf * (tf * (self.k1 + 1)) / denom

        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        return [BM25Result(chunk_id=cid, score=sc) for cid, sc in ranked[:top_k]]


# ---------------------------------------------------------------------------
# Corpus loaders
# ---------------------------------------------------------------------------


def build_from_sqlite(
    conn: sqlite3.Connection,
    text_column: str = "enriched_text",
    k1: float = DEFAULT_K1,
    b: float = DEFAULT_B,
) -> BM25Index:
    """
    Build a BM25 index from the SQLite ``corpus`` table.

    ``enriched_text`` (the Strategy-C context that was actually embedded) is used
    by default so lexical and dense sides see the same surface text; pass
    ``text_column="text"`` to index only the raw prose.
    """
    if text_column not in {"text", "enriched_text"}:
        raise ValueError("text_column must be 'text' or 'enriched_text'")

    idx = BM25Index(k1=k1, b=b)
    cursor = conn.execute(f"SELECT chunk_id, {text_column} FROM corpus")
    count = 0
    for chunk_id, text in cursor:
        idx.add(chunk_id, text or "")
        count += 1
    idx.finalize()
    logger.info("Built BM25 index from SQLite — %d documents.", count)
    return idx
