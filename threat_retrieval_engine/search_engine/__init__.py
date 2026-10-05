"""
threat_retrieval_engine.search_engine
=====================================
The core RAG indexing, search, and matching engine.
"""

from .validator import ThreatChunk, build_context
from .tokenizer import tokenize, extract_identifiers
from .duplicate_checker import DuplicateChecker
from .bm25_index import BM25Index, build_from_sqlite
from .exact_lookup import exact_lookup, ExactMatch
from .mitre_graph import MitreAttackGraph, AttackNode, AttackEdge

try:
    from .vectorizer import BGEVectorizer, VectorResult
except ImportError:
    pass

try:
    from .vector_database import (
        COLLECTION_NAME,
        setup_databases,
        store_chunks,
        fetch_text,
        fetch_chunk_metadata,
    )
except ImportError:
    pass

try:
    from .hybrid_search import HybridSearcher, HybridResult
except ImportError:
    pass

try:
    from .reranker import CrossEncoderReranker, RerankedResult
except ImportError:
    pass
