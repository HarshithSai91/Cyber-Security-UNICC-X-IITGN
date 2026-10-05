from __future__ import annotations

import json
import logging
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Callable

# Ensure root and internal directories are on sys.path
_API_DIR = Path(__file__).resolve().parent
_ENGINE_DIR = _API_DIR.parent
_ROOT_DIR = _ENGINE_DIR.parent
for p in [_ROOT_DIR, _ENGINE_DIR, _API_DIR, _ENGINE_DIR / "search_engine"]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

try:
    from threat_retrieval_engine.api.helpers import (
        build_citation,
        calculate_composite_score,
        classify_confidence_tier,
        extract_attribution,
        jaccard_similarity,
        parse_query_entities,
        ParsedEntities,
    )
    from threat_retrieval_engine.api.schemas import (
        AttributionSchema,
        CitationSchema,
        EvidenceBreakdownSchema,
        MatchResponse,
        PipelineProfileSchema,
        TopMatchSchema,
    )
except ImportError:
    try:
        from api.helpers import (
            build_citation,
            calculate_composite_score,
            classify_confidence_tier,
            extract_attribution,
            jaccard_similarity,
            parse_query_entities,
            ParsedEntities,
        )
        from api.schemas import (
            AttributionSchema,
            CitationSchema,
            EvidenceBreakdownSchema,
            MatchResponse,
            PipelineProfileSchema,
            TopMatchSchema,
        )
    except ImportError:
        from helpers import (
            build_citation,
            calculate_composite_score,
            classify_confidence_tier,
            extract_attribution,
            jaccard_similarity,
            parse_query_entities,
            ParsedEntities,
        )
        from schemas import (
            AttributionSchema,
            CitationSchema,
            EvidenceBreakdownSchema,
            MatchResponse,
            PipelineProfileSchema,
            TopMatchSchema,
        )

logger = logging.getLogger(__name__)


def _build_starter_attack_graph():
    """Construct an in-memory starter ATT&CK graph if enterprise-attack.json is not present."""
    from mitre_graph import MitreAttackGraph, AttackNode, AttackEdge

    g = MitreAttackGraph()
    # Core Actors
    g.add_node(AttackNode(stix_id="intrusion-set--apt29", kind="actor", name="APT29", attack_id="APT29", aliases=["Cozy Bear", "G0016"]))
    g.add_node(AttackNode(stix_id="intrusion-set--fin7", kind="actor", name="FIN7", attack_id="FIN7", aliases=["G0046"]))
    g.add_node(AttackNode(stix_id="malware--wannacry", kind="actor", name="WannaCry", attack_id="WannaCry", aliases=["S0366"]))
    
    # Core Techniques
    g.add_node(AttackNode(stix_id="attack-pattern--t1021-002", kind="technique", name="SMB/Windows Admin Shares", attack_id="T1021.002", aliases=[]))
    g.add_node(AttackNode(stix_id="attack-pattern--t1059-001", kind="technique", name="PowerShell", attack_id="T1059.001", aliases=[]))
    g.add_node(AttackNode(stix_id="attack-pattern--t1190", kind="technique", name="Exploit Public-Facing Application", attack_id="T1190", aliases=[]))

    # Core Malware / Tools
    g.add_node(AttackNode(stix_id="tool--psexec", kind="malware", name="PsExec", attack_id="PsExec", aliases=["S0029"]))
    g.add_node(AttackNode(stix_id="tool--cobaltstrike", kind="malware", name="Cobalt Strike", attack_id="Cobalt Strike", aliases=["S0154"]))

    # Core Edges
    g.add_edge(AttackEdge(source="intrusion-set--apt29", target="attack-pattern--t1021-002", relationship="uses"))
    g.add_edge(AttackEdge(source="intrusion-set--apt29", target="tool--psexec", relationship="uses"))
    g.add_edge(AttackEdge(source="malware--wannacry", target="attack-pattern--t1021-002", relationship="uses"))
    g.add_edge(AttackEdge(source="intrusion-set--fin7", target="attack-pattern--t1021-002", relationship="uses"))
    g.add_edge(AttackEdge(source="tool--psexec", target="attack-pattern--t1021-002", relationship="implements"))

    return g


class ThreatRetrieverEngine:
    """
    Unified Orchestrator coordinating:
      Engine 1: Exact Match (exact_lookup.py)
      Engine 2: Vector Hybrid Search (hybrid_search.py via BGE-M3 + BM25)
      Engine 3: MITRE ATT&CK Knowledge Graph (mitre_graph.py)
    """

    def __init__(
        self,
        qdrant_client=None,
        sqlite_conn=None,
        hybrid_searcher=None,
        attack_graph=None,
        reranker=None,
    ) -> None:
        self.qdrant = qdrant_client
        self.sqlite = sqlite_conn
        self.hybrid_searcher = hybrid_searcher
        self.attack_graph = attack_graph
        self.reranker = reranker
        self._initialized = False

    def initialize(self, qdrant_path: str | None = None, sqlite_path: str | None = None) -> None:
        """Initialize all three search engines and knowledge graph."""
        if self._initialized:
            return

        # 1. Databases (Qdrant + SQLite)
        if self.qdrant is None or self.sqlite is None:
            from vector_database import setup_databases
            db_kwargs = {}
            if qdrant_path:
                db_kwargs["qdrant_path"] = qdrant_path
            if sqlite_path:
                db_kwargs["sqlite_path"] = sqlite_path
            self.qdrant, self.sqlite = setup_databases(**db_kwargs)

        # 2. Knowledge Graph (MITRE STIX)
        if self.attack_graph is None:
            bundle_path = Path("./data/mitre/enterprise-attack.json")
            if bundle_path.is_file():
                from mitre_graph import load_attack_bundle
                self.attack_graph = load_attack_bundle(bundle_path)
            else:
                self.attack_graph = _build_starter_attack_graph()

        # 3. Hybrid Searcher (BM25 + BGE-M3)
        if self.hybrid_searcher is None:
            from bm25_index import build_from_sqlite, BM25Index
            from hybrid_search import HybridSearcher, default_query_encoder

            try:
                bm25 = build_from_sqlite(self.sqlite)
            except Exception:
                bm25 = BM25Index()

            # Vectorizer: Eagerly load model weights at startup & run warmup inference
            try:
                from vectorizer import BGEVectorizer
                logger.info("Pre-loading BGE-M3 embedding model during server startup...")
                vectorizer = BGEVectorizer(eager_load=True)
                query_encoder = default_query_encoder(vectorizer)
                # Warm up so first query does not suffer PyTorch initialization latency
                query_encoder("startup warmup query")
                logger.info("BGE-M3 embedding model preloaded and warmed up successfully.")
            except Exception as exc:
                logger.warning("BGEVectorizer load deferred or stubbed: %s", exc)
                query_encoder = lambda q: [0.0] * 1024

            self.hybrid_searcher = HybridSearcher(
                qdrant=self.qdrant,
                sqlite=self.sqlite,
                bm25=bm25,
                query_encoder=query_encoder,
            )

        # 4. Cross-Encoder Reranker
        if self.reranker is None:
            try:
                from reranker import CrossEncoderReranker
                logger.info("Pre-loading Cross-Encoder Reranker during server startup...")
                reranker_instance = CrossEncoderReranker()
                reranker_instance._load()
                self.reranker = reranker_instance
                logger.info("Reranker preloaded successfully.")
            except Exception as exc:
                logger.warning("Reranker load deferred or stubbed: %s", exc)
                self.reranker = None

        self._initialized = True
        logger.info("ThreatRetrieverEngine initialized with all engines.")

    def run_query(
        self,
        query: str,
        top_k: int = 5,
        alpha: float = 0.5,
    ) -> MatchResponse:
        """Execute exact match, vector hybrid search, and knowledge graph expansion."""
        import threading
        if not hasattr(self, "_lock") or self._lock is None:
            self._lock = threading.RLock()

        with self._lock:
            return self._run_query_internal(query=query, top_k=top_k, alpha=alpha)

    def _run_query_internal(
        self,
        query: str,
        top_k: int = 5,
        alpha: float = 0.5,
    ) -> MatchResponse:
        t_total_start = time.perf_counter()
        self.initialize()

        from exact_lookup import exact_lookup
        from vector_database import fetch_chunk_metadata, fetch_text

        query_threat_id = f"query_{int(time.time())}"
        query_ent = parse_query_entities(query)

        # -------------------------------------------------------------------
        # Engine 1: Exact Match Lookup (Qdrant & SQLite)
        # -------------------------------------------------------------------
        t_exact_start = time.perf_counter()
        exact_results = []
        try:
            exact_matches = exact_lookup(
                self.qdrant,
                self.sqlite,
                query=query,
                limit=top_k,
                hydrate=True,
            )
            for m in exact_matches:
                meta = m.metadata or fetch_chunk_metadata(m.chunk_id, self.sqlite) or {}
                txt = meta.get("text") or fetch_text(m.chunk_id, self.sqlite) or ""
                exact_results.append({
                    "chunk_id": m.chunk_id,
                    "doc_id": meta.get("doc_id", ""),
                    "source_org": meta.get("source_org", ""),
                    "text": txt,
                    "metadata": meta,
                    "entities": meta.get("entities", {}),
                    "exact_score": 1.0,
                    "dense_score": 1.0,
                })
        except Exception as exc:
            logger.warning("Exact match lookup encountered error: %s", exc)
        exact_match_ms = (time.perf_counter() - t_exact_start) * 1000

        # -------------------------------------------------------------------
        # Engine 2: Vector Hybrid Search (BGE-M3 + BM25 RRF)
        # -------------------------------------------------------------------
        t_vec_start = time.perf_counter()
        hybrid_results = []
        try:
            search_k = max(top_k * 4, 20)
            hits = self.hybrid_searcher.search(query=query, top_k=search_k)
            for h in hits:
                hybrid_results.append({
                    "chunk_id": h.chunk_id,
                    "rrf_score": h.rrf_score,
                    "dense_score": h.dense_score,
                    "lexical_rank": h.lexical_rank,
                    "payload": h.payload or {},
                })
        except Exception as exc:
            logger.warning("Hybrid search encountered error: %s", exc)
        vector_database_ms = (time.perf_counter() - t_vec_start) * 1000

        # -------------------------------------------------------------------
        # Merge & Hydrate Candidates from SQLite
        # -------------------------------------------------------------------
        candidate_map: dict[str, dict[str, Any]] = {}
        for er in exact_results:
            cid = er["chunk_id"]
            meta = er.get("metadata") or fetch_chunk_metadata(cid, self.sqlite) or {}
            txt = er.get("text") or fetch_text(cid, self.sqlite) or ""
            candidate_map[cid] = {
                "chunk_id": cid,
                "text": txt,
                "metadata": meta,
                "is_exact": True,
                "dense_score": er["dense_score"],
                "rrf_score": 1.0,
            }

        for hr in hybrid_results:
            cid = hr["chunk_id"]
            if cid not in candidate_map:
                meta = fetch_chunk_metadata(cid, self.sqlite) or {}
                txt = fetch_text(cid, self.sqlite) or (hr["payload"].get("text", "") if hr.get("payload") else "")
                candidate_map[cid] = {
                    "chunk_id": cid,
                    "text": txt,
                    "metadata": meta,
                    "is_exact": False,
                    "dense_score": hr["dense_score"],
                    "rrf_score": hr["rrf_score"],
                }

        # If no candidates returned from DB or search engines, candidate_map remains empty.

        # -------------------------------------------------------------------
        # Engine 2.5: Cross-Encoder Reranking
        # -------------------------------------------------------------------
        t_rerank_start = time.perf_counter()
        if getattr(self, "reranker", None) and candidate_map:
            try:
                # Pass candidates to reranker
                rerank_pairs = [(cid, c.get("text", "")) for cid, c in candidate_map.items()]
                reranked = self.reranker.rerank(query, rerank_pairs, top_k=top_k)
                
                # Rebuild candidate map using only the top_k reranked results
                new_candidate_map = {}
                for res in reranked:
                    cid = res.chunk_id
                    c = candidate_map[cid]
                    # Inject the cross-encoder score as the new semantic score
                    c["dense_score"] = res.rerank_score
                    new_candidate_map[cid] = c
                candidate_map = new_candidate_map
            except Exception as exc:
                logger.warning("Reranking bypassed: %s", exc)
            
        rerank_ms = (time.perf_counter() - t_rerank_start) * 1000
        # Add to vector_database_ms for profiling schema compliance
        vector_database_ms += rerank_ms

        # -------------------------------------------------------------------
        # Engine 3: Knowledge Graph Expansion (MITRE ATT&CK)
        # -------------------------------------------------------------------
        t_kg_start = time.perf_counter()
        chunk_graph_relations: dict[str, list[str]] = {}

        for cid, cand in candidate_map.items():
            meta = cand.get("metadata") or {}
            txt = cand.get("text") or ""
            raw_ent = meta.get("entities") or {}
            if isinstance(raw_ent, str):
                try:
                    raw_ent = json.loads(raw_ent)
                except Exception:
                    raw_ent = {}

            # Extract all mentions from text and metadata
            attr_dict = extract_attribution(query_ent, meta, txt)

            chunk_actors = list(raw_ent.get("threat_actors", [])) + query_ent.threat_actors
            chunk_ttps = list(set(raw_ent.get("mitre_ttps", []) + query_ent.mitre_techniques + attr_dict["matching_mitre_techniques"]))
            chunk_malware = list(set(raw_ent.get("malware_families", []) + query_ent.malware + attr_dict["shared_malware"]))

            expanded = self.attack_graph.expand(
                threat_actors=chunk_actors,
                techniques=chunk_ttps,
                malware=chunk_malware,
            )
            rels = list(expanded.get("relationships", []))

            # Enrich with authentic STIX relationships for any actors discovered during graph traversal
            for actor in expanded.get("actors", []):
                rels.extend(self.attack_graph.relationship_paths(actor))

            # Preserve order and eliminate duplicates
            chunk_graph_relations[cid] = list(dict.fromkeys(rels))

        knowledge_graph_ms = (time.perf_counter() - t_kg_start) * 1000

        # -------------------------------------------------------------------
        # Scoring & Classification
        # -------------------------------------------------------------------
        t_score_start = time.perf_counter()
        scored_candidates = []

        for cid, cand in candidate_map.items():
            meta = cand.get("metadata") or {}
            txt = cand.get("text") or ""
            attr_dict = extract_attribution(query_ent, meta, txt)

            # Calculate subscores based on query entity matching
            if query_ent.cves:
                cve_sim = 1.0 if attr_dict["matching_cves"] else 0.0
            else:
                cve_sim = 0.0

            if query_ent.ips or query_ent.hashes:
                ioc_sim = 1.0 if attr_dict["matching_iocs"] else 0.0
            else:
                ioc_sim = 0.0

            if query_ent.mitre_techniques:
                ttp_sim = 1.0 if attr_dict["matching_mitre_techniques"] else (0.85 if attr_dict["shared_malware"] else 0.0)
            elif attr_dict["shared_malware"]:
                ttp_sim = 0.85
            else:
                ttp_sim = 0.0

            has_threat_signals = bool(
                query_ent.cves or query_ent.ips or query_ent.hashes or
                query_ent.mitre_techniques or query_ent.malware or
                attr_dict["matching_cves"] or attr_dict["matching_iocs"] or
                attr_dict["matching_mitre_techniques"] or attr_dict["shared_malware"]
            )
            raw_dense = cand.get("dense_score")
            if raw_dense is not None:
                semantic_sim = float(raw_dense)
            elif has_threat_signals:
                semantic_sim = 0.58
            else:
                semantic_sim = 0.05

            composite = calculate_composite_score(
                ioc_score=ioc_sim,
                ttp_score=ttp_sim,
                semantic_score=semantic_sim,
                cve_score=cve_sim,
            )

            tier = classify_confidence_tier(composite)

            scored_candidates.append({
                "chunk_id": cid,
                "composite_score": composite,
                "confidence_tier": tier,
                "evidence_breakdown": EvidenceBreakdownSchema(
                    ioc_similarity=round(ioc_sim, 2),
                    cve_similarity=round(cve_sim, 2),
                    ttp_similarity=round(ttp_sim, 2),
                    semantic_similarity=round(semantic_sim, 2),
                ),
                "metadata": meta,
                "text": txt,
                "stix_relationships": chunk_graph_relations.get(cid, []),
                "attribution": attr_dict,
            })

        # Sort candidates descending by composite score
        scored_candidates.sort(key=lambda x: x["composite_score"], reverse=True)
        top_candidates = scored_candidates[:top_k]
        scoring_ms = (time.perf_counter() - t_score_start) * 1000

        # -------------------------------------------------------------------
        # Attribution & Citations
        # -------------------------------------------------------------------
        t_cite_start = time.perf_counter()
        top_matches: list[TopMatchSchema] = []

        for rank, cand in enumerate(top_candidates, start=1):
            attr_dict = extract_attribution(query_ent, cand["metadata"], cand["text"])
            citation_dict = build_citation(cand["chunk_id"], cand["metadata"], cand["text"])

            top_matches.append(
                TopMatchSchema(
                    rank=rank,
                    chunk_id=cand["chunk_id"],
                    composite_score=cand["composite_score"],
                    confidence_tier=cand["confidence_tier"],
                    evidence_breakdown=cand["evidence_breakdown"],
                    attribution=AttributionSchema(**attr_dict),
                    stix_relationships=cand["stix_relationships"],
                    citations=[CitationSchema(**citation_dict)],
                )
            )
        citation_ms = (time.perf_counter() - t_cite_start) * 1000

        total_ms = (time.perf_counter() - t_total_start) * 1000

        return MatchResponse(
            query_threat_id=query_threat_id,
            top_matches=top_matches,
            pipeline_profile=PipelineProfileSchema(
                exact_match_ms=round(exact_match_ms, 1),
                vector_database_ms=round(vector_database_ms, 1),
                knowledge_graph_ms=round(knowledge_graph_ms, 1),
                scoring_ms=round(scoring_ms, 1),
                citation_ms=round(citation_ms, 1),
                total_ms=round(total_ms, 1),
            ),
        )


# Global singleton instance for FastAPI lifespan
_orchestrator = ThreatRetrieverEngine()


def get_orchestrator() -> ThreatRetrieverEngine:
    return _orchestrator
