"""
tests/conftest.py
=================
Shared pytest fixtures for the Threat Retrieval & Matching Subsystem.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Ensure root paths are in sys.path
_TEST_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _TEST_DIR.parent
for p in [
    _REPO_ROOT,
    _REPO_ROOT / "threat_retrieval_engine",
    _REPO_ROOT / "threat_retrieval_engine" / "search_engine",
    _REPO_ROOT / "threat_retrieval_engine" / "api",
    _REPO_ROOT / "threat_retrieval_engine" / "benchmarks",
]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from threat_retrieval_engine.api.main import app
from threat_retrieval_engine.api.pipeline import ThreatRetrieverEngine
from threat_retrieval_engine.search_engine.bm25_index import BM25Index
from threat_retrieval_engine.search_engine.mitre_graph import (
    AttackEdge,
    AttackNode,
    MitreAttackGraph,
)


@pytest.fixture
def sample_corpus_conn() -> Generator[sqlite3.Connection, None, None]:
    """Provides an in-memory SQLite database populated with calibrated CTI chunks."""
    conn = sqlite3.connect(":memory:")
    conn.execute(
        """
        CREATE TABLE corpus (
            chunk_id     TEXT PRIMARY KEY,
            doc_id       TEXT NOT NULL,
            doc_title    TEXT NOT NULL,
            source_org   TEXT NOT NULL,
            published_date TEXT NOT NULL,
            char_start   INTEGER,
            char_end     INTEGER,
            text         TEXT NOT NULL,
            enriched_text TEXT NOT NULL,
            entities_json TEXT NOT NULL,
            inserted_at  TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )

    records = [
        (
            "chunk_eb_01",
            "CVE-2017-0144",
            "EternalBlue SMB Remote Code Execution",
            "NVD",
            "2017-03-14",
            0,
            250,
            "Attacker exploited CVE-2017-0144 using T1021.002 from host 198.51.100.24 with PsExec.",
            "CVE-2017-0144 EternalBlue SMB T1021.002 198.51.100.24 PsExec",
            json.dumps({
                "cves": ["CVE-2017-0144"],
                "mitre_ttps": ["T1021.002"],
                "threat_actors": ["APT29"],
                "malware_families": ["PsExec", "WannaCry"],
                "iocs": {
                    "ipv4": ["198.51.100.24"],
                    "ipv6": [],
                    "domains": [],
                    "urls": [],
                    "sha256": [],
                    "md5": [],
                },
                "severity": "CRITICAL",
            }),
        ),
        (
            "chunk_log4j_02",
            "CVE-2021-44228",
            "Apache Log4j Remote Code Execution (Log4Shell)",
            "NVD",
            "2021-12-10",
            0,
            300,
            "Apache Log4j2 JNDI features allow attackers to execute arbitrary code via LDAP lookups.",
            "CVE-2021-44228 Apache Log4j Log4Shell JNDI T1190 LDAP",
            json.dumps({
                "cves": ["CVE-2021-44228"],
                "mitre_ttps": ["T1190"],
                "threat_actors": [],
                "malware_families": [],
                "iocs": {"ipv4": [], "ipv6": [], "domains": [], "urls": [], "sha256": [], "md5": []},
                "severity": "CRITICAL",
            }),
        ),
        (
            "chunk_follina_03",
            "CVE-2022-30190",
            "Microsoft Windows Support Diagnostic Tool (MSDT) Vulnerability",
            "NVD",
            "2022-05-30",
            0,
            280,
            "A remote code execution vulnerability exists in MSDT when called using URL protocol from Word.",
            "CVE-2022-30190 Microsoft Windows MSDT Follina T1059.001 PowerShell",
            json.dumps({
                "cves": ["CVE-2022-30190"],
                "mitre_ttps": ["T1059.001"],
                "threat_actors": [],
                "malware_families": [],
                "iocs": {"ipv4": [], "ipv6": [], "domains": [], "urls": [], "sha256": [], "md5": []},
                "severity": "HIGH",
            }),
        ),
    ]

    conn.executemany(
        """
        INSERT INTO corpus (chunk_id, doc_id, doc_title, source_org, published_date,
                            char_start, char_end, text, enriched_text, entities_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        records,
    )
    conn.commit()

    yield conn
    conn.close()


@pytest.fixture
def sample_mitre_graph() -> MitreAttackGraph:
    """Provides a populated starter ATT&CK graph."""
    g = MitreAttackGraph()
    g.add_node(AttackNode("intrusion-set--apt29", "actor", "APT29", "APT29", ["Cozy Bear"]))
    g.add_node(AttackNode("attack-pattern--t1021-002", "technique", "SMB/Windows Admin Shares", "T1021.002", []))
    g.add_node(AttackNode("tool--psexec", "malware", "PsExec", "PsExec", ["S0029"]))
    g.add_edge(AttackEdge("intrusion-set--apt29", "attack-pattern--t1021-002", "uses"))
    g.add_edge(AttackEdge("intrusion-set--apt29", "tool--psexec", "uses"))
    return g


@pytest.fixture
def sample_bm25_index(sample_corpus_conn: sqlite3.Connection) -> BM25Index:
    """Builds a BM25Index over the sample corpus."""
    idx = BM25Index()
    cursor = sample_corpus_conn.execute("SELECT chunk_id, enriched_text FROM corpus")
    for cid, txt in cursor:
        idx.add(cid, txt)
    idx.finalize()
    return idx


@pytest.fixture
def test_engine(
    sample_corpus_conn: sqlite3.Connection,
    sample_mitre_graph: MitreAttackGraph,
    sample_bm25_index: BM25Index,
) -> ThreatRetrieverEngine:
    """Provides a fully initialized ThreatRetrieverEngine backed by in-memory fixtures."""
    mock_searcher = MagicMock()
    
    # Return structured hits from the BM25 index
    def mock_search(query: str, top_k: int = 20):
        raw_hits = sample_bm25_index.search(query, top_k=top_k)
        mock_hits = []
        for rank, rh in enumerate(raw_hits, start=1):
            h = MagicMock()
            h.chunk_id = rh.chunk_id
            h.rrf_score = 1.0 / (60 + rank)
            h.dense_score = 0.85
            h.lexical_rank = rank
            h.payload = {}
            mock_hits.append(h)
        return mock_hits

    mock_searcher.search.side_effect = mock_search

    engine = ThreatRetrieverEngine(
        qdrant_client=None,
        sqlite_conn=sample_corpus_conn,
        hybrid_searcher=mock_searcher,
        attack_graph=sample_mitre_graph,
        reranker=None,
    )
    engine._initialized = True
    return engine


@pytest.fixture
def test_client() -> Generator[TestClient, None, None]:
    """TestClient fixture for FastAPI endpoints."""
    with patch("threat_retrieval_engine.api.pipeline.ThreatRetrieverEngine.initialize", return_value=None):
        with TestClient(app) as client:
            yield client
