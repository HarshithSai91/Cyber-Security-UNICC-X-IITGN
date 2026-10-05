"""
tests/test_search_engine.py
===========================
Unit tests for the underlying search engine modules:
  - BM25Index (bm25_index.py)
  - MitreAttackGraph (mitre_graph.py)
  - Tokenizer (tokenizer.py)
"""

from __future__ import annotations

import pytest
from threat_retrieval_engine.search_engine.bm25_index import BM25Index
from threat_retrieval_engine.search_engine.mitre_graph import (
    AttackEdge,
    AttackNode,
    MitreAttackGraph,
)
from threat_retrieval_engine.search_engine.tokenizer import tokenize


def test_cyber_aware_tokenizer() -> None:
    text = "Attacker exploited CVE-2017-0144 using 198.51.100.24 and T1021.002."
    tokens = tokenize(text)

    # CVE, IP address, and MITRE TTP should remain preserved as whole tokens
    assert "cve-2017-0144" in tokens or "CVE-2017-0144" in [t.upper() for t in tokens]
    assert "198.51.100.24" in tokens
    assert "t1021.002" in tokens or "T1021.002" in [t.upper() for t in tokens]


def test_bm25_index_add_and_search() -> None:
    idx = BM25Index()
    idx.add("doc_1", "Log4j remote code execution CVE-2021-44228 in JNDI lookup")
    idx.add("doc_2", "EternalBlue SMB exploit CVE-2017-0144 lateral movement")
    idx.add("doc_3", "Windows MSDT Follina remote code execution CVE-2022-30190")
    idx.finalize()

    assert idx.size == 3

    hits = idx.search("EternalBlue SMB", top_k=2)
    assert len(hits) > 0
    assert hits[0].chunk_id == "doc_2"


def test_bm25_index_allowed_ids_filtering() -> None:
    idx = BM25Index()
    idx.add("doc_1", "vulnerability in Apache")
    idx.add("doc_2", "vulnerability in Microsoft")
    idx.finalize()

    # Allow only doc_1
    hits = idx.search("vulnerability", allowed_ids={"doc_1"})
    assert len(hits) == 1
    assert hits[0].chunk_id == "doc_1"


def test_mitre_attack_graph_expansion() -> None:
    g = MitreAttackGraph()
    # Nodes
    g.add_node(AttackNode("intrusion-set--apt29", "actor", "APT29", "APT29", ["Cozy Bear"]))
    g.add_node(AttackNode("attack-pattern--t1021-002", "technique", "SMB Admin Shares", "T1021.002", []))
    g.add_node(AttackNode("tool--psexec", "malware", "PsExec", "PsExec", []))

    # Edges
    g.add_edge(AttackEdge("intrusion-set--apt29", "attack-pattern--t1021-002", "uses"))
    g.add_edge(AttackEdge("tool--psexec", "attack-pattern--t1021-002", "implements"))

    assert "intrusion-set--apt29" in g.nodes
    assert "attack-pattern--t1021-002" in g.nodes

    # Query relations from technique
    connected = g.neighbors("T1021.002", direction="both")
    assert len(connected) >= 2
    names = [n.name for n in connected]
    assert "APT29" in names
    assert "PsExec" in names
