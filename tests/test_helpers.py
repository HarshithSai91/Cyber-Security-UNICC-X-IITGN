"""
tests/test_helpers.py
=====================
Precise unit tests for the empirically calibrated composite scoring formula
and 5-tier confidence classification. Every assertion uses EXACT floating-point
arithmetic derived directly from the calibrated optimal parameters:

    S = 0.40 * IOC + 0.20 * TTP + 0.20 * Semantic + 0.20 * CVE

Calibrated Maximum-Margin Decision Boundaries:
    UNSUPPORTED → WEAK    : 0.10
    WEAK        → PARTIAL : 0.45
    PARTIAL     → STRONG  : 0.65
    STRONG      → EXACT   : 0.85
"""

from __future__ import annotations

import math

try:
    import pytest
except ImportError:
    class _PytestStub:
        @staticmethod
        def approx(expected, abs=1e-9):
            class _ApproxVal:
                def __init__(self, val: float, tol: float):
                    self.val = val
                    self.tol = tol
                def __eq__(self, actual: object) -> bool:
                    if not isinstance(actual, (int, float)):
                        return False
                    return math.isclose(float(actual), self.val, abs_tol=self.tol)
            return _ApproxVal(expected, abs)
    pytest = _PytestStub()

from threat_retrieval_engine.api.helpers import (
    build_citation,
    calculate_composite_score,
    classify_confidence_tier,
    extract_attribution,
    jaccard_similarity,
    parse_query_entities,
    CALIBRATED_SCORING_WEIGHTS,
    CALIBRATED_CONFIDENCE_THRESHOLDS,
)

# ---------------------------------------------------------------------------
# Constants — mirror exactly what is in helpers.py
# ---------------------------------------------------------------------------
W = CALIBRATED_SCORING_WEIGHTS          # (0.40, 0.20, 0.20, 0.20)
TH = CALIBRATED_CONFIDENCE_THRESHOLDS

W_IOC = W[0]   # 0.40
W_TTP = W[1]   # 0.20
W_SEM = W[2]   # 0.20
W_CVE = W[3]   # 0.20


# ===========================================================================
# GROUP 1 — Entity Extraction
# ===========================================================================

def test_parse_cve_ip_mitre_malware() -> None:
    """CVE, IPv4, MITRE technique, and known malware are all extracted correctly."""
    query = "Attacker exploited CVE-2017-0144 from 198.51.100.24 using T1021.002 with PsExec"
    parsed = parse_query_entities(query)

    assert parsed.cves == ["CVE-2017-0144"]
    assert "198.51.100.24" in parsed.ips
    assert "T1021.002" in parsed.mitre_techniques
    assert "PsExec" in parsed.malware


def test_parse_cve_case_insensitive() -> None:
    """CVE IDs are normalised to uppercase regardless of query casing."""
    parsed = parse_query_entities("vulnerability cve-2022-30190 was used")
    assert "CVE-2022-30190" in parsed.cves


def test_parse_multiple_cves() -> None:
    """Multiple CVEs in a single query are all captured."""
    parsed = parse_query_entities("CVE-2021-44228 and CVE-2021-26855 were chained")
    assert "CVE-2021-44228" in parsed.cves
    assert "CVE-2021-26855" in parsed.cves


def test_parse_sha256_and_md5() -> None:
    """Both SHA-256 (64 hex chars) and MD5 (32 hex chars) hashes are extracted."""
    query = (
        "Payload MD5 5d41402abc4b2a76b9719d911017c592 "
        "SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    parsed = parse_query_entities(query)
    assert "5d41402abc4b2a76b9719d911017c592" in parsed.hashes
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in parsed.hashes


def test_parse_empty_query() -> None:
    """Empty query returns empty entity lists — no crash."""
    parsed = parse_query_entities("")
    assert parsed.cves == []
    assert parsed.ips == []
    assert parsed.hashes == []
    assert parsed.mitre_techniques == []


# ===========================================================================
# GROUP 2 — Jaccard Similarity
# ===========================================================================

def test_jaccard_identical_sets() -> None:
    assert jaccard_similarity(["a", "b", "c"], ["a", "b", "c"]) == 1.0


def test_jaccard_disjoint_sets() -> None:
    assert jaccard_similarity(["a", "b"], ["c", "d"]) == 0.0


def test_jaccard_empty_sets() -> None:
    assert jaccard_similarity([], []) == 0.0


def test_jaccard_partial_overlap() -> None:
    # |intersection| = 1 (a), |union| = 3 (a, b, c) -> 1/3
    result = jaccard_similarity(["a", "b"], ["a", "c"])
    assert result == pytest.approx(1.0 / 3.0, abs=1e-9)


def test_jaccard_case_insensitive() -> None:
    """Jaccard normalises to lowercase before comparison."""
    assert jaccard_similarity(["CVE-2021"], ["cve-2021"]) == 1.0


# ===========================================================================
# GROUP 3 — Composite Score Formula (Exact Arithmetic)
# ===========================================================================

def test_formula_all_ones() -> None:
    """All signals at maximum -> score = 0.40 + 0.20 + 0.20 + 0.20 = 1.0."""
    assert calculate_composite_score(1.0, 1.0, 1.0, 1.0) == 1.0


def test_formula_all_zeros() -> None:
    """All signals at zero -> score = 0.0."""
    assert calculate_composite_score(0.0, 0.0, 0.0, 0.0) == 0.0


def test_formula_ioc_only() -> None:
    """IOC signal alone contributes exactly w_IOC = 0.40."""
    assert calculate_composite_score(1.0, 0.0, 0.0, 0.0) == 0.40


def test_formula_ttp_only() -> None:
    """TTP signal alone contributes exactly w_TTP = 0.20."""
    assert calculate_composite_score(0.0, 1.0, 0.0, 0.0) == 0.20


def test_formula_semantic_only() -> None:
    """Semantic signal alone contributes exactly w_Sem = 0.20."""
    assert calculate_composite_score(0.0, 0.0, 1.0, 0.0) == 0.20


def test_formula_cve_only() -> None:
    """CVE signal alone contributes exactly w_CVE = 0.20."""
    assert calculate_composite_score(0.0, 0.0, 0.0, 1.0) == 0.20


def test_formula_strong_canonical() -> None:
    """STRONG tier canonical vector: IOC=1.0, TTP=0.85, Sem=0.82, CVE=0.0."""
    # 0.40*1.0 + 0.20*0.85 + 0.20*0.82 + 0.20*0.0
    # = 0.40   + 0.17      + 0.164     + 0.0 = 0.734
    assert calculate_composite_score(1.0, 0.85, 0.82, 0.0) == 0.7340


def test_formula_partial_canonical() -> None:
    """PARTIAL tier canonical vector: IOC=0.0, TTP=0.85, Sem=0.74, CVE=1.0."""
    # 0.40*0.0 + 0.20*0.85 + 0.20*0.74 + 0.20*1.0
    # = 0.0    + 0.17      + 0.148     + 0.20 = 0.518
    assert calculate_composite_score(0.0, 0.85, 0.74, 1.0) == 0.5180


def test_formula_strong_beats_partial_wide_margin() -> None:
    """STRONG canonical (0.7340) outscores PARTIAL canonical (0.5180) by a wide margin (+0.2160)."""
    strong = calculate_composite_score(1.0, 0.85, 0.82, 0.0)
    partial = calculate_composite_score(0.0, 0.85, 0.74, 1.0)
    margin = round(strong - partial, 4)
    assert margin == 0.2160, f"Expected margin +0.2160, got {margin}"


def test_formula_unsupported_canonical() -> None:
    """UNSUPPORTED benign noise vector: all signals near-zero -> score = 0.0160."""
    # 0.20 * 0.08 = 0.016
    assert calculate_composite_score(0.0, 0.0, 0.08, 0.0) == 0.0160


def test_formula_exact_canonical() -> None:
    """EXACT tier canonical vector: all signals strong -> score = 0.9800."""
    # 0.40*1.0 + 0.20*1.0 + 0.20*0.90 + 0.20*1.0 = 0.40 + 0.20 + 0.18 + 0.20 = 0.98
    assert calculate_composite_score(1.0, 1.0, 0.90, 1.0) == 0.9800


def test_formula_linearity() -> None:
    """Superposition: score(A+B) == score(A) + score(B) for non-overlapping signals."""
    score_a = calculate_composite_score(1.0, 0.0, 0.0, 0.0)
    score_b = calculate_composite_score(0.0, 0.0, 0.0, 1.0)
    score_ab = calculate_composite_score(1.0, 0.0, 0.0, 1.0)
    assert score_ab == pytest.approx(score_a + score_b, abs=1e-9)


def test_formula_monotonicity() -> None:
    """Increasing any single signal strictly increases composite score."""
    base = calculate_composite_score(0.5, 0.5, 0.5, 0.5)
    assert calculate_composite_score(0.9, 0.5, 0.5, 0.5) > base
    assert calculate_composite_score(0.5, 0.9, 0.5, 0.5) > base
    assert calculate_composite_score(0.5, 0.5, 0.9, 0.5) > base
    assert calculate_composite_score(0.5, 0.5, 0.5, 0.9) > base


def test_formula_weights_sum_to_one() -> None:
    """Simplex constraint: weights form a valid probability distribution."""
    assert sum(W) == pytest.approx(1.0, abs=1e-9)
    assert all(w >= 0.05 for w in W)


def test_formula_custom_weights() -> None:
    """Custom weight override works correctly."""
    score = calculate_composite_score(
        ioc_score=0.0, ttp_score=1.0, semantic_score=0.8, cve_score=1.0,
        weights=(0.35, 0.25, 0.25, 0.15),
    )
    assert score == 0.60


# ===========================================================================
# GROUP 4 — Tier Classification (Exact Boundary Values)
# ===========================================================================

def test_classify_exact_tier_boundaries() -> None:
    """EXACT: score in [0.85, 1.0]."""
    assert classify_confidence_tier(0.85) == "EXACT"
    assert classify_confidence_tier(0.98) == "EXACT"
    assert classify_confidence_tier(1.00) == "EXACT"


def test_classify_strong_tier_boundaries() -> None:
    """STRONG: score in [0.65, 0.8499]."""
    assert classify_confidence_tier(0.65) == "STRONG"
    assert classify_confidence_tier(0.7340) == "STRONG"
    assert classify_confidence_tier(0.8499) == "STRONG"


def test_classify_partial_tier_boundaries() -> None:
    """PARTIAL: score in [0.45, 0.6499]."""
    assert classify_confidence_tier(0.45) == "PARTIAL"
    assert classify_confidence_tier(0.5180) == "PARTIAL"
    assert classify_confidence_tier(0.6499) == "PARTIAL"


def test_classify_weak_tier_boundaries() -> None:
    """WEAK: score in [0.10, 0.4499]."""
    assert classify_confidence_tier(0.10) == "WEAK"
    assert classify_confidence_tier(0.3160) == "WEAK"
    assert classify_confidence_tier(0.4499) == "WEAK"


def test_classify_unsupported_tier_boundaries() -> None:
    """UNSUPPORTED: score below 0.10."""
    assert classify_confidence_tier(0.0160) == "UNSUPPORTED"
    assert classify_confidence_tier(0.0999) == "UNSUPPORTED"
    assert classify_confidence_tier(0.0000) == "UNSUPPORTED"


def test_classify_all_five_tiers_distinct() -> None:
    """All 5 tiers map to distinct, non-overlapping score segments."""
    scores = {
        "UNSUPPORTED": 0.05,
        "WEAK":        0.25,
        "PARTIAL":     0.55,
        "STRONG":      0.75,
        "EXACT":       0.95,
    }
    for exp, sc in scores.items():
        assert classify_confidence_tier(sc) == exp


# ===========================================================================
# GROUP 5 — Attribution and Citation
# ===========================================================================

def test_extract_attribution_cve_and_mitre() -> None:
    query = "Attacker exploited CVE-2017-0144 using T1021.002"
    parsed = parse_query_entities(query)
    metadata = {
        "entities": {
            "cves": ["CVE-2017-0144"],
            "mitre_ttps": ["T1021.002"],
            "threat_actors": ["APT29"],
            "malware_families": ["PsExec"],
            "iocs": {"ipv4": ["198.51.100.24"]},
        }
    }
    text = "Attacker executed T1021.002 over SMB."
    attr = extract_attribution(parsed, metadata, text)
    assert "CVE-2017-0144" in attr["matching_cves"]
    assert "T1021.002" in attr["matching_mitre_techniques"]


def test_build_citation_fields() -> None:
    metadata = {
        "doc_id": "CVE-2021-44228",
        "doc_title": "Apache Log4j Vulnerability",
        "source_org": "NVD",
        "published_date": "2021-12-10",
        "char_start": 0,
        "char_end": 150,
    }
    text = "JNDI lookup vulnerability in Log4j enables remote arbitrary code execution."
    citation = build_citation("chunk_123", metadata, text)
    assert citation["doc_id"] == "CVE-2021-44228"
    assert citation["source_org"] == "NVD"
    assert "JNDI lookup" in citation["text_snippet"]
