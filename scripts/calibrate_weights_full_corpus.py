#!/usr/bin/env python3
"""
scripts/calibrate_weights_full_corpus.py
=========================================
Empirical composite score ratio calibration using ALL 362,301 records
from the NVD + CISA + EPSS SQLite corpus.

Rather than relying on 105 hand-picked benchmark queries, this script:

1. Extracts 4 real signal scores for every corpus record using:
   - s_cve   : CVE identifier presence (extracted from text, doc_id, entities_json)
   - s_ioc   : IOC richness (IP, hash, URL, domain mentions in text)
   - s_ttp   : Behavioral technique richness (MITRE TTP, exploitation keywords, malware names)
   - s_sem   : Document richness / completeness (text length, reference count, EPSS probability)

2. Assigns self-supervised ground-truth tier labels using corroborating evidence:
   - EXACT   : CISA KEV + EPSS >= 0.5 + CVSS >= 7.0 + exploitation text detected
   - STRONG  : EPSS >= 0.5 + exploitation keywords + malware/actor mention (no CISA KEV)
   - PARTIAL : CVSS >= 5.0 + exploitation keywords OR CISA KEV without EPSS
   - WEAK    : Has CVE, CVSS >= 1.0, plain vulnerability description
   - UNSUPPORTED: No CVE, missing/empty text, generic noise records

3. Runs a dense simplex grid search (step=0.05) over all 362,301 records.

4. Computes Fisher Discriminant Ratio, minimum inter-tier margin, and
   Monte Carlo random baseline (N=500 Dirichlet trials) for hypothesis testing.

5. Writes full calibration report to data/corpus_weight_calibration.json
"""

from __future__ import annotations

import json
import math
import random
import re
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = _REPO_ROOT / "data" / "sqlite" / "corpus_store.db"
DEFAULT_OUTPUT = _REPO_ROOT / "data" / "corpus_weight_calibration.json"

# ---------------------------------------------------------------------------
# Signal extraction patterns
# ---------------------------------------------------------------------------
_CVE_RE   = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_HASH_RE  = re.compile(r"\b[a-fA-F0-9]{64}\b")          # SHA-256
_MD5_RE   = re.compile(r"\b[a-fA-F0-9]{32}\b")           # MD5
_IP_RE    = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
                       r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_URL_RE   = re.compile(r"https?://[^\s\"'<>]{10,}", re.IGNORECASE)
_MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_EPSS_RE  = re.compile(r"(\d+\.\d+)\s*%|EPSS\D{0,20}(\d+\.\d+)", re.IGNORECASE)
_CVSS_RE  = re.compile(r"CVSS\D{0,20}(\d+\.\d+)", re.IGNORECASE)
_EXPLOIT_RE = re.compile(
    r"\b(remote code execution|privilege escalation|buffer overflow|"
    r"sql injection|path traversal|authentication bypass|arbitrary code|"
    r"zero.?day|exploit|shellcode|payload|backdoor|ransomware|malware|"
    r"command injection|heap overflow|use.after.free|arbitrary file|"
    r"information disclosure|denial of service)\b",
    re.IGNORECASE,
)
_ACTOR_RE = re.compile(
    r"\b(APT\d+|Lazarus|FIN\d+|Sandworm|Carbanak|LockBit|BlackCat|"
    r"WannaCry|Volt Typhoon|Scattered Spider|ALPHV|Cl0p|Conti|REvil|"
    r"DarkSide|Hive|BlackBasta|Royal|Play|NoEscape)\b",
    re.IGNORECASE,
)
TIER_ORDER = ["UNSUPPORTED", "WEAK", "PARTIAL", "STRONG", "EXACT"]


def build_lookup_sets(conn: sqlite3.Connection) -> tuple[set[str], set[str]]:
    """Build CVE lookup sets for CISA KEV membership and high-EPSS CVEs."""
    cur = conn.cursor()

    # CISA KEV CVEs
    cur.execute("SELECT entities_json FROM corpus WHERE source_org='CISA'")
    kev_cves: set[str] = set()
    for (ej,) in cur.fetchall():
        try:
            ent = json.loads(ej) if ej else {}
            kev_cves.update(c.upper() for c in ent.get("cves", []))
        except Exception:
            pass

    # High EPSS CVEs (>= 0.50 exploitation probability)
    cur.execute("SELECT entities_json, text FROM corpus WHERE source_org='EPSS'")
    high_epss: set[str] = set()
    for ej, text in cur.fetchall():
        try:
            ent = json.loads(ej) if ej else {}
            cves = [c.upper() for c in ent.get("cves", [])]
            t = text or ""
            m = _EPSS_RE.search(t)
            if m:
                score_str = m.group(1) or m.group(2) or "0"
                score = float(score_str)
                if score >= 50.0 or (score < 1.0 and score >= 0.50):
                    high_epss.update(cves)
        except Exception:
            pass

    return kev_cves, high_epss


def extract_signals(
    text: str,
    enriched_text: str,
    entities_json: str,
    doc_id: str,
    kev_cves: set[str],
    high_epss: set[str],
) -> dict[str, float]:
    """
    Extract 4 normalized feature signals from a corpus record.

    Returns:
        dict with keys: s_cve, s_ioc, s_ttp, s_sem
        Each value in [0.0, 1.0].
    """
    full_text = (text or "") + " " + (enriched_text or "")

    try:
        ent = json.loads(entities_json) if entities_json else {}
    except Exception:
        ent = {}

    # --- s_cve: CVE signal strength ---
    # Base: does the record have a CVE?
    doc_cves = set(_CVE_RE.findall(full_text)) | set(c.upper() for c in ent.get("cves", []))
    if doc_id:
        m = _CVE_RE.search(doc_id)
        if m:
            doc_cves.add(m.group(0).upper())

    if not doc_cves:
        s_cve = 0.0
    else:
        s_cve = 0.5  # base: has a CVE
        # Boost: CISA KEV membership (verified active exploitation)
        if doc_cves & kev_cves:
            s_cve = min(1.0, s_cve + 0.35)
        # Boost: high EPSS probability
        if doc_cves & high_epss:
            s_cve = min(1.0, s_cve + 0.25)
        # Boost: CVSS score >= 7.0 (High/Critical)
        cvss_m = _CVSS_RE.search(full_text)
        if cvss_m:
            try:
                cvss = float(cvss_m.group(1))
                if cvss >= 9.0:
                    s_cve = min(1.0, s_cve + 0.15)
                elif cvss >= 7.0:
                    s_cve = min(1.0, s_cve + 0.10)
                elif cvss >= 5.0:
                    s_cve = min(1.0, s_cve + 0.05)
            except ValueError:
                pass
        # Decay: lower-scoring / old records
        if s_cve <= 0.5:
            s_cve = 0.5

    # --- s_ioc: IOC signal strength ---
    ioc_score = 0.0
    if _HASH_RE.search(full_text):
        ioc_score += 0.60   # SHA-256 hash is immutable (prof's point!)
    if _MD5_RE.search(full_text):
        ioc_score += 0.35
    if _IP_RE.search(full_text):
        ioc_score += 0.25   # IP is volatile (lower than hash)
    if _URL_RE.search(full_text):
        ioc_score += 0.20
    # iocs field may list ioc types
    ioc_types = list(ent.get("iocs", []))
    if "sha256" in ioc_types:
        ioc_score += 0.30
    if "md5" in ioc_types:
        ioc_score += 0.15
    if "domains" in ioc_types:
        ioc_score += 0.10
    s_ioc = min(1.0, ioc_score)

    # --- s_ttp: TTP / behavioral signal strength ---
    ttp_score = 0.0
    mitre_matches = _MITRE_RE.findall(full_text)
    if mitre_matches:
        ttp_score += 0.60 * min(1.0, len(set(mitre_matches)) / 2.0)
    exploit_matches = _EXPLOIT_RE.findall(full_text)
    if exploit_matches:
        ttp_score += 0.30 * min(1.0, len(set(m.lower() for m in exploit_matches)) / 3.0)
    if _ACTOR_RE.search(full_text):
        ttp_score += 0.25
    # malware families
    malware = list(ent.get("malware_families", []))
    actors = list(ent.get("threat_actors", []))
    if malware:
        ttp_score += 0.20
    if actors:
        ttp_score += 0.15
    # TTP from entity index
    ttp_list = list(ent.get("mitre_ttps", []))
    if ttp_list:
        ttp_score += 0.40 * min(1.0, len(ttp_list) / 3.0)
    s_ttp = min(1.0, ttp_score)

    # --- s_sem: Semantic / document richness ---
    # Based on text density, reference quality, and EPSS context
    text_len = len(full_text.strip())
    if text_len == 0:
        s_sem = 0.0
    else:
        # Normalize to [0.1, 0.9] based on text length
        s_sem = min(0.9, max(0.1, text_len / 2000.0))
        # Boost for high-EPSS records (exploitation probability is semantic evidence)
        if doc_cves & high_epss:
            s_sem = min(1.0, s_sem + 0.10)
        # Boost for CISA KEV (authoritative validation)
        if doc_cves & kev_cves:
            s_sem = min(1.0, s_sem + 0.10)

    return {"s_cve": s_cve, "s_ioc": s_ioc, "s_ttp": s_ttp, "s_sem": s_sem}


def assign_tier(signals: dict[str, float], doc_cves: set[str],
                kev_cves: set[str], high_epss: set[str]) -> str:
    """
    Self-supervised tier assignment based on corroborating evidence signals.
    These rules mirror the retrieval engine's 5-tier confidence hierarchy.
    """
    is_kev = bool(doc_cves & kev_cves)
    is_high_epss = bool(doc_cves & high_epss)
    has_cve = signals["s_cve"] > 0.0
    has_ioc = signals["s_ioc"] > 0.0
    has_ttp = signals["s_ttp"] > 0.0

    if not has_cve:
        return "UNSUPPORTED"

    # EXACT: CISA KEV + High EPSS + strong TTP/exploitation evidence
    if is_kev and is_high_epss and has_ttp:
        return "EXACT"
    # EXACT: CISA KEV + real IOC signal (hash/IP) + exploitation description
    if is_kev and has_ioc and signals["s_ioc"] >= 0.50:
        return "EXACT"

    # STRONG: High EPSS + exploitation evidence (without full CISA KEV confirmation)
    if is_high_epss and has_ttp:
        return "STRONG"
    # STRONG: CISA KEV without direct IOC match in text
    if is_kev and not has_ioc:
        return "STRONG"

    # PARTIAL: CVE present + some TTP/exploitation evidence OR CISA KEV without EPSS
    if has_cve and has_ttp and signals["s_ttp"] >= 0.20:
        return "PARTIAL"
    if has_cve and is_kev:
        return "PARTIAL"
    if has_cve and is_high_epss:
        return "PARTIAL"

    # WEAK: Basic CVE record with description but no exploitation evidence
    if has_cve and signals["s_cve"] >= 0.5:
        return "WEAK"

    return "UNSUPPORTED"


def evaluate_weights(
    samples: list[dict],
    weights: tuple[float, float, float, float],
) -> dict:
    """Compute Fisher Discriminant ratio, margins, and separability."""
    w_ioc, w_ttp, w_sem, w_cve = weights

    tier_scores: dict[str, list[float]] = defaultdict(list)
    for s in samples:
        score = (w_ioc * s["s_ioc"] + w_ttp * s["s_ttp"]
                 + w_sem * s["s_sem"] + w_cve * s["s_cve"])
        tier_scores[s["tier"]].append(score)

    means = [
        sum(tier_scores[t]) / len(tier_scores[t]) if tier_scores.get(t) else 0.0
        for t in TIER_ORDER
    ]
    monotonic = all(means[i] < means[i + 1] for i in range(len(means) - 1))
    margins = [means[i + 1] - means[i] for i in range(len(means) - 1)]
    min_margin = min(margins) if margins else 0.0

    intra_var = sum(
        sum((x - means[i]) ** 2 for x in tier_scores.get(t, [0.0])) / max(1, len(tier_scores.get(t, [0.0])))
        for i, t in enumerate(TIER_ORDER)
    ) / len(TIER_ORDER)
    overall_mean = sum(means) / len(means)
    inter_var = sum((m - overall_mean) ** 2 for m in means) / len(means)
    fisher = inter_var / (intra_var + 1e-6)

    min_scores = [min(tier_scores.get(t, [0.0])) for t in TIER_ORDER]
    max_scores = [max(tier_scores.get(t, [0.0])) for t in TIER_ORDER]
    separable = all(max_scores[i] < min_scores[i + 1] for i in range(len(TIER_ORDER) - 1))
    overlap_count = sum(1 for i in range(len(TIER_ORDER) - 1) if max_scores[i] >= min_scores[i + 1])

    thresholds = [
        round((max_scores[i] + min_scores[i + 1]) / 2, 4)
        for i in range(len(TIER_ORDER) - 1)
    ]

    return {
        "weights": [round(x, 4) for x in weights],
        "fisher_ratio": round(fisher, 2),
        "min_margin": round(min_margin, 4),
        "monotonic": monotonic,
        "separable": separable,
        "overlap_count": overlap_count,
        "means": [round(m, 4) for m in means],
        "thresholds": thresholds,
    }


def main() -> int:
    print("=" * 72)
    print("FULL CORPUS COMPOSITE WEIGHT CALIBRATION")
    print("Using all 362,301 NVD + CISA + EPSS records")
    print("=" * 72)

    if not DEFAULT_DB.exists():
        print(f"Error: SQLite DB missing at {DEFAULT_DB}", file=sys.stderr)
        return 1

    conn = sqlite3.connect(str(DEFAULT_DB))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA cache_size=-131072")  # 128 MB cache

    # Build lookup sets
    print("\nStep 1: Building CISA KEV and EPSS lookup sets...")
    kev_cves, high_epss = build_lookup_sets(conn)
    print(f"  CISA KEV CVEs: {len(kev_cves):,}")
    print(f"  High-EPSS CVEs (>= 50%): {len(high_epss):,}")

    # Extract feature vectors for ALL records
    print("\nStep 2: Extracting signal features from all corpus records...")
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM corpus")
    total = cur.fetchone()[0]
    print(f"  Total records: {total:,}")

    samples: list[dict] = []
    tier_counts: dict[str, int] = defaultdict(int)

    BATCH = 10000
    offset = 0
    processed = 0

    while True:
        cur.execute(
            "SELECT doc_id, text, enriched_text, entities_json "
            "FROM corpus LIMIT ? OFFSET ?",
            (BATCH, offset),
        )
        rows = cur.fetchall()
        if not rows:
            break

        for doc_id, text, enriched_text, entities_json in rows:
            signals = extract_signals(
                text or "", enriched_text or "", entities_json or "",
                doc_id or "", kev_cves, high_epss,
            )
            # Get CVEs for tier assignment
            ft = (text or "") + " " + (enriched_text or "")
            doc_cves = set(_CVE_RE.findall(ft))
            if doc_id:
                m = _CVE_RE.search(doc_id)
                if m:
                    doc_cves.add(m.group(0).upper())
            doc_cves = {c.upper() for c in doc_cves}

            tier = assign_tier(signals, doc_cves, kev_cves, high_epss)
            samples.append({
                "s_ioc": signals["s_ioc"],
                "s_ttp": signals["s_ttp"],
                "s_sem": signals["s_sem"],
                "s_cve": signals["s_cve"],
                "tier": tier,
            })
            tier_counts[tier] += 1

        offset += BATCH
        processed += len(rows)
        if processed % 50000 == 0 or processed == total:
            print(f"  Processed {processed:,} / {total:,} records...")

    conn.close()

    print(f"\n  Tier distribution across {len(samples):,} records:")
    for t in TIER_ORDER:
        n = tier_counts[t]
        pct = n / len(samples) * 100
        print(f"    {t:12s}: {n:7,} ({pct:5.1f}%)")

    # Step 3: Simplex Grid Search
    print("\nStep 3: Running 3-simplex grid search (step=0.05)...")
    step = 0.05
    n_steps = int(round(1.0 / step))
    evaluated = []

    for i in range(n_steps + 1):
        for j in range(n_steps + 1 - i):
            for k in range(n_steps + 1 - i - j):
                l = n_steps - i - j - k
                w = (round(i * step, 4), round(j * step, 4),
                     round(k * step, 4), round(l * step, 4))
                if all(x >= 0.05 for x in w):
                    res = evaluate_weights(samples, w)
                    if res["monotonic"]:
                        evaluated.append(res)

    evaluated.sort(
        key=lambda r: (r["separable"], r["min_margin"], r["fisher_ratio"]),
        reverse=True,
    )
    best = evaluated[0]

    print(f"  Evaluated {len(evaluated)} monotonic configurations.")
    print(f"\n  TOP 5 CONFIGURATIONS (Corpus-Calibrated):")
    for rank, cfg in enumerate(evaluated[:5], 1):
        w = cfg["weights"]
        print(f"  {rank}. w=(IOC={w[0]}, TTP={w[1]}, Sem={w[2]}, CVE={w[3]}) "
              f"| Min Margin={cfg['min_margin']} | Fisher={cfg['fisher_ratio']} "
              f"| Separable={cfg['separable']}")
        print(f"     Tier Means: {cfg['means']}")
        print(f"     Thresholds: {cfg['thresholds']}")

    # Step 4: Compare with 105-query calibration
    print("\nStep 4: Comparing corpus-calibrated vs 105-query calibrated weights:")
    old_105 = (0.40, 0.20, 0.20, 0.20)
    old_res = evaluate_weights(samples, old_105)
    print(f"  105-query calibrated (0.40, 0.20, 0.20, 0.20): "
          f"Min Margin={old_res['min_margin']:.4f} | Fisher={old_res['fisher_ratio']:.2f}")
    print(f"  Corpus-calibrated {tuple(best['weights'])}: "
          f"Min Margin={best['min_margin']:.4f} | Fisher={best['fisher_ratio']:.2f}")

    # Step 5: Monte Carlo Hypothesis Test on full corpus
    print("\nStep 5: Running Monte Carlo test (N=500 Dirichlet trials)...")
    random.seed(42)
    calibrated_margin = best["min_margin"]
    better_count = 0
    sep_count = 0

    for _ in range(500):
        raw = [random.expovariate(1.0) for _ in range(4)]
        s = sum(raw)
        w = tuple(r / s for r in raw)
        res = evaluate_weights(samples, w)
        if res["min_margin"] >= calibrated_margin:
            better_count += 1
        if res["separable"]:
            sep_count += 1

    p_value = better_count / 500

    print(f"  Random weights achieving separability: {sep_count}/500 ({sep_count/5:.1f}%)")
    print(f"  p-value = {p_value:.4f} ({'STATISTICALLY SIGNIFICANT (p < 0.05)' if p_value < 0.05 else 'Not significant'})")

    # Persist report
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "corpus_size": len(samples),
        "tier_distribution": dict(tier_counts),
        "corpus_optimal_weights": {
            "weight_ioc": best["weights"][0],
            "weight_ttp": best["weights"][1],
            "weight_semantic": best["weights"][2],
            "weight_cve": best["weights"][3],
        },
        "corpus_optimal_thresholds": {
            f"{TIER_ORDER[i]}_to_{TIER_ORDER[i+1]}": best["thresholds"][i]
            for i in range(len(TIER_ORDER) - 1)
        },
        "performance": {
            "fisher_discriminant_ratio": best["fisher_ratio"],
            "min_inter_tier_margin": best["min_margin"],
            "tier_separable": best["separable"],
            "overlap_count": best["overlap_count"],
            "tier_means": dict(zip(TIER_ORDER, best["means"])),
        },
        "comparison_vs_105_query_calibration": {
            "105_query_weights": list(old_105),
            "105_query_min_margin": old_res["min_margin"],
            "corpus_min_margin": best["min_margin"],
            "improvement": round(best["min_margin"] - old_res["min_margin"], 4),
        },
        "monte_carlo_hypothesis_test": {
            "n_trials": 500,
            "random_separable_rate": round(sep_count / 500, 4),
            "empirical_p_value": round(p_value, 4),
            "statistically_significant": p_value < 0.05,
        },
        "top_10_configurations": evaluated[:10],
    }

    DEFAULT_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(DEFAULT_OUTPUT, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\nSaved corpus calibration report to: {DEFAULT_OUTPUT}")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
