#!/usr/bin/env python3
"""
Evaluate full 1,000 dataset against the Threat Retrieval Engine.
Measures:
1. Exact score distribution (min, max, mean, std) per tier
2. Empirical Safety Margins between all adjacent tiers
3. Classification Accuracy and Confusion Matrix
"""
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

# Setup paths
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from threat_retrieval_engine.api.helpers import (
    calculate_composite_score,
    classify_confidence_tier,
    parse_query_entities
)

def extract_signals_for_query(query_text: str):
    parsed = parse_query_entities(query_text)
    
    # 1. IOC score: direct IP or Hash match
    s_ioc = 1.0 if (parsed.ips or parsed.hashes) else 0.0
    
    # 2. TTP score: MITRE ATT&CK technique or known actor match
    s_ttp = 1.0 if parsed.mitre_techniques else (0.80 if parsed.threat_actors else 0.0)
    
    # 3. CVE score: explicit CVE identifier
    s_cve = 1.0 if parsed.cves else 0.0
    
    # 4. Semantic score: keyword richness / query content
    tokens = set(query_text.lower().split())
    cti_terms = {"vulnerability", "exploit", "cve", "attacker", "ransomware", "lateral", "movement", "c2", "malicious", "payload", "trojan", "advisory"}
    overlap = len(tokens.intersection(cti_terms))
    s_sem = min(1.0, 0.20 + 0.15 * overlap) if overlap > 0 else 0.05
    
    return {
        "s_ioc": s_ioc,
        "s_ttp": s_ttp,
        "s_sem": s_sem,
        "s_cve": s_cve
    }

def evaluate():
    with open('data/benchmark_dataset_1000.json') as f:
        benchmarks = json.load(f)

    print(f"Loaded {len(benchmarks)} benchmark scenarios from data/benchmark_dataset_1000.json.")

    scores_by_tier = defaultdict(list)
    confusion = defaultdict(lambda: defaultdict(int))
    
    weights = (0.40, 0.20, 0.20, 0.20)
    
    for item in benchmarks:
        expected = item["expected_tier"]
        query_text = item["query"]
        
        signals = extract_signals_for_query(query_text)
        
        score = calculate_composite_score(
            ioc_score=signals["s_ioc"],
            ttp_score=signals["s_ttp"],
            semantic_score=signals["s_sem"],
            cve_score=signals["s_cve"],
            weights=weights
        )
        
        predicted = classify_confidence_tier(score)
        
        scores_by_tier[expected].append(score)
        confusion[expected][predicted] += 1

    print("\n" + "="*70)
    print(" EMPIRICAL RESULTS ON 1,000 REALISTIC BENCHMARK SCENARIOS")
    print("="*70)
    
    tier_order = ["UNSUPPORTED", "WEAK", "PARTIAL", "STRONG", "EXACT"]
    
    print(f"{'Tier':<12} {'N':<6} {'Min':<8} {'Max':<8} {'Mean':<8} {'Std':<8}")
    print("-" * 55)
    for t in tier_order:
        sc = scores_by_tier[t]
        n = len(sc)
        s_min = min(sc)
        s_max = max(sc)
        s_mean = sum(sc) / n
        s_std = math.sqrt(sum((x - s_mean) ** 2 for x in sc) / n)
        print(f"{t:<12} {n:<6} {s_min:<8.4f} {s_max:<8.4f} {s_mean:<8.4f} {s_std:<8.4f}")

    print("\n" + "="*70)
    print(" EMPIRICAL SAFETY MARGINS ACROSS 1,000 SCENARIOS")
    print("="*70)
    
    for i in range(len(tier_order) - 1):
        lower_tier = tier_order[i]
        upper_tier = tier_order[i+1]
        max_lower = max(scores_by_tier[lower_tier])
        min_upper = min(scores_by_tier[upper_tier])
        gap = min_upper - max_lower
        print(f"{lower_tier} -> {upper_tier}:")
        print(f"   Max({lower_tier}) = {max_lower:.4f}")
        print(f"   Min({upper_tier}) = {min_upper:.4f}")
        print(f"   Safety Gap = {gap:+.4f}\n")

    total_correct = sum(confusion[t][t] for t in tier_order)
    total_cases = len(benchmarks)
    print("="*70)
    print(f"Overall Tier Classification Accuracy: {total_correct}/{total_cases} ({total_correct/total_cases*100:.2f}%)")
    print("="*70)
    print("\nConfusion Matrix (Rows=Expected, Cols=Predicted):")
    print(f"{'':<14} " + " ".join(f"{t:>11}" for t in tier_order))
    for exp in tier_order:
        row = f"{exp:<14} " + " ".join(f"{confusion[exp][pred]:>11}" for pred in tier_order)
        print(row)

if __name__ == "__main__":
    evaluate()
