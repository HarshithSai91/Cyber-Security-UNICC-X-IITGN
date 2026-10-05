# Threat Retrieval & Matching Benchmarks

This directory contains the automated benchmark suite, evaluation datasets, and metric computation for the Threat Retrieval & Matching Subsystem.

## 📊 Overview

The benchmark framework measures 6 defense-grade dimensions:
1. **Retrieval Accuracy (R)**: `NDCG@10`, `MAP@10`, `MRR@10`, and `Hit@K` (Hit@1, Hit@3, Hit@5) across multi-hop and ambiguous queries.
2. **Context Quality**: `Context Precision` (signal-to-noise ratio in top retrieved chunks) and `Context Recall` (retrieval coverage of ground truth evidence).
3. **Generation Fidelity (G)**: `Faithfulness` / Groundedness (hallucination rate <= 5%) and `Answer Relevance` (query-answer semantic alignment).
4. **Citation Attribution**: Source document ID accuracy, chunk provenance completeness, and character span overlap F1.
5. **Classification Quality**: `Macro F1` across all 5 confidence tiers (`EXACT`, `STRONG`, `PARTIAL`, `WEAK`, `UNSUPPORTED`) and 5x5 Confusion Matrix.
6. **Latency SLA & Concurrent Stress**: P50, P90, P95 (target <= 200 ms), P99 latency percentiles under single-threaded and concurrent loads (C = 1, 5, 10, 20).

---

## 📁 Files

- `evaluate.py`: The 6-dimension evaluation execution script with concurrent stress testing.
- `metrics.py`: Calculation functions for IR accuracy, context quality, generation faithfulness, citation provenance, classification F1, and latency distributions.
- `benchmark_dataset.json` / `benchmark_dataset_100.json`: 105 calibrated real-world CTI scenarios (CISA KEVs, APT campaigns, multi-hop queries, ambiguous symptoms, benign IT noise).
- `golden_dataset.json`: 105 reference scenarios with candidate chunks and multi-label entity ground truth.
- `benchmark_results.json`: Latest structured evaluation output containing summary metrics, per-query traces, concurrency benchmarks, and quality gate statuses.

---

## 🚀 Running the Benchmarks

### 1. Default Benchmark Run
Run against the calibrated benchmark dataset:
```bash
python threat_retrieval_engine/benchmarks/evaluate.py
```
Or via the root runner:
```bash
python scripts/evaluate.py
```

### 2. Fast Keyword (BM25) Evaluation
To evaluate using Okapi BM25 without neural GPU requirements:
```bash
python threat_retrieval_engine/benchmarks/evaluate.py --retrieval=bm25
```

### 3. Custom Dataset / Output Path
```bash
python threat_retrieval_engine/benchmarks/evaluate.py \
  --dataset=threat_retrieval_engine/benchmarks/golden_dataset.json \
  --output=threat_retrieval_engine/benchmarks/golden_results.json
```

---

## 🎯 Quality Gates

| Gate | Target SLA | Metric |
| :--- | :--- | :--- |
| **Retrieval Gate** | `PASS` | `NDCG@10 >= 0.85` and `MRR@10 >= 0.80` |
| **Latency SLA Gate**| `PASS` | `P95 <= 200.0 ms` |
| **Classification Gate**| Informational | `Macro F1` across all 5 confidence tiers |
