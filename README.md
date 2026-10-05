# UNICC / IITGN Capstone — Team 2: Cyber Threat Intelligence Platform

This repository integrates the complete deliverables of **Team 2**:
* **Subsystem 1 (Knowledge Foundation & Ingestion)**: Normalized CVE feeds, CISA KEV ingestion, and historical threat telemetry.
* **Subsystem 2 (Threat Retrieval & Matching Engine)**: Defense-grade hybrid retrieval, multi-factor composite scoring ($40\%$ IOC, $20\%$ TTP, $20\%$ Semantic, $20\%$ CVE), 5-tier threat classification, citation attribution, and automated RAG evaluation.

---

## 📂 Repository Structure

```text
combined/
├── config/
│   └── retrieval_config.yaml          # Subsystem 2 calibrated weights & thresholds
├── data/
│   ├── benchmark_dataset.json         # Canonical 105 scenario evaluation dataset
│   ├── benchmark_dataset_1000.json    # Scaled 1,000 scenario evaluation dataset
│   ├── golden_dataset.json            # Reference golden threat intelligence corpus
│   ├── corpus_weight_calibration.json # Parameter sweep results across 3-simplex
│   └── weight_optimization_results.json
├── docs/
│   ├── API_REFERENCE.md               # Subsystem 2 REST API endpoints & schemas
│   ├── ARCHITECTURE.md                # Subsystem 2 architecture & components
│   ├── BENCHMARKS.md                  # Comprehensive benchmark evaluation report
│   └── SCORING_RATIO_CALIBRATION.md   # Mathematical derivation & proofs
├── knowledge_foundation/              # Subsystem 1: Teammate Deliverables
│   ├── NORMALIZED_CVE_DATA_GUIDE.md   # Schema reference for normalized CVE records
│   ├── feeds/
│   │   ├── cve_normalized_lookup.py   # Python module for CVE querying & normalization
│   │   ├── lookup.ipynb               # Interactive search & exploration notebook
│   │   └── updater.ipynb              # Automated pipeline to refresh live feeds
│   └── normalized_cves/               # Standardized JSON records (CVE benchmarks)
├── scripts/
│   ├── evaluate.py                    # Root entry point for RAG benchmark suite
│   ├── evaluate_1000_benchmarks.py    # 1,000-scenario evaluation runner
│   ├── expand_dataset_1000.py         # Reproducible dataset generator (N=1,000)
│   ├── simulate_1000_trials.py        # Monte Carlo simulation script
│   └── tune_composite_weights.py      # Simplex grid search optimizer
├── tests/
│   ├── conftest.py                    # Pytest fixtures and test clients
│   ├── test_api.py                    # FastAPI route testing
│   ├── test_benchmarks.py             # Performance & SLA tests
│   ├── test_helpers.py                # Scoring, parsing & citation tests
│   ├── test_metrics.py                # Metric calculation tests
│   ├── test_pipeline.py               # End-to-end pipeline tests
│   ├── test_real_ratio_experiments.py # Empirical ratio verification tests
│   └── test_search_engine.py          # Hybrid retrieval & storage tests
├── threat_retrieval_engine/           # Subsystem 2: Core Retrieval Engine
│   ├── api/                           # FastAPI app, routers, and pipeline
│   ├── benchmarks/                    # Benchmark metrics & evaluators
│   └── search_engine/                 # Vector, lexical, & graph retrieval engine
├── pyproject.toml                     # Python package & dependency configuration
├── .gitignore                         # Standard defense-grade repository exclusions
└── LICENSE                            # Apache 2.0 License
```

---

## 🚀 Quickstart & Setup

### 1. Requirements
* Python 3.11+
* Dependencies: Install via `pip install -e .` or `pip install -r requirements.txt`

### 2. Run the Threat Retrieval API
```bash
uvicorn threat_retrieval_engine.api.main:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Run the Unit & Integration Tests
```bash
pytest tests/ -v
```

### 4. Run the Full 1,000-Scenario Benchmark Evaluation
```bash
python scripts/evaluate_1000_benchmarks.py
```
