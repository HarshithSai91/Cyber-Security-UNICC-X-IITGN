#!/usr/bin/env python3
"""
scripts/evaluate.py
===================
Root entry point redirecting to threat_retrieval_engine/benchmarks/evaluate.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add repo root to sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from threat_retrieval_engine.benchmarks.evaluate import main

if __name__ == "__main__":
    main()
