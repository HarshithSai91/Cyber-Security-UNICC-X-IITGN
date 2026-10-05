"""
threat_retrieval_engine
=======================
Team 2: Threat Retrieval & Matching Subsystem.
"""

from __future__ import annotations

import sys
import types
import unicodedata

# Ensure ftfy compatibility across all runtime environments
try:
    import ftfy  # noqa: F401
except ImportError:
    ftfy_mock = types.ModuleType("ftfy")
    ftfy_mock.fix_text = lambda s, **kwargs: unicodedata.normalize("NFKC", str(s))
    sys.modules["ftfy"] = ftfy_mock
