"""
duplicate_checker.py
====================
Detects near-duplicate threat reports before they are stored in the database.

How it works:
  1. Chop text into overlapping 3-word chunks called "shingles".
  2. Compute a MinHash signature (128 permutations) for each chunk.
  3. Use Locality Sensitive Hashing (LSH) to quickly group similar documents.
  4. If two documents share >= 90% of their shingles, the newer one is blocked.

Why 90%?
  With 128 permutations, the math of LSH allows configuring bands and rows
  such that the algorithm's detection curve peaks near 0.90, catching
  real-world copies (which differ only in headers, footers, and dates)
  without false-positiving on reports that merely discuss the same topic.

Output: A filtered list of ThreatChunks with duplicates removed.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Generator, Iterable
try:
    from datasketch import MinHash, MinHashLSH
except ImportError:
    MinHash = Any  # type: ignore
    MinHashLSH = Any  # type: ignore

try:
    from threat_retrieval_engine.search_engine.validator import ThreatChunk
except ImportError:
    from validator import ThreatChunk

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
NUM_PERMUTATIONS = 128
SIMILARITY_THRESHOLD = 0.90   # 90% Jaccard similarity → duplicate
SHINGLE_SIZE = 3               # 3-gram word shingles


# ---------------------------------------------------------------------------
# Shingling
# ---------------------------------------------------------------------------


def _tokenize(text: str) -> list[str]:
    """Lowercase and split into words, stripping punctuation."""
    return re.findall(r"[a-z0-9]+", text.lower())


def _make_shingles(text: str, size: int = SHINGLE_SIZE) -> set[bytes]:
    """
    Convert text to a set of n-gram word shingles.
    Each shingle is 'size' consecutive words joined by a space.
    Encoded as bytes for MinHash compatibility.

    Example (size=3):
      "the hacker used a virus" →
      {"the hacker used", "hacker used a", "used a virus"}
    """
    words = _tokenize(text)
    if len(words) < size:
        # Document too short — treat entire text as one shingle
        return {" ".join(words).encode("utf-8")}
    return {
        " ".join(words[i : i + size]).encode("utf-8")
        for i in range(len(words) - size + 1)
    }


# ---------------------------------------------------------------------------
# MinHash computation
# ---------------------------------------------------------------------------


def _compute_minhash(text: str) -> MinHash:
    """Compute a 128-permutation MinHash signature for a piece of text."""
    m = MinHash(num_perm=NUM_PERMUTATIONS)
    for shingle in _make_shingles(text):
        m.update(shingle)
    return m


# ---------------------------------------------------------------------------
# Duplicate Checker
# ---------------------------------------------------------------------------


class DuplicateChecker:
    """
    Stateful duplicate checker. Feed chunks in one at a time.
    The first time a document appears it is kept.
    Any later document that is >=90% similar to an existing one is dropped.

    Usage:
        checker = DuplicateChecker()
        unique_chunks = list(checker.filter(chunks))
    """

    def __init__(self, threshold: float = SIMILARITY_THRESHOLD) -> None:
        self._lsh = MinHashLSH(threshold=threshold, num_perm=NUM_PERMUTATIONS)
        self._seen: dict[str, str] = {}   # chunk_id → doc_title (for logging)
        self._threshold = threshold
        logger.info(
            "DuplicateChecker initialized — threshold=%.2f permutations=%d shingle_size=%d",
            threshold, NUM_PERMUTATIONS, SHINGLE_SIZE,
        )

    def is_duplicate(self, chunk: ThreatChunk) -> bool:
        """
        Returns True if a near-duplicate of this chunk already exists.
        If not a duplicate, registers this chunk in the index.
        """
        m = _compute_minhash(chunk.text)
        neighbors = self._lsh.query(m)

        if neighbors:
            logger.debug(
                "Duplicate detected: chunk_id=%s similar to %s",
                chunk.chunk_id,
                neighbors[0],
            )
            return True

        # Not a duplicate — register it
        try:
            self._lsh.insert(chunk.chunk_id, m)
            self._seen[chunk.chunk_id] = chunk.doc_title
        except ValueError:
            # chunk_id already inserted (shouldn't happen but be safe)
            pass
        return False

    def filter(self, chunks: Iterable[ThreatChunk]) -> Generator[ThreatChunk, None, None]:
        """
        Yield only unique chunks, dropping near-duplicates.
        Logs how many were dropped.
        """
        total = 0
        dropped = 0
        for chunk in chunks:
            total += 1
            if self.is_duplicate(chunk):
                dropped += 1
            else:
                yield chunk

        logger.info(
            "Deduplication complete — total=%d kept=%d dropped=%d",
            total, total - dropped, dropped,
        )

    def reset(self) -> None:
        """Clear the index (useful between pipeline runs in tests)."""
        self._lsh = MinHashLSH(threshold=self._threshold, num_perm=NUM_PERMUTATIONS)
        self._seen.clear()
