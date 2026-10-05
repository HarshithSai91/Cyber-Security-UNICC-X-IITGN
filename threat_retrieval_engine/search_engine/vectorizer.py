"""
vectorizer.py
=============
Turns ThreatChunk objects into dense + sparse vector embeddings using BGE-M3.

Responsibilities:
  1. Load the BAAI/bge-m3 model once (GPU if available, else CPU)
  2. Apply hardware-adaptive batch sizes (64 on GPU, 16 on CPU)
  3. Run single-pass vectorization: 1024-dim dense + SPLADE sparse weights
  4. Apply L2 unit normalization so dot-product == cosine similarity
  5. Accept Strategy-C enriched context strings from validator.build_context()

Output: VectorResult per chunk — ready to be stored in vector_database.py
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# BGE-M3 batch sizes
# ---------------------------------------------------------------------------
GPU_BATCH_SIZE = 64
CPU_BATCH_SIZE = 16


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class VectorResult:
    """Holds everything the vector_database.py needs for one chunk."""

    chunk_id: str
    dense_vector: list[float]                  # 1024-dimensional, L2-normalized
    sparse_vector: dict[int, float]            # SPLADE: {token_id: weight}
    enriched_text: str                         # the context string that was embedded


# ---------------------------------------------------------------------------
# BGE-M3 Vectorizer
# ---------------------------------------------------------------------------


class BGEVectorizer:
    """
    Loads BGE-M3 once and exposes an encode() method for batches of text.

    Usage:
        vectorizer = BGEVectorizer()
        results = vectorizer.encode([(chunk_id, context_text), ...])
    """

    MODEL_NAME = "BAAI/bge-m3"

    def __init__(self, eager_load: bool = False) -> None:
        import torch  # imported lazily so callers using only VectorResult avoid the heavy dep

        self._model: Any = None  # loaded lazily on first call or when eager_load=True
        self._use_gpu = torch.cuda.is_available()
        self._batch_size = GPU_BATCH_SIZE if self._use_gpu else CPU_BATCH_SIZE
        logger.info(
            "BGEVectorizer initialized — device=%s batch_size=%d",
            "CUDA" if self._use_gpu else "CPU",
            self._batch_size,
        )
        if eager_load:
            self._load_model()

    def load_model(self) -> None:
        """Explicitly load the BGE-M3 model weights into memory (e.g. during server startup)."""
        self._load_model()

    def _load_model(self) -> None:
        """Lazy-load the model so import time stays fast."""
        if self._model is not None:
            return
        try:
            from FlagEmbedding import BGEM3FlagModel  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "FlagEmbedding is not installed. Run: pip install FlagEmbedding>=1.2.10"
            ) from exc

        logger.info("Loading BGE-M3 model from %s …", self.MODEL_NAME)
        self._model = BGEM3FlagModel(
            self.MODEL_NAME,
            use_fp16=self._use_gpu,  # fp16 only on GPU
        )
        logger.info("BGE-M3 model loaded successfully.")

    def encode(self, items: list[tuple[str, str]]) -> list[VectorResult]:
        """
        Vectorize a list of (chunk_id, text) pairs.

        Args:
            items: List of (chunk_id, enriched_context_text) tuples.

        Returns:
            List of VectorResult — one per input item.
        """
        self._load_model()

        chunk_ids = [item[0] for item in items]
        texts = [item[1] for item in items]

        results: list[VectorResult] = []

        # Process in hardware-appropriate batches
        for batch_start in range(0, len(texts), self._batch_size):
            batch_texts = texts[batch_start : batch_start + self._batch_size]
            batch_ids = chunk_ids[batch_start : batch_start + self._batch_size]

            logger.info(
                "Vectorizing batch %d–%d of %d …",
                batch_start + 1,
                min(batch_start + self._batch_size, len(texts)),
                len(texts),
            )

            output = self._model.encode(
                batch_texts,
                batch_size=self._batch_size,
                max_length=8192,
                return_dense=True,
                return_sparse=True,
                return_colbert_vecs=False,
            )

            dense_vecs: np.ndarray = output["dense_vecs"]      # shape: (batch, 1024)
            sparse_weights: list[dict] = output["lexical_weights"]  # list of {token_id: weight}

            # L2 unit-normalize dense vectors so dot-product == cosine similarity
            norms = np.linalg.norm(dense_vecs, axis=1, keepdims=True)
            norms = np.where(norms == 0, 1.0, norms)           # avoid divide-by-zero
            dense_vecs = dense_vecs / norms

            for i, (cid, text) in enumerate(zip(batch_ids, batch_texts)):
                # Convert sparse weights: keys may be ints or strings — normalize to int
                raw_sparse: dict = sparse_weights[i]
                sparse: dict[int, float] = {
                    int(k): float(v) for k, v in raw_sparse.items()
                }

                results.append(
                    VectorResult(
                        chunk_id=cid,
                        dense_vector=dense_vecs[i].tolist(),
                        sparse_vector=sparse,
                        enriched_text=text,
                    )
                )

        logger.info("Vectorization complete — %d chunks processed.", len(results))
        return results
