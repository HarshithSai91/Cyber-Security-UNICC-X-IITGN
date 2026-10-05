"""
vector_database.py
==================
Manages both storage backends:

  1. Qdrant (in-process, embedded on disk) — stores dense + sparse vectors
     with Int8 scalar quantization and payload filter indexes.
  2. SQLite (WAL mode) — stores full text, raw metadata, and provenance.

Workflow:
  - Call setup_databases() once at startup.
  - Call store_chunks(vector_results, chunks) to persist a batch.
  - Call fetch_text(chunk_id) to retrieve full text by ID from SQLite.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

try:
    from qdrant_client import QdrantClient
    from qdrant_client.models import (
        Distance,
        FieldCondition,
        Filter,
        HnswConfigDiff,
        MatchValue,
        PayloadSchemaType,
        PointStruct,
        ScalarQuantizationConfig,
        ScalarType,
        SparseVector,
        SparseVectorParams,
        VectorParams,
    )
except ImportError:
    QdrantClient = Any  # type: ignore

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent

try:
    from threat_retrieval_engine.search_engine.vectorizer import VectorResult
except Exception:
    VectorResult = Any  # type: ignore

try:
    from threat_retrieval_engine.search_engine.validator import ThreatChunk
except Exception:
    ThreatChunk = Any  # type: ignore

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults (anchored to repository root, can be overridden via config)
# ---------------------------------------------------------------------------
DEFAULT_QDRANT_PATH = str(_REPO_ROOT / "data" / "qdrant_storage")
DEFAULT_SQLITE_PATH = str(_REPO_ROOT / "data" / "sqlite" / "corpus_store.db")
COLLECTION_NAME = "threat_intelligence_kb"
DENSE_DIM = 1024

# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------


def setup_qdrant(qdrant_path: str = DEFAULT_QDRANT_PATH, reset: bool = False) -> Any:
    """
    Initialize embedded Qdrant (zero Docker, zero ports — runs in-process on disk).
    Creates the threat_intelligence_kb collection if it does not already exist.
    """
    if QdrantClient is None or QdrantClient is Any:
        logger.info("QdrantClient is not installed or available; operating without Qdrant.")
        return None
    try:
        Path(qdrant_path).mkdir(parents=True, exist_ok=True)
        client = QdrantClient(path=qdrant_path)
        logger.info("Qdrant embedded client ready at: %s", qdrant_path)
    except Exception as exc:
        logger.warning("Failed to initialize Qdrant at %s: %s; running without Qdrant.", qdrant_path, exc)
        return None

    existing = {col.name for col in client.get_collections().collections}
    if reset and COLLECTION_NAME in existing:
        logger.info("Resetting Qdrant collection '%s' …", COLLECTION_NAME)
        client.delete_collection(COLLECTION_NAME)
        existing.remove(COLLECTION_NAME)

    if COLLECTION_NAME not in existing:
        logger.info("Creating Qdrant collection '%s' …", COLLECTION_NAME)
        client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config={
                "dense": VectorParams(size=DENSE_DIM, distance=Distance.COSINE)
            },
            sparse_vectors_config={
                "sparse": SparseVectorParams()
            },
            hnsw_config=HnswConfigDiff(m=32, ef_construct=200),
            quantization_config=ScalarQuantizationConfig(
                type=ScalarType.INT8,
                quantile=0.99,
                always_ram=True,
            ),
        )

        # Payload filter indexes — for fast pre-filtered search
        for field_name in ("source_org", "severity", "cves", "mitre_ttps", "threat_actors"):
            client.create_payload_index(
                collection_name=COLLECTION_NAME,
                field_name=field_name,
                field_schema=PayloadSchemaType.KEYWORD,
            )
        client.create_payload_index(
            collection_name=COLLECTION_NAME,
            field_name="published_date",
            field_schema=PayloadSchemaType.DATETIME,
        )
        logger.info("Collection '%s' created with all payload indexes.", COLLECTION_NAME)
    else:
        logger.info("Collection '%s' already exists — skipping creation.", COLLECTION_NAME)

    return client


def setup_sqlite(sqlite_path: str = DEFAULT_SQLITE_PATH, reset: bool = False) -> sqlite3.Connection:
    """
    Open the SQLite corpus store in WAL mode for fast concurrent reads.
    Creates the table if it does not exist.
    """
    Path(sqlite_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(sqlite_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA case_sensitive_like=ON;")
    if reset:
        logger.info("Resetting SQLite table 'corpus' …")
        conn.execute("DROP TABLE IF EXISTS corpus;")
        conn.commit()

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS corpus (
            chunk_id     TEXT PRIMARY KEY,
            doc_id       TEXT NOT NULL,
            doc_title    TEXT NOT NULL,
            source_org   TEXT NOT NULL,
            published_date TEXT NOT NULL,
            char_start   INTEGER,
            char_end     INTEGER,
            text         TEXT NOT NULL,
            enriched_text TEXT NOT NULL,
            entities_json TEXT NOT NULL,
            inserted_at  TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    conn.commit()
    logger.info("SQLite corpus store ready at: %s", sqlite_path)
    return conn


def setup_databases(
    qdrant_path: str = DEFAULT_QDRANT_PATH,
    sqlite_path: str = DEFAULT_SQLITE_PATH,
    reset: bool = False,
) -> tuple[QdrantClient, sqlite3.Connection]:
    """Call once at startup. Returns (qdrant_client, sqlite_conn)."""
    qdrant = setup_qdrant(qdrant_path, reset=reset)
    sqlite = setup_sqlite(sqlite_path, reset=reset)
    return qdrant, sqlite


# ---------------------------------------------------------------------------
# Store chunks
# ---------------------------------------------------------------------------


def store_chunks(
    vector_results: list[VectorResult],
    chunks: list[ThreatChunk],
    qdrant: QdrantClient,
    sqlite: sqlite3.Connection,
) -> None:
    """
    Persist a batch of vector results + their source ThreatChunks.

    - Dense + sparse vectors → Qdrant (with searchable payload)
    - Full text + metadata  → SQLite (fetched by chunk_id after search)
    """
    chunk_map: dict[str, ThreatChunk] = {c.chunk_id: c for c in chunks}

    qdrant_points: list[PointStruct] = []
    sqlite_rows: list[tuple] = []

    for vr in vector_results:
        chunk = chunk_map.get(vr.chunk_id)
        if chunk is None:
            logger.warning("No ThreatChunk found for chunk_id=%s — skipping.", vr.chunk_id)
            continue

        # Build Qdrant payload (metadata stored alongside vector)
        payload: dict[str, Any] = {
            "chunk_id": chunk.chunk_id,
            "doc_id": chunk.doc_id,
            "doc_title": chunk.doc_title,
            "source_org": chunk.source_org,
            "published_date": chunk.published_date.isoformat(),
            "severity": chunk.entities.severity,
            "cves": chunk.entities.cves,
            "mitre_ttps": chunk.entities.mitre_ttps,
            "threat_actors": chunk.entities.threat_actors,
            "malware_families": chunk.entities.malware_families,
            "char_start": chunk.char_start,
            "char_end": chunk.char_end,
        }

        sparse_indices = list(vr.sparse_vector.keys())
        sparse_values = list(vr.sparse_vector.values())

        qdrant_points.append(
            PointStruct(
                id=_chunk_id_to_uint(vr.chunk_id),
                vector={
                    "dense": vr.dense_vector,
                    "sparse": SparseVector(indices=sparse_indices, values=sparse_values),
                },
                payload=payload,
            )
        )

        sqlite_rows.append((
            chunk.chunk_id,
            chunk.doc_id,
            chunk.doc_title,
            chunk.source_org,
            chunk.published_date.isoformat(),
            chunk.char_start,
            chunk.char_end,
            chunk.text,
            vr.enriched_text,
            json.dumps(chunk.entities.model_dump()),
        ))

    # Qdrant upsert
    if qdrant_points:
        qdrant.upsert(collection_name=COLLECTION_NAME, points=qdrant_points)
        logger.info("Upserted %d vectors into Qdrant.", len(qdrant_points))

    # SQLite insert (ignore duplicates)
    if sqlite_rows:
        sqlite.executemany(
            """
            INSERT OR IGNORE INTO corpus
                (chunk_id, doc_id, doc_title, source_org, published_date,
                 char_start, char_end, text, enriched_text, entities_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            sqlite_rows,
        )
        sqlite.commit()
        logger.info("Inserted %d rows into SQLite.", len(sqlite_rows))


# ---------------------------------------------------------------------------
# Search and Fetch Operations (For Suhani & Harshith Sai)
# ---------------------------------------------------------------------------


def search_vectors(
    qdrant: QdrantClient,
    query_dense_vector: list[float],
    top_k: int = 10,
    filter_dict: dict[str, Any] | None = None,
    collection_name: str = COLLECTION_NAME,
) -> list[dict[str, Any]]:
    """
    Search the Qdrant index using a dense vector with optional metadata filtering.
    Used by Suhani (for hybrid search fusion) and Harshith Sai (for matching).
    """
    if qdrant is None or qdrant is Any:
        return []
    query_filter = None
    if filter_dict:
        conditions = [
            FieldCondition(key=k, match=MatchValue(value=v))
            for k, v in filter_dict.items()
        ]
        query_filter = Filter(must=conditions)

    res = qdrant.query_points(
        collection_name=collection_name,
        query=query_dense_vector,
        using="dense",
        query_filter=query_filter,
        limit=top_k,
    )
    return [
        {
            "id": hit.id,
            "chunk_id": hit.payload.get("chunk_id") if hit.payload else None,
            "score": hit.score,
            "payload": hit.payload,
        }
        for hit in res.points
    ]


def fetch_text(chunk_id: str, sqlite: sqlite3.Connection) -> str | None:
    """
    Sub-millisecond lookup of the full prose text by chunk_id.
    Call this after a Qdrant search returns a list of chunk IDs.
    """
    row = sqlite.execute(
        "SELECT text FROM corpus WHERE chunk_id = ?", (chunk_id,)
    ).fetchone()
    return row[0] if row else None


def fetch_chunk_metadata(chunk_id: str, sqlite: sqlite3.Connection) -> dict[str, Any] | None:
    """Return full metadata row (including character offsets) for a chunk_id."""
    row = sqlite.execute(
        "SELECT chunk_id, doc_id, doc_title, source_org, published_date, "
        "char_start, char_end, text, enriched_text, entities_json "
        "FROM corpus WHERE chunk_id = ?",
        (chunk_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "chunk_id": row[0],
        "doc_id": row[1],
        "doc_title": row[2],
        "source_org": row[3],
        "published_date": row[4],
        "char_start": row[5],
        "char_end": row[6],
        "text": row[7],
        "enriched_text": row[8],
        "entities": json.loads(row[9]),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _chunk_id_to_uint(chunk_id: str) -> int:
    """
    Qdrant point IDs must be unsigned integers or UUIDs.
    We hash the chunk_id to a stable unsigned 64-bit integer.
    Works for both hex chunk_ids (from make_chunk_id) and arbitrary strings (tests).
    """
    import hashlib
    digest = hashlib.sha256(chunk_id.encode("utf-8")).digest()
    # Take first 8 bytes → 64-bit unsigned int
    return int.from_bytes(digest[:8], byteorder="big")
