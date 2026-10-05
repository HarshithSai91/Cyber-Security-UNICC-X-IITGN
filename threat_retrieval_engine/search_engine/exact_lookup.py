"""
exact_lookup.py
===============
Deterministic exact-identifier lookup — the fast path for IOC and CVE queries.

When an analyst pastes a raw observable ("has CVE-2017-0144 shown up before?",
"who owns 198.51.100.24?", a file hash from a sandbox) there is no need to run
dense/lexical ranking at all: an exact string match is both faster and more
correct. This module short-circuits straight to the matching chunks.

Two backends are used, picking whichever is authoritative for each identifier
kind:

* **Qdrant payload filter** for the keyword-indexed fields (``cves``,
  ``mitre_ttps``, ``threat_actors``) — an indexed, near-constant-time match.
* **SQLite ``entities_json`` scan** for IOCs (IPv4/IPv6, hashes, domains, URLs)
  which live in the corpus store but are not Qdrant payload indexes.

The caller can pass either explicit identifiers or a free-text query; in the
latter case identifiers are pulled out with :func:`tokenizer.extract_identifiers`.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass, field
from typing import Any

try:
    from qdrant_client import QdrantClient
    from qdrant_client.models import FieldCondition, Filter, MatchAny
except ImportError:
    QdrantClient = Any  # type: ignore

try:
    from threat_retrieval_engine.search_engine.tokenizer import extract_identifiers
    from threat_retrieval_engine.search_engine.vector_database import COLLECTION_NAME, fetch_chunk_metadata
except ImportError:
    from tokenizer import extract_identifiers
    from vector_database import COLLECTION_NAME, fetch_chunk_metadata

logger = logging.getLogger(__name__)

# Map identifier kinds from the tokenizer onto where they can be found.
# Qdrant-indexed keyword fields:
_QDRANT_FIELDS = {
    "cve": "cves",
    "mitre": "mitre_ttps",
}
# SQLite entities_json paths (matched as JSON string literals):
_SQLITE_KINDS = ("ipv4", "ipv6", "hash", "domain", "url")


@dataclass
class ExactMatch:
    chunk_id: str
    matched_field: str          # e.g. "cves", "iocs.ipv4"
    matched_value: str          # the identifier that matched
    metadata: dict[str, Any] = field(default_factory=dict)


def _qdrant_lookup(
    qdrant: QdrantClient,
    field_name: str,
    values: list[str],
    limit: int,
) -> list[tuple[str, str]]:
    """Return (chunk_id, matched_value) via a Qdrant payload filter (MatchAny)."""
    if not values:
        return []
    # Qdrant keyword payloads for CVEs are stored upper-case; match both cases.
    variants = sorted({v for val in values for v in (val, val.upper(), val.lower())})
    flt = Filter(must=[FieldCondition(key=field_name, match=MatchAny(any=variants))])
    points, _ = qdrant.scroll(
        collection_name=COLLECTION_NAME,
        scroll_filter=flt,
        limit=limit,
        with_payload=True,
        with_vectors=False,
    )
    out: list[tuple[str, str]] = []
    value_set = {v.lower() for v in variants}
    for p in points:
        payload = p.payload or {}
        cid = payload.get("chunk_id")
        if not cid:
            continue
        # Report which requested value actually matched
        hit_val = next(
            (fv for fv in payload.get(field_name, []) if str(fv).lower() in value_set),
            values[0],
        )
        out.append((cid, str(hit_val)))
    return out


def _sqlite_lookup(
    sqlite: sqlite3.Connection,
    value: str,
    limit: int,
) -> list[str]:
    """Find chunk_ids whose entities match ``value`` via entity_index or entities_json."""
    try:
        rows = sqlite.execute(
            "SELECT chunk_id FROM entity_index WHERE entity_value = ? LIMIT ?",
            (value, limit),
        ).fetchall()
        if rows:
            return [r[0] for r in rows]
    except Exception:
        pass
    needle = f'%"{value}"%'
    rows = sqlite.execute(
        "SELECT chunk_id FROM corpus WHERE entities_json LIKE ? LIMIT ?",
        (needle, limit),
    ).fetchall()
    return [r[0] for r in rows]


def exact_lookup(
    qdrant: QdrantClient,
    sqlite: sqlite3.Connection,
    query: str | None = None,
    identifiers: dict[str, list[str]] | None = None,
    limit: int = 50,
    hydrate: bool = True,
) -> list[ExactMatch]:
    """
    Look up historical chunks that contain the given security identifiers.

    Parameters
    ----------
    query : str | None
        Free-text query; identifiers are auto-extracted from it.
    identifiers : dict[str, list[str]] | None
        Explicit identifiers keyed by kind ("cve", "ipv4", "ipv6", "hash",
        "domain", "url", "mitre"). Merged with anything found in ``query``.
    limit : int
        Max matches per identifier kind.
    hydrate : bool
        If True, attach full chunk metadata (text, doc_id, provenance) from SQLite.

    Returns
    -------
    list[ExactMatch] — de-duplicated by chunk_id (first match wins).
    """
    ids: dict[str, list[str]] = {}
    if query:
        for kind, vals in extract_identifiers(query).items():
            ids.setdefault(kind, []).extend(vals)
    if identifiers:
        for kind, vals in identifiers.items():
            ids.setdefault(kind, []).extend(v.lower() for v in vals)

    if not ids:
        return []

    seen: set[str] = set()
    matches: list[ExactMatch] = []

    def _record(chunk_id: str, field_name: str, value: str) -> None:
        if chunk_id in seen:
            return
        seen.add(chunk_id)
        meta = fetch_chunk_metadata(chunk_id, sqlite) if hydrate else {}
        matches.append(
            ExactMatch(
                chunk_id=chunk_id,
                matched_field=field_name,
                matched_value=value,
                metadata=meta or {},
            )
        )

    # 1) Qdrant-indexed keyword fields (CVEs, MITRE techniques)
    for kind, field_name in _QDRANT_FIELDS.items():
        vals = ids.get(kind)
        if not vals:
            continue
        if qdrant is not None and QdrantClient is not Any:
            try:
                for cid, matched_val in _qdrant_lookup(qdrant, field_name, vals, limit):
                    _record(cid, field_name, matched_val)
            except Exception as exc:  # noqa: BLE001 — payload index may be absent
                logger.warning("Qdrant exact lookup on %s failed (%s); skipping.", field_name, exc)
        else:
            for val in vals:
                v_clean = val.upper()
                rows = sqlite.execute(
                    "SELECT chunk_id FROM corpus WHERE doc_id = ? OR doc_id LIKE ? LIMIT ?",
                    (v_clean, f"{v_clean}%", limit),
                ).fetchall()
                if not rows:
                    try:
                        rows = sqlite.execute(
                            "SELECT chunk_id FROM entity_index WHERE entity_value = ? OR entity_value = ? LIMIT ?",
                            (v_clean, val, limit),
                        ).fetchall()
                    except Exception:
                        pass
                for (cid,) in rows:
                    _record(cid, field_name, v_clean)

    # 2) SQLite IOC scan (IPs, hashes, domains, URLs)
    for kind in _SQLITE_KINDS:
        for value in ids.get(kind, []):
            for cid in _sqlite_lookup(sqlite, value, limit):
                _record(cid, f"iocs.{kind}", value)

    logger.info("Exact lookup matched %d chunk(s) across %d identifier kinds.",
                len(matches), len(ids))
    return matches
