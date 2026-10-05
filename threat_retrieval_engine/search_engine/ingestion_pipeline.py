"""
ingestion_pipeline.py
=====================
The CTI data ingestion and indexing pipeline orchestrator.

Pipeline flow (in order):
  1. validator.py   — Parse raw data → ThreatChunks (clean + validated)
  2. duplicate_checker.py — Drop near-duplicate chunks (90% threshold)
  3. vectorizer.py  — Embed unique chunks with BGE-M3 (dense + sparse)
  4. vector_database.py — Store vectors in Qdrant, full text in SQLite

Usage:
    python ingestion_pipeline.py
    python ingestion_pipeline.py --feeds kev,epss
    python ingestion_pipeline.py --reset --max-chunks 1000

    Or run with --help to see all options.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent

try:
    from threat_retrieval_engine.search_engine.validator import (
        ThreatChunk,
        build_context,
        parse_cisa_kev_csv,
        parse_cvelist_directory,
        parse_epss_csv,
        parse_normalized_directory,
        parse_normalized_jsonl,
        parse_nvd_directory,
    )
    from threat_retrieval_engine.search_engine.duplicate_checker import DuplicateChecker
    from threat_retrieval_engine.search_engine.vectorizer import BGEVectorizer
    from threat_retrieval_engine.search_engine.vector_database import setup_databases, store_chunks
except ImportError:
    from validator import (
        ThreatChunk,
        build_context,
        parse_cisa_kev_csv,
        parse_cvelist_directory,
        parse_epss_csv,
        parse_normalized_directory,
        parse_normalized_jsonl,
        parse_nvd_directory,
    )
    from duplicate_checker import DuplicateChecker
    from vectorizer import BGEVectorizer
    from vector_database import setup_databases, store_chunks

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pipeline settings
# ---------------------------------------------------------------------------
STORE_BATCH_SIZE = 500   # How many chunks to vectorize + store per batch


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


import os
import re

DATED_FILE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})", re.IGNORECASE)


def _get_file_sort_key(path: Path) -> tuple[str, float]:
    """Extract ISO date YYYY-MM-DD from filename if present, falling back to mtime."""
    match = DATED_FILE_RE.search(path.name)
    date_str = match.group(1) if match else "0000-00-00"
    try:
        mtime = path.stat().st_mtime
    except OSError:
        mtime = 0.0
    return (date_str, mtime)


def find_latest_kev_file(search_dirs: list[Path]) -> Path | None:
    """Dynamically discover the latest CISA KEV CSV snapshot across search directories."""
    patterns = [
        "*cisa_kev*.csv",
        "*known_exploited_vulnerabilities*.csv",
        "*cisa*.csv",
        "*kev*.csv",
    ]
    candidates: list[Path] = []
    for d in search_dirs:
        if d.is_dir():
            for pat in patterns:
                candidates.extend(p for p in d.glob(pat) if p.is_file())
    if not candidates:
        return None
    unique_candidates = list({c.resolve(): c for c in candidates}.values())
    return max(unique_candidates, key=_get_file_sort_key)


def find_latest_epss_file(search_dirs: list[Path]) -> Path | None:
    """Dynamically discover the latest EPSS scores CSV snapshot across search directories."""
    patterns = [
        "*epss_scores*.csv",
        "*epss*.csv",
    ]
    candidates: list[Path] = []
    for d in search_dirs:
        if d.is_dir():
            for pat in patterns:
                candidates.extend(p for p in d.glob(pat) if p.is_file())
    if not candidates:
        return None
    unique_candidates = list({c.resolve(): c for c in candidates}.values())
    return max(unique_candidates, key=_get_file_sort_key)


def find_nvd_directory(search_dirs: list[Path]) -> Path | None:
    """Dynamically discover directory containing yearly NVD JSON feed files."""
    for d in search_dirs:
        if not d.is_dir():
            continue
        # Direct check for subdirectories containing "nvd" with json files
        for sub in d.iterdir():
            if sub.is_dir() and "nvd" in sub.name.lower() and any(sub.glob("*.json")):
                return sub
        # Check if directory itself contains yearly JSON files (e.g. 2002.json, 2026.json, ...)
        if any(re.match(r"^\d{4}\.json$", p.name) for p in d.glob("*.json")):
            return d
    return None


def find_cvelist_directory(search_dirs: list[Path]) -> Path | None:
    """Dynamically discover directory containing CVE List V5 repository."""
    for d in search_dirs:
        if not d.is_dir():
            continue
        for sub in d.iterdir():
            if sub.is_dir() and "cvelist" in sub.name.lower():
                cves_sub = sub / "cves"
                if cves_sub.is_dir() and any(cves_sub.iterdir()):
                    return cves_sub
                if any(sub.glob("CVE-*.json")):
                    return sub
        cves_direct = d / "cves"
        if cves_direct.is_dir() and any(cves_direct.iterdir()):
            return cves_direct
    return None


def auto_discover_feeds(base_dirs: list[Path] | None = None) -> dict[str, Path]:
    """
    Dynamically discover all 4 live threat feeds without hardcoded filenames or dates:
      1. CISA KEV (most recent dated CSV)
      2. EPSS (most recent dated CSV)
      3. NVD feeds directory (yearly JSON files)
      4. CVE List V5 directory (CVE JSON tree)
    """
    if base_dirs is None:
        base_dirs = []
        env_dir = os.environ.get("CTI_FEEDS_DIR")
        if env_dir:
            base_dirs.append(Path(env_dir))
        base_dirs.extend([
            _REPO_ROOT / "knowledge_foundation" / "feeds",
            _REPO_ROOT / "knowledge_foundation",
            _REPO_ROOT / "data" / "feeds",
            _REPO_ROOT / "data",
            _REPO_ROOT,
        ])

    discovered: dict[str, Path] = {}

    kev = find_latest_kev_file(base_dirs)
    if kev:
        discovered["kev_csv"] = kev

    epss = find_latest_epss_file(base_dirs)
    if epss:
        discovered["epss_csv"] = epss

    nvd = find_nvd_directory(base_dirs)
    if nvd:
        discovered["nvd_dir"] = nvd

    cvelist = find_cvelist_directory(base_dirs)
    if cvelist:
        discovered["cvelist_dir"] = cvelist

    return discovered


def run_pipeline(
    normalized_dir: Path | None = None,
    normalized_jsonl: Path | None = None,
    nvd_dir: Path | None = None,
    cvelist_dir: Path | None = None,
    kev_csv: Path | None = None,
    epss_csv: Path | None = None,
    qdrant_path: str = str(_REPO_ROOT / "data" / "qdrant_storage"),
    sqlite_path: str = str(_REPO_ROOT / "data" / "sqlite" / "corpus_store.db"),
    max_chunks: int | None = None,
    reset: bool = False,
) -> int:
    """
    End-to-end ingestion pipeline:
    Parse → Deduplicate → Vectorize → Store
    """
    logger.info("=== Pipeline Start ===")

    # Step 1: Setup databases (creates collections/tables if needed)
    logger.info("Step 1/4 — Setting up databases (reset=%s) …", reset)
    qdrant, sqlite = setup_databases(qdrant_path, sqlite_path, reset=reset)

    # Step 2: Parse all sources into a unified stream of ThreatChunks
    logger.info("Step 2/4 — Ingesting data sources …")

    def all_chunks():
        # Active real-world threat feeds
        if kev_csv and kev_csv.is_file():
            logger.info("  [1/4] Parsing CISA KEV CSV: %s", kev_csv)
            yield from parse_cisa_kev_csv(kev_csv)

        if epss_csv and epss_csv.is_file():
            logger.info("  [2/4] Parsing EPSS CSV: %s", epss_csv)
            yield from parse_epss_csv(epss_csv)

        if nvd_dir and nvd_dir.is_dir():
            logger.info("  [3/4] Parsing NVD yearly JSON directory: %s", nvd_dir)
            yield from parse_nvd_directory(nvd_dir)

        if cvelist_dir and cvelist_dir.is_dir():
            logger.info("  [4/4] Parsing CVE List V5 directory: %s", cvelist_dir)
            yield from parse_cvelist_directory(cvelist_dir)

        # Test fixture intake (only if explicitly provided via code)
        if normalized_dir and normalized_dir.is_dir():
            logger.info("  [Test Fixture] Parsing normalized JSON from: %s", normalized_dir)
            yield from parse_normalized_directory(normalized_dir)

        if normalized_jsonl and normalized_jsonl.is_file():
            logger.info("  [Test Fixture] Streaming normalized JSONL: %s", normalized_jsonl)
            yield from parse_normalized_jsonl(normalized_jsonl)

    # Step 3: Deduplicate
    logger.info("Step 3/4 — Deduplicating chunks …")
    checker = DuplicateChecker()

    # Step 4: Vectorize + Store in batches
    logger.info("Step 4/4 — Vectorizing and storing chunks …")
    vectorizer = BGEVectorizer()

    batch_chunks: list[ThreatChunk] = []
    total_stored = 0

    for chunk in checker.filter(all_chunks()):
        batch_chunks.append(chunk)

        if len(batch_chunks) >= STORE_BATCH_SIZE:
            stored = _process_batch(batch_chunks, vectorizer, qdrant, sqlite)
            total_stored += stored
            logger.info("Progress: %d chunks vectorized and persisted.", total_stored)
            batch_chunks = []
            if max_chunks and total_stored >= max_chunks:
                logger.info("Reached max_chunks limit (%d). Stopping.", max_chunks)
                break

        if max_chunks and (total_stored + len(batch_chunks)) >= max_chunks:
            break

    # Process any remaining chunks
    if batch_chunks and (not max_chunks or total_stored < max_chunks):
        if max_chunks:
            batch_chunks = batch_chunks[: max_chunks - total_stored]
        stored = _process_batch(batch_chunks, vectorizer, qdrant, sqlite)
        total_stored += stored
        logger.info("Progress: %d chunks vectorized and persisted.", total_stored)

    logger.info("=== Pipeline Complete — %d chunks stored. ===", total_stored)
    return total_stored


def _process_batch(
    chunks: list[ThreatChunk],
    vectorizer: BGEVectorizer,
    qdrant,
    sqlite,
) -> int:
    """Vectorize and store one batch. Returns number of chunks stored."""
    items = [(chunk.chunk_id, build_context(chunk)) for chunk in chunks]
    vector_results = vectorizer.encode(items)
    store_chunks(vector_results, chunks, qdrant, sqlite)
    return len(chunks)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run CTI ingestion pipeline on ONLY the 4 knowledge_foundation threat feeds."
    )
    parser.add_argument(
        "--feeds",
        type=str,
        default="all",
        help="Comma-separated list of feeds to ingest: 'kev', 'epss', 'nvd', 'cvelist', or 'all' (default: all).",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Wipe and recreate Qdrant collection and SQLite database before ingesting.",
    )
    parser.add_argument(
        "--max-chunks",
        type=int,
        default=None,
        help="Optional limit on total chunks to ingest (useful for quick testing on live data).",
    )
    parser.add_argument(
        "--kev-csv",
        type=Path,
        default=None,
        help="Explicit path to CISA KEV catalog CSV (e.g. cisa_kev-YYYY-MM-DD.csv or known_exploited_vulnerabilities.csv).",
    )
    parser.add_argument(
        "--epss-csv",
        type=Path,
        default=None,
        help="Explicit path to EPSS scores CSV (e.g. epss_scores-YYYY-MM-DD.csv).",
    )
    parser.add_argument(
        "--nvd-dir",
        type=Path,
        default=None,
        help="Explicit path to directory containing yearly NVD JSON feeds (YYYY.json).",
    )
    parser.add_argument(
        "--cvelist-dir",
        type=Path,
        default=None,
        help="Explicit path to CVE List V5 directory (cves/YYYY/).",
    )
    parser.add_argument(
        "--normalized-dir",
        type=Path,
        default=None,
        help=argparse.SUPPRESS,  # Reserved for mock fixture unit tests only
    )
    parser.add_argument(
        "--normalized-jsonl",
        type=Path,
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--qdrant-path",
        type=str,
        default=str(_REPO_ROOT / "data" / "qdrant_storage"),
        help="Directory for embedded Qdrant storage.",
    )
    parser.add_argument(
        "--sqlite-path",
        type=str,
        default=str(_REPO_ROOT / "data" / "sqlite" / "corpus_store.db"),
        help="Path for SQLite corpus database.",
    )
    return parser.parse_args()


def _format_feed_summary(path: Path | None, kind: str) -> str:
    """Dynamically format feed path and contents without hardcoded strings."""
    if not path or not path.exists():
        return "[NOT FOUND / DISABLED]"
    if path.is_file():
        match = DATED_FILE_RE.search(path.name)
        date_info = f" (detected date: {match.group(1)})" if match else ""
        try:
            size_mb = path.stat().st_size / (1024 * 1024)
            return f"{path} [{size_mb:.2f} MB{date_info}]"
        except OSError:
            return f"{path}{date_info}"
    if path.is_dir():
        if kind == "nvd":
            count = len(list(path.glob("*.json")))
            return f"{path} [{count} yearly feed files detected]"
        if kind == "cvelist":
            count = sum(1 for _ in path.rglob("CVE-*.json"))
            return f"{path} [{count:,} CVE files detected]"
        return str(path)
    return str(path)


if __name__ == "__main__":
    args = _parse_args()

    # Determine which of the 4 feeds are selected
    selected_feeds = [f.strip().lower() for f in args.feeds.split(",") if f.strip()]
    run_all = "all" in selected_feeds

    # Auto-discover real feeds dynamically
    discovered = auto_discover_feeds()

    kev_path = args.kev_csv if args.kev_csv else (discovered.get("kev_csv") if (run_all or "kev" in selected_feeds) else None)
    epss_path = args.epss_csv if args.epss_csv else (discovered.get("epss_csv") if (run_all or "epss" in selected_feeds) else None)
    nvd_path = args.nvd_dir if args.nvd_dir else (discovered.get("nvd_dir") if (run_all or "nvd" in selected_feeds) else None)
    cvelist_path = args.cvelist_dir if args.cvelist_dir else (discovered.get("cvelist_dir") if (run_all or "cvelist" in selected_feeds) else None)

    norm_path = args.normalized_dir
    norm_jsonl = args.normalized_jsonl

    logger.info("================================================================================")
    logger.info("CTI INGESTION PIPELINE: TARGETING EXCLUSIVELY THE 4 KNOWLEDGE FOUNDATION FEEDS")
    logger.info("================================================================================")
    logger.info("1. CISA KEV:    %s", _format_feed_summary(kev_path, "kev"))
    logger.info("2. EPSS Scores: %s", _format_feed_summary(epss_path, "epss"))
    logger.info("3. NVD Feeds:   %s", _format_feed_summary(nvd_path, "nvd"))
    logger.info("4. CVE List V5: %s", _format_feed_summary(cvelist_path, "cvelist"))
    logger.info("================================================================================")

    run_pipeline(
        normalized_dir=norm_path,
        normalized_jsonl=norm_jsonl,
        nvd_dir=nvd_path,
        cvelist_dir=cvelist_path,
        kev_csv=kev_path,
        epss_csv=epss_path,
        qdrant_path=args.qdrant_path,
        sqlite_path=args.sqlite_path,
        max_chunks=args.max_chunks,
        reset=args.reset,
    )
