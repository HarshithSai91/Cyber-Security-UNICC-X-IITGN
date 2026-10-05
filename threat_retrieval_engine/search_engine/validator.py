"""
validator.py
============
Handles data intake for the CTI pipeline.

Primary mode:
  Directly ingests Team 1's unified normalized CVE records
  (from cve_normalized_lookup.py: CVE-ID_normalized.json or JSONL).
  These records already unify NVD, CVE List V5, CISA KEV, and EPSS.

Fallback mode:
  Can also parse raw NVD JSON, CVE V5 JSON, CISA KEV CSV, and EPSS CSV
  if raw downloads are provided directly.

Responsibilities:
  1. Parse Team 1's normalized JSON records (and raw sources as fallback)
  2. Validate and clean the text (sanitizer)
  3. Quarantine broken/corrupt records
  4. Build enriched context strings for the vectorizer (Strategy C)
  5. Enforce token limits (8,192 max for BGE-M3)
  6. Inject asymmetric query prefix at query-time

Output: Stream of validated ThreatChunk objects ready for deduplication & vectorization.
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Iterator, Literal, Optional

try:
    import ftfy
except ImportError:
    pass

try:
    from pydantic import BaseModel, Field, field_validator
except ImportError:
    from dataclasses import dataclass, field as _field

    class BaseModel:
        def __init__(self, **kwargs: Any) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

        def dict(self) -> dict[str, Any]:
            return self.__dict__

        def model_dump(self) -> dict[str, Any]:
            return self.__dict__

    def Field(default: Any = ..., **kwargs: Any) -> Any:
        if default is ...:
            if "default_factory" in kwargs:
                return _field(default_factory=kwargs["default_factory"])
            return _field()
        return _field(default=default)

    def field_validator(*args: Any, **kwargs: Any) -> Any:
        def decorator(fn: Any) -> Any:
            return fn
        return decorator

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MIN_CHARS = 15
MAX_CHARS = 32_000
MAX_TOKENS = 8_192
QUERY_PREFIX = "Represent this sentence for searching relevant passages: "

# ---------------------------------------------------------------------------
# Pydantic Schema  (ThreatChunk contract)
# ---------------------------------------------------------------------------


class IOCEntities(BaseModel):
    ipv4: list[str] = Field(default_factory=list)
    ipv6: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    sha256: list[str] = Field(default_factory=list)
    md5: list[str] = Field(default_factory=list)


class CyberEntities(BaseModel):
    cves: list[str] = Field(default_factory=list)
    iocs: IOCEntities = Field(default_factory=IOCEntities)
    mitre_ttps: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] = "UNKNOWN"


class ThreatChunk(BaseModel):
    chunk_id: str = Field(..., description="Unique deterministic chunk ID")
    doc_id: str = Field(..., description="Parent document identifier")
    doc_title: str = Field(..., description="Advisory or CVE title")
    source_org: str = Field(..., description="NVD, CISA, EPSS, CVE_LIST_V5")
    published_date: datetime = Field(..., description="ISO-8601 published date")
    page_number: Optional[int] = None
    section_header: str = ""
    text: str = Field(..., min_length=MIN_CHARS, description="Primary clean content")
    entities: CyberEntities = Field(default_factory=CyberEntities)
    char_start: Optional[int] = None
    char_end: Optional[int] = None
    bbox: Optional[list[float]] = None

    @field_validator("text")
    @classmethod
    def text_must_not_be_too_long(cls, v: str) -> str:
        if len(v) > MAX_CHARS:
            raise ValueError(f"text exceeds {MAX_CHARS} characters")
        return v


# ---------------------------------------------------------------------------
# Text Cleaning / Sanitizer
# ---------------------------------------------------------------------------


def sanitize_text(raw: Any) -> str:
    """Fix broken unicode and normalize whitespace."""
    if not isinstance(raw, str):
        raw = str(raw or "")
    # ftfy fixes mojibake (â€™ → ', \ufffd → correct char, smart quotes, etc.)
    fixed = ftfy.fix_text(raw)
    # Collapse whitespace
    return re.sub(r"\s+", " ", fixed).strip()


def clean_optional(value: Any) -> str | None:
    """Clean optional string or return None if empty/NA."""
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = sanitize_text(value)
        if cleaned.casefold() in {"", "n/a", "na", "not applicable"}:
            return None
        return cleaned
    return str(value)


def is_valid_text(text: str) -> bool:
    """Check character-length boundaries."""
    return MIN_CHARS <= len(text) <= MAX_CHARS


# ---------------------------------------------------------------------------
# Deterministic Chunk ID
# ---------------------------------------------------------------------------


def make_chunk_id(doc_id: str, text: str) -> str:
    payload = f"{doc_id}::{text[:200]}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


# ---------------------------------------------------------------------------
# CVSS → Severity mapping
# ---------------------------------------------------------------------------

CVSS_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


def cvss_score_to_severity(score: Any) -> Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
    try:
        s = float(score)
        if s >= 9.0:
            return "CRITICAL"
        elif s >= 7.0:
            return "HIGH"
        elif s >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    except (TypeError, ValueError):
        return "UNKNOWN"


# ---------------------------------------------------------------------------
# Strategy C: Context Builder
# ---------------------------------------------------------------------------


def build_context(chunk: ThreatChunk) -> str:
    """
    Enrich chunk text with metadata anchors before vectorization.
    This is what actually gets embedded — not the raw text alone.
    """
    cves_str = ", ".join(chunk.entities.cves) if chunk.entities.cves else "none"
    malware_str = (
        ", ".join(chunk.entities.malware_families) if chunk.entities.malware_families else "none"
    )
    ttps_str = ", ".join(chunk.entities.mitre_ttps) if chunk.entities.mitre_ttps else "none"

    return (
        f"Document: {chunk.doc_title} | "
        f"Section: {chunk.section_header} | "
        f"Content: {chunk.text} | "
        f"CVEs: {cves_str} | "
        f"Malware: {malware_str} | "
        f"TTPs: {ttps_str}"
    )


def add_query_prefix(query: str) -> str:
    """
    Prepend the asymmetric search prefix to a user query at query-time.
    Documents at index-time do NOT get this prefix — only queries do.
    """
    return f"{QUERY_PREFIX}{query}"


# ---------------------------------------------------------------------------
# Token Sequence Gate
# ---------------------------------------------------------------------------


def check_token_limit(text: str, tokenizer: Any) -> bool:
    """
    Returns True if text is within the BGE-M3 limit of 8,192 tokens.
    Call this before vectorizing. Pass a HuggingFace tokenizer instance.
    """
    tokens = tokenizer.encode(text, add_special_tokens=True)
    if len(tokens) > MAX_TOKENS:
        logger.warning(
            "Text exceeds token limit (%d > %d). Will be silently truncated by BGE-M3.",
            len(tokens),
            MAX_TOKENS,
        )
        return False
    return True


# ---------------------------------------------------------------------------
# Team 1 Unified Normalized CVE Parsers (Primary Mode)
# ---------------------------------------------------------------------------


def parse_normalized_record(data: dict[str, Any]) -> ThreatChunk | None:
    """
    Parse a single unified normalized CVE JSON dictionary
    (as generated by Team 1's cve_normalized_lookup.py / lookup.ipynb).
    """
    cve_id = sanitize_text(data.get("cve_id", "")).upper()
    if not cve_id:
        return None

    title = clean_optional(data.get("title"))
    doc_title = f"{cve_id} — {title}" if title else f"CVE Advisory — {cve_id}"

    # Extract primary English description
    descriptions = data.get("descriptions", [])
    raw_text = ""
    for d in descriptions:
        lang = str(d.get("language", "en")).lower()
        if lang.startswith("en") and d.get("text"):
            raw_text = d.get("text", "")
            break
    if not raw_text and descriptions:
        raw_text = descriptions[0].get("text", "")

    text = sanitize_text(raw_text)

    # If description was empty/too short, construct descriptive fallback from normalized fields
    if not is_valid_text(text):
        parts = [f"{cve_id}: {title or 'Security vulnerability'}."]
        products = []
        for ap in data.get("affected_products", []):
            v = ap.get("vendor") or ""
            p = ap.get("product") or ""
            if v or p:
                products.append(f"{v} {p}".strip())
        if products:
            parts.append(f"Affects: {', '.join(products[:3])}.")
        kev = data.get("cisa_kev", {})
        if kev.get("listed"):
            parts.append("Confirmed exploited in the wild according to CISA KEV.")
        epss = data.get("epss", {})
        if epss.get("score") is not None:
            parts.append(f"EPSS score: {epss.get('score')}.")
        text = sanitize_text(" ".join(parts))

    if not is_valid_text(text):
        return None

    # Published date extraction
    dates = data.get("dates", {})
    date_str = (
        dates.get("date_published")
        or dates.get("nvd_published")
        or dates.get("date_reserved")
        or ""
    )
    try:
        published_date = datetime.fromisoformat(str(date_str).replace("Z", "+00:00"))
        if published_date.tzinfo is None:
            published_date = published_date.replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        published_date = datetime.now(timezone.utc)

    # Determine highest CVSS severity
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] = "UNKNOWN"
    highest_score: float | None = None
    for metric in data.get("cvss_metrics", []):
        score = metric.get("base_score")
        if score is not None:
            try:
                s_float = float(score)
                if highest_score is None or s_float > highest_score:
                    highest_score = s_float
                    severity = cvss_score_to_severity(s_float)
            except (ValueError, TypeError):
                pass
        elif metric.get("base_severity") and severity == "UNKNOWN":
            sev_str = str(metric.get("base_severity")).upper()
            if sev_str in CVSS_SEVERITY_MAP:
                severity = sev_str  # type: ignore[assignment]

    # If in CISA KEV and still unknown/low, mark as at least HIGH
    if data.get("cisa_kev", {}).get("listed") and severity in ("UNKNOWN", "LOW", "MEDIUM"):
        severity = "HIGH"

    # Weaknesses (CWE IDs)
    cwe_ids = []
    for w in data.get("weaknesses", []):
        cid = w.get("cwe_id")
        if cid:
            cwe_ids.append(str(cid))

    source_org = ", ".join(data.get("available_sources", [])) or "TEAM1_NORMALIZED"

    chunk_id = make_chunk_id(cve_id, text)
    return ThreatChunk(
        chunk_id=chunk_id,
        doc_id=cve_id,
        doc_title=doc_title,
        source_org=source_org,
        published_date=published_date,
        section_header="Normalized Vulnerability Record",
        text=text,
        entities=CyberEntities(
            cves=[cve_id],
            severity=severity,
        ),
    )


def parse_normalized_directory(norm_dir: Path) -> Generator[ThreatChunk, None, None]:
    """
    Ingest all Team 1 normalized JSON files (e.g. CVE-*_normalized.json or *.json)
    from a directory.
    """
    quarantine_dir = norm_dir.parent / "quarantined"
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    quarantine_log = quarantine_dir / f"normalized_failed_{_timestamp()}.jsonl"

    stats = {"total": 0, "valid": 0, "quarantined": 0}
    json_files = sorted(norm_dir.glob("*.json"))
    logger.info("Found %d normalized JSON files in %s", len(json_files), norm_dir)

    for json_file in json_files:
        stats["total"] += 1
        try:
            with json_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
            chunk = parse_normalized_record(data)
            if chunk is not None:
                stats["valid"] += 1
                yield chunk
            else:
                stats["quarantined"] += 1
                _quarantine(quarantine_log, {"file": json_file.name, "reason": "invalid_or_missing_fields"})
        except Exception as exc:
            stats["quarantined"] += 1
            _quarantine(quarantine_log, {"file": json_file.name, "reason": str(exc)})

    logger.info(
        "Normalized directory parse complete — total=%d valid=%d quarantined=%d",
        stats["total"], stats["valid"], stats["quarantined"],
    )


def parse_normalized_jsonl(jsonl_path: Path) -> Generator[ThreatChunk, None, None]:
    """
    Stream Team 1 normalized CVE records line-by-line from a JSONL file.
    """
    quarantine_dir = jsonl_path.parent / "quarantined"
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    quarantine_log = quarantine_dir / f"normalized_jsonl_failed_{_timestamp()}.jsonl"

    stats = {"total": 0, "valid": 0, "quarantined": 0}
    with jsonl_path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            stats["total"] += 1
            try:
                data = json.loads(line)
                chunk = parse_normalized_record(data)
                if chunk is not None:
                    stats["valid"] += 1
                    yield chunk
                else:
                    stats["quarantined"] += 1
                    _quarantine(quarantine_log, {"line": line_num, "reason": "validation_failed"})
            except Exception as exc:
                stats["quarantined"] += 1
                _quarantine(quarantine_log, {"line": line_num, "reason": str(exc)})

    logger.info(
        "Normalized JSONL parse complete — total=%d valid=%d quarantined=%d",
        stats["total"], stats["valid"], stats["quarantined"],
    )


# ---------------------------------------------------------------------------
# Fallback Raw Parsers (Used when raw feeds are ingested directly)
# ---------------------------------------------------------------------------


def _iter_nvd_vulnerabilities(path: Path, chunk_size: int = 1024 * 1024) -> Iterator[dict[str, Any]]:
    """Stream the NVD vulnerabilities array without loading the whole file."""
    marker = '"vulnerabilities"'
    decoder = json.JSONDecoder()
    with path.open("r", encoding="utf-8") as stream:
        buffer = ""
        while marker not in buffer:
            chunk = stream.read(chunk_size)
            if not chunk:
                raise ValueError(f"No vulnerabilities array found in {path}")
            buffer += chunk

        marker_at = buffer.index(marker) + len(marker)
        array_at = buffer.find("[", marker_at)
        while array_at < 0:
            chunk = stream.read(chunk_size)
            if not chunk:
                raise ValueError(f"Incomplete vulnerabilities array in {path}")
            buffer += chunk
            array_at = buffer.find("[", marker_at)
        buffer = buffer[array_at + 1 :]

        while True:
            buffer = buffer.lstrip()
            if buffer.startswith(","):
                buffer = buffer[1:].lstrip()
            if buffer.startswith("]"):
                return
            try:
                value, end = decoder.raw_decode(buffer)
            except json.JSONDecodeError:
                chunk = stream.read(chunk_size)
                if not chunk:
                    raise ValueError(f"Invalid or truncated JSON in {path}")
                buffer += chunk
                continue
            if isinstance(value, dict):
                yield value
            buffer = buffer[end:]


def parse_nvd_directory(nvd_dir: Path) -> Generator[ThreatChunk, None, None]:
    """
    Parse all NVD yearly JSON files (2002.json … YYYY.json) into ThreatChunks.
    Quarantines broken records to data/quarantined/.
    """
    quarantine_dir = nvd_dir.parent / "quarantined"
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    quarantine_log = quarantine_dir / f"nvd_failed_{_timestamp()}.jsonl"

    stats = {"total": 0, "valid": 0, "quarantined": 0}

    for json_file in sorted(nvd_dir.glob("*.json")):
        logger.info("Parsing NVD file: %s", json_file.name)
        try:
            for wrapper in _iter_nvd_vulnerabilities(json_file):
                stats["total"] += 1
                cve = wrapper.get("cve", wrapper)
                cve_id: str = cve.get("id", "UNKNOWN").upper()

                # Extract description (prefer English)
                descriptions = cve.get("descriptions", [])
                raw_text = ""
                for d in descriptions:
                    if d.get("lang", "").lower().startswith("en"):
                        raw_text = d.get("value", "")
                        break
                if not raw_text and descriptions:
                    raw_text = descriptions[0].get("value", "")

                text = sanitize_text(raw_text)
                if not is_valid_text(text):
                    _quarantine(quarantine_log, {"cve_id": cve_id, "reason": "invalid_text_length", "raw": raw_text[:200]})
                    stats["quarantined"] += 1
                    continue

                # Dates
                published_str = cve.get("published", "")
                try:
                    published_date = datetime.fromisoformat(published_str.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    published_date = datetime.now(timezone.utc)

                # CVSS severity
                severity = "UNKNOWN"
                metrics = cve.get("metrics", {})
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metric_list = metrics.get(key, [])
                    if metric_list:
                        score = metric_list[0].get("cvssData", {}).get("baseScore")
                        severity = cvss_score_to_severity(score)
                        break

                # CVE list from cve_id itself
                cve_list = [cve_id] if cve_id != "UNKNOWN" else []

                # Weaknesses → CWE
                weaknesses = cve.get("weaknesses", [])
                cwe_ids = []
                for w in weaknesses:
                    for desc in w.get("description", []):
                        val = desc.get("value", "")
                        if val.startswith("CWE-"):
                            cwe_ids.append(val)

                doc_id = cve_id
                chunk_id = make_chunk_id(doc_id, text)
                title = cve.get("sourceIdentifier", "NVD Advisory") + f" — {cve_id}"

                try:
                    chunk = ThreatChunk(
                        chunk_id=chunk_id,
                        doc_id=doc_id,
                        doc_title=title,
                        source_org="NVD",
                        published_date=published_date,
                        section_header="Vulnerability Description",
                        text=text,
                        entities=CyberEntities(
                            cves=cve_list,
                            severity=severity,  # type: ignore[arg-type]
                        ),
                    )
                    stats["valid"] += 1
                    yield chunk
                except Exception as exc:
                    _quarantine(quarantine_log, {"cve_id": cve_id, "reason": str(exc), "raw": text[:200]})
                    stats["quarantined"] += 1

        except Exception as file_exc:
            logger.error("Failed to parse file %s: %s", json_file.name, file_exc)

    logger.info(
        "NVD parse complete — total=%d valid=%d quarantined=%d",
        stats["total"], stats["valid"], stats["quarantined"],
    )


# ---------------------------------------------------------------------------
# CVE List V5 JSON Parser  (git tree directory)
# ---------------------------------------------------------------------------


def parse_cvelist_directory(cvelist_dir: Path) -> Generator[ThreatChunk, None, None]:
    """
    Walk the CVE List V5 git tree (cves/YYYY/NNNNxxx/CVE-YYYY-NNNNN.json)
    and emit ThreatChunks.
    """
    quarantine_dir = cvelist_dir.parent.parent / "quarantined"
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    quarantine_log = quarantine_dir / f"cvelist_failed_{_timestamp()}.jsonl"

    stats = {"total": 0, "valid": 0, "quarantined": 0}

    for json_file in sorted(cvelist_dir.rglob("CVE-*.json")):
        stats["total"] += 1
        try:
            with json_file.open("r", encoding="utf-8") as f:
                data: dict[str, Any] = json.load(f)

            cve_meta = data.get("cveMetadata", {})
            cve_id: str = cve_meta.get("cveId", json_file.stem).upper()
            state: str = cve_meta.get("state", "")
            if state.upper() == "REJECTED":
                stats["quarantined"] += 1
                _quarantine(quarantine_log, {"cve_id": cve_id, "reason": "rejected_cve"})
                continue

            containers = data.get("containers", {})
            cna = containers.get("cna", {})
            descriptions = cna.get("descriptions", [])
            raw_text = ""
            for d in descriptions:
                if d.get("lang", "").lower().startswith("en"):
                    raw_text = d.get("value", "")
                    break
            if not raw_text and descriptions:
                raw_text = descriptions[0].get("value", "")

            text = sanitize_text(raw_text)
            if not is_valid_text(text):
                _quarantine(quarantine_log, {"cve_id": cve_id, "reason": "invalid_text_length"})
                stats["quarantined"] += 1
                continue

            published_str = cve_meta.get("datePublished", "")
            try:
                published_date = datetime.fromisoformat(published_str.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                published_date = datetime.now(timezone.utc)

            assigner = cve_meta.get("assignerShortName", "CVE_LIST_V5")
            title = cna.get("title", f"{cve_id} Advisory")

            chunk_id = make_chunk_id(cve_id, text)
            try:
                chunk = ThreatChunk(
                    chunk_id=chunk_id,
                    doc_id=cve_id,
                    doc_title=title,
                    source_org="CVE_LIST_V5",
                    published_date=published_date,
                    section_header="CNA Description",
                    text=text,
                    entities=CyberEntities(cves=[cve_id]),
                )
                stats["valid"] += 1
                yield chunk
            except Exception as exc:
                _quarantine(quarantine_log, {"cve_id": cve_id, "reason": str(exc)})
                stats["quarantined"] += 1

        except Exception as exc:
            logger.error("Failed to parse %s: %s", json_file.name, exc)
            stats["quarantined"] += 1

    logger.info(
        "CVE List V5 parse complete — total=%d valid=%d quarantined=%d",
        stats["total"], stats["valid"], stats["quarantined"],
    )


# ---------------------------------------------------------------------------
# CISA KEV CSV Parser
# ---------------------------------------------------------------------------


def parse_cisa_kev_csv(csv_path: Path) -> Generator[ThreatChunk, None, None]:
    """
    Parse the CISA Known Exploited Vulnerabilities CSV.
    Fields: cveID, vendorProject, product, vulnerabilityName, dateAdded,
            requiredAction, dueDate, knownRansomwareCampaignUse, notes
    """
    quarantine_dir = csv_path.parent / "quarantined"
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    quarantine_log = quarantine_dir / f"kev_failed_{_timestamp()}.jsonl"

    stats = {"total": 0, "valid": 0, "quarantined": 0}

    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            stats["total"] += 1
            cve_id = sanitize_text(row.get("cveID", "")).upper()
            if not cve_id:
                stats["quarantined"] += 1
                continue

            vuln_name = sanitize_text(row.get("vulnerabilityName", ""))
            product = sanitize_text(row.get("product", ""))
            vendor = sanitize_text(row.get("vendorProject", ""))
            required_action = sanitize_text(row.get("requiredAction", ""))
            notes = sanitize_text(row.get("notes", ""))

            text_parts = [f"Vulnerability: {vuln_name}"]
            if vendor:
                text_parts.append(f"Vendor: {vendor}")
            if product:
                text_parts.append(f"Product: {product}")
            if required_action:
                text_parts.append(f"Required Action: {required_action}")
            if notes:
                text_parts.append(f"Notes: {notes}")

            text = " | ".join(text_parts)
            text = sanitize_text(text)

            if not is_valid_text(text):
                _quarantine(quarantine_log, {"cve_id": cve_id, "reason": "invalid_text_length"})
                stats["quarantined"] += 1
                continue

            date_str = row.get("dateAdded", "")
            try:
                published_date = datetime.fromisoformat(date_str)
                if published_date.tzinfo is None:
                    published_date = published_date.replace(tzinfo=timezone.utc)
            except (ValueError, AttributeError):
                published_date = datetime.now(timezone.utc)

            chunk_id = make_chunk_id(cve_id + "_KEV", text)
            try:
                chunk = ThreatChunk(
                    chunk_id=chunk_id,
                    doc_id=cve_id + "_KEV",
                    doc_title=f"CISA KEV — {cve_id}: {vuln_name}",
                    source_org="CISA",
                    published_date=published_date,
                    section_header="Known Exploited Vulnerability",
                    text=text,
                    entities=CyberEntities(cves=[cve_id], severity="HIGH"),
                )
                stats["valid"] += 1
                yield chunk
            except Exception as exc:
                _quarantine(quarantine_log, {"cve_id": cve_id, "reason": str(exc)})
                stats["quarantined"] += 1

    logger.info(
        "CISA KEV parse complete — total=%d valid=%d quarantined=%d",
        stats["total"], stats["valid"], stats["quarantined"],
    )


# ---------------------------------------------------------------------------
# EPSS CSV Parser
# ---------------------------------------------------------------------------


def parse_epss_csv(csv_path: Path) -> Generator[ThreatChunk, None, None]:
    """
    Parse the EPSS CSV (cve, epss, percentile) into ThreatChunks.
    Only includes CVEs with high EPSS scores (>= 0.5) to avoid noise.
    """
    quarantine_dir = csv_path.parent / "quarantined"
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    quarantine_log = quarantine_dir / f"epss_failed_{_timestamp()}.jsonl"

    stats = {"total": 0, "valid": 0, "quarantined": 0, "skipped_low_score": 0}

    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        # Skip metadata comment line if present
        first_line = f.readline()
        if not first_line.startswith("#"):
            f.seek(0)
        reader = csv.DictReader(f)
        for row in reader:
            stats["total"] += 1
            cve_id = sanitize_text(row.get("cve", "")).upper()
            if not cve_id:
                stats["quarantined"] += 1
                continue

            try:
                epss_score = float(row.get("epss", 0))
                percentile = float(row.get("percentile", 0))
            except (ValueError, TypeError):
                stats["quarantined"] += 1
                _quarantine(quarantine_log, {"cve_id": cve_id, "reason": "invalid_epss_score"})
                continue

            # Skip low-scoring CVEs — they don't add useful signal
            if epss_score < 0.5:
                stats["skipped_low_score"] += 1
                continue

            text = (
                f"{cve_id} has an EPSS exploitation probability score of "
                f"{epss_score:.4f} ({epss_score * 100:.1f}%), "
                f"placing it in the {percentile * 100:.1f}th percentile of all scored CVEs. "
                f"This indicates a high likelihood of exploitation in the next 30 days."
            )
            text = sanitize_text(text)

            if not is_valid_text(text):
                _quarantine(quarantine_log, {"cve_id": cve_id, "reason": "invalid_text_length"})
                stats["quarantined"] += 1
                continue

            chunk_id = make_chunk_id(cve_id + "_EPSS", text)
            try:
                chunk = ThreatChunk(
                    chunk_id=chunk_id,
                    doc_id=cve_id + "_EPSS",
                    doc_title=f"EPSS Score — {cve_id}",
                    source_org="EPSS",
                    published_date=datetime.now(timezone.utc),
                    section_header="Exploitation Probability",
                    text=text,
                    entities=CyberEntities(cves=[cve_id], severity="HIGH" if epss_score >= 0.8 else "MEDIUM"),
                )
                stats["valid"] += 1
                yield chunk
            except Exception as exc:
                _quarantine(quarantine_log, {"cve_id": cve_id, "reason": str(exc)})
                stats["quarantined"] += 1

    logger.info(
        "EPSS parse complete — total=%d valid=%d quarantined=%d skipped_low_score=%d",
        stats["total"], stats["valid"], stats["quarantined"], stats["skipped_low_score"],
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")


def _quarantine(log_path: Path, record: dict[str, Any]) -> None:
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


# ---------------------------------------------------------------------------
# Team 1 Validation Suite CLI
# (What Team 2 provides to Team 1 to test their outputs against our schema)
# ---------------------------------------------------------------------------


def validate_file(file_path: Path) -> dict[str, int]:
    """
    Validate a JSON or JSONL file against the ThreatChunk schema contract.
    Prints pass/fail details and summary.
    """
    if not file_path.exists():
        print(f"Error: File not found: {file_path}")
        return {"valid": 0, "failed": 1}

    stats = {"valid": 0, "failed": 0}
    print(f"\n[Validator] Checking schema contract for: {file_path}")

    def check_dict(data: dict[str, Any], label: str):
        try:
            chunk = parse_normalized_record(data)
            if chunk is None:
                # Try direct ThreatChunk parse if already formatted
                chunk = ThreatChunk.model_validate(data)
            stats["valid"] += 1
            print(f"  [PASS] {label}: Validated chunk '{chunk.chunk_id}' (doc: {chunk.doc_id})")
        except Exception as exc:
            stats["failed"] += 1
            print(f"  [FAIL] {label}: {exc}")

    if file_path.suffix.lower() == ".jsonl":
        with file_path.open("r", encoding="utf-8") as f:
            for idx, line in enumerate(f, 1):
                line = line.strip()
                if line:
                    try:
                        check_dict(json.loads(line), f"Line {idx}")
                    except json.JSONDecodeError as err:
                        stats["failed"] += 1
                        print(f"  [FAIL] Line {idx}: Invalid JSON syntax: {err}")
    else:
        with file_path.open("r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                if isinstance(data, list):
                    for idx, item in enumerate(data, 1):
                        check_dict(item, f"Record {idx}")
                else:
                    check_dict(data, "Single Record")
            except Exception as exc:
                stats["failed"] += 1
                print(f"  [FAIL] Could not parse JSON file: {exc}")

    print(f"\n[Summary] Valid: {stats['valid']} | Failed: {stats['failed']}")
    return stats


if __name__ == "__main__":
    import argparse

    cli_parser = argparse.ArgumentParser(
        description="Team 2 Validation Suite: Validate Team 1 output files against the ThreatChunk schema contract."
    )
    cli_parser.add_argument(
        "--validate-file",
        type=Path,
        required=True,
        help="Path to JSON or JSONL file to validate.",
    )
    args = cli_parser.parse_args()
    summary = validate_file(args.validate_file)
    sys.exit(0 if summary["failed"] == 0 else 1)
