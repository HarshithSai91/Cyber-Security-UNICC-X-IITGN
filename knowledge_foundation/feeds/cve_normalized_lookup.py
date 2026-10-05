#!/usr/bin/env python3
"""Look up one CVE in the locally downloaded NVD and CVE List V5 data.

The script does not download anything. It reads both local source formats,
normalizes their useful fields, prints normalized JSON, and then prints a
human-readable summary.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit, urlunsplit


CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$", re.IGNORECASE)
DATED_CSV_RE = re.compile(r"-(\d{4}-\d{2}-\d{2})(?:\.csv)?$", re.IGNORECASE)


def clean_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value)).strip()


def clean_optional(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = clean_text(value)
        if cleaned.casefold() in {"", "n/a", "na", "not applicable"}:
            return None
        return cleaned
    return value


def normalized_name(value: Any) -> str:
    text = clean_text(value or "").casefold().replace("_", " ").replace("-", " ")
    return re.sub(r"[^a-z0-9]+", "", text)


def clean_url(value: Any) -> str:
    url = clean_text(value or "")
    # Some source records accidentally contain doubled schemes.
    url = re.sub(r"^(?:https?://)+(https?://)", r"\1", url, flags=re.IGNORECASE)
    if url.lower().startswith("http://https://"):
        url = "https://" + url[len("http://https://") :]
    if url.lower().startswith("https://http://"):
        url = "http://" + url[len("https://http://") :]
    try:
        parts = urlsplit(url)
        if parts.scheme.lower() in {"http", "https"}:
            url = urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, parts.fragment))
    except ValueError:
        pass
    return url


def reference_key(url: str) -> str:
    try:
        parts = urlsplit(url)
        if parts.netloc:
            return urlunsplit(("", parts.netloc.casefold(), parts.path.rstrip("/"), parts.query, parts.fragment))
    except ValueError:
        pass
    return url.casefold().rstrip("/")


def parse_cve_id(value: str) -> tuple[str, int, int]:
    cve_id = value.strip().upper()
    match = CVE_RE.fullmatch(cve_id)
    if not match:
        raise ValueError("Expected a CVE ID such as CVE-2024-12345")
    return cve_id, int(match.group(1)), int(match.group(2))


def nvd_file_for_year(data_dir: Path, year: int) -> Path:
    # This download stores CVE years 1999-2002 together in 2002.json.
    filename_year = 2002 if year <= 2002 else year
    return data_dir / "nvd_cve_data" / f"{filename_year}.json"


def cvelist_file_for_id(data_dir: Path, cve_id: str, year: int, number: int) -> Path:
    bucket = f"{number // 1000}xxx"
    return data_dir / "cvelistV5-live" / "cves" / str(year) / bucket / f"{cve_id}.json"


def latest_dated_file(data_dir: Path, prefix: str) -> Path | None:
    candidates = [p for p in data_dir.glob(f"{prefix}-*") if p.is_file()]
    if not candidates:
        return None

    def sort_key(path: Path) -> tuple[str, float]:
        match = DATED_CSV_RE.search(path.name)
        return (match.group(1) if match else "0000-00-00", path.stat().st_mtime)

    return max(candidates, key=sort_key)


def load_kev_record(path: Path | None, cve_id: str) -> dict[str, Any] | None:
    if path is None:
        return None
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            if str(row.get("cveID", "")).strip().upper() == cve_id:
                return dict(row)
    return None


def load_epss_record(path: Path | None, cve_id: str) -> tuple[dict[str, Any] | None, dict[str, str]]:
    if path is None:
        return None, {}
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        first_line = stream.readline().strip()
        metadata: dict[str, str] = {}
        if first_line.startswith("#"):
            for item in first_line[1:].split(","):
                if ":" in item:
                    key, value = item.split(":", 1)
                    metadata[key.strip()] = value.strip()
        else:
            stream.seek(0)
        for row in csv.DictReader(stream):
            if str(row.get("cve", "")).strip().upper() == cve_id:
                return dict(row), metadata
    return None, metadata


def iter_nvd_vulnerabilities(path: Path, chunk_size: int = 1024 * 1024) -> Iterator[dict[str, Any]]:
    """Stream the large NVD vulnerabilities array using only Python stdlib."""
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


def load_nvd_record(path: Path, cve_id: str) -> dict[str, Any] | None:
    if not path.exists():
        return None
    for wrapper in iter_nvd_vulnerabilities(path):
        cve = wrapper.get("cve", {})
        if cve.get("id", "").upper() == cve_id:
            return cve
    return None


def load_json_if_present(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    return value if isinstance(value, dict) else None


def unique_strings(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def append_description(out: dict[str, Any], lang: Any, value: Any, source: str, provider: Any) -> None:
    if not value:
        return
    candidate = {
        "language": str(lang or "und"),
        "text": clean_text(value),
        "sources": [source],
        "providers": unique_strings([provider]),
    }
    for existing in out["descriptions"]:
        if existing["language"] == candidate["language"] and existing["text"] == candidate["text"]:
            existing["sources"] = unique_strings(existing["sources"] + candidate["sources"])
            existing["providers"] = unique_strings(existing["providers"] + candidate["providers"])
            return
    out["descriptions"].append(candidate)


def append_reference(out: dict[str, Any], ref: dict[str, Any], source: str, provider: Any) -> None:
    original_url = clean_text(ref.get("url", ""))
    url = clean_url(original_url)
    if not url:
        return
    for existing in out["references"]:
        if reference_key(existing["url"]) == reference_key(url):
            if existing["url"].startswith("http://") and url.startswith("https://"):
                existing["url"] = url
            existing["original_urls"] = unique_strings(existing["original_urls"] + [original_url])
            existing["names"] = unique_strings(existing["names"] + [ref.get("name")])
            existing["tags"] = unique_strings(existing["tags"] + list(ref.get("tags", []) or []))
            existing["sources"] = unique_strings(existing["sources"] + [source])
            existing["providers"] = unique_strings(existing["providers"] + [provider, ref.get("source")])
            return
    out["references"].append(
        {
            "url": url,
            "original_urls": unique_strings([original_url]),
            "names": unique_strings([ref.get("name")]),
            "tags": unique_strings(list(ref.get("tags", []) or [])),
            "sources": [source],
            "providers": unique_strings([provider, ref.get("source")]),
        }
    )


def normalize_versions(versions: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for version in versions or []:
        if not isinstance(version, dict):
            continue
        result.append(
            {
                key: version[key]
                for key in (
                    "version", "status", "versionType", "lessThan", "lessThanOrEqual",
                    "versionStartIncluding", "versionStartExcluding",
                    "versionEndIncluding", "versionEndExcluding", "changes",
                )
                if key in version
            }
        )
    return result


def append_affected(out: dict[str, Any], item: dict[str, Any], source: str, provider: Any) -> None:
    normalized = {
        "vendor": clean_optional(item.get("vendor")),
        "product": clean_optional(item.get("product")),
        "package_name": clean_optional(item.get("packageName")),
        "package_url": clean_optional(item.get("packageURL")),
        "repository": clean_optional(item.get("repo")),
        "collection_url": clean_optional(item.get("collectionURL")),
        "default_status": clean_optional(item.get("defaultStatus")),
        "versions": normalize_versions(item.get("versions")),
        "cpes": unique_strings(list(item.get("cpes", []) or [])),
        "platforms": unique_strings(list(item.get("platforms", []) or [])),
        "modules": unique_strings(list(item.get("modules", []) or [])),
        "sources": [source],
        "providers": unique_strings([provider]),
    }
    identity = tuple(normalized_name(normalized[k]) for k in ("vendor", "product", "package_name"))
    for existing in out["affected_products"]:
        existing_identity = tuple(normalized_name(existing[k]) for k in ("vendor", "product", "package_name"))
        if existing_identity == identity:
            # Prefer a well-capitalized spelling when sources differ only by case.
            for key in ("vendor", "product", "package_name"):
                new_value = normalized[key]
                old_value = existing[key]
                if new_value and (not old_value or (str(new_value).isupper() and not str(old_value).isupper())):
                    existing[key] = new_value
            for version in normalized["versions"]:
                if version not in existing["versions"]:
                    existing["versions"].append(version)
            existing["cpes"] = unique_strings(existing["cpes"] + normalized["cpes"])
            existing["platforms"] = unique_strings(existing["platforms"] + normalized["platforms"])
            existing["modules"] = unique_strings(existing["modules"] + normalized["modules"])
            existing["sources"] = unique_strings(existing["sources"] + normalized["sources"])
            existing["providers"] = unique_strings(existing["providers"] + normalized["providers"])
            return
    out["affected_products"].append(normalized)


def append_weakness(out: dict[str, Any], identifier: Any, description: Any, source: str, provider: Any) -> None:
    identifier_text = clean_optional(identifier)
    description_text = clean_optional(description)
    if not identifier_text and not description_text:
        return
    candidate = {
        "id": identifier_text,
        "description": description_text,
        "sources": [source],
        "providers": unique_strings([provider]),
    }
    for existing in out["weaknesses"]:
        if existing["id"] == identifier_text and existing["description"] == description_text:
            existing["sources"] = unique_strings(existing["sources"] + [source])
            existing["providers"] = unique_strings(existing["providers"] + [provider])
            return
    out["weaknesses"].append(candidate)


def append_narrative(out: dict[str, Any], kind: str, value: Any, lang: Any, source: str, provider: Any) -> None:
    if not value:
        return
    candidate = {
        "type": kind,
        "language": str(lang or "und"),
        "text": clean_text(value),
        "source": source,
        "provider": provider,
    }
    if candidate not in out["additional_information"]:
        out["additional_information"].append(candidate)


def append_metric(
    out: dict[str, Any], metric_name: str, metric: dict[str, Any], source: str, provider: Any
) -> None:
    if metric_name.lower().startswith("ssvc"):
        data = metric.get("ssvcData", metric)
        out["ssvc"].append(
            {
                "version": data.get("version"),
                "role": data.get("role"),
                "timestamp": data.get("timestamp"),
                "options": data.get("options", []),
                "source": source,
                "provider": metric.get("source", provider),
            }
        )
        return

    data = metric.get("cvssData")
    if data is None and metric_name.lower().startswith("cvss"):
        data = metric
    if not isinstance(data, dict):
        other = metric.get("other")
        if isinstance(other, dict) and str(other.get("type", "")).upper() == "SSVC":
            content = other.get("content", {})
            out["ssvc"].append(
                {
                    "version": content.get("version"),
                    "role": content.get("role"),
                    "timestamp": content.get("timestamp"),
                    "options": content.get("options", []),
                    "source": source,
                    "provider": provider,
                }
            )
        return

    out["cvss_metrics"].append(
        {
            "version": data.get("version"),
            "vector": data.get("vectorString"),
            "base_score": data.get("baseScore"),
            "base_severity": data.get("baseSeverity", metric.get("baseSeverity")),
            "exploitability_score": metric.get("exploitabilityScore"),
            "impact_score": metric.get("impactScore"),
            "metric_type": metric.get("type"),
            "source": source,
            "provider": metric.get("source", provider),
            "details": data,
        }
    )


def blank_result(cve_id: str) -> dict[str, Any]:
    return {
        "cve_id": cve_id,
        "available_sources": [],
        "state": {"cve_list": None, "nvd": None},
        "dates": {},
        "assigner": {},
        "title": None,
        "descriptions": [],
        "affected_products": [],
        "cvss_metrics": [],
        "ssvc": [],
        "weaknesses": [],
        "references": [],
        "cpe_configurations": [],
        "cpe_matches": [],
        "tags": [],
        "known_exploited": {},
        "cisa_kev": {
            "catalog_available": False,
            "listed": False,
            "catalog_file": None,
        },
        "epss": {
            "dataset_available": False,
            "score_available": False,
            "dataset_file": None,
            "model_version": None,
            "score_date": None,
            "score": None,
            "percentile": None,
        },
        "additional_information": [],
        "provenance": [],
    }


def add_nvd(out: dict[str, Any], cve: dict[str, Any], source_file: Path) -> None:
    out["available_sources"].append("NVD")
    out["state"]["nvd"] = cve.get("vulnStatus")
    out["dates"]["nvd_published"] = cve.get("published")
    out["dates"]["nvd_last_modified"] = cve.get("lastModified")
    out["assigner"]["nvd_source_identifier"] = cve.get("sourceIdentifier")
    out["provenance"].append({"source": "NVD", "file": str(source_file)})

    provider = cve.get("sourceIdentifier")
    for desc in cve.get("descriptions", []) or []:
        append_description(out, desc.get("lang"), desc.get("value"), "NVD", provider)
    for block in cve.get("affected", []) or []:
        block_provider = block.get("source", provider)
        for item in block.get("affectedData", []) or []:
            append_affected(out, item, "NVD", block_provider)
    for metric_name, metrics in (cve.get("metrics", {}) or {}).items():
        for metric in metrics or []:
            if isinstance(metric, dict):
                append_metric(out, metric_name, metric, "NVD", provider)
    for weakness in cve.get("weaknesses", []) or []:
        weakness_provider = weakness.get("source", provider)
        for desc in weakness.get("description", []) or []:
            value = desc.get("value")
            append_weakness(out, value if str(value).startswith("CWE-") else None, value, "NVD", weakness_provider)
    for ref in cve.get("references", []) or []:
        append_reference(out, ref, "NVD", provider)
    out["cpe_configurations"].extend(cve.get("configurations", []) or [])
    for group in cve.get("cveTags", []) or []:
        if isinstance(group, dict):
            out["tags"].extend(group.get("tags", []) or [])
    out["tags"] = unique_strings(out["tags"])

    kev_mapping = {
        "date_added": "cisaExploitAdd",
        "action_due": "cisaActionDue",
        "required_action": "cisaRequiredAction",
        "vulnerability_name": "cisaVulnerabilityName",
    }
    for normalized_key, source_key in kev_mapping.items():
        if cve.get(source_key) is not None:
            out["known_exploited"][normalized_key] = cve[source_key]
    for source_key, kind in (
        ("evaluatorComment", "nvd_evaluator_comment"),
        ("evaluatorImpact", "nvd_evaluator_impact"),
        ("evaluatorSolution", "solution"),
    ):
        append_narrative(out, kind, cve.get(source_key), "en", "NVD", "nvd@nist.gov")
    for comment in cve.get("vendorComments", []) or []:
        append_narrative(
            out, "vendor_comment", comment.get("comment"), "en", "NVD", comment.get("organization")
        )


def add_cvelist_container(out: dict[str, Any], container: dict[str, Any], kind: str) -> None:
    provider_meta = container.get("providerMetadata", {}) or {}
    provider = provider_meta.get("shortName", provider_meta.get("orgId"))
    source = f"CVE_LIST_{kind.upper()}"
    if kind == "cna" and container.get("title"):
        out["title"] = clean_text(container["title"])
    for desc in container.get("descriptions", []) or []:
        append_description(out, desc.get("lang"), desc.get("value"), source, provider)
    for item in container.get("affected", []) or []:
        append_affected(out, item, source, provider)
    for problem in container.get("problemTypes", []) or []:
        for desc in problem.get("descriptions", []) or []:
            append_weakness(
                out, desc.get("cweId"), desc.get("description"), source, provider
            )
    for ref in container.get("references", []) or []:
        append_reference(out, ref, source, provider)
    for metric in container.get("metrics", []) or []:
        if not isinstance(metric, dict):
            continue
        for metric_name in ("cvssV2_0", "cvssV3_0", "cvssV3_1", "cvssV4_0"):
            if isinstance(metric.get(metric_name), dict):
                append_metric(out, metric_name, metric[metric_name], source, provider)
        if isinstance(metric.get("other"), dict):
            append_metric(out, "other", metric, source, provider)
    for field, narrative_type in (
        ("solutions", "solution"),
        ("workarounds", "workaround"),
        ("exploits", "exploit"),
        ("configurations", "configuration"),
        ("rejectedReasons", "rejection_reason"),
    ):
        for item in container.get(field, []) or []:
            append_narrative(out, narrative_type, item.get("value"), item.get("lang"), source, provider)
    for item in container.get("timeline", []) or []:
        text = f"{item.get('time', '')}: {item.get('value', '')}".strip(": ")
        append_narrative(out, "timeline", text, item.get("lang"), source, provider)
    for item in container.get("impacts", []) or []:
        capec = item.get("capecId")
        for desc in item.get("descriptions", []) or []:
            text = desc.get("value")
            if capec:
                text = f"{capec}: {text}"
            append_narrative(out, "impact", text, desc.get("lang"), source, provider)
    out["tags"].extend(container.get("tags", []) or [])
    out["tags"] = unique_strings(out["tags"])
    if container.get("cpeApplicability"):
        out["cpe_configurations"].extend(container["cpeApplicability"])


def add_cvelist(out: dict[str, Any], record: dict[str, Any], source_file: Path) -> None:
    out["available_sources"].append("CVE_LIST_V5")
    meta = record.get("cveMetadata", {}) or {}
    out["state"]["cve_list"] = meta.get("state")
    for source_key, normalized_key in (
        ("dateReserved", "cve_reserved"),
        ("datePublished", "cve_published"),
        ("dateUpdated", "cve_updated"),
        ("dateRejected", "cve_rejected"),
    ):
        if meta.get(source_key) is not None:
            out["dates"][normalized_key] = meta[source_key]
    out["assigner"]["org_id"] = meta.get("assignerOrgId")
    out["assigner"]["short_name"] = meta.get("assignerShortName")
    out["provenance"].append(
        {
            "source": "CVE_LIST_V5",
            "file": str(source_file),
            "schema_version": record.get("dataVersion"),
        }
    )
    containers = record.get("containers", {}) or {}
    cna = containers.get("cna")
    if isinstance(cna, dict):
        add_cvelist_container(out, cna, "cna")
    for adp in containers.get("adp", []) or []:
        if isinstance(adp, dict):
            add_cvelist_container(out, adp, "adp")


def add_kev(out: dict[str, Any], row: dict[str, Any] | None, source_file: Path | None) -> None:
    kev = out["cisa_kev"]
    kev["catalog_available"] = source_file is not None
    kev["catalog_file"] = str(source_file) if source_file else None
    if row is None:
        return

    kev.update(
        {
            "listed": True,
            "vendor_project": clean_optional(row.get("vendorProject")),
            "product": clean_optional(row.get("product")),
            "vulnerability_name": clean_optional(row.get("vulnerabilityName")),
            "date_added": clean_optional(row.get("dateAdded")),
            "short_description": clean_optional(row.get("shortDescription")),
            "required_action": clean_optional(row.get("requiredAction")),
            "due_date": clean_optional(row.get("dueDate")),
            "known_ransomware_campaign_use": clean_optional(row.get("knownRansomwareCampaignUse")),
            "notes": clean_optional(row.get("notes")),
            "cwes": unique_strings(re.findall(r"CWE-[0-9]+", row.get("cwes") or "")),
        }
    )
    out["available_sources"].append("CISA_KEV")
    out["provenance"].append({"source": "CISA_KEV", "file": str(source_file)})
    out["known_exploited"].update(
        {
            "date_added": kev["date_added"],
            "action_due": kev["due_date"],
            "required_action": kev["required_action"],
            "vulnerability_name": kev["vulnerability_name"],
            "known_ransomware_campaign_use": kev["known_ransomware_campaign_use"],
            "source": "CISA_KEV",
        }
    )
    append_description(out, "en", kev["short_description"], "CISA_KEV", "CISA")
    append_affected(
        out,
        {"vendor": kev["vendor_project"], "product": kev["product"], "versions": []},
        "CISA_KEV",
        "CISA",
    )
    for cwe in kev["cwes"]:
        append_weakness(out, cwe, cwe, "CISA_KEV", "CISA")
    append_narrative(out, "required_action", kev["required_action"], "en", "CISA_KEV", "CISA")
    append_narrative(out, "kev_notes", kev["notes"], "en", "CISA_KEV", "CISA")
    for url in re.findall(r"https?://[^\s;]+", kev["notes"] or ""):
        append_reference(
            out,
            {"url": url.rstrip(".,)"), "tags": ["CISA KEV Reference"]},
            "CISA_KEV",
            "CISA",
        )


def add_epss(
    out: dict[str, Any], row: dict[str, Any] | None, metadata: dict[str, str], source_file: Path | None
) -> None:
    epss = out["epss"]
    epss.update(
        {
            "dataset_available": source_file is not None,
            "dataset_file": str(source_file) if source_file else None,
            "model_version": metadata.get("model_version"),
            "score_date": metadata.get("score_date"),
        }
    )
    if row is None:
        return
    try:
        score = float(row["epss"])
        percentile = float(row["percentile"])
    except (KeyError, TypeError, ValueError):
        return
    epss.update({"score_available": True, "score": score, "percentile": percentile})
    out["available_sources"].append("EPSS")
    out["provenance"].append(
        {
            "source": "EPSS",
            "file": str(source_file),
            "model_version": metadata.get("model_version"),
            "score_date": metadata.get("score_date"),
        }
    )


def collect_provider_aliases(record: dict[str, Any] | None) -> dict[str, str]:
    aliases: dict[str, str] = {}
    if not record:
        return aliases
    meta = record.get("cveMetadata", {}) or {}
    if meta.get("assignerOrgId") and meta.get("assignerShortName"):
        aliases[str(meta["assignerOrgId"]).casefold()] = str(meta["assignerShortName"])
    containers = record.get("containers", {}) or {}
    candidates = []
    if isinstance(containers.get("cna"), dict):
        candidates.append(containers["cna"])
    candidates.extend(x for x in containers.get("adp", []) or [] if isinstance(x, dict))
    for container in candidates:
        provider = container.get("providerMetadata", {}) or {}
        if provider.get("orgId") and provider.get("shortName"):
            aliases[str(provider["orgId"]).casefold()] = str(provider["shortName"])
    return aliases


def provider_display_name(value: Any, aliases: dict[str, str]) -> str | None:
    original = clean_optional(value)
    if original is None:
        return None
    text = str(original)
    lower = text.casefold()
    if lower in aliases:
        text = aliases[lower]
        lower = text.casefold()

    standard = {
        "nvd": "NVD",
        "nvd@nist.gov": "NVD",
        "cisa": "CISA",
        "cisa-adp": "CISA",
        "redhat": "Red Hat",
        "redhat-sadp": "Red Hat",
        "secalert@redhat.com": "Red Hat",
        "ibm": "IBM",
        "psirt@us.ibm.com": "IBM",
        "microsoft": "Microsoft",
        "secure@microsoft.com": "Microsoft",
        "snyk": "Snyk",
    }
    if lower in standard:
        return standard[lower]

    # If an email/label contains a known short name, use that readable name.
    normalized_original = normalized_name(text)
    for short_name in aliases.values():
        if len(normalized_name(short_name)) >= 3 and normalized_name(short_name) in normalized_original:
            return provider_display_name(short_name, {})
    return text


def extract_cpe_matches(configurations: list[Any]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            criteria = value.get("criteria")
            if isinstance(criteria, str) and criteria.startswith("cpe:2.3:"):
                parts = criteria.split(":")
                if len(parts) >= 6:
                    candidate = {
                        "criteria": criteria,
                        "part": parts[2],
                        "vendor": parts[3].replace("_", " ").replace("\\", ""),
                        "product": parts[4].replace("_", " ").replace("\\", ""),
                        "version": None if parts[5] in {"*", "-"} else parts[5].replace("\\", ""),
                        "vulnerable": value.get("vulnerable"),
                    }
                    for key in (
                        "versionStartIncluding", "versionStartExcluding",
                        "versionEndIncluding", "versionEndExcluding",
                    ):
                        if key in value:
                            candidate[key] = value[key]
                    if candidate not in matches:
                        matches.append(candidate)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(configurations)
    return matches


def finalize_normalization(out: dict[str, Any], aliases: dict[str, str]) -> None:
    for description in out["descriptions"]:
        description["providers"] = unique_strings(
            [provider_display_name(x, aliases) for x in description["providers"]]
        )
    for item in out["affected_products"]:
        item["vendor"] = provider_display_name(item.get("vendor"), aliases)
        item["product_aliases"] = unique_strings([item.get("product")])
        item["providers"] = unique_strings(
            [provider_display_name(x, aliases) for x in item["providers"]]
        )
    coalesced_products: list[dict[str, Any]] = []
    for item in out["affected_products"]:
        item_vendor = normalized_name(item.get("vendor"))
        item_product = normalized_name(item.get("product"))
        item_versions = {
            (str(v.get("version")), str(v.get("status"))) for v in item.get("versions", [])
        }
        merged = False
        for existing in coalesced_products:
            existing_product = normalized_name(existing.get("product"))
            existing_versions = {
                (str(v.get("version")), str(v.get("status"))) for v in existing.get("versions", [])
            }
            related_product_names = (
                item_product and existing_product
                and (item_product.startswith(existing_product) or existing_product.startswith(item_product))
            )
            if (
                item_vendor == normalized_name(existing.get("vendor"))
                and related_product_names and item_versions and item_versions == existing_versions
            ):
                existing["product_aliases"] = unique_strings(
                    existing["product_aliases"] + item["product_aliases"]
                )
                # Prefer the more descriptive product label for display.
                if len(str(item.get("product") or "")) > len(str(existing.get("product") or "")):
                    existing["product"] = item["product"]
                for key in ("cpes", "platforms", "modules", "sources", "providers"):
                    existing[key] = unique_strings(existing[key] + item[key])
                merged = True
                break
        if not merged:
            coalesced_products.append(item)
    out["affected_products"] = coalesced_products
    for weakness in out["weaknesses"]:
        weakness["providers"] = unique_strings(
            [provider_display_name(x, aliases) for x in weakness["providers"]]
        )
    for reference in out["references"]:
        reference["providers"] = unique_strings(
            [provider_display_name(x, aliases) for x in reference["providers"]]
        )
    for item in out["additional_information"]:
        item["provider"] = provider_display_name(item.get("provider"), aliases)

    deduplicated_metrics: list[dict[str, Any]] = []
    metric_index: dict[tuple[Any, ...], dict[str, Any]] = {}
    for metric in out["cvss_metrics"]:
        original_provider = metric.get("provider")
        provider = provider_display_name(original_provider, aliases)
        metric["provider"] = provider
        metric["original_providers"] = unique_strings([original_provider])
        metric["sources"] = unique_strings([metric.pop("source", None)])
        score = metric.get("base_score")
        numeric_score = float(score) if isinstance(score, (int, float)) else score
        key = (
            str(metric.get("version")), numeric_score,
            str(metric.get("base_severity") or "").upper(),
            str(metric.get("vector") or ""), normalized_name(provider),
        )
        existing = metric_index.get(key)
        if existing:
            existing["sources"] = unique_strings(existing["sources"] + metric["sources"])
            existing["original_providers"] = unique_strings(
                existing["original_providers"] + metric["original_providers"]
            )
        else:
            metric_index[key] = metric
            deduplicated_metrics.append(metric)
    out["cvss_metrics"] = deduplicated_metrics

    deduplicated_ssvc: list[dict[str, Any]] = []
    seen_ssvc: set[str] = set()
    for item in out["ssvc"]:
        item["provider"] = provider_display_name(item.get("provider"), aliases)
        key = json.dumps(
            {k: item.get(k) for k in ("version", "role", "options", "provider")},
            sort_keys=True,
        )
        if key not in seen_ssvc:
            seen_ssvc.add(key)
            deduplicated_ssvc.append(item)
    out["ssvc"] = deduplicated_ssvc
    out["cpe_matches"] = extract_cpe_matches(out["cpe_configurations"])


def normalize(
    cve_id: str,
    nvd: dict[str, Any] | None,
    cvelist: dict[str, Any] | None,
    kev: dict[str, Any] | None,
    epss: dict[str, Any] | None,
    epss_metadata: dict[str, str],
    nvd_path: Path,
    cvelist_path: Path,
    kev_path: Path | None,
    epss_path: Path | None,
) -> dict[str, Any]:
    result = blank_result(cve_id)
    if nvd:
        add_nvd(result, nvd, nvd_path)
    if cvelist:
        add_cvelist(result, cvelist, cvelist_path)
    add_kev(result, kev, kev_path)
    add_epss(result, epss, epss_metadata, epss_path)
    finalize_normalization(result, collect_provider_aliases(cvelist))
    result["available_sources"] = unique_strings(result["available_sources"])
    return result


def version_text(version: dict[str, Any]) -> str:
    raw_version = clean_optional(version.get("version"))
    less_than = clean_optional(version.get("lessThan"))
    less_equal = clean_optional(version.get("lessThanOrEqual"))
    if str(raw_version or "").casefold() in {"0", "*"} and str(less_than or "").casefold() in {
        "unspecified", "*",
    }:
        return "all versions"
    parts = []
    if raw_version is not None:
        parts.append(str(raw_version))
    if less_than is not None:
        parts.append(f"up to, but not including, {less_than}")
    if less_equal is not None:
        parts.append(f"up to and including {less_equal}")
    return " ".join(parts) or "unspecified version"


def affected_category(item: dict[str, Any]) -> str:
    statuses = [
        str(v.get("status", "")).casefold()
        for v in item.get("versions", [])
        if v.get("status")
    ]
    default_status = str(item.get("default_status") or "").casefold()
    if "affected" in statuses:
        return "affected"
    if statuses and all(status == "unaffected" for status in statuses):
        return "unaffected"
    if default_status == "affected":
        return "affected"
    if default_status == "unaffected":
        return "unaffected"
    return "unknown"


CWE_EXPLANATIONS = {
    "CWE-20": "The software does not properly check input supplied to it.",
    "CWE-22": "An attacker may access files outside the intended folder.",
    "CWE-78": "An attacker may inject operating-system commands.",
    "CWE-79": "An attacker may inject malicious content into a web page.",
    "CWE-89": "An attacker may manipulate a database query.",
    "CWE-94": "An attacker may inject and run malicious code.",
    "CWE-119": "The software handles memory incorrectly, which may cause crashes or code execution.",
    "CWE-121": "Too much data can overwrite stack memory and potentially run malicious code.",
    "CWE-203": "Different responses may reveal information that should remain secret.",
    "CWE-204": "Observable responses may reveal sensitive information.",
    "CWE-281": "The software does not correctly preserve permissions.",
    "CWE-295": "The software does not correctly verify a digital certificate.",
    "CWE-416": "The software may continue using memory after it has been released.",
    "CWE-502": "The software trusts specially prepared data and may run attacker-controlled code.",
    "CWE-787": "The software may write outside an allowed memory area.",
    "CWE-863": "The software does not correctly check whether an action is authorized.",
}


def plain_impact(description: str) -> list[str]:
    text = description.casefold()
    impacts: list[str] = []
    rules = (
        (("remote code execution", "execute arbitrary code", "arbitrary code execution"),
         "An attacker may be able to run malicious commands or programs on the affected system."),
        (("privilege escalation", "gain privileges", "elevation of privilege"),
         "An attacker may be able to gain permissions they should not have."),
        (("information disclosure", "disclose sensitive", "sensitive information"),
         "Private or sensitive information may be exposed."),
        (("read arbitrary files", "access arbitrary files"),
         "A local attacker may be able to read files they should not be allowed to see."),
        (("denial of service", "crash", "become unavailable"),
         "The affected service may crash or become unavailable."),
        (("authentication bypass", "bypass authentication"),
         "An attacker may be able to get past a login or identity check."),
        (("sql injection",),
         "An attacker may be able to read or change information in the application database."),
        (("cross-site scripting", "xss"),
         "An attacker may be able to place malicious content in a web page viewed by other users."),
        (("path traversal",),
         "An attacker may be able to access files outside the intended folder."),
    )
    for phrases, explanation in rules:
        if any(phrase in text for phrase in phrases) and explanation not in impacts:
            impacts.append(explanation)
    if not impacts:
        impacts.append("The weakness may allow an attacker to compromise the affected product or disrupt it.")
    return impacts


def attack_requirements(metric: dict[str, Any] | None) -> list[str]:
    if not metric:
        return []
    details = metric.get("details", {}) or {}
    result = []
    attack_vector = str(details.get("attackVector", details.get("accessVector", ""))).upper()
    if attack_vector == "NETWORK":
        result.append("The attack may be carried out remotely over a network.")
    elif attack_vector == "LOCAL":
        result.append("The attacker normally needs local access to the affected computer.")
    elif attack_vector == "ADJACENT_NETWORK":
        result.append("The attacker normally needs access to the same or a nearby network.")
    elif attack_vector == "PHYSICAL":
        result.append("The attacker needs physical access to the affected device.")

    privileges = str(details.get("privilegesRequired", "")).upper()
    authentication = str(details.get("authentication", "")).upper()
    if privileges == "NONE" or (authentication == "NONE" and attack_vector == "NETWORK"):
        result.append("The attacker may not need an account or existing access privileges.")
    elif privileges == "LOW":
        result.append("The attacker needs a basic, low-privilege account.")
    elif privileges == "HIGH":
        result.append("The attacker needs a highly privileged account first.")

    interaction = str(details.get("userInteraction", "")).upper()
    if interaction == "NONE":
        result.append("A victim does not need to click or open anything for the attack to work.")
    elif interaction == "REQUIRED":
        result.append("The attack requires a user to perform an action, such as opening a file or link.")
    return result


def human_summary(data: dict[str, Any]) -> str:
    lines = [data["cve_id"]]
    if data.get("title"):
        lines.append(str(data["title"]))

    english = [d["text"] for d in data["descriptions"] if d["language"].lower().startswith("en")]
    descriptions = english or [d["text"] for d in data["descriptions"]]
    description = descriptions[0] if descriptions else "No description is available in the downloaded data."

    lines.append("\nPLAIN-ENGLISH EXPLANATION")
    for impact in plain_impact(description):
        lines.append("- " + impact)
    if "deserial" in description.casefold():
        lines.append(
            "- In simple terms, the software may trust a specially prepared message and turn it into active program code."
        )

    lines.append("\nOriginal technical description:\n" + description)

    products_by_category: dict[str, list[str]] = {"affected": [], "unknown": [], "unaffected": []}
    for item in data["affected_products"]:
        name = " / ".join(unique_strings([item.get("vendor"), item.get("product"), item.get("package_name")]))
        if not name:
            continue
        category = affected_category(item)
        item_versions = item.get("versions", [])
        matching_versions = [
            v for v in item_versions if str(v.get("status", "")).casefold() == category
        ]
        versions_to_show = matching_versions or item_versions
        versions = ", ".join(version_text(v) for v in versions_to_show[:5])
        label = name + (f" - {versions}" if versions else "")
        if label not in products_by_category[category]:
            products_by_category[category].append(label)

    products = products_by_category["affected"] or products_by_category["unknown"]
    if not products:
        for cpe in data.get("cpe_matches", []):
            if cpe.get("vulnerable") is False:
                continue
            label = " / ".join(unique_strings([cpe.get("vendor"), cpe.get("product")]))
            if cpe.get("version"):
                label += f" - {cpe['version']}"
            if label and label not in products:
                products.append(label)
    if products:
        lines.append("\nWHO MAY BE AFFECTED")
        lines.extend("- " + product for product in products[:10])
        if len(products) > 10:
            lines.append(f"- Plus {len(products) - 10} additional affected product entries.")
    if products_by_category["unaffected"]:
        lines.append(
            f"- The source data separately identifies {len(products_by_category['unaffected'])} product entries as unaffected."
        )

    metrics = sorted(
        data["cvss_metrics"],
        key=lambda m: (float(m.get("base_score") or -1), str(m.get("version") or "")),
        reverse=True,
    )
    if metrics:
        highest = metrics[0]
        score = float(highest["base_score"])
        severity = str(highest.get("base_severity") or "Unrated").title()
        provider = highest.get("provider") or "an unnamed provider"
        lines.append("\nHOW SERIOUS IS IT?")
        lines.append(
            f"- The highest recorded CVSS rating is {score:.1f} out of 10 ({severity}), assessed by {provider}."
        )
        lines.append("- CVSS measures the possible damage and difficulty of an attack; a score near 10 is extremely serious.")
        lines.extend("- " + text for text in attack_requirements(highest))
        other_assessments = []
        seen = {(highest.get("version"), score, highest.get("provider"))}
        for metric in metrics[1:]:
            metric_score = metric.get("base_score")
            key = (metric.get("version"), metric_score, metric.get("provider"))
            if key in seen or not isinstance(metric_score, (int, float)):
                continue
            seen.add(key)
            other_assessments.append(
                f"{metric.get('provider') or 'Another provider'}: {float(metric_score):.1f}/10 "
                f"({str(metric.get('base_severity') or 'unrated').title()}, CVSS {metric.get('version') or '?'})"
            )
        if other_assessments:
            lines.append("- Other organizations produced these assessments because scoring judgments can differ:")
            lines.extend("  - " + assessment for assessment in other_assessments[:6])

    weakness_ids = unique_strings(w.get("id") for w in data["weaknesses"])
    weakness_ids = [w for w in weakness_ids if w not in {"NVD-CWE-noinfo", "NVD-CWE-Other"}]
    if weakness_ids:
        lines.append("\nWHAT KIND OF SOFTWARE MISTAKE IS THIS?")
        for weakness in weakness_ids[:8]:
            explanation = CWE_EXPLANATIONS.get(weakness)
            lines.append(f"- {weakness}: {explanation or 'A standardized category for this software weakness.'}")

    lines.append("\nIS IT BEING USED BY ATTACKERS?")
    kev = data["cisa_kev"]
    if kev["catalog_available"] and kev["listed"]:
        lines.append("- Yes. CISA has placed it in the Known Exploited Vulnerabilities catalog, meaning real-world exploitation is confirmed.")
        if kev.get("date_added"):
            lines.append(f"- CISA added it on {kev['date_added']}.")
        ransomware = str(kev.get("known_ransomware_campaign_use") or "").casefold()
        if ransomware == "known":
            lines.append("- CISA reports that it has been used in known ransomware campaigns.")
        elif ransomware == "unknown":
            lines.append("- CISA has not confirmed whether ransomware groups are using it.")
    elif kev["catalog_available"]:
        lines.append("- CISA has not listed it in the downloaded KEV catalog. This does not guarantee that nobody is exploiting it.")
    else:
        lines.append("- The KEV file is unavailable, so confirmed-exploitation status cannot be checked.")

    epss = data["epss"]
    if epss["score_available"]:
        score_percent = epss["score"] * 100
        percentile_percent = epss["percentile"] * 100
        higher_than = percentile_percent
        lines.append(
            f"- The EPSS model estimates an approximately {score_percent:.1f}% chance of exploitation in the next 30 days."
        )
        lines.append(
            f"- Its EPSS percentile is {percentile_percent:.2f}, meaning its predicted risk is higher than about {higher_than:.2f}% of scored CVEs."
        )
    elif epss["dataset_available"]:
        lines.append("- No EPSS prediction is available. This means unknown risk, not zero risk.")
    else:
        lines.append("- The EPSS file is unavailable, so predicted exploitation likelihood cannot be checked.")

    lines.append("\nWHAT SHOULD A USER OR ORGANIZATION DO?")
    useful = [x for x in data["additional_information"] if x["type"] in {"solution", "workaround"}]
    if kev.get("listed"):
        due = f" by {kev['due_date']}" if kev.get("due_date") else ""
        lines.append(f"- Treat this as urgent and apply the vendor's fix or recommended mitigation{due}.")
        lines.append("- If no safe fix or mitigation exists, stop using or isolate the affected product.")
    elif useful:
        lines.append("- Review and apply the vendor-provided fix or workaround.")
    else:
        lines.append("- Check the vendor advisory, update the affected product, and restrict exposure until it is fixed.")
    for item in useful[:3]:
        lines.append(f"- Published {item['type']}: {item['text']}")

    states = []
    if data["state"].get("cve_list"):
        states.append(f"CVE List: {data['state']['cve_list']}")
    if data["state"].get("nvd"):
        states.append(f"NVD: {data['state']['nvd']}")
    if states:
        lines.append("\nRECORD STATUS")
        lines.append("- " + "; ".join(states))
        lines.append("- These labels describe the database record's publication/review state, not the current danger level.")

    if data["references"]:
        lines.append("\nWHERE TO VERIFY OR LEARN MORE")
        lines.extend("- " + reference["url"] for reference in data["references"][:6])
    lines.append("\nDATA SOURCES USED: " + ", ".join(data["available_sources"]))
    return "\n".join(lines)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(
        description="Normalize one CVE from the locally downloaded NVD and CVE List V5 data."
    )
    parser.add_argument("cve_id", nargs="?", help="CVE ID, for example CVE-2024-3094")
    parser.add_argument(
        "--data-dir", type=Path, default=Path(__file__).resolve().parent.parent,
        help="Directory containing nvd_cve_data and cvelistV5-main",
    )
    parser.add_argument("--json-only", action="store_true", help="Print only normalized JSON")
    parser.add_argument("--summary-only", action="store_true", help="Print only the human-readable summary")
    args = parser.parse_args()

    raw_id = args.cve_id or input("Enter CVE ID: ")
    try:
        cve_id, year, number = parse_cve_id(raw_id)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    data_dir = args.data_dir.resolve()
    nvd_path = nvd_file_for_year(data_dir, year)
    cvelist_path = cvelist_file_for_id(data_dir, cve_id, year, number)
    kev_path = latest_dated_file(data_dir, "cisa_kev")
    epss_path = latest_dated_file(data_dir, "epss_scores")
    try:
        nvd = load_nvd_record(nvd_path, cve_id)
        cvelist = load_json_if_present(cvelist_path)
        kev = load_kev_record(kev_path, cve_id)
        epss, epss_metadata = load_epss_record(epss_path, cve_id)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Error reading local data: {exc}", file=sys.stderr)
        return 1

    if nvd is None and cvelist is None and kev is None and epss is None:
        print(
            f"{cve_id} was not found in any downloaded dataset.\n"
            f"Checked NVD: {nvd_path}\nChecked CVE List: {cvelist_path}\n"
            f"Checked CISA KEV: {kev_path}\nChecked EPSS: {epss_path}",
            file=sys.stderr,
        )
        return 3

    normalized = normalize(
        cve_id, nvd, cvelist, kev, epss, epss_metadata,
        nvd_path, cvelist_path, kev_path, epss_path,
    )
    if not args.summary_only:
        print(json.dumps(normalized, ensure_ascii=False, indent=2))
    if not args.json_only:
        if not args.summary_only:
            print("\n" + "=" * 78 + "\nHUMAN-READABLE SUMMARY\n" + "=" * 78)
        print(human_summary(normalized))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
