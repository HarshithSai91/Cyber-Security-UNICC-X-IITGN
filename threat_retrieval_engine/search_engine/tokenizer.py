"""
tokenizer.py
============
Cyber-aware tokenization for lexical (BM25) search.

Generic whitespace/word tokenizers shred security observables: a CVE id like
``CVE-2017-0144`` becomes ``cve``, ``2017``, ``0144``; an IPv4 address becomes
four integers; a SHA-256 hash survives but a dotted domain does not. That
destroys exact-match precision — the single most important property for CTI
retrieval.

This tokenizer runs in two passes:

  1. **Preserve pass** — regex-extract high-value identifiers (CVE ids, IPv4/IPv6
     addresses, hashes, domains, URLs, MITRE technique ids, registry keys) as
     *atomic* tokens. They are lower-cased but never split.
  2. **Word pass** — everything left over is tokenized as ordinary lowercase
     word/number tokens.

The atomic tokens are emitted verbatim (lowercased) so that a query for
``CVE-2017-0144`` lands on exactly the documents that mention it.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Identifier patterns (order matters — most specific first)
# ---------------------------------------------------------------------------

# CVE-YYYY-NNNN(+)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# MITRE ATT&CK technique / sub-technique, e.g. T1021 or T1021.002
MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Hashes: sha256 (64), sha1 (40), md5 (32) — hex strings of exact length
HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")

# IPv4 (optionally CIDR); we validate octets loosely here, precisely below
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")

# IPv6 (compact match — good enough to keep it atomic)
IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")

# URLs
URL_RE = re.compile(r"\bhttps?://[^\s<>\"')]+", re.IGNORECASE)

# Windows registry keys, e.g. HKLM\Software\... or HKEY_LOCAL_MACHINE\...
REGISTRY_RE = re.compile(r"\bHK(?:LM|CU|CR|U|CC|EY_[A-Z_]+)\\[^\s]+", re.IGNORECASE)

# Domains / hostnames with a known-ish TLD shape (2+ labels, alpha TLD >= 2)
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)

# Ordinary word/number tokens for the residual text
WORD_RE = re.compile(r"[a-z0-9]+")

# Ordered list of (name, pattern) applied in the preserve pass
_ATOMIC_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("url", URL_RE),
    ("registry", REGISTRY_RE),
    ("cve", CVE_RE),
    ("hash", HASH_RE),
    ("ipv6", IPV6_RE),
    ("ipv4", IPV4_RE),
    ("mitre", MITRE_RE),
    ("domain", DOMAIN_RE),
]

# A single sentinel char that never appears in real tokens, used to blank out
# already-consumed spans so later patterns don't re-match inside them.
_MASK = "\x00"


def _valid_ipv4(token: str) -> bool:
    """Reject false-positive dotted numbers like version strings 1.2.3.4567."""
    host = token.split("/", 1)[0]
    parts = host.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def extract_identifiers(text: str) -> dict[str, list[str]]:
    """
    Return the atomic security identifiers found in ``text``, grouped by kind.
    Values are lowercased and de-duplicated while preserving first-seen order.
    Useful on its own for the exact-identifier lookup path.
    """
    found: dict[str, list[str]] = {name: [] for name, _ in _ATOMIC_PATTERNS}
    working = text
    for name, pattern in _ATOMIC_PATTERNS:
        for match in pattern.finditer(working):
            raw = match.group(0)
            if name == "ipv4" and not _valid_ipv4(raw):
                continue
            low = raw.lower()
            if low not in found[name]:
                found[name].append(low)
            # Mask the matched span so it is not re-tokenized as words / other kinds
            start, end = match.span()
            working = working[:start] + (_MASK * (end - start)) + working[end:]
    return {k: v for k, v in found.items() if v}


def tokenize(text: str) -> list[str]:
    """
    Tokenize ``text`` for lexical indexing, preserving security identifiers as
    single atomic tokens and lowercasing everything.

    Example
    -------
    >>> tokenize("Exploit of CVE-2017-0144 from 198.51.100.24 (T1021.002)")
    ['exploit', 'of', 'cve-2017-0144', 'from', '198.51.100.24', 't1021.002']
    """
    if not text:
        return []

    working = text
    atomic_tokens: list[tuple[int, str]] = []  # (original_start, token)

    for name, pattern in _ATOMIC_PATTERNS:
        for match in pattern.finditer(working):
            raw = match.group(0)
            if name == "ipv4" and not _valid_ipv4(raw):
                continue
            start, end = match.span()
            atomic_tokens.append((start, raw.lower()))
            working = working[:start] + (_MASK * (end - start)) + working[end:]

    # Residual word tokens, tagged with their position so we can interleave
    word_tokens = [(m.start(), m.group(0)) for m in WORD_RE.finditer(working.lower())]

    # Merge by original position to keep natural reading order
    merged = sorted(atomic_tokens + word_tokens, key=lambda pair: pair[0])
    return [tok for _, tok in merged]
