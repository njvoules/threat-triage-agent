"""
detector.py — Indicator type detection and log extraction.

Supports: IPv4, IPv6, MD5, SHA1, SHA256, Domain, Log Snippet.
For log snippets, also extracts embedded sub-indicators.
"""

import re
import socket
from enum import Enum
from typing import List, Dict


class IndicatorType(Enum):
    IPV4 = "IPv4 Address"
    IPV6 = "IPv6 Address"
    DOMAIN = "Domain"
    MD5 = "MD5 Hash"
    SHA1 = "SHA1 Hash"
    SHA256 = "SHA256 Hash"
    LOG_SNIPPET = "Log Snippet"


# Compiled patterns
_RE_IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_RE_IPV6 = re.compile(
    r"^("
    r"([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,7}:|"
    r"([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}|"
    r"::[0-9a-fA-F]{0,4}"
    r")$"
)
_RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
_RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
_RE_DOMAIN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}$"
)

# Patterns used to extract sub-indicators from log snippets
_RE_EXTRACT_IPV4 = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_RE_EXTRACT_SHA256 = re.compile(r"\b([a-fA-F0-9]{64})\b")
_RE_EXTRACT_SHA1 = re.compile(r"\b([a-fA-F0-9]{40})\b")
_RE_EXTRACT_MD5 = re.compile(r"\b([a-fA-F0-9]{32})\b")
_RE_EXTRACT_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:com|net|org|io|co|uk|de|ru|cn|info|biz|xyz|top|tk|ml|ga|cf|gq|gov|edu|mil|int)\b",
    re.IGNORECASE,
)


def detect_indicator_type(indicator: str) -> IndicatorType:
    """Return the IndicatorType for the given raw indicator string."""
    s = indicator.strip()

    # IPv4
    m = _RE_IPV4.match(s)
    if m:
        octets = [int(g) for g in m.groups()]
        if all(0 <= o <= 255 for o in octets):
            return IndicatorType.IPV4

    # IPv6
    if _RE_IPV6.match(s):
        return IndicatorType.IPV6

    # Hashes (longest first to avoid SHA1 matching on SHA256 prefix)
    if _RE_SHA256.match(s):
        return IndicatorType.SHA256
    if _RE_SHA1.match(s):
        return IndicatorType.SHA1
    if _RE_MD5.match(s):
        return IndicatorType.MD5

    # Domain
    if _RE_DOMAIN.match(s) and "." in s:
        return IndicatorType.DOMAIN

    return IndicatorType.LOG_SNIPPET


def extract_indicators_from_log(log: str) -> List[Dict]:
    """
    Extract embedded sub-indicators from a raw log snippet.
    Returns a list of dicts: {"value": str, "type": IndicatorType}
    Deduplicates and skips loopback/link-local addresses.
    """
    found: Dict[str, IndicatorType] = {}

    def add(value: str, itype: IndicatorType):
        value = value.strip()
        if value not in found:
            found[value] = itype

    # IPs
    for match in _RE_EXTRACT_IPV4.finditer(log):
        ip = match.group(1)
        parts = ip.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            if not ip.startswith(("127.", "0.", "169.254.")):
                add(ip, IndicatorType.IPV4)

    # Hashes (order matters — SHA256 > SHA1 > MD5 by length)
    for match in _RE_EXTRACT_SHA256.finditer(log):
        add(match.group(1), IndicatorType.SHA256)

    remaining = log
    for match in _RE_EXTRACT_SHA256.finditer(log):
        remaining = remaining.replace(match.group(1), "")

    for match in _RE_EXTRACT_SHA1.finditer(remaining):
        add(match.group(1), IndicatorType.SHA1)

    remaining2 = remaining
    for match in _RE_EXTRACT_SHA1.finditer(remaining):
        remaining2 = remaining2.replace(match.group(1), "")

    for match in _RE_EXTRACT_MD5.finditer(remaining2):
        add(match.group(1), IndicatorType.MD5)

    # Domains
    for match in _RE_EXTRACT_DOMAIN.finditer(log):
        domain = match.group(0).lower().rstrip(".")
        add(domain, IndicatorType.DOMAIN)

    return [{"value": v, "type": t} for v, t in found.items()]
