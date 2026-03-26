"""
enricher.py — Threat intelligence enrichment from multiple sources.

Always-available (no API key required):
  - ipinfo.io        — IP geolocation, ASN, org
  - DNS resolution   — Forward/reverse lookups

Free API key required (sign up at the links below):
  - URLhaus          — abuse.ch/urlhaus  →  ABUSECH_API_KEY
  - MalwareBazaar    — bazaar.abuse.ch   →  ABUSECH_API_KEY  (same key)
  - ThreatFox        — threatfox.abuse.ch → ABUSECH_API_KEY  (same key)

Optional free API keys (additional coverage):
  - AbuseIPDB        — abuseipdb.com      →  ABUSEIPDB_API_KEY
  - VirusTotal       — virustotal.com     →  VT_API_KEY

Note: abuse.ch now requires a single free API key for all three of their
      services (URLhaus, MalwareBazaar, ThreatFox). Register at:
      https://bazaar.abuse.ch/api/  (free, no restrictions on lookups)
"""

import os
import re
import socket
import json
import requests
from typing import Dict, List, Any, Optional
from modules.detector import IndicatorType, extract_indicators_from_log

TIMEOUT = 10  # seconds per HTTP request


def _abusech_key() -> str:
    """Return the abuse.ch API key from env, or empty string if not set."""
    return os.environ.get("ABUSECH_API_KEY", "").strip()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get(url: str, **kwargs) -> Optional[requests.Response]:
    try:
        r = requests.get(url, timeout=TIMEOUT, **kwargs)
        r.raise_for_status()
        return r
    except Exception as e:
        return None


def _post(url: str, data=None, json_body=None, headers=None) -> Optional[requests.Response]:
    try:
        r = requests.post(
            url,
            data=data,
            json=json_body,
            headers=headers or {},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        return r
    except Exception as e:
        return None


# ---------------------------------------------------------------------------
# Source: ipinfo.io
# ---------------------------------------------------------------------------

def _enrich_ipinfo(ip: str) -> Dict:
    result = {"source": "ipinfo.io", "available": False}
    r = _get(f"https://ipinfo.io/{ip}/json")
    if not r:
        result["error"] = "Request failed"
        return result
    try:
        data = r.json()
        result.update(
            {
                "available": True,
                "ip": data.get("ip"),
                "hostname": data.get("hostname"),
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country"),
                "org": data.get("org"),          # e.g. "AS15169 Google LLC"
                "timezone": data.get("timezone"),
                "bogon": data.get("bogon", False),
            }
        )
        # Split ASN from org string
        org = data.get("org", "")
        asn_match = re.match(r"(AS\d+)\s+(.*)", org)
        if asn_match:
            result["asn"] = asn_match.group(1)
            result["isp"] = asn_match.group(2)
        else:
            result["asn"] = None
            result["isp"] = org
    except Exception as e:
        result["error"] = str(e)
    return result


# ---------------------------------------------------------------------------
# Source: URLhaus (abuse.ch) — IPs and Domains
# ---------------------------------------------------------------------------

def _enrich_urlhaus(host: str) -> Dict:
    result = {"source": "URLhaus", "available": False}
    key = _abusech_key()
    if not key:
        result["skipped"] = "No ABUSECH_API_KEY set"
        return result
    r = _post(
        "https://urlhaus-api.abuse.ch/v1/host/",
        data={"host": host},
        headers={"Auth-Key": key},
    )
    if not r:
        result["error"] = "Request failed"
        return result
    try:
        data = r.json()
        status = data.get("query_status", "")
        result["available"] = True
        result["query_status"] = status

        if status == "is_host":
            urls = data.get("urls", [])
            result["malicious_url_count"] = len(urls)
            result["url_statuses"] = list(
                {u.get("url_status") for u in urls if u.get("url_status")}
            )
            result["tags"] = list(
                {tag for u in urls for tag in (u.get("tags") or [])}
            )
            result["threat_types"] = list(
                {u.get("threat") for u in urls if u.get("threat")}
            )
            # Sample up to 3 URLs for the report
            result["sample_urls"] = [u.get("url") for u in urls[:3] if u.get("url")]
        else:
            result["malicious_url_count"] = 0
    except Exception as e:
        result["error"] = str(e)
    return result


# ---------------------------------------------------------------------------
# Source: MalwareBazaar (abuse.ch) — File Hashes
# ---------------------------------------------------------------------------

def _enrich_malwarebazaar(file_hash: str) -> Dict:
    result = {"source": "MalwareBazaar", "available": False}
    key = _abusech_key()
    if not key:
        result["skipped"] = "No ABUSECH_API_KEY set"
        return result
    r = _post(
        "https://mb-api.abuse.ch/api/v1/",
        data={"query": "get_info", "hash": file_hash},
        headers={"Auth-Key": key},
    )
    if not r:
        result["error"] = "Request failed"
        return result
    try:
        data = r.json()
        status = data.get("query_status", "")
        result["available"] = True
        result["query_status"] = status

        if status == "ok":
            entries = data.get("data", [])
            if entries:
                entry = entries[0]
                result["found"] = True
                result["file_name"] = entry.get("file_name")
                result["file_type"] = entry.get("file_type")
                result["file_size"] = entry.get("file_size")
                result["mime_type"] = entry.get("mime_type")
                result["malware_family"] = entry.get("file_information", [{}])
                # Prefer the signature field
                result["signature"] = entry.get("signature")
                result["tags"] = entry.get("tags") or []
                result["first_seen"] = entry.get("first_seen")
                result["last_seen"] = entry.get("last_seen")
                result["reporter"] = entry.get("reporter")
                result["delivery_method"] = entry.get("delivery_method")
                result["intelligence"] = entry.get("intelligence", {})
            else:
                result["found"] = False
        else:
            result["found"] = False
    except Exception as e:
        result["error"] = str(e)
    return result


# ---------------------------------------------------------------------------
# Source: ThreatFox (abuse.ch) — IPs, Domains, Hashes
# ---------------------------------------------------------------------------

def _enrich_threatfox(indicator: str) -> Dict:
    result = {"source": "ThreatFox", "available": False}
    key = _abusech_key()
    if not key:
        result["skipped"] = "No ABUSECH_API_KEY set"
        return result
    r = _post(
        "https://threatfox-api.abuse.ch/api/v1/",
        json_body={"query": "search_ioc", "search_term": indicator},
        headers={"Content-Type": "application/json", "Auth-Key": key},
    )
    if not r:
        result["error"] = "Request failed"
        return result
    try:
        data = r.json()
        status = data.get("query_status", "")
        result["available"] = True
        result["query_status"] = status

        if status == "ok":
            iocs = data.get("data", [])
            result["found"] = True
            result["ioc_count"] = len(iocs)

            if iocs:
                best = iocs[0]
                result["ioc_type"] = best.get("ioc_type")
                result["threat_type"] = best.get("threat_type")
                result["threat_type_desc"] = best.get("threat_type_desc")
                result["malware"] = best.get("malware")
                result["malware_printable"] = best.get("malware_printable")
                result["malware_alias"] = best.get("malware_alias")
                result["confidence_level"] = best.get("confidence_level", 0)
                result["reporter"] = best.get("reporter")
                result["first_seen"] = best.get("first_seen")
                result["last_seen"] = best.get("last_seen")
                result["tags"] = best.get("tags") or []
                result["all_threats"] = list(
                    {i.get("malware_printable") for i in iocs if i.get("malware_printable")}
                )
        else:
            result["found"] = False
    except Exception as e:
        result["error"] = str(e)
    return result


# ---------------------------------------------------------------------------
# Source: AbuseIPDB (optional, requires ABUSEIPDB_API_KEY)
# ---------------------------------------------------------------------------

def _enrich_abuseipdb(ip: str) -> Dict:
    result = {"source": "AbuseIPDB", "available": False}
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        result["skipped"] = "No ABUSEIPDB_API_KEY set"
        return result

    r = _get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
        headers={"Key": api_key, "Accept": "application/json"},
    )
    if not r:
        result["error"] = "Request failed"
        return result
    try:
        data = r.json().get("data", {})
        result.update(
            {
                "available": True,
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "num_distinct_users": data.get("numDistinctUsers", 0),
                "last_reported_at": data.get("lastReportedAt"),
                "country_code": data.get("countryCode"),
                "usage_type": data.get("usageType"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "is_tor": data.get("isTor", False),
                "is_whitelisted": data.get("isWhitelisted", False),
                "hostnames": data.get("hostnames", []),
            }
        )
    except Exception as e:
        result["error"] = str(e)
    return result


# ---------------------------------------------------------------------------
# Source: VirusTotal (optional, requires VT_API_KEY)
# ---------------------------------------------------------------------------

def _enrich_virustotal(indicator: str, itype: IndicatorType) -> Dict:
    result = {"source": "VirusTotal", "available": False}
    api_key = os.environ.get("VT_API_KEY", "").strip()
    if not api_key:
        result["skipped"] = "No VT_API_KEY set"
        return result

    type_map = {
        IndicatorType.IPV4: f"ip_addresses/{indicator}",
        IndicatorType.IPV6: f"ip_addresses/{indicator}",
        IndicatorType.DOMAIN: f"domains/{indicator}",
        IndicatorType.MD5: f"files/{indicator}",
        IndicatorType.SHA1: f"files/{indicator}",
        IndicatorType.SHA256: f"files/{indicator}",
    }
    endpoint = type_map.get(itype)
    if not endpoint:
        result["skipped"] = "Unsupported type"
        return result

    r = _get(
        f"https://www.virustotal.com/api/v3/{endpoint}",
        headers={"x-apikey": api_key},
    )
    if not r:
        result["error"] = "Request failed (check key or rate limit)"
        return result
    try:
        data = r.json().get("data", {}).get("attributes", {})
        result["available"] = True

        # Common fields
        stats = data.get("last_analysis_stats", {})
        result["malicious"] = stats.get("malicious", 0)
        result["suspicious"] = stats.get("suspicious", 0)
        result["harmless"] = stats.get("harmless", 0)
        result["undetected"] = stats.get("undetected", 0)
        result["total_engines"] = sum(stats.values()) if stats else 0
        result["reputation"] = data.get("reputation", 0)

        # Type-specific
        if itype in (IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256):
            result["meaningful_name"] = data.get("meaningful_name")
            result["type_description"] = data.get("type_description")
            result["size"] = data.get("size")
            result["first_submission_date"] = data.get("first_submission_date")
            result["popular_threat_label"] = (
                data.get("popular_threat_classification", {}).get("suggested_threat_label")
            )

        if itype in (IndicatorType.IPV4, IndicatorType.IPV6):
            result["as_owner"] = data.get("as_owner")
            result["country"] = data.get("country")
            result["network"] = data.get("network")

        if itype == IndicatorType.DOMAIN:
            result["registrar"] = data.get("registrar")
            result["creation_date"] = data.get("creation_date")
            result["categories"] = data.get("categories", {})

    except Exception as e:
        result["error"] = str(e)
    return result


# ---------------------------------------------------------------------------
# Source: DNS resolution
# ---------------------------------------------------------------------------

def _enrich_dns(indicator: str, itype: IndicatorType) -> Dict:
    result = {"source": "DNS", "available": True}
    try:
        if itype == IndicatorType.DOMAIN:
            try:
                addr = socket.gethostbyname(indicator)
                result["resolved_ip"] = addr
            except socket.gaierror:
                result["resolved_ip"] = None
                result["resolution_failed"] = True

        elif itype in (IndicatorType.IPV4, IndicatorType.IPV6):
            try:
                hostname = socket.gethostbyaddr(indicator)[0]
                result["reverse_hostname"] = hostname
            except socket.herror:
                result["reverse_hostname"] = None
    except Exception as e:
        result["error"] = str(e)
        result["available"] = False
    return result


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def enrich_indicator(indicator: str, itype: IndicatorType) -> Dict:
    """
    Enrich an indicator with all applicable threat intel sources.
    Returns a dict with 'sources' key and optionally 'sub_indicators' for logs.
    """
    sources: List[Dict] = []

    if itype in (IndicatorType.IPV4, IndicatorType.IPV6):
        sources.append(_enrich_ipinfo(indicator))
        sources.append(_enrich_dns(indicator, itype))
        sources.append(_enrich_urlhaus(indicator))
        sources.append(_enrich_threatfox(indicator))
        sources.append(_enrich_abuseipdb(indicator))
        sources.append(_enrich_virustotal(indicator, itype))

    elif itype == IndicatorType.DOMAIN:
        sources.append(_enrich_dns(indicator, itype))
        sources.append(_enrich_urlhaus(indicator))
        sources.append(_enrich_threatfox(indicator))
        sources.append(_enrich_virustotal(indicator, itype))

    elif itype in (IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256):
        sources.append(_enrich_malwarebazaar(indicator))
        sources.append(_enrich_threatfox(indicator))
        sources.append(_enrich_virustotal(indicator, itype))

    elif itype == IndicatorType.LOG_SNIPPET:
        sub_indicators = extract_indicators_from_log(indicator)
        enriched_subs = []
        for sub in sub_indicators:
            sub_enrichment = enrich_indicator(sub["value"], sub["type"])
            enriched_subs.append(
                {
                    "value": sub["value"],
                    "type": sub["type"],
                    "enrichment": sub_enrichment,
                }
            )
        return {
            "sources": sources,
            "sub_indicators": enriched_subs,
            "raw_log": indicator,
        }

    return {"sources": sources}
