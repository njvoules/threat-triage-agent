"""
reporter.py — Report generation, terminal rendering, and file persistence.

Generates a structured triage report from enrichment + scoring data.
Reports are saved as timestamped .txt files in the /reports folder.
"""

import os
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any

from modules.detector import IndicatorType


# ---------------------------------------------------------------------------
# Response actions database
# ---------------------------------------------------------------------------

_RESPONSE_ACTIONS: Dict[str, Dict[str, List[str]]] = {
    "ip_critical": {
        "immediate": [
            "Block this IP at all perimeter firewalls and WAF rules immediately.",
            "Isolate any internal hosts observed communicating with this IP.",
            "Revoke any active sessions originating from or destined to this IP.",
            "Escalate to incident response team — treat as active compromise.",
        ],
        "investigate": [
            "Search SIEM/EDR for all historical connections to/from this IP (last 90 days).",
            "Review firewall allow rules that may permit traffic to this IP.",
            "Check proxy logs for HTTP/S requests; extract URLs and user-agents.",
            "Identify the first internal host that contacted this IP.",
            "Determine what data may have been transmitted.",
        ],
        "long_term": [
            "Add to automated threat feed blocklist and SOAR playbooks.",
            "Submit IP to AbuseIPDB to contribute to community intelligence.",
            "Consider geo-blocking the source country if not business-critical.",
            "Review and tighten egress filtering policies.",
        ],
    },
    "ip_high": {
        "immediate": [
            "Block this IP at perimeter firewall as a precaution.",
            "Alert endpoint protection team to scan any hosts that connected to this IP.",
        ],
        "investigate": [
            "Pull SIEM logs for all connections to/from this IP.",
            "Verify whether any internal assets communicated with this IP recently.",
            "Check if this IP appears in DNS logs or proxy logs.",
        ],
        "long_term": [
            "Add to watchlist / block at next change window.",
            "Monitor for recurrence in threat intelligence feeds.",
        ],
    },
    "ip_medium": {
        "immediate": [
            "Flag this IP in SIEM with elevated alert priority.",
        ],
        "investigate": [
            "Review recent connections to this IP and the nature of traffic.",
            "Cross-reference with other threat indicators from the same timeframe.",
        ],
        "long_term": [
            "Add to monitoring watchlist.",
            "Re-evaluate if additional suspicious activity is linked to this IP.",
        ],
    },
    "ip_low": {
        "immediate": [],
        "investigate": [
            "Note for documentation; no immediate action required.",
            "Review context in which this IP appeared (log source, user activity).",
        ],
        "long_term": ["Continue monitoring standard baselines."],
    },
    "domain_critical": {
        "immediate": [
            "Block DNS resolution of this domain at all DNS resolvers (RPZ or sinkhole).",
            "Add to web proxy category block list.",
            "Identify all internal users/systems that resolved or visited this domain.",
            "Escalate to incident response — potential active C2 or phishing campaign.",
        ],
        "investigate": [
            "Query DNS logs for all hosts that resolved this domain.",
            "Check proxy/web gateway logs for HTTP/S requests to this domain.",
            "Identify any downloaded files or POST requests to this domain.",
            "Determine if credentials may have been submitted (phishing context).",
        ],
        "long_term": [
            "Submit domain to threat intelligence sharing platforms.",
            "Report phishing domain to registrar and hosting provider for takedown.",
            "Review email filtering rules to catch similar lookalike domains.",
            "Add domain pattern to DLP and email gateway rules.",
        ],
    },
    "domain_high": {
        "immediate": [
            "Block this domain at DNS resolver and web proxy.",
            "Alert users who may have visited this domain.",
        ],
        "investigate": [
            "Identify internal hosts that resolved or browsed to this domain.",
            "Check for any file downloads associated with this domain.",
        ],
        "long_term": [
            "Add to blocklist and threat feed.",
            "Report to abuse contact of domain registrar.",
        ],
    },
    "domain_medium": {
        "immediate": [
            "Flag domain in DNS monitoring and proxy logs.",
        ],
        "investigate": [
            "Review resolution history and traffic volume for this domain.",
            "Check for associated phishing or malware hosting indicators.",
        ],
        "long_term": [
            "Monitor domain for escalating threat signals.",
        ],
    },
    "domain_low": {
        "immediate": [],
        "investigate": [
            "Document context; no immediate action required.",
        ],
        "long_term": ["Continue standard monitoring."],
    },
    "hash_critical": {
        "immediate": [
            "Quarantine any file matching this hash on ALL endpoints immediately.",
            "Isolate affected system(s) from the network.",
            "Preserve forensic image of affected system before remediation.",
            "Escalate to incident response — assume full system compromise.",
        ],
        "investigate": [
            "Search all endpoints via EDR/AV for this hash.",
            "Identify how the file arrived (email, download, USB, lateral movement).",
            "Review process execution tree — what did the malware spawn?",
            "Check for persistence mechanisms (registry, scheduled tasks, services).",
            "Audit credentials on compromised host — assume all are stolen.",
            "Look for lateral movement from the compromised host.",
        ],
        "long_term": [
            "Push hash to EDR/AV policy as blocked indicator.",
            "Submit sample to AV vendors and threat sharing platforms.",
            "Conduct post-incident review and update detection rules.",
            "Patch the initial access vector that allowed delivery.",
        ],
    },
    "hash_high": {
        "immediate": [
            "Quarantine file and isolate affected host.",
            "Engage endpoint security team for triage.",
        ],
        "investigate": [
            "Run EDR hunt for this hash across all endpoints.",
            "Review process execution context and parent process.",
            "Check for network connections established by this file.",
        ],
        "long_term": [
            "Add hash to EDR block list and AV signatures.",
            "Review delivery channel and patch if applicable.",
        ],
    },
    "hash_medium": {
        "immediate": [
            "Flag file for detailed AV/sandbox analysis.",
        ],
        "investigate": [
            "Submit file to sandbox for behavioral analysis.",
            "Identify origin of the file and distribution vector.",
        ],
        "long_term": [
            "Monitor for similar indicators; add to watchlist.",
        ],
    },
    "hash_low": {
        "immediate": [],
        "investigate": [
            "Document and cross-reference with other indicators.",
        ],
        "long_term": ["No immediate action; continue monitoring."],
    },
    "log_snippet": {
        "immediate": [
            "Review the source system generating these log entries.",
            "Correlate with other log sources (SIEM, firewall, EDR) for the same timeframe.",
        ],
        "investigate": [
            "Identify the originating user account or process.",
            "Determine if extracted IPs/domains/hashes are associated with known threats.",
            "Look for patterns suggesting automated attack tools (rapid sequential attempts).",
        ],
        "long_term": [
            "Tune detection rules to alert on similar log patterns.",
            "Consider deploying honeypots if scanning activity is detected.",
        ],
    },
}


def _get_response_actions(itype: IndicatorType, severity: str) -> Dict[str, List[str]]:
    if itype == IndicatorType.LOG_SNIPPET:
        return _RESPONSE_ACTIONS.get("log_snippet", {})

    severity_lower = severity.lower()
    if severity_lower == "critical":
        severity_lower = "critical"
    elif severity_lower == "high":
        severity_lower = "high"
    elif severity_lower == "medium":
        severity_lower = "medium"
    else:
        severity_lower = "low"

    type_map = {
        IndicatorType.IPV4: "ip",
        IndicatorType.IPV6: "ip",
        IndicatorType.DOMAIN: "domain",
        IndicatorType.MD5: "hash",
        IndicatorType.SHA1: "hash",
        IndicatorType.SHA256: "hash",
    }
    prefix = type_map.get(itype, "ip")
    key = f"{prefix}_{severity_lower}"
    return _RESPONSE_ACTIONS.get(key, _RESPONSE_ACTIONS.get(f"{prefix}_low", {}))


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

def generate_report(
    indicator: str,
    itype: IndicatorType,
    severity: str,
    score: int,
    enrichment_data: Dict,
    mitre_mappings: List[Dict],
) -> Dict:
    """Assemble the report dict from all analysis components."""
    response_actions = _get_response_actions(itype, severity)
    intel_summary = _build_intel_summary(itype, enrichment_data)

    return {
        "indicator": indicator,
        "type": itype.value,
        "severity": severity,
        "score": score,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "intel_summary": intel_summary,
        "mitre_mappings": mitre_mappings,
        "response_actions": response_actions,
        "enrichment_raw": enrichment_data,
    }


def _build_intel_summary(itype: IndicatorType, enrichment_data: Dict) -> List[Dict]:
    """Convert raw enrichment data into human-readable summary blocks."""
    blocks = []

    def src_by_name(name: str) -> Dict:
        for s in enrichment_data.get("sources", []):
            if s.get("source") == name:
                return s
        return {}

    if itype in (IndicatorType.IPV4, IndicatorType.IPV6):
        # ipinfo
        ipinfo = src_by_name("ipinfo.io")
        if ipinfo.get("available"):
            lines = []
            if ipinfo.get("bogon"):
                lines.append("  Note: Bogon/private address space")
            loc_parts = [p for p in [ipinfo.get("city"), ipinfo.get("region"), ipinfo.get("country")] if p]
            if loc_parts:
                lines.append(f"  Location : {', '.join(loc_parts)}")
            if ipinfo.get("org"):
                lines.append(f"  Org/ASN  : {ipinfo['org']}")
            if ipinfo.get("hostname"):
                lines.append(f"  Hostname : {ipinfo['hostname']}")
            if ipinfo.get("timezone"):
                lines.append(f"  Timezone : {ipinfo['timezone']}")
            blocks.append({"source": "ipinfo.io", "lines": lines})

        # DNS
        dns = src_by_name("DNS")
        if dns.get("available") and dns.get("reverse_hostname"):
            blocks.append({"source": "DNS (Reverse)", "lines": [f"  PTR Record : {dns['reverse_hostname']}"]})

        # URLhaus
        urlhaus = src_by_name("URLhaus")
        if urlhaus.get("skipped"):
            blocks.append({"source": "URLhaus (abuse.ch)", "lines": [f"  [Skipped — {urlhaus['skipped']}]"]})
        elif urlhaus.get("available"):
            if urlhaus.get("malicious_url_count", 0) > 0:
                lines = [
                    f"  Status     : MALICIOUS HOST — {urlhaus['malicious_url_count']} malicious URL(s) found",
                    f"  Threats    : {', '.join(urlhaus.get('threat_types', [])) or 'N/A'}",
                    f"  Tags       : {', '.join(urlhaus.get('tags', [])) or 'None'}",
                ]
                for url in urlhaus.get("sample_urls", []):
                    lines.append(f"  Sample URL : {url}")
            else:
                lines = ["  Status     : Not found in URLhaus database"]
            blocks.append({"source": "URLhaus (abuse.ch)", "lines": lines})

        # ThreatFox
        _append_threatfox_block(blocks, src_by_name("ThreatFox"))

        # AbuseIPDB
        abuseipdb = src_by_name("AbuseIPDB")
        if abuseipdb.get("available"):
            score_val = abuseipdb.get("abuse_confidence_score", 0)
            lines = [
                f"  Abuse Score   : {score_val}%  ({'HIGH RISK' if score_val >= 70 else 'MODERATE' if score_val >= 30 else 'LOW RISK'})",
                f"  Total Reports : {abuseipdb.get('total_reports', 0)} ({abuseipdb.get('num_distinct_users', 0)} unique reporters)",
                f"  Last Reported : {abuseipdb.get('last_reported_at') or 'N/A'}",
                f"  Usage Type    : {abuseipdb.get('usage_type') or 'N/A'}",
                f"  ISP           : {abuseipdb.get('isp') or 'N/A'}",
                f"  Tor Exit Node : {'Yes' if abuseipdb.get('is_tor') else 'No'}",
            ]
            blocks.append({"source": "AbuseIPDB", "lines": lines})
        elif abuseipdb.get("skipped"):
            blocks.append({"source": "AbuseIPDB", "lines": [f"  [Skipped — {abuseipdb['skipped']}]"]})

        # VirusTotal
        _append_vt_block(blocks, src_by_name("VirusTotal"))

    elif itype == IndicatorType.DOMAIN:
        # DNS
        dns = src_by_name("DNS")
        if dns.get("available"):
            if dns.get("resolved_ip"):
                lines = [f"  Resolves To : {dns['resolved_ip']}"]
            elif dns.get("resolution_failed"):
                lines = ["  Resolution  : FAILED (domain may be down or sinkholed)"]
            else:
                lines = ["  DNS         : No resolution data"]
            blocks.append({"source": "DNS", "lines": lines})

        _append_urlhaus_domain_block(blocks, src_by_name("URLhaus"))
        _append_threatfox_block(blocks, src_by_name("ThreatFox"))
        _append_vt_block(blocks, src_by_name("VirusTotal"))

    elif itype in (IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256):
        # MalwareBazaar
        mbz = src_by_name("MalwareBazaar")
        if mbz.get("skipped"):
            blocks.append({"source": "MalwareBazaar (abuse.ch)", "lines": [f"  [Skipped — {mbz['skipped']}]"]})
        elif mbz.get("available"):
            if mbz.get("found"):
                lines = [
                    f"  Status      : MALWARE CONFIRMED",
                    f"  File Name   : {mbz.get('file_name') or 'N/A'}",
                    f"  File Type   : {mbz.get('file_type') or 'N/A'}",
                    f"  Signature   : {mbz.get('signature') or 'N/A'}",
                    f"  Tags        : {', '.join(mbz.get('tags', [])) or 'None'}",
                    f"  First Seen  : {mbz.get('first_seen') or 'N/A'}",
                    f"  Last Seen   : {mbz.get('last_seen') or 'N/A'}",
                    f"  Delivery    : {mbz.get('delivery_method') or 'N/A'}",
                ]
                intel = mbz.get("intelligence", {})
                if intel.get("downloads"):
                    lines.append(f"  Downloads   : {intel['downloads']}")
                if intel.get("uploads"):
                    lines.append(f"  Uploads     : {intel['uploads']}")
            else:
                lines = ["  Status      : Not found in MalwareBazaar database"]
            blocks.append({"source": "MalwareBazaar (abuse.ch)", "lines": lines})

        _append_threatfox_block(blocks, src_by_name("ThreatFox"))
        _append_vt_block(blocks, src_by_name("VirusTotal"))

    elif itype == IndicatorType.LOG_SNIPPET:
        sub_indicators = enrichment_data.get("sub_indicators", [])
        if sub_indicators:
            lines = [f"  Extracted {len(sub_indicators)} indicator(s) from log:"]
            for sub in sub_indicators:
                lines.append(f"    • [{sub['type'].value}] {sub['value']}")
            blocks.append({"source": "Log Analysis", "lines": lines})

            for sub in sub_indicators:
                sub_summary = _build_intel_summary(sub["type"], sub["enrichment"])
                for blk in sub_summary:
                    blk["source"] = f"  [{sub['value']}] {blk['source']}"
                    blocks.append(blk)
        else:
            blocks.append({
                "source": "Log Analysis",
                "lines": ["  No extractable indicators found in log snippet."],
            })

    return blocks


def _append_threatfox_block(blocks: List, src: Dict):
    if src.get("skipped"):
        blocks.append({"source": "ThreatFox (abuse.ch)", "lines": [f"  [Skipped — {src['skipped']}]"]})
        return
    if not src.get("available"):
        return
    if src.get("found"):
        lines = [
            f"  Status      : IOC FOUND in ThreatFox",
            f"  Malware     : {src.get('malware_printable') or 'N/A'}",
            f"  Threat Type : {src.get('threat_type_desc') or src.get('threat_type') or 'N/A'}",
            f"  Confidence  : {src.get('confidence_level', 0)}%",
            f"  Tags        : {', '.join(src.get('tags', [])) or 'None'}",
            f"  First Seen  : {src.get('first_seen') or 'N/A'}",
            f"  Last Seen   : {src.get('last_seen') or 'N/A'}",
        ]
        if src.get("all_threats") and len(src["all_threats"]) > 1:
            lines.append(f"  All Threats : {', '.join(src['all_threats'])}")
    else:
        lines = ["  Status      : Not found in ThreatFox database"]
    blocks.append({"source": "ThreatFox (abuse.ch)", "lines": lines})


def _append_urlhaus_domain_block(blocks: List, src: Dict):
    if src.get("skipped"):
        blocks.append({"source": "URLhaus (abuse.ch)", "lines": [f"  [Skipped — {src['skipped']}]"]})
        return
    if not src.get("available"):
        return
    if src.get("malicious_url_count", 0) > 0:
        lines = [
            f"  Status     : MALICIOUS HOST — {src['malicious_url_count']} malicious URL(s) found",
            f"  Threats    : {', '.join(src.get('threat_types', [])) or 'N/A'}",
            f"  Tags       : {', '.join(src.get('tags', [])) or 'None'}",
        ]
        for url in src.get("sample_urls", []):
            lines.append(f"  Sample URL : {url}")
    else:
        lines = ["  Status     : Not found in URLhaus database"]
    blocks.append({"source": "URLhaus (abuse.ch)", "lines": lines})


def _append_vt_block(blocks: List, src: Dict):
    if src.get("skipped"):
        blocks.append({"source": "VirusTotal", "lines": [f"  [Skipped — {src['skipped']}]"]})
        return
    if not src.get("available"):
        return
    malicious = src.get("malicious", 0)
    suspicious = src.get("suspicious", 0)
    total = src.get("total_engines", 0)
    lines = [
        f"  Detections  : {malicious} malicious, {suspicious} suspicious / {total} engines",
        f"  Reputation  : {src.get('reputation', 0)} (negative = bad)",
    ]
    if src.get("meaningful_name"):
        lines.append(f"  File Name   : {src['meaningful_name']}")
    if src.get("popular_threat_label"):
        lines.append(f"  Threat Label: {src['popular_threat_label']}")
    if src.get("type_description"):
        lines.append(f"  File Type   : {src['type_description']}")
    if src.get("as_owner"):
        lines.append(f"  AS Owner    : {src['as_owner']}")
    if src.get("registrar"):
        lines.append(f"  Registrar   : {src['registrar']}")
    blocks.append({"source": "VirusTotal", "lines": lines})


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_SEVERITY_COLORS = {
    "Critical": "\033[91m",  # bright red
    "High":     "\033[31m",  # red
    "Medium":   "\033[33m",  # yellow
    "Low":      "\033[32m",  # green
}
_RESET = "\033[0m"
_BOLD  = "\033[1m"
_DIM   = "\033[2m"
_CYAN  = "\033[36m"
_WHITE = "\033[97m"

_WIDTH = 72

# Use ASCII fallbacks when the terminal encoding can't handle box-drawing chars
import sys as _sys
_UNICODE_OK = getattr(_sys.stdout, "encoding", "ascii").lower().replace("-", "") in (
    "utf8", "utf16", "utf32", "utf8sig"
)
_BOX_TL  = "╔" if _UNICODE_OK else "+"
_BOX_TR  = "╗" if _UNICODE_OK else "+"
_BOX_BL  = "╚" if _UNICODE_OK else "+"
_BOX_BR  = "╝" if _UNICODE_OK else "+"
_BOX_H   = "═" if _UNICODE_OK else "="
_BOX_V   = "║" if _UNICODE_OK else "|"
_HR_CHAR = "─" if _UNICODE_OK else "-"


def _hr(char: str = None) -> str:
    return (char or _HR_CHAR) * _WIDTH


def _center(text: str, char: str = " ") -> str:
    return text.center(_WIDTH)


def _severity_badge(severity: str, score: int, color: bool = True) -> str:
    sev_color = _SEVERITY_COLORS.get(severity, "") if color else ""
    reset = _RESET if color else ""
    bold = _BOLD if color else ""
    return f"{bold}{sev_color}[ {severity.upper()} - {score}/100 ]{reset}"


def print_report(report: Dict, color: bool = True) -> None:
    """Render the report to stdout with optional ANSI color."""
    bold  = _BOLD  if color else ""
    reset = _RESET if color else ""
    cyan  = _CYAN  if color else ""
    dim   = _DIM   if color else ""

    print()
    print(bold + _BOX_TL + _BOX_H * (_WIDTH - 2) + _BOX_TR + reset)
    print(bold + _BOX_V  + _center("  THREAT TRIAGE REPORT  ") + _BOX_V  + reset)
    print(bold + _BOX_BL + _BOX_H * (_WIDTH - 2) + _BOX_BR + reset)

    print(dim + f"\n  Generated : {report['generated_at']}" + reset)

    # Indicator details
    print()
    print(bold + cyan + "INDICATOR DETAILS" + reset)
    print(_hr())
    ind = report["indicator"]
    display_ind = (ind[:64] + "...") if len(ind) > 64 else ind
    print(f"  Indicator : {display_ind}")
    print(f"  Type      : {report['type']}")
    print(f"  Severity  : {_severity_badge(report['severity'], report['score'], color)}")

    # Intel summary
    print()
    print(bold + cyan + "THREAT INTEL SUMMARY" + reset)
    print(_hr())
    for block in report["intel_summary"]:
        print(f"\n  [{block['source']}]")
        for line in block["lines"]:
            print(line)

    # MITRE ATT&CK
    print()
    print(bold + cyan + "MITRE ATT&CK MAPPING" + reset)
    print(_hr())
    mappings = report["mitre_mappings"]
    if mappings:
        header = f"  {'Tactic':<26}  {'ID':<12}  {'Technique':<32}  Confidence"
        print(header)
        print("  " + _HR_CHAR * (_WIDTH - 4))
        for m in mappings:
            conf_color = {
                "High":   _SEVERITY_COLORS.get("High", ""),
                "Medium": _SEVERITY_COLORS.get("Medium", ""),
                "Low":    _SEVERITY_COLORS.get("Low", ""),
            }.get(m["confidence"], "") if color else ""
            print(
                f"  {m['tactic']:<26}  {m['technique_id']:<12}  {m['technique']:<32}  "
                f"{conf_color}{m['confidence']}{reset}"
            )
    else:
        print("  No MITRE ATT&CK techniques mapped for this indicator.")

    # Response actions
    actions = report["response_actions"]
    if actions:
        print()
        print(bold + cyan + "RECOMMENDED RESPONSE ACTIONS" + reset)
        print(_hr())

        sections = [
            ("immediate", "IMMEDIATE"),
            ("investigate", "INVESTIGATE"),
            ("long_term", "LONG-TERM"),
        ]
        for key, label in sections:
            items = actions.get(key, [])
            if items:
                print(f"\n  {bold}[{label}]{reset}")
                for i, item in enumerate(items, 1):
                    wrapped = textwrap.wrap(item, width=_WIDTH - 8)
                    for j, line in enumerate(wrapped):
                        if j == 0:
                            print(f"    {i}. {line}")
                        else:
                            print(f"       {line}")

    print()
    print(_hr(_BOX_H))
    print()


def _report_to_text(report: Dict) -> str:
    """Render report as plain text (no ANSI codes) for file output."""
    lines = []
    lines.append("=" * _WIDTH)
    lines.append(_center("THREAT TRIAGE REPORT"))
    lines.append("=" * _WIDTH)
    lines.append(f"\nGenerated : {report['generated_at']}\n")

    lines.append("INDICATOR DETAILS")
    lines.append(_hr())
    ind = report["indicator"]
    display_ind = (ind[:64] + "...") if len(ind) > 64 else ind
    lines.append(f"  Indicator : {display_ind}")
    lines.append(f"  Type      : {report['type']}")
    lines.append(f"  Severity  : {report['severity']}  [Score: {report['score']}/100]")

    lines.append("\nTHREAT INTEL SUMMARY")
    lines.append(_hr())
    for block in report["intel_summary"]:
        lines.append(f"\n  [{block['source']}]")
        for line in block["lines"]:
            lines.append(line)

    lines.append("\nMITRE ATT&CK MAPPING")
    lines.append(_hr())
    mappings = report["mitre_mappings"]
    if mappings:
        lines.append(f"  {'Tactic':<26}  {'ID':<12}  {'Technique':<32}  Confidence")
        lines.append("  " + "-" * (_WIDTH - 4))
        for m in mappings:
            lines.append(
                f"  {m['tactic']:<26}  {m['technique_id']:<12}  {m['technique']:<32}  {m['confidence']}"
            )
    else:
        lines.append("  No MITRE ATT&CK techniques mapped.")

    actions = report["response_actions"]
    if actions:
        lines.append("\nRECOMMENDED RESPONSE ACTIONS")
        lines.append(_hr())
        for key, label in [("immediate", "IMMEDIATE"), ("investigate", "INVESTIGATE"), ("long_term", "LONG-TERM")]:
            items = actions.get(key, [])
            if items:
                lines.append(f"\n  [{label}]")
                for i, item in enumerate(items, 1):
                    wrapped = textwrap.wrap(item, width=_WIDTH - 8)
                    for j, line in enumerate(wrapped):
                        if j == 0:
                            lines.append(f"    {i}. {line}")
                        else:
                            lines.append(f"       {line}")

    lines.append("\n" + "=" * _WIDTH)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# File persistence
# ---------------------------------------------------------------------------

def save_report(report: Dict, output_dir: str = "reports") -> str:
    """
    Save report as a timestamped .txt file.
    Returns the full path of the saved file.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Build a safe filename from the indicator
    raw_indicator = report["indicator"]
    safe_indicator = re.sub(r"[^\w.\-]", "_", raw_indicator[:40]).strip("_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"triage_{timestamp}_{safe_indicator}.txt"
    filepath = os.path.join(output_dir, filename)

    text = _report_to_text(report)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(text)

    return filepath


import re  # needed for save_report
