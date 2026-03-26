"""
scorer.py — Severity scoring and MITRE ATT&CK mapping.

Scoring model (0–100):
  Each intelligence source contributes points based on what it found.
  Score is clamped to 100 and thresholded into severity buckets:
    0–19  → Low
    20–44 → Medium
    45–69 → High
    70+   → Critical

MITRE ATT&CK:
  Findings from each source are mapped to relevant tactics and techniques.
  Mappings are heuristic — based on indicator type and threat context.
"""

from typing import Tuple, List, Dict, Any
from modules.detector import IndicatorType


# ---------------------------------------------------------------------------
# Severity thresholds
# ---------------------------------------------------------------------------

SEVERITY_THRESHOLDS = [
    (70, "Critical"),
    (45, "High"),
    (20, "Medium"),
    (0,  "Low"),
]


def _score_to_severity(score: int) -> str:
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "Low"


# ---------------------------------------------------------------------------
# MITRE ATT&CK reference data
# ---------------------------------------------------------------------------

# Format: (tactic_id, tactic_name, technique_id, technique_name)
MITRE = {
    "recon_scanning":       ("TA0043", "Reconnaissance",         "T1046",     "Network Service Discovery"),
    "resource_dev":         ("TA0042", "Resource Development",   "T1583.001", "Acquire Infrastructure: Domains"),
    "initial_phishing":     ("TA0001", "Initial Access",         "T1566.002", "Spearphishing Link"),
    "initial_exploit":      ("TA0001", "Initial Access",         "T1190",     "Exploit Public-Facing Application"),
    "exec_malicious_file":  ("TA0002", "Execution",              "T1204.002", "Malicious File"),
    "exec_script":          ("TA0002", "Execution",              "T1059",     "Command and Scripting Interpreter"),
    "persistence_task":     ("TA0003", "Persistence",            "T1053",     "Scheduled Task/Job"),
    "defense_inject":       ("TA0005", "Defense Evasion",        "T1055",     "Process Injection"),
    "cred_store":           ("TA0006", "Credential Access",      "T1555",     "Credentials from Password Stores"),
    "cred_input_capture":   ("TA0006", "Credential Access",      "T1056",     "Input Capture"),
    "cred_brute":           ("TA0006", "Credential Access",      "T1110",     "Brute Force"),
    "discovery_net":        ("TA0007", "Discovery",              "T1046",     "Network Service Discovery"),
    "lateral_remote":       ("TA0008", "Lateral Movement",       "T1021",     "Remote Services"),
    "collection_data":      ("TA0009", "Collection",             "T1005",     "Data from Local System"),
    "c2_app_layer":         ("TA0011", "Command and Control",    "T1071.001", "Application Layer Protocol: Web Protocols"),
    "c2_nonapp":            ("TA0011", "Command and Control",    "T1095",     "Non-Application Layer Protocol"),
    "c2_encrypted":         ("TA0011", "Command and Control",    "T1573",     "Encrypted Channel"),
    "c2_dns":               ("TA0011", "Command and Control",    "T1071.004", "Application Layer Protocol: DNS"),
    "c2_dga":               ("TA0011", "Command and Control",    "T1568.002", "Dynamic Resolution: Domain Generation Algorithms"),
    "c2_proxy":             ("TA0011", "Command and Control",    "T1090.003", "Proxy: Multi-hop Proxy"),
    "exfil_transfer":       ("TA0010", "Exfiltration",           "T1048",     "Exfiltration Over Alternative Protocol"),
    "exfil_auto":           ("TA0010", "Exfiltration",           "T1020",     "Automated Exfiltration"),
    "impact_ransomware":    ("TA0040", "Impact",                 "T1486",     "Data Encrypted for Impact"),
    "impact_defacement":    ("TA0040", "Impact",                 "T1491",     "Defacement"),
    "ingress_tool":         ("TA0011", "Command and Control",    "T1105",     "Ingress Tool Transfer"),
}


def _make_mapping(key: str, confidence: str = "Medium") -> Dict:
    t = MITRE[key]
    return {
        "tactic_id":     t[0],
        "tactic":        t[1],
        "technique_id":  t[2],
        "technique":     t[3],
        "confidence":    confidence,
    }


# ---------------------------------------------------------------------------
# Source-specific scoring helpers
# ---------------------------------------------------------------------------

def _score_urlhaus(src: Dict) -> Tuple[int, List[Dict]]:
    score = 0
    mitre: List[Dict] = []
    if not src.get("available") or src.get("query_status") != "is_host":
        return score, mitre

    count = src.get("malicious_url_count", 0)
    threats = [t.lower() for t in (src.get("threat_types") or [])]
    tags = [t.lower() for t in (src.get("tags") or [])]

    if count > 0:
        score += min(30, 10 + count * 2)  # 10 base + 2/URL, max 30

    if any("malware" in t for t in threats):
        score += 10
        mitre.append(_make_mapping("exec_malicious_file", "High"))
        mitre.append(_make_mapping("ingress_tool", "Medium"))

    if any("phishing" in t for t in threats):
        score += 10
        mitre.append(_make_mapping("initial_phishing", "High"))
        mitre.append(_make_mapping("resource_dev", "Medium"))

    if any("botnet" in t or "c2" in t for t in threats + tags):
        score += 15
        mitre.append(_make_mapping("c2_app_layer", "High"))

    return score, mitre


def _score_threatfox(src: Dict) -> Tuple[int, List[Dict]]:
    score = 0
    mitre: List[Dict] = []
    if not src.get("available") or not src.get("found"):
        return score, mitre

    confidence = src.get("confidence_level", 0)
    threat_type = (src.get("threat_type") or "").lower()
    malware = (src.get("malware_printable") or "").lower()
    tags = [t.lower() for t in (src.get("tags") or [])]

    # Base score from ThreatFox confidence
    if confidence >= 75:
        score += 35
        conf_label = "High"
    elif confidence >= 50:
        score += 22
        conf_label = "Medium"
    else:
        score += 12
        conf_label = "Low"

    # Threat type mappings
    if "botnet_cc" in threat_type or "c2" in threat_type:
        mitre.append(_make_mapping("c2_app_layer", conf_label))
        mitre.append(_make_mapping("c2_encrypted", "Low"))

    if "payload_delivery" in threat_type:
        mitre.append(_make_mapping("exec_malicious_file", conf_label))
        mitre.append(_make_mapping("ingress_tool", "Medium"))

    if "phishing" in threat_type:
        mitre.append(_make_mapping("initial_phishing", conf_label))

    # Malware family keywords
    if any(k in malware for k in ("ransom", "locker", "crypt")):
        score += 10
        mitre.append(_make_mapping("impact_ransomware", conf_label))

    if any(k in malware for k in ("stealer", "spy", "keylog", "grabber")):
        score += 5
        mitre.append(_make_mapping("cred_input_capture", conf_label))
        mitre.append(_make_mapping("exfil_auto", "Medium"))

    if any(k in malware for k in ("rat", "remote", "backdoor", "trojan")):
        score += 5
        mitre.append(_make_mapping("c2_app_layer", conf_label))
        mitre.append(_make_mapping("lateral_remote", "Low"))

    if any(k in malware for k in ("miner", "coin")):
        mitre.append(_make_mapping("exec_script", "Medium"))

    if "dga" in tags:
        mitre.append(_make_mapping("c2_dga", conf_label))

    if "tor" in tags:
        mitre.append(_make_mapping("c2_proxy", "Medium"))

    return score, mitre


def _score_abuseipdb(src: Dict) -> Tuple[int, List[Dict]]:
    score = 0
    mitre: List[Dict] = []
    if not src.get("available"):
        return score, mitre

    abuse_score = src.get("abuse_confidence_score", 0)
    is_tor = src.get("is_tor", False)
    usage = (src.get("usage_type") or "").lower()

    if abuse_score >= 80:
        score += 40
    elif abuse_score >= 50:
        score += 25
    elif abuse_score >= 20:
        score += 12
    elif abuse_score > 0:
        score += 5

    if is_tor:
        score += 10
        mitre.append(_make_mapping("c2_proxy", "High"))

    if "scanning" in usage or "brute" in usage:
        mitre.append(_make_mapping("recon_scanning", "High"))
        mitre.append(_make_mapping("cred_brute", "Medium"))

    if abuse_score >= 50:
        mitre.append(_make_mapping("initial_exploit", "Medium"))

    return score, mitre


def _score_malwarebazaar(src: Dict) -> Tuple[int, List[Dict]]:
    score = 0
    mitre: List[Dict] = []
    if not src.get("available") or not src.get("found"):
        return score, mitre

    score += 45  # Known malware hash is always at least High
    tags = [t.lower() for t in (src.get("tags") or [])]
    sig = (src.get("signature") or "").lower()

    mitre.append(_make_mapping("exec_malicious_file", "High"))

    if any(k in sig or k in tags for k in ("ransom", "locker", "crypt", "wanna")):
        score += 20
        mitre.append(_make_mapping("impact_ransomware", "High"))
        mitre.append(_make_mapping("collection_data", "Medium"))

    if any(k in sig or k in tags for k in ("stealer", "spy", "keylog", "formgrab")):
        score += 15
        mitre.append(_make_mapping("cred_input_capture", "High"))
        mitre.append(_make_mapping("cred_store", "High"))
        mitre.append(_make_mapping("exfil_auto", "Medium"))

    if any(k in sig or k in tags for k in ("rat", "remote", "backdoor")):
        score += 15
        mitre.append(_make_mapping("c2_app_layer", "High"))
        mitre.append(_make_mapping("lateral_remote", "Medium"))

    if any(k in sig or k in tags for k in ("loader", "dropper", "downloader", "stager")):
        score += 10
        mitre.append(_make_mapping("ingress_tool", "High"))
        mitre.append(_make_mapping("exec_script", "Medium"))
        mitre.append(_make_mapping("defense_inject", "Low"))

    if any(k in sig or k in tags for k in ("miner", "coin", "xmr")):
        score += 5
        mitre.append(_make_mapping("exec_script", "Medium"))

    if any(k in sig or k in tags for k in ("worm", "propagat", "spread")):
        score += 10
        mitre.append(_make_mapping("lateral_remote", "High"))

    return score, mitre


def _score_virustotal(src: Dict) -> Tuple[int, List[Dict]]:
    score = 0
    mitre: List[Dict] = []
    if not src.get("available"):
        return score, mitre

    malicious = src.get("malicious", 0)
    suspicious = src.get("suspicious", 0)
    label = (src.get("popular_threat_label") or "").lower()

    if malicious > 20:
        score += 40
    elif malicious > 10:
        score += 30
    elif malicious > 4:
        score += 20
    elif malicious > 0:
        score += 12
    if suspicious > 5:
        score += 8
    elif suspicious > 0:
        score += 4

    if malicious > 0:
        mitre.append(_make_mapping("exec_malicious_file", "High" if malicious > 10 else "Medium"))

    for kw, key in [
        ("ransom",  "impact_ransomware"),
        ("trojan",  "c2_app_layer"),
        ("stealer", "cred_input_capture"),
        ("miner",   "exec_script"),
        ("backdoor","c2_app_layer"),
        ("dropper", "ingress_tool"),
    ]:
        if kw in label:
            mitre.append(_make_mapping(key, "Medium"))

    return score, mitre


def _score_ipinfo(src: Dict) -> Tuple[int, List[Dict]]:
    """Small penalty/bonus adjustments from geo/ASN data."""
    score = 0
    mitre: List[Dict] = []
    if not src.get("available"):
        return score, mitre
    if src.get("bogon"):
        score -= 5  # Private/reserved addresses are less likely external threats
    return score, mitre


# ---------------------------------------------------------------------------
# Log snippet aggregation
# ---------------------------------------------------------------------------

def _score_log_snippet(enrichment_data: Dict) -> Tuple[int, List[Dict]]:
    """
    For log snippets, score across all extracted sub-indicators and
    return the worst-case score + union of MITRE mappings.
    """
    sub_indicators = enrichment_data.get("sub_indicators", [])
    if not sub_indicators:
        return 5, []

    max_score = 0
    all_mitre: List[Dict] = []

    for sub in sub_indicators:
        sub_itype = sub["type"]
        sub_enrichment = sub["enrichment"]
        sub_score, _, sub_mitre = calculate_severity(sub_itype, sub_enrichment)
        # Convert severity back to numeric for comparison
        numeric = {"Low": 5, "Medium": 30, "High": 55, "Critical": 80}
        n = numeric.get(sub_score, 5)
        if n > max_score:
            max_score = n
        for m in sub_mitre:
            if m not in all_mitre:
                all_mitre.append(m)

    # Add brute-force / lateral movement hints from log keywords
    raw = enrichment_data.get("raw_log", "").lower()
    if any(k in raw for k in ("failed password", "authentication failure", "invalid user", "failed login")):
        max_score = max(max_score, 20)
        all_mitre.append(_make_mapping("cred_brute", "Medium"))
    if any(k in raw for k in ("sql", "union select", "' or '", "xp_cmdshell")):
        max_score = max(max_score, 45)
        all_mitre.append(_make_mapping("initial_exploit", "High"))
    if any(k in raw for k in ("powershell", "cmd.exe", "/bin/sh", "/bin/bash", "wget", "curl")):
        max_score = max(max_score, 30)
        all_mitre.append(_make_mapping("exec_script", "Medium"))
    if any(k in raw for k in ("lateral", "psexec", "wmiexec", "mimikatz", "pass-the-hash")):
        max_score = max(max_score, 55)
        all_mitre.append(_make_mapping("lateral_remote", "High"))
        all_mitre.append(_make_mapping("cred_store", "High"))

    return max_score, all_mitre


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def calculate_severity(
    itype: IndicatorType,
    enrichment_data: Dict,
) -> Tuple[str, int, List[Dict]]:
    """
    Compute (severity_label, numeric_score, mitre_mappings).
    mitre_mappings is a deduplicated list of MITRE ATT&CK dicts.
    """
    if itype == IndicatorType.LOG_SNIPPET:
        raw_score, mitre = _score_log_snippet(enrichment_data)
        raw_score = max(0, min(100, raw_score))
        return _score_to_severity(raw_score), raw_score, _dedupe_mitre(mitre)

    total = 0
    all_mitre: List[Dict] = []

    scorer_map = {
        "ipinfo.io":    _score_ipinfo,
        "URLhaus":      _score_urlhaus,
        "ThreatFox":    _score_threatfox,
        "AbuseIPDB":    _score_abuseipdb,
        "MalwareBazaar":_score_malwarebazaar,
        "VirusTotal":   _score_virustotal,
    }

    for src in enrichment_data.get("sources", []):
        source_name = src.get("source", "")
        fn = scorer_map.get(source_name)
        if fn:
            s, m = fn(src)
            total += s
            all_mitre.extend(m)

    total = max(0, min(100, total))
    return _score_to_severity(total), total, _dedupe_mitre(all_mitre)


def _dedupe_mitre(mappings: List[Dict]) -> List[Dict]:
    """Remove duplicate technique entries, keeping highest confidence."""
    conf_order = {"High": 3, "Medium": 2, "Low": 1}
    seen: Dict[str, Dict] = {}
    for m in mappings:
        key = m["technique_id"]
        if key not in seen or conf_order.get(m["confidence"], 0) > conf_order.get(seen[key]["confidence"], 0):
            seen[key] = m
    # Sort by tactic_id then technique_id
    return sorted(seen.values(), key=lambda x: (x["tactic_id"], x["technique_id"]))
