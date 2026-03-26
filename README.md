# Threat Triage Agent

A modular CLI tool for rapid threat indicator triage. Feed it an IP address, domain, file hash, or raw log snippet and it returns a structured report with severity classification, threat intel from multiple sources, MITRE ATT&CK mappings, and response recommendations.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Analyze an IP
python main.py 203.0.113.42

# Analyze a domain
python main.py malware.example.com

# Analyze a file hash (MD5 / SHA1 / SHA256)
python main.py 44d88612fea8a8f36de82e1278abb02f

# Analyze a raw log snippet
python main.py "Failed password for root from 203.0.113.42 port 22 ssh2"

# Print only — don't save to file
python main.py --no-save 8.8.8.8

# Save reports to a custom directory
python main.py --output-dir /tmp/reports 1.2.3.4
```

## API Keys

### Required (free, strongly recommended)

| Source | Env Var | Sign up |
|---|---|---|
| URLhaus + MalwareBazaar + ThreatFox | `ABUSECH_API_KEY` | https://bazaar.abuse.ch/api/ |

These three abuse.ch services share a single free API key and are the primary detection sources for the tool. Without this key, threat lookups are skipped.

### Optional (free accounts)

| Source | Env Var | What it adds |
|---|---|---|
| [VirusTotal](https://www.virustotal.com/gui/join-us) | `VT_API_KEY` | Multi-engine AV scanning for hashes, IP/domain reputation |
| [AbuseIPDB](https://www.abuseipdb.com/register) | `ABUSEIPDB_API_KEY` | IP abuse confidence score, report history, Tor detection |

### Setting keys

```bash
# Copy the example and fill in your keys
cp .env.example .env
```

```
# .env
ABUSECH_API_KEY=your_key_here
VT_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

Or set them as environment variables directly:

```bash
export ABUSECH_API_KEY=your_key_here
```

## Always-Available Sources (No Key Required)

| Source | Coverage | Notes |
|---|---|---|
| [ipinfo.io](https://ipinfo.io) | IP geo, ASN, org | 50k req/month free |
| DNS | Forward/reverse lookups | Built-in, no external call |

## Output

Each run produces:

1. **Terminal output** — colored triage report with all findings
2. **Saved report** — `reports/triage_YYYYMMDD_HHMMSS_<indicator>.txt`

### Report sections

```
INDICATOR DETAILS     — Indicator value, detected type, severity badge (score/100)
THREAT INTEL SUMMARY  — Findings from each source, organized by source
MITRE ATT&CK MAPPING  — Mapped tactics and techniques with confidence level
RECOMMENDED ACTIONS   — Immediate, investigative, and long-term response steps
```

### Severity levels

| Level | Score | Meaning |
|---|---|---|
| **Critical** | 70–100 | Active threat confirmed by high-confidence sources. Immediate action required. |
| **High** | 45–69 | Strong indicators of malicious activity. Prioritize investigation. |
| **Medium** | 20–44 | Suspicious signals. Investigate and monitor. |
| **Low** | 0–19 | Minimal or no threat signals found. |

## Project Structure

```
threat-triage-agent/
├── main.py               # CLI entry point, argument parsing, pipeline orchestration
├── modules/
│   ├── detector.py       # Indicator type detection + log snippet extraction
│   ├── enricher.py       # Threat intel enrichment from all sources
│   ├── scorer.py         # Severity scoring model + MITRE ATT&CK mapping
│   └── reporter.py       # Report rendering (terminal + file) + response actions
├── reports/              # Auto-created; timestamped .txt reports saved here
├── requirements.txt
├── .env.example
└── README.md
```

### Module responsibilities

#### `modules/detector.py`
- `detect_indicator_type(indicator)` — Classifies a string as IPv4, IPv6, MD5, SHA1, SHA256, Domain, or Log Snippet using regex patterns.
- `extract_indicators_from_log(log)` — Parses a log snippet and extracts all embedded IPs, domains, and hashes for sub-analysis.

#### `modules/enricher.py`
- `enrich_indicator(indicator, type)` — Dispatches enrichment calls appropriate to the indicator type and returns a unified dict of source results.
- Source functions: `_enrich_ipinfo`, `_enrich_urlhaus`, `_enrich_malwarebazaar`, `_enrich_threatfox`, `_enrich_abuseipdb`, `_enrich_virustotal`, `_enrich_dns`
- For log snippets, calls `extract_indicators_from_log` and recursively enriches each sub-indicator.

#### `modules/scorer.py`
- `calculate_severity(type, enrichment_data)` — Aggregates scores from each source using a points-based model, returns `(severity_label, score, mitre_mappings)`.
- Each source has its own scoring function (`_score_urlhaus`, `_score_threatfox`, etc.) that also emits MITRE technique mappings based on the findings.
- MITRE mappings are deduplicated and sorted; highest confidence wins on conflict.

#### `modules/reporter.py`
- `generate_report(...)` — Assembles the final report dict from all components.
- `print_report(report)` — Renders to terminal with ANSI color (auto-disabled when not a TTY).
- `save_report(report, dir)` — Renders plain-text version and saves to timestamped file.
- Contains a `_RESPONSE_ACTIONS` database of pre-written response steps keyed by `{type}_{severity}`.

## Example Output

```
INDICATOR DETAILS
────────────────────────────────────────────────────────────────────────
  Indicator : 198.51.100.23
  Type      : IPv4 Address
  Severity  : [ HIGH — 57/100 ]

THREAT INTEL SUMMARY
────────────────────────────────────────────────────────────────────────

  [ipinfo.io]
  Location : Amsterdam, North Holland, NL
  Org/ASN  : AS12345 ExampleHosting B.V.
  Timezone : Europe/Amsterdam

  [URLhaus (abuse.ch)]
  Status     : MALICIOUS HOST — 3 malicious URL(s) found
  Threats    : malware_download
  Tags       : Emotet, doc

  [ThreatFox (abuse.ch)]
  Status      : IOC FOUND in ThreatFox
  Malware     : Emotet
  Threat Type : Command and Control server
  Confidence  : 75%

MITRE ATT&CK MAPPING
────────────────────────────────────────────────────────────────────────
  Tactic                      ID            Technique                         Confidence
  ──────────────────────────────────────────────────────────────────────
  Execution                   T1204.002     Malicious File                    High
  Command and Control         T1071.001     Application Layer Protocol: Web   High
  Command and Control         T1105         Ingress Tool Transfer             Medium

RECOMMENDED RESPONSE ACTIONS
────────────────────────────────────────────────────────────────────────

  [IMMEDIATE]
    1. Block this IP at all perimeter firewalls and WAF rules immediately.
    2. Isolate any internal hosts observed communicating with this IP.
    ...
```

## Flags

```
positional arguments:
  indicator        IP, domain, hash, or raw log snippet to analyze

options:
  --no-save        Print to terminal only; do not save a report file
  --output-dir DIR Save reports to this directory (default: ./reports)
  --no-banner      Suppress the ASCII art banner
  --no-color       Disable ANSI color output
  -h, --help       Show help and exit
```
