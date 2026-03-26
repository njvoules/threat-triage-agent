#!/usr/bin/env python3
"""
Threat Triage Agent — CLI entry point.

Usage:
  python main.py <indicator>
  python main.py "8.8.8.8"
  python main.py "malware.example.com"
  python main.py "44d88612fea8a8f36de82e1278abb02f"
  python main.py "Failed password for root from 203.0.113.42 port 22 ssh2"
  python main.py --no-save 1.2.3.4
"""

import argparse
import sys
import os

# Ensure stdout/stderr can handle the full Unicode range on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Load .env if python-dotenv is installed
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from modules.detector import detect_indicator_type, IndicatorType
from modules.enricher import enrich_indicator
from modules.scorer import calculate_severity
from modules.reporter import generate_report, save_report, print_report


_BANNER = r"""
  _____ _                    _     _____     _
 |_   _| |__  _ __ ___  __ _| |_  |_   _| __(_) __ _  __ _  ___
   | | | '_ \| '__/ _ \/ _` | __|   | || '__| |/ _` |/ _` |/ _ \
   | | | | | | | |  __/ (_| | |_    | || |  | | (_| | (_| |  __/
   |_| |_| |_|_|  \___|\__,_|\__|   |_||_|  |_|\__,_|\__, |\___|
                                                       |___/
  A g e n t                   github.com/threat-triage-agent
"""


def _print_banner():
    print(_BANNER)


def _check_api_keys():
    """Warn if API keys are not set."""
    required = {"ABUSECH_API_KEY": "URLhaus/MalwareBazaar/ThreatFox (abuse.ch)"}
    optional = {
        "VT_API_KEY": "VirusTotal",
        "ABUSEIPDB_API_KEY": "AbuseIPDB",
    }
    missing_req = [name for env, name in required.items() if not os.environ.get(env, "").strip()]
    missing_opt = [name for env, name in optional.items() if not os.environ.get(env, "").strip()]

    if missing_req:
        print(f"  [!] Required key not set: {', '.join(missing_req)}")
        print(f"      Free signup at https://bazaar.abuse.ch/api/  (set ABUSECH_API_KEY)")
    if missing_opt:
        print(f"  [i] Optional sources not configured: {', '.join(missing_opt)}")
    if missing_req or missing_opt:
        print(f"      See .env.example for details.\n")


def main():
    parser = argparse.ArgumentParser(
        prog="threat-triage",
        description="Threat Triage Agent — Analyze and classify threat indicators",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
indicator types supported:
  IPv4 / IPv6 address   e.g.  203.0.113.42
  Domain name           e.g.  evil.example.com
  MD5 hash              e.g.  44d88612fea8a8f36de82e1278abb02f
  SHA1 hash             e.g.  da39a3ee5e6b4b0d3255bfef95601890afd80709
  SHA256 hash           e.g.  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  Raw log snippet       e.g.  "Failed password for root from 203.0.113.42 port 22"

examples:
  python main.py 8.8.8.8
  python main.py malware.example.com
  python main.py 44d88612fea8a8f36de82e1278abb02f
  python main.py "Failed password for root from 192.0.2.100 port 22 ssh2"
  python main.py --no-save 1.2.3.4
  python main.py --output-dir /tmp/reports 1.2.3.4

api keys (optional, for additional sources):
  export VT_API_KEY=<your_virustotal_key>
  export ABUSEIPDB_API_KEY=<your_abuseipdb_key>
        """,
    )
    parser.add_argument(
        "indicator",
        nargs="?",
        help="Indicator to analyze (IP, domain, hash, or raw log snippet)",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Print report to terminal only; do not save to file",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        metavar="DIR",
        help="Directory to save report files (default: ./reports)",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the ASCII banner",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output",
    )

    args = parser.parse_args()

    if not args.no_banner:
        _print_banner()

    _check_api_keys()

    # Get indicator from args or prompt interactively
    if args.indicator:
        indicator = args.indicator.strip()
    else:
        try:
            indicator = input("  Enter indicator: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n  Aborted.")
            sys.exit(0)

    if not indicator:
        print("  Error: No indicator provided. Use --help for usage.")
        sys.exit(1)

    use_color = not args.no_color and sys.stdout.isatty()

    # ── Step 1: Detect type ────────────────────────────────────────────────
    print(f"  [1/4] Detecting indicator type ...", end="", flush=True)
    indicator_type = detect_indicator_type(indicator)
    print(f"\r  [1/4] Type detected          : {indicator_type.value}")

    # ── Step 2: Enrich ─────────────────────────────────────────────────────
    print(f"  [2/4] Querying threat intelligence sources ...", end="", flush=True)
    enrichment_data = enrich_indicator(indicator, indicator_type)
    source_count = len(enrichment_data.get("sources", []))
    sub_count = len(enrichment_data.get("sub_indicators", []))
    if sub_count:
        print(f"\r  [2/4] Enrichment complete     : {sub_count} sub-indicators extracted and enriched")
    else:
        print(f"\r  [2/4] Enrichment complete     : {source_count} source(s) queried")

    # ── Step 3: Score ──────────────────────────────────────────────────────
    print(f"  [3/4] Scoring and mapping to MITRE ATT&CK ...", end="", flush=True)
    severity, score, mitre_mappings = calculate_severity(indicator_type, enrichment_data)
    print(f"\r  [3/4] Severity classification : {severity}  [{score}/100]  |  {len(mitre_mappings)} MITRE technique(s) mapped")

    # ── Step 4: Report ─────────────────────────────────────────────────────
    print(f"  [4/4] Generating report ...")
    report = generate_report(
        indicator,
        indicator_type,
        severity,
        score,
        enrichment_data,
        mitre_mappings,
    )

    print_report(report, color=use_color)

    if not args.no_save:
        filepath = save_report(report, args.output_dir)
        print(f"  Report saved -> {filepath}\n")


if __name__ == "__main__":
    main()
