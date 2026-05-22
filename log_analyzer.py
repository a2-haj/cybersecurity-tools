#!/usr/bin/env python3
"""
SOC Analyst Log Analyzer

Reads a log file line-by-line, extracts IP addresses, detects potential SQL
injection keywords (e.g. SELECT, UNION, INSERT, or URL-encoded SELECT%20),
and counts failed login attempts indicated by HTTP status codes 401 or 403.

Usage:
    python3 log_analyzer.py /path/to/logfile.log

The script prints a concise summary to stdout.
"""

import argparse
import collections
import json
import os
import re
import stat
import sys
from datetime import datetime


def compile_patterns():
    """Compile and return regular expressions used by the analyzer.

    Returns a tuple: (ip_regex, sqli_regex, status_regex)
    """
    # Simple IPv4 pattern (matches common dotted-quad IPs). This intentionally
    # keeps validation lenient to catch IPs in many log formats.
    ip_regex = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

    # SQLi keywords and a common URL-encoded variant. Case-insensitive.
    sqli_regex = re.compile(r"(?:SELECT|UNION|INSERT|UPDATE|DELETE|SELECT%20)", re.I)

    # Look for HTTP status codes 401 or 403 as whole words.
    status_regex = re.compile(r"\b(401|403)\b")

    return ip_regex, sqli_regex, status_regex


def analyze_log(path):
    """Analyze the log file at `path` and return analysis results.

    The returned dict contains counters and collections useful to a SOC analyst.
    """
    ip_regex, sqli_regex, status_regex = compile_patterns()

    total_lines = 0
    ip_counter = collections.Counter()
    sqli_counter = 0
    sqli_examples = []
    failed_counter = 0
    failed_by_ip = collections.Counter()
    alerts = []  # structured alert records

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                total_lines += 1

                # Extract all IPs on the line (if any) and count them.
                ips = ip_regex.findall(line)
                for ip in ips:
                    ip_counter[ip] += 1

                # Detect SQLi keywords anywhere in the line.
                if sqli_regex.search(line):
                    sqli_counter += 1
                    # Save a short example for an analyst to inspect later.
                    if len(sqli_examples) < 10:
                        sqli_examples.append(line.strip())
                    alerts.append({
                        "type": "SQLi",
                        "ips": ips if ips else ["<unknown>"],
                        "line_number": total_lines,
                        "line": line.strip(),
                    })

                # Detect failed login HTTP status codes 401/403. Attribute the
                # event to the first IP on the line if available, otherwise to
                # '<unknown>'.
                m = status_regex.search(line)
                if m:
                    failed_counter += 1
                    src_ip = ips[0] if ips else "<unknown>"
                    failed_by_ip[src_ip] += 1
                    alerts.append({
                        "type": "Failed Login",
                        "ip": src_ip,
                        "status": m.group(1),
                        "line_number": total_lines,
                        "line": line.strip(),
                    })

    except FileNotFoundError:
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print(f"Error: permission denied reading: {path}", file=sys.stderr)
        sys.exit(3)

    return {
        "total_lines": total_lines,
        "unique_ips": len(ip_counter),
        "top_ips": ip_counter.most_common(10),
        "sqli_count": sqli_counter,
        "sqli_examples": sqli_examples,
        "failed_count": failed_counter,
        "failed_by_ip": failed_by_ip.most_common(10),
        "alerts": alerts,
    }


def save_alerts_json(alerts, output_path):
    """Save structured alerts to a JSON file (pretty-printed)."""
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "alert_count": len(alerts),
        "alerts": alerts,
    }
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def generate_block_script(alerts, script_path):
    """Generate a shell script containing iptables commands to block IPs.

    Collects unique IPv4 addresses referenced in alerts and writes an
    executable script that adds DROP rules for each IP.
    """
    ip_regex, _, _ = compile_patterns()

    ips = set()
    for a in alerts:
        if a.get("type") == "SQLi":
            for ip in a.get("ips", []):
                if ip != "<unknown>" and ip_regex.fullmatch(ip):
                    ips.add(ip)
        elif a.get("type") == "Failed Login":
            ip = a.get("ip")
            if ip and ip != "<unknown>" and ip_regex.fullmatch(ip):
                ips.add(ip)

    # Write the script
    with open(script_path, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\n")
        fh.write("# block_ips.sh - generated by log_analyzer.py\n")
        fh.write("# Adds iptables DROP rules for detected malicious IPs\n\n")
        for ip in sorted(ips):
            # Use -I to insert at top; operators may adjust for their env.
            fh.write(f"iptables -I INPUT -s {ip} -j DROP\n")

    # Make the script executable by the owner
    try:
        os.chmod(script_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH)
    except OSError:
        # If chmod fails, it's non-fatal; the user can `chmod +x` manually.
        pass


def print_summary(result, path):
    """Print a human-friendly summary of the analysis results."""
    print(f"Log analysis: {path}")
    print("-" * 60)
    print(f"Total lines processed : {result['total_lines']}")
    print(f"Unique IPs found      : {result['unique_ips']}")

    print("\nTop IPs (by occurrences):")
    if result['top_ips']:
        for ip, count in result['top_ips']:
            print(f"  {ip:15}  {count}")
    else:
        print("  (none found)")

    print(f"\nPotential SQLi hits   : {result['sqli_count']}")
    if result['sqli_examples']:
        print("  Examples:")
        for ex in result['sqli_examples']:
            print(f"    {ex}")

    print(f"\nFailed login attempts  : {result['failed_count']}")
    if result['failed_by_ip']:
        print("  Failed by IP (top):")
        for ip, count in result['failed_by_ip']:
            print(f"    {ip:15}  {count}")


def build_arg_parser():
    p = argparse.ArgumentParser(description="SOC log analyzer: IPs, SQLi, failed logins")
    p.add_argument("logfile", help="Path to the log file to analyze")
    return p


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    result = analyze_log(args.logfile)
    print_summary(result, args.logfile)

    # Determine output locations next to the log file (or current dir).
    base_dir = os.path.dirname(os.path.abspath(args.logfile)) or os.getcwd()
    alerts_path = os.path.join(base_dir, "security_alerts.json")
    script_path = os.path.join(base_dir, "block_ips.sh")

    # Save structured alerts and generate a block script.
    try:
        save_alerts_json(result.get("alerts", []), alerts_path)
        print(f"Saved alerts JSON     : {alerts_path}")
    except Exception as e:
        print(f"Warning: failed to write alerts JSON: {e}", file=sys.stderr)

    try:
        generate_block_script(result.get("alerts", []), script_path)
        print(f"Generated block script: {script_path}")
    except Exception as e:
        print(f"Warning: failed to generate block script: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
