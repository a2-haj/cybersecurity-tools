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
import re
import sys


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

                # Detect failed login HTTP status codes 401/403. Attribute the
                # event to the first IP on the line if available, otherwise to
                # '<unknown>'.
                m = status_regex.search(line)
                if m:
                    failed_counter += 1
                    src_ip = ips[0] if ips else "<unknown>"
                    failed_by_ip[src_ip] += 1

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
    }


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


if __name__ == "__main__":
    main()
