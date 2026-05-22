#!/usr/bin/env python3
"""
Threat Validator

A cybersecurity validation tool that ingests an alert and automatically validates
its outcome by parsing a secondary server response log or database status.

If the response contains an error or zero bytes transferred, the alert is
classified as 'Mitigated/False Alarm'. If the response is a 200 OK with a large
payload size, the alert is escalated to 'CRITICAL: Verified Breach' and a JSON
incident report is generated.

Usage:
    python3 threat_validator.py --alert alert.json --response server_response.log
    python3 threat_validator.py --alert security_alerts.json --response responses/
    python3 threat_validator.py --alert '{"type": "SQLi", "target": "app"}' --response server_response.log

Output:
    Writes a master JSON incident report to stdout and optionally to a file.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone


MIN_CRITICAL_PAYLOAD_BYTES = 1000


def parse_alert(input_value):
    """Parse an alert JSON object from text or a file path."""
    if os.path.exists(input_value):
        with open(input_value, "r", encoding="utf-8") as fh:
            return json.load(fh)

    try:
        return json.loads(input_value)
    except json.JSONDecodeError:
        raise ValueError("Alert input must be a valid JSON string or path to a JSON file.")


def parse_alerts(input_value):
    """Return a list of alert objects from a JSON alert payload or file."""
    raw_alert = parse_alert(input_value)
    if isinstance(raw_alert, dict):
        if "alerts" in raw_alert and isinstance(raw_alert["alerts"], list):
            return raw_alert["alerts"]
        return [raw_alert]
    if isinstance(raw_alert, list):
        return raw_alert
    raise ValueError("Parsed alert data must be a JSON object or array of objects.")


def parse_response_source(path):
    """Return a list of response log paths from a file or directory."""
    if os.path.isdir(path):
        entries = [os.path.join(path, name) for name in sorted(os.listdir(path))]
        logs = [entry for entry in entries if os.path.isfile(entry)]
        if not logs:
            raise FileNotFoundError(f"No response logs found in directory: {path}")
        return logs
    if os.path.isfile(path):
        return [path]
    raise FileNotFoundError(f"Response log not found: {path}")


def parse_response_log(path):
    """Parse a server response or database status log to determine validation data."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Response log not found: {path}")

    status_code = None
    error_detected = False
    payload_size = None
    db_rows = None
    raw_lines = []

    status_re = re.compile(r"HTTP/\d(?:\.\d)?\s+(\d{3})")
    content_length_re = re.compile(r"Content-Length:\s*(\d+)", re.I)
    bytes_re = re.compile(r"(?:bytes|payload|size)[:=]\s*(\d+)", re.I)
    db_rows_re = re.compile(r"(?:rows returned|rows affected|row_count)[:=]\s*(\d+)", re.I)
    error_re = re.compile(r"\b(ERROR|FAIL|EXCEPTION|500|502|503|504|404)\b", re.I)

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            raw_lines.append(line.rstrip("\n"))
            if status_code is None:
                status_match = status_re.search(line)
                if status_match:
                    status_code = int(status_match.group(1))

            if payload_size is None:
                content_length_match = content_length_re.search(line)
                if content_length_match:
                    payload_size = int(content_length_match.group(1))
                else:
                    bytes_match = bytes_re.search(line)
                    if bytes_match:
                        payload_size = int(bytes_match.group(1))

            if db_rows is None:
                db_rows_match = db_rows_re.search(line)
                if db_rows_match:
                    db_rows = int(db_rows_match.group(1))

            if error_re.search(line):
                error_detected = True

    return {
        "status_code": status_code,
        "payload_size": payload_size,
        "db_rows": db_rows,
        "error_detected": error_detected,
        "raw_log": raw_lines,
    }


def extract_alert_ips(alert):
    """Extract potential IP addresses from an alert object."""
    ips = set()
    for key in ("ip", "src_ip", "source_ip", "client_ip"):
        value = alert.get(key)
        if isinstance(value, str):
            ips.add(value)
        elif isinstance(value, list):
            ips.update(value)

    if isinstance(alert.get("ips"), list):
        ips.update([item for item in alert["ips"] if isinstance(item, str)])

    # Fallback: parse IPs from the alert line text if available.
    if "line" in alert and isinstance(alert["line"], str):
        ips.update(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", alert["line"]))

    return [ip for ip in ips if isinstance(ip, str)]


def find_best_response_path(alert, response_paths):
    """Attempt to correlate an alert with the best response log path."""
    if len(response_paths) == 1:
        return response_paths[0]

    alert_ips = extract_alert_ips(alert)
    candidates = []

    for path in response_paths:
        filename = os.path.basename(path)
        for ip in alert_ips:
            if ip in filename:
                return path
        if "line_number" in alert and str(alert["line_number"]) in filename:
            candidates.append(path)

    if candidates:
        return candidates[0]

    for path in response_paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            if any(ip in content for ip in alert_ips):
                return path
        except OSError:
            continue

    return response_paths[0] if response_paths else None


def validate_alerts(alerts, response_paths):
    """Validate a list of alerts using available response logs."""
    reports = []
    for index, alert in enumerate(alerts, start=1):
        response_path = find_best_response_path(alert, response_paths)
        if response_path:
            response_data = parse_response_log(response_path)
        else:
            response_data = {
                "status_code": None,
                "payload_size": None,
                "db_rows": None,
                "error_detected": False,
                "raw_log": [],
            }
        classification, summary = classify_alert(alert, response_data)
        response_data["summary"] = summary
        report = build_incident_report(alert, response_data, classification)
        report["response_path"] = response_path
        report["alert_index"] = index
        reports.append(report)
    return reports


def build_master_report(incident_reports):
    """Create a master incident report covering all validated alerts."""
    classification_counts = {}
    for entry in incident_reports:
        classification = entry.get("classification", "Unknown")
        classification_counts[classification] = classification_counts.get(classification, 0) + 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "incident_count": len(incident_reports),
        "classification_counts": classification_counts,
        "incident_reports": incident_reports,
    }


def classify_alert(alert, response_data):
    """Return a validation classification and summary based on response content."""
    status_code = response_data.get("status_code")
    payload_size = response_data.get("payload_size")
    db_rows = response_data.get("db_rows")
    error_detected = response_data.get("error_detected")

    if error_detected:
        return "Mitigated/False Alarm", "Server response contained an error condition."

    if payload_size == 0:
        return "Mitigated/False Alarm", "The response payload size was zero bytes."

    if status_code == 200 and payload_size is not None and payload_size >= MIN_CRITICAL_PAYLOAD_BYTES:
        return "CRITICAL: Verified Breach", (
            "Server returned 200 OK with a large payload, indicating sensitive data disclosure.")

    if status_code == 200 and db_rows == 0:
        return "Mitigated/False Alarm", "Database returned zero rows for the suspected query."

    if status_code and status_code >= 400:
        return "Mitigated/False Alarm", f"Server returned HTTP status {status_code}, which indicates the attack was blocked or failed."

    return "Validated/Needs Review", "The response does not clearly indicate a breach, but the alert remains unconfirmed."


def build_incident_report(alert, response_data, classification):
    """Create a JSON-compatible incident report object."""
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "alert": alert,
        "validation": {
            "status_code": response_data.get("status_code"),
            "payload_size": response_data.get("payload_size"),
            "db_rows": response_data.get("db_rows"),
            "error_detected": response_data.get("error_detected"),
        },
        "classification": classification,
        "summary": response_data.get("summary"),
    }
    return report


def save_json_report(report, path):
    """Write the incident report to a JSON file."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)


def build_argument_parser():
    parser = argparse.ArgumentParser(description="Threat Validator: validate alerts using secondary response logs or database status.")
    parser.add_argument("--alert", required=True, help="Alert JSON string or path to a JSON alert file. Supports batch files like security_alerts.json with an alerts list.")
    parser.add_argument("--response", required=True, help="Path to a response log file or directory containing response logs.")
    parser.add_argument("--output", default="incident_report.json", help="Optional path to write the master JSON incident report.")
    parser.add_argument("--threshold", type=int, default=MIN_CRITICAL_PAYLOAD_BYTES,
                        help="Payload byte threshold to escalate an alert to CRITICAL.")
    return parser


def main():
    parser = build_argument_parser()
    args = parser.parse_args()

    try:
        alerts = parse_alerts(args.alert)
    except Exception as exc:
        print(f"ERROR: invalid alert input: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        response_paths = parse_response_source(args.response)
    except Exception as exc:
        print(f"ERROR: unable to locate response log(s): {exc}", file=sys.stderr)
        sys.exit(2)

    global MIN_CRITICAL_PAYLOAD_BYTES
    MIN_CRITICAL_PAYLOAD_BYTES = args.threshold

    incident_reports = validate_alerts(alerts, response_paths)
    master_report = build_master_report(incident_reports)

    json_text = json.dumps(master_report, indent=2)
    print(json_text)

    try:
        save_json_report(master_report, args.output)
        print(f"Incident report written to: {args.output}")
    except Exception as exc:
        print(f"WARNING: failed to write report file: {exc}", file=sys.stderr)

    critical_count = master_report["classification_counts"].get("CRITICAL: Verified Breach", 0)
    false_count = master_report["classification_counts"].get("Mitigated/False Alarm", 0)
    pending_count = master_report["classification_counts"].get("Validated/Needs Review", 0)

    print(f"Summary: {len(incident_reports)} incident(s) processed.")
    print(f"  CRITICAL: {critical_count}")
    print(f"  Mitigated/False Alarm: {false_count}")
    print(f"  Needs Review: {pending_count}")


if __name__ == "__main__":
    main()
