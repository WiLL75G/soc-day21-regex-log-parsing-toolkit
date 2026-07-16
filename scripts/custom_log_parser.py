#!/usr/bin/env python3
"""
Custom Log Parser SOC Analyst Toolkit
Author: William Gokah
GitHub: WiLL75G
Purpose: Parse non-standard application log formats into structured JSON
         ready for SIEM ingestion. Demonstrates the workflow used to
         onboard custom log sources into production SIEM environments.

Usage: python3 custom_log_parser.py
"""

import re
import json


# ============================================
# CUSTOM LOG FORMAT PATTERN
# ============================================
# Format example:
# [10-Jan-2026 02:14:33.421][ERROR][AUTH][uid:1001][IP:203.0.113.45] Message here
#
# Each bracket captures one field. The whole regex acts as a single
# extraction template that turns each line into a structured event.

LOG_PATTERN = re.compile(
    r'\[(?P<timestamp>[^\]]+)\]'       # timestamp inside brackets
    r'\[(?P<level>\w+)\]'              # log level (ERROR, INFO, etc.)
    r'\[(?P<component>\w+)\]'          # subsystem (AUTH, DB, etc.)
    r'\[uid:(?P<uid>\d+)\]'            # user ID
    r'\[IP:(?P<ip>[^\]]+)\]'           # IP address
    r'\s+(?P<message>.+)'              # message text
)


# ============================================
# ALERT PATTERNS - what should fire alerts
# ============================================

ALERT_PATTERNS = {
    'brute_force':       r'Authentication failed.*attempt (\d+) of',
    'account_locked':    r'Account LOCKED',
    'suspicious_query':  r'Unusual query pattern|possible enumeration',
    'admin_query':       r'WHERE admin=1',
}


def parse_custom_log(filepath):
    """Parse custom application log into structured events and alerts."""

    events = []
    alerts = []

    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[!] File not found: {filepath}")
        return

    for line_num, line in enumerate(lines, 1):
        match = LOG_PATTERN.match(line.strip())
        if not match:
            print(f"[!] Line {line_num} did not match format - skipping")
            continue

        # Convert regex match to dict
        event = match.groupdict()
        event['line'] = line_num

        # Check for alert conditions
        for alert_name, pattern in ALERT_PATTERNS.items():
            if re.search(pattern, event['message'], re.IGNORECASE):
                alert = {
                    'line':       line_num,
                    'alert_type': alert_name,
                    'severity':   event['level'],
                    'ip':         event['ip'],
                    'uid':        event['uid'],
                    'component':  event['component'],
                    'timestamp':  event['timestamp'],
                    'message':    event['message']
                }
                alerts.append(alert)

        events.append(event)

    # Print parsed summary
    print(f"\n{'='*60}")
    print(f"  CUSTOM LOG PARSER REPORT")
    print(f"  File: {filepath}")
    print(f"{'='*60}")
    print(f"\n[+] Parsed {len(events)} log events")
    print(f"[!] Found {len(alerts)} alert conditions\n")

    # Show alerts in human-readable form
    if alerts:
        print("--- ALERTS DETECTED ---")
        for alert in alerts:
            print(f"\n[{alert['severity']}] Line {alert['line']}")
            print(f"  Type:      {alert['alert_type'].upper()}")
            print(f"  Component: {alert['component']}")
            print(f"  IP:        {alert['ip']}")
            print(f"  UID:       {alert['uid']}")
            print(f"  Time:      {alert['timestamp']}")
            print(f"  Message:   {alert['message']}")

    # Export structured JSON for SIEM ingestion
    output = {
        'total_events': len(events),
        'total_alerts': len(alerts),
        'alerts':       alerts,
        'events':       events
    }

    output_path = 'sample-output/parsed_custom_log.json'
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\n{'='*60}")
    print(f"[+] Structured output saved to: {output_path}")
    print(f"[+] Ready for SIEM ingestion (Splunk HEC, ELK, OpenSearch)")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    parse_custom_log("sample-logs/custom_app.log")
