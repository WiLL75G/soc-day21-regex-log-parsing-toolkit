#!/usr/bin/env python3
"""
IOC Extractor - SOC Analyst Toolkit
Author: William Gokah
GitHub: WiLL75G
Purpose: Extract and categorize IOCs from raw log files
Usage: python3 ioc_extractor.py <logfile>
"""

import re
import sys
from collections import Counter

# ============================================
# IOC REGEX PATTERNS
# ============================================

PATTERNS = {
    "IPv4 Addresses": r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
                      r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
    "Email Addresses": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "MD5 Hashes": r'\b[a-fA-F0-9]{32}\b',
    "SHA256 Hashes": r'\b[a-fA-F0-9]{64}\b',
    "URLs": r'https?://[^\s"\'<>\]]+',
    "Port Numbers": r'(?i)(?:port|dst_port)\s*[=:\s]\s*(\d{1,5})',
    "ISO Timestamps": r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',
    "CVE IDs": r'CVE-\d{4}-\d{4,7}',
}

# Suspicious patterns - flag these specifically
SUSPICIOUS = {
    "Scanner User Agents": r'(?i)(sqlmap|nikto|nmap|masscan|'
                           r'zgrab|python-requests|go-http|'
                           r'dirbuster|gobuster)',
    "Directory Traversal": r'\.\./|\.\.\\|%2e%2e|%252e',
    "SQL Injection Indicators": r"(?i)(union\s+select|'or\s+'|"
                                r"1=1|drop\s+table|insert\s+into)",
    "Suspicious Ports": r'(?:port|dst_port)\s*[=:\s]\s*'
                        r'(4444|1337|31337|8888|9999|4445)',
}


def extract_iocs(filepath):
    """Extract all IOCs from a log file."""

    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[!] File not found: {filepath}")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  IOC EXTRACTION REPORT")
    print(f"  File: {filepath}")
    print(f"  Lines: {content.count(chr(10))}")
    print(f"{'='*60}")

    # Extract standard IOCs
    results = {}
    for ioc_type, pattern in PATTERNS.items():
        matches = re.findall(pattern, content)
        # Flatten if groups captured
        matches = [m[0] if isinstance(m, tuple) else m
                   for m in matches]
        if matches:
            results[ioc_type] = Counter(matches)

    # Print standard IOCs
    print("\n--- EXTRACTED IOCs ---")
    for ioc_type, counts in results.items():
        if counts:
            print(f"\n[+] {ioc_type} ({len(counts)} unique):")
            for value, count in counts.most_common(10):
                print(f"    {value:<50} Count: {count}")

    # Extract suspicious patterns
    print("\n--- SUSPICIOUS PATTERNS DETECTED ---")
    found_suspicious = False
    for name, pattern in SUSPICIOUS.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            found_suspicious = True
            print(f"\n[!] {name}:")
            for match in set(matches[:5]):
                print(f"    FLAGGED: {match}")

    if not found_suspicious:
        print("[+] No immediately suspicious patterns detected.")

    # Generate IOC summary
    print(f"\n{'='*60}")
    print("  SUMMARY")
    print(f"{'='*60}")
    total_iocs = sum(len(v) for v in results.values())
    print(f"Total unique IOC types found: {len(results)}")
    print(f"Total unique IOC values: {total_iocs}")

    if "IPv4 Addresses" in results:
        print(f"\nTop IPs to investigate:")
        for ip, count in results["IPv4 Addresses"].most_common(5):
            flag = " <- INVESTIGATE" if count > 3 else ""
            print(f"  {ip} - seen {count} times{flag}")

    print(f"\n[*] Extraction complete.")
    print(f"[*] Add extracted IOCs to VirusTotal, AbuseIPDB,")
    print(f"    and your SIEM watchlist immediately.\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 ioc_extractor.py <logfile>")
        print("Example: python3 ioc_extractor.py ssh_auth.log")
        sys.exit(1)

    extract_iocs(sys.argv[1])
