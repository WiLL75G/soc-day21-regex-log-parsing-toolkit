# Optimized Splunk SPL Detection Queries
# Author: William Gokah
# GitHub: WiLL75G
# Purpose: Production-style detection rules using regex extraction in Splunk SPL

These 5 queries demonstrate detection engineering patterns commonly used by
Tier 1 SOC analysts. Each was built against a custom lab dataset and verified
in Splunk Enterprise. They cover validated IOC extraction, multi-pattern log
parsing, watchlist matching, multi-attack classification, and hash-based
malware detection.

---

## Query 1 - Validated IP Extraction with Verdict Classification

**Purpose:** Identify SSH brute force attackers and tag each by severity based on attempt count.

**Source:** SSH authentication log

```spl
index=main sourcetype=ssh_auth_lab "Failed password"
| rex "from (?<src_ip>(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))"
| where isnotnull(src_ip)
| stats count as attempts by src_ip
| sort -attempts
| eval verdict=case(
    attempts >= 20, "CRITICAL - Active Brute Force",
    attempts >= 10, "HIGH - Likely Brute Force",
    attempts >= 5,  "MEDIUM - Investigate",
    true(),         "LOW - Monitor"
)
| table src_ip, attempts, verdict
```

**Detection logic:** Validated IPv4 regex (rejects garbage like 999.999.999.999), stats aggregation for attempt counting, case-based severity tagging.

---

## Query 2 - Multi-Pattern Custom Log Parser

**Purpose:** Extract structured fields from a custom security event log with no built-in Splunk parser.

**Source:** Custom security events log

```spl
index=main sourcetype=soc_security_events
| rex "(?<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+(?<severity>CRITICAL|HIGH|MEDIUM|LOW|INFO|ALERT)"
| rex "user=(?<username>\w+)"
| rex "src_ip=(?<src_ip>[\d.]+)"
| rex "event=(?<event_type>\w+)"
| rex "email=(?<email>[^\s]+)"
| where isnotnull(event_type)
| table timestamp, severity, username, src_ip, email, event_type
| sort -timestamp
```

**Detection logic:** Chained rex commands extract one field each (production SIEM pattern). Null-safe table output handles events with missing fields.

---

## Query 3 - IOC Watchlist Cross-Source Matching

**Purpose:** Detect any event across all log sources that contains a watchlisted attacker IP.

**Source:** All indexed logs

```spl
index=main earliest=0
| rex "(?<ip_found>(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))"
| where ip_found IN (
    "203.0.113.45",
    "185.220.101.33",
    "198.51.100.22",
    "45.33.32.156"
)
| eval alert="WATCHLISTED IP DETECTED: " . ip_found
| table _time, host, sourcetype, ip_found, alert
| sort -_time
```

**Detection logic:** Searches across all sourcetypes simultaneously. Same IP appearing in multiple log types reveals multi-vector attackers (IOC pivot).

**Production upgrade:** Replace hardcoded IP list with a lookup file fed by automated threat intelligence feeds.

---

## Query 4 - Web Attack Multi-Pattern Detection with Classification

**Purpose:** Scan web access logs for directory traversal, SQL injection, and scanner activity. Auto-classify each attack by type.

**Source:** Apache access log

```spl
index=main sourcetype=apache_access.log
| rex "\"(?<method>GET|POST|PUT|DELETE)\s+(?<uri>[^\s]+)"
| rex field=uri "(?<traversal>\.\.\/|%2e%2e|%252e)"
| rex field=uri "(?<sqli>union\s+select|'or\s+'|1=1)"
| rex "\"(?<useragent>[^\"]+)\"$"
| rex "^(?<src_ip>[\d.]+)"
| eval attack_type=case(
    isnotnull(traversal),                                                       "Directory Traversal",
    isnotnull(sqli),                                                            "SQL Injection",
    match(useragent, "(?i)sqlmap|nikto|nmap|masscan|python-requests|curl"),     "Scanner Detected",
    true(),                                                                     "Clean"
)
| where attack_type != "Clean"
| stats count by src_ip, attack_type, uri
| sort -count
```

**Detection logic:** Priority-ordered case statement assigns one attack_type per event. Action-based indicators (traversal, SQLi) take priority over presence-based indicators (scanner UA).

**Known gap:** Scanner regex must be updated as new attack tools emerge. Coverage testing should be part of every rule's lifecycle.

---

## Query 5 - Hash-Based Malware IOC Detection

**Purpose:** Detect known malware file hashes anywhere in the environment. Highest-fidelity rule type in a SOC's arsenal (near-zero false positive rate).

**Source:** All indexed logs

```spl
index=main earliest=0
| rex "(?<md5_hash>\b[a-fA-F0-9]{32}\b)"
| rex "(?<sha256_hash>\b[a-fA-F0-9]{64}\b)"
| eval hash=coalesce(sha256_hash, md5_hash)
| where isnotnull(hash)
| where hash IN (
    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    "44d88612fea8a8f36de82e1278abb02f",
    "5f4dcc3b5aa765d61d8327deb882cf99"
)
| eval alert="KNOWN MALWARE HASH DETECTED: " . hash
| table _time, host, sourcetype, hash, alert
| sort -_time
```

**Detection logic:** Separate rex for MD5 (32 chars) and SHA256 (64 chars), coalesced into single hash field. Watchlist filter then matches against known malware hashes.

**Limitation:** Only detects known threats. Must be paired with behavior-based detection (process anomalies, persistence, lateral movement) for novel malware coverage.

---

## ---

## Future Improvements

These queries were built and tested inline. Future iterations would:

1. **Move field extractions to props.conf** — defining the regex captures at the
   sourcetype level so they happen automatically at search time, removing the
   need for repeated rex commands in every query.

2. **Replace hardcoded IP and hash watchlists with lookup files** — backed by
   automated threat intelligence feeds (AbuseIPDB, AlienVault OTX, internal
   threat intel) so the queries stay stable while the indicators evolve.

3. **Add automated VirusTotal enrichment** — using the `lookup` command against
   a cached VT feed to score hashes by AV engine detection rate, surfacing
   the highest-risk indicators first.

4. **Wire results into alert actions** — Slack notifications for CRITICAL
   verdicts, ticket creation for malware hash hits, automated EDR queries
   for watchlist IP matches.

5. **Expand scanner detection regex** — review monthly against new attack
   tool releases. Current rule covers sqlmap, nikto, nmap, masscan,
   python-requests, curl; future tools (e.g., dirsearch, ffuf, feroxbuster)
   need to be added as they appear in production logs.
