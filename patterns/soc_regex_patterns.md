# SOC Regex Pattern Library
# Author: William Gokah
# GitHub: WiLL75G
# Purpose: IOC extraction from security logs

---

## PATTERN 1: IPv4 Address Extraction
Pattern: \b(?:\d{1,3}\.){3}\d{1,3}\b

Breakdown:
\b          - word boundary (prevents partial matches)
(?:         - non-capturing group
\d{1,3}     - 1 to 3 digits
\.          - literal dot
){3}        - repeated 3 times
\d{1,3}     - final octet
\b          - closing word boundary

Test on: "Failed password from 203.0.113.45 port 22"
Extracts: 203.0.113.45

Bash usage:
grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' ssh_auth.log

---

## PATTERN 2: Email Address Extraction
Pattern: [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}

Breakdown:
[a-zA-Z0-9._%+-]+ - username characters (one or more)
@                 - literal @ symbol
[a-zA-Z0-9.-]+    - domain name
\.                - literal dot
[a-zA-Z]{2,}      - TLD (2 or more letters)

Bash usage:
grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' security_events.log

---

## PATTERN 3: MD5 Hash Extraction
Pattern: \b[a-fA-F0-9]{32}\b

Breakdown:
\b              - word boundary
[a-fA-F0-9]     - hex characters (0-9 and a-f)
{32}            - exactly 32 characters
\b              - word boundary

MD5 is always exactly 32 hex characters.

Bash usage:
grep -oE '\b[a-fA-F0-9]{32}\b' security_events.log

---

## PATTERN 4: SHA256 Hash Extraction
Pattern: \b[a-fA-F0-9]{64}\b

SHA256 is always exactly 64 hex characters.

---

## PATTERN 5: URL/Domain Extraction
Pattern: https?://[^\s"'<>]+

Breakdown:
https?      - http or https (s is optional)
://         - literal
[^\s"'<>]+  - any char except space/quote/bracket (one or more)

Bash usage:
grep -oE 'https?://[^[:space:]"<>]+' security_events.log

---

## PATTERN 6: Timestamp Extraction (ISO 8601)
Pattern: \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z

Extracts: 2026-01-10T02:14:00Z

---

## PATTERN 7: Windows Event ID Extraction
Pattern: EventID[=:\s]+(\d{4})

Extracts the 4-digit Event ID from Windows logs.

---

## PATTERN 8: Port Number Extraction
Pattern: (?:port|Port|PORT)\s+(\d{1,5})

Extracts port numbers that follow the word "port".

Bash usage:
grep -oE -i 'port\s+[0-9]{1,5}' ssh_auth.log

---

## PATTERN 9: HTTP Status Code Extraction
Pattern: "\s([2345]\d{2})\s

Extracts HTTP status codes (200, 403, 404, 500, etc.)
from Apache/Nginx access logs.

Bash usage:
grep -oE '" [0-9]{3} ' apache_access.log

---

## PATTERN 10: Suspicious User Agent Detection
Pattern: sqlmap|nikto|nmap|masscan|zgrab|curl|python-requests|go-http

These are common scanner and attack tool user agents.

Bash usage:
grep -iE 'sqlmap|nikto|nmap|masscan|python-requests|curl' apache_access.log

---

## PATTERN 11: SSH Failed Login Extraction
Pattern: Failed password for (\w+) from ([\d.]+)

Capture Groups:
Group 1: username targeted
Group 2: source IP address

Bash usage:
grep -oE 'Failed password for \w+ from [0-9.]+' ssh_auth.log

---

## PATTERN 12: Log Level Severity Extraction
Pattern: \] (CRITICAL|HIGH|MEDIUM|LOW|INFO|ALERT|WARNING) 

Note: This format assumes severity sits OUTSIDE the timestamp brackets,
separated by spaces (e.g. "[2026-01-10T03:14:00Z] CRITICAL user=admin").
If your log format wraps severity in its own brackets (e.g. "[CRITICAL]"),
use this pattern instead: \[(CRITICAL|HIGH|MEDIUM|LOW|INFO|ALERT|WARNING)\]

Bash usage:
grep -E '\] (CRITICAL|HIGH|MEDIUM|LOW|INFO|ALERT) ' security_events.logo
