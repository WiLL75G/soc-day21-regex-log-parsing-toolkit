# Log Parsing & Detection Engineering Toolkit: Regex to Splunk SPL (SOC Tier 1)

---

## Executive Summary

This project demonstrates the full regex-based investigation workflow used by SOC Tier 1 analysts and detection engineers from raw log inspection on the Linux command line, through Python automation, into production-style Splunk SPL detection rules.

Built across a self managed home lab (macOS host + Kali VM + Splunk Enterprise), the toolkit covers IOC extraction, multi-pattern detection, IOC pivoting across log sources, and the onboarding of non-standard application logs into SIEM-ready JSON.

**Key deliverable:** a complete, reproducible detection engineering portfolio 12 documented regex patterns, 2 Python scripts, 5 production-style Splunk SPL queries, and structured evidence files demonstrating each technique against multi-log attack scenarios.

---

## Project Methodology

The lab simulates a Tier 1 SOC analyst's investigation workflow across 7 phases:

1. **Regex fundamentals** IP, hash, URL, and User-Agent pattern construction tested in regex101
2. **Lab data creation** 4 sample log formats (SSH auth, Apache access, custom security events, custom application)
3. **Pattern library** 12 documented IOC extraction patterns with breakdown and bash usage
4. **Manual extraction** grep based IOC extraction with output saved as forensic evidence files
5. **Python automation** IOC extractor categorizing findings across multiple log formats with suspicious-pattern flagging
6. **SIEM deployment** 5 optimized Splunk SPL queries demonstrating validated extraction, multi-pattern parsing, IOC watchlisting, attack classification, and hash-based detection
7. **Custom log onboarding** Python parser turning non standard application logs into structured JSON ready for SIEM ingestion

---

## IOCs Extracted in the Lab

| Type | Value | Source | Context |
|---|---|---|---|
| Attacker IP | 203.0.113.45 | SSH, Apache, Security Events | Multi-vector attacker brute force + scanner + traversal |
| Attacker IP | 185.220.101.33 | SSH, Apache | Brute force + python-requests webshell drop |
| Attacker IP | 198.51.100.22 | SSH, Apache | Brute force + curl /etc/passwd probe |
| Internal IP | 10.0.2.87 | Security Events | Internal port scan possible compromised host |
| Email | admin@company.com | Security Events | Phishing victim |
| MD5 Hash | a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 | Security Events | invoice.exe malware sample |
| Typosquatted URL | http://paypa1.com/login | Security Events | Homograph attack 1 substituted for l |

---

## MITRE ATT&CK Coverage

| Tactic | Technique | ID | Lab Evidence |
|---|---|---|---|
| Credential Access | Brute Force | T1110 | SSH Failed password events from 3 external IPs |
| Initial Access | Phishing: Spearphishing Link | T1566.002 | PHISHING_CLICK event with typosquatted domain |
| Discovery | Network Service Scanning | T1046 | Internal 10.0.2.87 scanning /24 range, 1000 ports |
| Initial Access | Exploit Public-Facing Application | T1190 | sqlmap probes on /admin/login.php |
| Discovery | File and Directory Discovery | T1083 | Directory traversal /../../../etc/shadow |
| Persistence | Create Account: Local Account | T1136.001 | Service account svc_backup2 created by Administrator |
| Execution | User Execution: Malicious File | T1204.002 | invoice.exe malware detection |

---

## Key Analyst Findings

**Multi-vector attacker correlation** The IP 203.0.113.45 was observed across three independent log sources within the same time window: SSH brute force, Apache scanner activity (sqlmap on /admin/login.php), and Apache directory traversal (/../../../etc/shadow via Nikto). This is a textbook case of cross log IOC pivoting single log analysis would have surfaced three separate minor events; cross-source correlation reveals one coordinated multi vector campaign requiring Tier 2 escalation.

**Detection coverage gap identified** The initial Splunk web attack detection rule classified only 2 of 4 known attacks because the scanner User-Agent regex did not cover curl and python requests. The rule fired correctly on detected events but missed 50% of attacks silently. Fix required expanding the regex pattern. This is the single most important lesson for detection engineers: a rule that fires on some attacks is not a working rule; it is a partial blind spot. Coverage testing must be part of every rule's lifecycle.

**Typosquatting requires explicit pattern coverage** The Python IOC extractor did not flag http://paypa1.com/login (a homograph attack substituting 1 for l) because the pattern library did not include typosquatting heuristics. Standard URL extraction surfaced the URL, but classification as malicious required domain-substitution rules. Future iterations should include brand-substitution pattern matching.

---

## Analyst Insight

Regex is not a security skill in itself it is the universal interface between unstructured log data and the structured detection logic that protects an environment. Every detection engineer, SIEM admin, and Tier 1 analyst spends meaningful time writing, optimizing, and debugging regex. This project demonstrates that workflow end-to-end: from raw log inspection on a Linux command line, through scripted automation, into a production SIEM, and finally to onboarding entirely new log sources via custom parsers. The toolkit produced here is not a learning exercise it is a working set of detection patterns and scripts that can be adapted to any text-based log source in production.

---

## Learning Outcomes

- Built 12 reusable regex patterns covering IPs, hashes, emails, URLs, ports, timestamps, CVEs, and severity tags
- Demonstrated regex fluency across three syntax variants: bash grep -E, Python re module, and Splunk rex command
- Implemented validated IPv4 patterns that reject malformed octets
- Built priority-ordered classification logic in Splunk SPL using eval case() statements
- Identified and corrected a real detection coverage gap in a live SPL rule
- Wrote a Python custom-log parser that turns non-standard application logs into SIEM-ready JSON
- Documented production deployment patterns as future improvements

---

## Repository Structure

- patterns/ 12 documented IOC extraction patterns
- scripts/ Python IOC extractor + custom log parser
- splunk/ 5 production-style Splunk detection queries
- sample-logs/ 4 lab log files (SSH, Apache, security events, custom app)
- sample-output/ grep evidence files + parsed JSON output
- screenshots/ annotated workflow screenshots (01_ through 22b_)

---

## Future Improvements

1. Move field extractions to props.conf so regex captures happen automatically at search time
2. Replace hardcoded IP and hash watchlists with lookup files fed by threat intelligence feeds
3. Add automated VirusTotal enrichment via lookup against a cached VT feed
4. Wire detection rules into alert actions (Slack, ticketing, EDR queries)
5. Expand scanner detection regex monthly as new attack tools emerge
6. Add typosquatting / homograph detection patterns for brand-substitution attacks
7. Performance-test patterns against large log volumes to identify backtracking risks

---

## Tools & Environment

- Host OS: macOS
- Lab VM: Kali Linux (UTM)
- SIEM: Splunk Enterprise (running on macOS host)
- Languages: Python 3, Bash
- Regex flavors: PCRE2, Python re, Splunk rex
- Testing: regex101.com (PCRE2 mode)

---

## Conclusion

This toolkit is the practical, reproducible foundation of a SOC Tier 1 analyst's daily work regex fluency across three syntax variants, automation in Python, detection engineering in Splunk, and the ability to onboard a new log source from scratch. It is built on a self managed home lab, validated end-to-end, and honestly documents the coverage gaps and detection limitations encountered during development. Recruiters and hiring managers reviewing this repo can read the scripts, run the queries, examine the evidence files, and verify the work independently.
