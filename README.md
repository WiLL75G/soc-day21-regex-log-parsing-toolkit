# Log Parsing and Detection Engineering, Regex to Splunk SPL

Regex is the interface between raw log text and detection logic. This is that workflow end to end: grep on the command line, Python automation, then production style SPL, including the rule that missed half its attacks and how that got found.

## At a Glance

| Field | Detail |
| --- | --- |
| Work Type | Detection engineering, log parsing, IOC extraction |
| Environment | macOS host, Kali VM, Splunk Enterprise |
| Regex Flavours | bash grep -E, Python re, Splunk rex |
| Delivered | 12 patterns, 2 Python scripts, 5 SPL queries, 4 sample log formats |
| Key Finding | A working rule classified only 2 of 4 known attacks and fired correctly the whole time |

## What This Is

Every SOC runs on regex whether anyone admits it or not. Field extraction, rule authoring, log onboarding, all of it is pattern matching against text somebody else formatted.

The lab builds the same workflow three ways, because a pattern that works in grep does not automatically work in Splunk, and knowing where the flavours diverge is the difference between writing a rule and debugging one at 2am.

Scope stated plainly: the logs are lab generated across four formats. The patterns, the scripts, and the SPL are real and reusable. The attack scenarios are constructed to exercise them.

## Method

Seven phases, each producing an artefact.

Regex fundamentals, patterns built and tested in regex101 for IPs, hashes, URLs, and User Agents.

Lab data, four log formats: SSH auth, Apache access, custom security events, custom application.

Pattern library, 12 documented extraction patterns with breakdown and bash usage.

Manual extraction, grep based, output saved as evidence files.

Python automation, an IOC extractor that categorises findings across formats and flags suspicious patterns.

SIEM deployment, 5 SPL queries covering validated extraction, multi pattern parsing, IOC watchlisting, attack classification, and hash detection.

Custom log onboarding, a Python parser turning a non standard application log into structured JSON ready for ingest.

## IOCs Extracted

| Type | Value | Source | Context |
| --- | --- | --- | --- |
| Attacker IP | 203.0.113.45 | SSH, Apache, security events | Multi vector, brute force plus scanner plus traversal |
| Attacker IP | 185.220.101.33 | SSH, Apache | Brute force plus python-requests webshell drop |
| Attacker IP | 198.51.100.22 | SSH, Apache | Brute force plus curl /etc/passwd probe |
| Internal IP | 10.0.2.87 | Security events | Internal port scan, possible compromised host |
| Email | admin@company.com | Security events | Phishing target |
| MD5 | a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 | Security events | invoice.exe sample |
| Typosquatted URL | http://paypa1.com/login | Security events | Homograph, digit 1 substituted for letter l |

## MITRE ATT&CK Coverage

| Tactic | Technique | ID | Evidence |
| --- | --- | --- | --- |
| Credential Access | Brute force | T1110 | SSH failed password events from three external IPs |
| Initial Access | Phishing, spearphishing link | T1566.002 | Phishing click event with typosquatted domain |
| Initial Access | Exploit public facing application | T1190 | sqlmap probes against /admin/login.php |
| Discovery | Network service discovery | T1046 | 10.0.2.87 scanning the /24, 1000 ports |
| Discovery | File and directory discovery | T1083 | Directory traversal to /etc/shadow |
| Persistence | Create account, local account | T1136.001 | svc_backup2 created by Administrator |
| Execution | User execution, malicious file | T1204.002 | invoice.exe detection |

## Finding, Cross Log Correlation

203.0.113.45 appears in three independent log sources inside the same window.

SSH: brute force attempts.

Apache: sqlmap against /admin/login.php.

Apache: directory traversal to /etc/shadow via Nikto.

Read one log at a time and this is three minor events, each individually closeable. Read across them and it is one operator running three techniques against the same target, which is a Tier 2 escalation.

The pivot only works because the IOCs were extracted into a common format first. Correlation is not an insight you have, it is a thing the data structure either permits or does not.

## Finding, The Rule That Missed Half

The web attack detection rule classified 2 of 4 known attacks.

The cause: the scanner User Agent regex covered sqlmap and Nikto, and did not cover curl or python-requests.

The rule fired correctly every single time it fired. Nothing errored. Nothing looked broken. The dashboard showed detections. And half the attacks went past silently.

This is the most useful thing in the repo.

A rule that fires is not a rule that works. A rule that fires on some attacks is a blind spot with a green light on it, and it is more dangerous than no rule at all, because no rule prompts a question and a partial rule prompts confidence.

The only reason this surfaced is that the attack set was known. Coverage was measured against ground truth rather than against whether the rule produced output. In production nobody hands you the answer key, which is why coverage testing has to be built into a rule's lifecycle rather than assumed from the fact that it alerts.

## Finding, Typosquatting Needs Explicit Rules

The Python extractor pulled http://paypa1.com/login out of the logs correctly. It did not flag it.

Standard URL extraction is a syntax problem and it worked. Recognising paypa1 as an attack on paypal is a semantics problem, and no URL regex solves it, because the string is a perfectly valid URL.

Extraction and classification are different jobs. The pattern library did the first one and had nothing for the second. Brand substitution heuristics are the gap, and naming it is more useful than pretending the extractor caught it.

## What This Demonstrates

Building 12 reusable patterns across IPs, hashes, emails, URLs, ports, timestamps, CVEs, and severity tags.

Writing the same logic three ways, bash grep -E, Python re, and Splunk rex, and knowing where the flavours break.

Validated IPv4 patterns that reject malformed octets rather than matching anything with three dots.

Priority ordered classification in SPL using eval case statements.

Finding a real coverage gap in a live rule by testing against known attacks rather than trusting the output.

Pivoting an IOC across three log sources to turn separate events into one campaign.

Writing a parser that onboards a non standard log source into SIEM ready JSON.

Documenting the gaps found rather than the version where everything worked.

## Where It Goes Next

Move field extractions into props.conf so captures happen at search time automatically.

Replace hardcoded IP and hash watchlists with lookup files fed by threat intel.

Add VirusTotal enrichment via a cached lookup.

Wire rules into alert actions rather than leaving them as searches.

Expand the scanner User Agent regex on a schedule, since the gap that was found once will recur as tooling changes.

Add homograph and brand substitution patterns.

Performance test the patterns against volume to find backtracking risks before production does.

## Environment

| Component | Detail |
| --- | --- |
| Host | macOS |
| Lab VM | Kali Linux, UTM |
| SIEM | Splunk Enterprise |
| Languages | Python 3, Bash |
| Regex flavours | PCRE2, Python re, Splunk rex |
| Testing | regex101, PCRE2 mode |

## Repository Structure

```
regex-log-parsing-toolkit/
├── README.md
├── patterns/          12 documented IOC extraction patterns
├── scripts/           Python IOC extractor and custom log parser
├── splunk/            5 detection queries
├── sample-logs/       4 lab log files
├── sample-output/     grep evidence files and parsed JSON
└── screenshots/       annotated workflow, 01 through 22b
```

---

[![LinkedIn](https://img.shields.io/badge/LinkedIn-WilliamInCyber-blue?style=flat&logo=linkedin)](https://linkedin.com/in/WilliamInCyber)
[![X](https://img.shields.io/badge/X-@WilliamInCyber-black?style=flat&logo=x)](https://x.com/WilliamInCyber)
