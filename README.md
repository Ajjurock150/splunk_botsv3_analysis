# 🛡️ Splunk BOTSv3 — Security Operations Center (SOC) Analysis

> A hands-on threat hunting and incident response project using the **Boss of the SOC (BOTS) v3** dataset in Splunk Enterprise. This project demonstrates real-world blue team skills including log analysis, attack detection, threat hunting, and security dashboard development.

---

## 📌 Project Overview

| Detail | Info |
|--------|------|
| **Dataset** | Boss of the SOC (BOTS) v3 by Splunk |
| **Platform** | Splunk Enterprise 7.1.7+ |
| **Data Size** | ~320 MB (pre-indexed) |
| **Index** | `index=botsv3` |
| **Focus** | Threat hunting, incident response, SIEM rule development |

---

## 🎯 What This Project Covers

This project simulates the work of a SOC analyst investigating a multi-stage attack scenario involving:

- 🔍 **Reconnaissance & scanning** — port scans, web crawlers, tool fingerprinting
- 🔑 **Credential attacks** — brute force, password spray, Kerberoasting
- 🦠 **Malware & ransomware** — file encryption patterns, process injection, LOLBins
- 🌐 **Web application attacks** — SQLi, XSS, directory traversal
- 📡 **C2 communication** — DNS tunneling, beaconing detection
- ↔️ **Lateral movement** — SMB, PsExec, RDP, Pass-the-Hash
- ⬆️ **Privilege escalation** — group membership changes, token impersonation
- 📤 **Data exfiltration** — outbound transfer analysis, S3 access logs
- ☁️ **AWS cloud threats** — CloudTrail, GuardDuty, IAM abuse
- 📧 **O365 threats** — phishing, inbox rules, impossible travel
- 👤 **User behaviour analytics** — off-hours logins, multi-system access

---

## 📁 Repository Structure

```
splunk-botsv3-soc-analysis/
│
├── README.md                          ← This file
│
├── dashboards/
│   └── botsv3_dashboard.xml           ← Import-ready Splunk Classic XML dashboard
│
├── queries/
│   └── SPL_Query_Library.md           ← 60+ SPL queries across 15 attack categories
│
└── screenshots/
    ├── 01_executive_summary.png        ← Screenshots here
    ├── 02_brute_force.png
    ├── 03_ransomware.png
    ├── 04_aws_threats.png
    └── ...
```

---

## ⚙️ Setup Instructions

### 1. Install Splunk Enterprise
Download the free trial: https://www.splunk.com/en_us/download/splunk-enterprise.html

### 2. Download the BOTSv3 Dataset
```
Dataset: https://github.com/splunk/botsv3
Size: 320.1 MB | Format: Pre-indexed Splunk
MD5: d7ccca99a01cff070dff3c139cdc10eb
```

### 3. Install Required Splunk Apps
The dataset requires these add-ons from Splunkbase. Install all before loading data:

| App | Version | Purpose |
|-----|---------|---------|
| Splunk Common Information Model | 4.11.0 | Field normalization |
| Splunk Add-on for Microsoft Windows | 4.8.4 | Windows event logs |
| Microsoft Sysmon Add-on | 8.0.0 | Sysmon events |
| Splunk Add-on for AWS | 4.5.0 | CloudTrail, GuardDuty |
| Splunk Add-on for Symantec Endpoint | 2.3.0 | AV events |
| Splunk Stream Add-on | 7.1.2 | Network stream data |
| Splunk Add-on for Microsoft Office 365 | 1.0.0 | O365 events |
| Microsoft Azure AD Reporting Add-on | 1.0.1 | Azure AD sign-ins |

> Full list: See [BOTSv3 GitHub README](https://github.com/splunk/botsv3)

### 4. Load the Dataset
```bash
# Unzip into Splunk apps directory
unzip botsv3_data_set.zip -d $SPLUNK_HOME/etc/apps/

# Restart Splunk
$SPLUNK_HOME/bin/splunk restart
```

### 5. Verify Data is Loaded
```spl
index=botsv3 earliest=0 | stats count
```

### 6. Import the Dashboard
1. In Splunk, go to **Settings → User Interface → Views**
2. Click **Create New View**
3. Select **Source** editor
4. Paste the contents of `dashboards/botsv3_dashboard.xml`
5. Save

---

## 🔍 Key SPL Queries (Quick Reference)

### Baseline — What data do I have?
```spl
index=botsv3 earliest=0
| stats count by sourcetype
| sort -count
```

### Brute Force Detection
```spl
index=botsv3 sourcetype=wineventlog EventCode=4625 earliest=0
| stats count by src_ip, user
| where count > 10
| sort -count
```

### Ransomware — Unusual File Extensions
```spl
index=botsv3 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=11 earliest=0
| rex field=TargetFilename "\.(?<extension>[^.]+)$"
| search NOT extension IN ("exe","dll","log","tmp","dat","txt","pdf","docx")
| stats count by extension, host
| sort -count
```

### AWS Root Account Usage
```spl
index=botsv3 sourcetype=aws:cloudtrail earliest=0 "userIdentity.type"="Root"
| table _time, eventName, sourceIPAddress, userAgent
```

### Kerberoasting Detection
```spl
index=botsv3 sourcetype=wineventlog EventCode=4769 earliest=0 TicketEncryptionType=0x17
| stats count by AccountName, ServiceName, ClientAddress
| sort -count
```

> 📖 **Full query library with 60+ queries:** See [`queries/SPL_Query_Library.md`](queries/SPL_Query_Library.md)

---

## 🗺️ MITRE ATT&CK Coverage

| Tactic | Technique | Query Category |
|--------|-----------|----------------|
| Reconnaissance | T1046 — Network Service Scanning | Port Scan Detection |
| Initial Access | T1190 — Exploit Public-Facing App | Web App Attacks |
| Credential Access | T1110 — Brute Force | Failed Login Analysis |
| Credential Access | T1558.003 — Kerberoasting | EventCode 4769 Analysis |
| Credential Access | T1003.001 — LSASS Dumping | Mimikatz Detection |
| Execution | T1059.001 — PowerShell | Encoded Command Detection |
| Execution | T1047 — WMI | WmiPrvSE Spawning |
| Persistence | T1547.001 — Registry Run Keys | Sysmon Event 13 |
| Persistence | T1053.005 — Scheduled Tasks | EventCode 4698 |
| Privilege Escalation | T1098 — Account Manipulation | EventCode 4728/4732 |
| Defense Evasion | T1070.001 — Clear Event Logs | EventCode 1102/104 |
| Defense Evasion | T1218 — LOLBins | LOLBAS Process Monitoring |
| Lateral Movement | T1021.001 — RDP | EventCode 4624 Type 10 |
| Lateral Movement | T1021.002 — SMB | Stream SMB Analysis |
| Collection | T1114.003 — Email Forwarding | O365 Inbox Rules |
| Exfiltration | T1041 — Exfil over C2 | Outbound Bytes Analysis |
| Command & Control | T1071.004 — DNS C2 | DNS Tunneling Detection |
| Impact | T1486 — Data Encrypted | Ransomware File Analysis |
| Cloud | T1078.004 — Cloud Valid Accounts | AWS Root Usage |
| Cloud | T1526 — Cloud Service Discovery | CloudTrail AccessDenied |

---

## 📊 Dashboard Panels Overview

The `botsv3_dashboard.xml` contains **30 panels** across these categories:

| Section | Panels |
|---------|--------|
| Executive Summary KPIs | 6 single-value panels |
| Event Timeline & Sourcetypes | 2 panels |
| Reconnaissance & Scanning | 2 panels |
| Brute Force & Credentials | 4 panels |
| Malware & Ransomware | 3 panels |
| Web Application Attacks | 2 panels |
| C2 & DNS Tunneling | 2 panels |
| Lateral Movement | 2 panels |
| Data Exfiltration | 2 panels |
| AWS Cloud Threats | 4 panels |
| O365 & Email Threats | 2 panels |
| Privilege Escalation & Persistence | 2 panels |
| Sysmon Deep Dive | 2 panels |
| Kerberoasting & Anti-Forensics | 2 panels |
| User Behaviour Analytics | 2 panels |

---

## 💡 SPL Functions Used in This Project

| Function | Category | Description |
|----------|----------|-------------|
| `stats count` | Aggregation | Count events |
| `stats dc()` | Aggregation | Distinct/unique count |
| `stats sum()` | Aggregation | Sum field values |
| `stats avg()`, `stdev()` | Aggregation | Average, standard deviation |
| `stats values()` | Aggregation | Collect all unique values |
| `timechart` | Visualization | Time-series charts |
| `eval` | Field creation | Compute new fields |
| `eval case()` | Conditional | Multi-condition evaluation |
| `eval if()` | Conditional | Single condition |
| `rex` | Extraction | Regex field extraction |
| `where` | Filtering | Post-aggregation filter |
| `search` | Filtering | Pattern matching |
| `sort` | Ordering | Sort results |
| `head` / `tail` | Limiting | Top/bottom N results |
| `rename` | Field ops | Rename fields |
| `table` | Output | Format as table |
| `fields` | Output | Include/exclude fields |
| `dedup` | Deduplication | Remove duplicates |
| `bin _time span=` | Time | Bucket events by time |
| `strftime()` | Time | Format timestamps |
| `len()` | String | String length |
| `match()` | String | Regex match in eval |
| `replace()` | String | Regex substitution |
| `round()` | Math | Round numbers |
| `streamstats` | Running stats | Cumulative calculations |
| `eventstats` | Global stats | Add avg/stdev to all rows |

---

## 🏆 Skills Demonstrated

- **SIEM Administration** — Splunk Enterprise setup, app management, index configuration
- **Threat Hunting** — Proactive investigation using behavioural analytics and anomaly detection
- **Incident Response** — Identifying attack chains from initial access through exfiltration
- **SPL (Splunk Processing Language)** — Advanced query writing across 25+ SPL functions
- **MITRE ATT&CK Framework** — Mapping detections to real-world threat techniques
- **Dashboard Development** — Building operational security dashboards from scratch
- **Cloud Security** — AWS CloudTrail, GuardDuty, IAM, VPC Flow Log analysis
- **Log Analysis** — Windows Event Logs, Sysmon, Linux, network stream data

---

## 📚 Resources

- [Splunk BOTSv3 Official GitHub](https://github.com/splunk/botsv3)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Splunk SPL Quick Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [Sysmon Configuration Guide](https://github.com/SwiftOnSecurity/sysmon-config)
- [Sigma Rules for Splunk](https://github.com/SigmaHQ/sigma)

---

## 📄 License

Dataset distributed by Splunk under its own license. See [BOTSv3 repo](https://github.com/splunk/botsv3) for terms.  
Project code and queries by Ajay Ratnam Mandru — MIT License.

---

*⚠️ The BOTSv3 dataset contains evidence from real and simulated security incidents. Use for educational purposes only.*
