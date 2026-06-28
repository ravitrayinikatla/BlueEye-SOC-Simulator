# 👁 BlueEye SOC Simulator v2

A Python-based Security Operations Center (SOC) simulator that generates cyberattack logs, detects threats using custom detection rules, maps alerts to MITRE ATT&CK, and displays everything in a professional dark SOC dashboard.

## Objective

Cybersecurity students and SOC beginners face a common problem — they understand the theory but have no practical environment to apply it. Tools like Splunk, IBM QRadar, and Microsoft Sentinel that are used in real SOC environments are behind expensive licenses and enterprise access, making hands-on learning impossible for most learners.

BlueEye SOC Simulator was built to solve exactly that.

* See how real cyberattacks generate logs across different systems
* Understand how a SIEM detects threats using rule-based correlation
* Practice the full SOC analyst workflow — from alert triage to incident resolution
* Learn how MITRE ATT&CK is used to classify and understand attacker behavior
* Extract IOCs and check them against real threat intelligence platforms like VirusTotal and AbuseIPDB
* Investigate incidents, document findings, and resolve cases — exactly like a Tier-1 and Tier-2 SOC analyst does every day

This project is designed to operate in both offline and online environments.

## **Offline Mode**

Log analysis
IOC extraction
Local detection rules
Report generation

## **Online Mode**

VirusTotal reputation checks
MITRE ATT&CK mapping
Threat intelligence enrichment
CVE lookups

The goal is to bridge the gap between theoretical cybersecurity knowledge and real-world SOC operations — without needing access to any paid platform or enterprise tool.

## Key Features

* Attack Simulation — 8 real-world cyberattacks simulated across 6 different log sources
* Log Generation — Realistic JSON logs from Linux Auth, DNS, Firewall, Web Server, Windows Security, and Bash History
* Detection Engine — Custom Python rule-based detection with threat severity scoring from 0 to 100
* MITRE ATT&CK Mapping — Every alert automatically mapped to a technique ID, technique name, and tactic
* Incident Queue — Full status lifecycle tracking — NEW → INVESTIGATING → RESOLVED → FALSE POSITIVE
* Investigation Panel — Per-incident deep dive with IOCs, attack timeline, Windows Event IDs, and analyst notes
* IOC Viewer — All attacker IPs and domains aggregated across alerts with direct VirusTotal and AbuseIPDB links
* REST API — /api/alerts endpoint returns all alerts as JSON for integration with external tools
* SOC Dashboard — Professional dark UI inspired by Splunk with severity chart, tactic breakdown, and live clock

## Architecture

```
LAYER 1 — ATTACK SIMULATION
generators/generate_all.py
Simulates 8 attacks and writes JSON logs to /logs/
          ↓
LAYER 2 — DETECTION ENGINE
detection/engine.py
Reads logs → applies detection rules → scores threats → maps to MITRE ATT&CK
          ↓
LAYER 3 — INCIDENT MANAGEMENT
incident_response/manager.py
Assigns incident IDs → tracks status → stores analyst notes
          ↓
LAYER 4 — SOC DASHBOARD
app.py → dashboard.html / investigate.html / iocs.html
Displays alerts → investigation panel → IOC viewer
```

## SOC Analyst Workflow

```
Step 1  — NEW alert appears on the dashboard
          ↓
Step 2  — Analyst opens the Investigation Panel
          ↓
Step 3  — Reads incident details — Source IP, Host, Threat Score
          ↓
Step 4  — Checks MITRE ATT&CK technique — understands how the attack works
          ↓
Step 5  — Reviews IOCs — checks attacker IP on VirusTotal and AbuseIPDB
          ↓
Step 6  — Reads Windows Event IDs — understands what attacker did on the system
          ↓
Step 7  — Reviews Attack Timeline — understands the sequence of events
          ↓
Step 8  — Changes status NEW → INVESTIGATING
          ↓
Step 9  — Documents findings in Investigation Notes
          ↓
Step 10 — Takes remediation action — block IP, isolate host, reset credentials
          ↓
Step 11 — Changes status INVESTIGATING → RESOLVED ✅
```

## Repository Structure

BlueEye-SOC-Simulator/
│
├── generators/
│   └── generate_all.py
├── detection/
│   └── engine.py
├── incident_response/
│   └── manager.py
├── dashboard/
│   └── templates/
│       ├── base.html
│       ├── dashboard.html
│       ├── investigate.html
│       └── iocs.html
├── logs/
├── app.py
└── README.md

## Attacks Simulated

| Attack | MITRE ID | Severity |
|--------|----------|----------|
| Brute Force → Account Compromise | T1110 | 🔴 Critical |
| Privilege Escalation | T1078 | 🔴 Critical |
| Data Exfiltration | T1041 | 🔴 Critical |
| C2 Beaconing | T1071.001 | 🔴 Critical |
| DNS Tunneling | T1071.004 | 🟠 High |
| SQL Injection | T1190 | 🟠 High |
| Port Scan | T1046 | 🟠 High |
| Cross-Site Scripting (XSS) | T1059.007 | 🟡 Medium |

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/ravitrayinikatla/BlueEye-SOC-Simulator.git
cd BlueEye-SOC-Simulator

# 2. Install dependencies
pip install flask

# 3. Generate attack logs
python generators/generate_all.py

# 4. Start the dashboard
python app.py
```

Open browser — http://127.0.0.1:5000

## Dashboard Pages

Page                  URL                  Description
Alert Dashboard       /                    View all detected threats and severity chart
Investigation Panel   /investigate/id      Deep dive into any alert — IOCs, timeline, MITRE, notes
IOC Viewer            /iocs                All attacker IPs and domains with threat intel links
REST API              /api/alerts          Get all alerts as JSON

## Tools Used

- Python
- Flask
- Chart.js
- MITRE ATT&CK Framework
- VirusTotal
- AbuseIPDB
- VS Code
- Git
- GitHub

## References

- MITRE ATT&CK Framework
- OWASP Top 10 (2021)
- VirusTotal Documentation
- AbuseIPDB Documentation
- Flask Documentation
- Cybersecurity and Infrastructure Security Agency (CISA)

## Outcome

Successfully built a fully functional SOC simulator that replicates the real analyst workflow — generating attack logs across 6 log sources, detecting 8 attack types, mapping every alert to MITRE ATT&CK, and providing a professional dashboard with incident investigation, IOC extraction, and status tracking.

## Author

Katla Ravitrayini
https://github.com/ravitrayinikatla
