# 👁 BlueEye SOC Simulator v2

> A Python-based Security Operations Center (SOC) simulator that generates realistic attack logs, runs detection rules across multiple log sources, maps alerts to MITRE ATT&CK, and displays everything in a professional dark SOC dashboard.

Built as a cybersecurity portfolio project demonstrating **Detection Engineering**, **SOC Monitoring**, **Incident Response**, and **Threat Intelligence** skills.

---

## 🔥 What It Does

| Feature | Details |
|---|---|
| **Attack Simulation** | 8 attack types: Brute Force, DNS Tunneling, Port Scan, SQL Injection, XSS, Privilege Escalation, Data Exfiltration, C2 Beaconing |
| **Log Sources** | Linux Auth, DNS, Firewall, Web Server, Windows Security, Linux Bash History |
| **Detection Engine** | Rule-based detection with severity scoring (0–100) |
| **MITRE ATT&CK** | Every alert maps to a MITRE technique ID, technique name, and tactic |
| **Incident Queue** | Status tracking (NEW / INVESTIGATING / RESOLVED / FALSE POSITIVE) |
| **Investigation Panel** | Per-alert deep-dive: IOCs, attack timeline, analyst notes, MITRE details |
| **IOC Viewer** | Aggregated Indicators of Compromise with VirusTotal / AbuseIPDB links |
| **REST API** | `/api/alerts` returns JSON for integration with other tools |

---

## 📁 Project Structure

```
BlueEye-SOC-Simulator/
│
├── generators/
│   └── generate_all.py        # Master attack log generator (8 attack types)
│
├── detection/
│   └── engine.py              # Detection rules + MITRE ATT&CK mapping
│
├── incident_response/
│   └── manager.py             # Incident status, analyst assignment, notes
│
├── dashboard/
│   └── templates/
│       ├── base.html          # Shared dark SOC UI layout
│       ├── dashboard.html     # Main alert queue + severity chart
│       ├── investigate.html   # Per-incident investigation panel
│       └── iocs.html          # IOC viewer with threat intel links
│
├── logs/                      # Generated attack logs (JSON)
├── app.py                     # Flask application entry point
└── README.md
```

---

## ⚡ Quick Start

### 1. Install dependencies

```bash
pip install flask
```

### 2. Generate attack logs

```bash
python generators/generate_all.py
```

This creates 7 log files in `/logs/` simulating:
- Brute force with account compromise
- DNS tunneling via TXT/NULL queries
- Port scanning (18 ports)
- SQL injection via `sqlmap`
- XSS attempts
- Windows privilege escalation (Event IDs: 4688, 4672, 4624, 4698, 7045)
- Data exfiltration commands
- C2 beaconing at regular intervals

### 3. Start the dashboard

```bash
python app.py
```

Open: **http://127.0.0.1:5000**

---

## 🖥 Dashboard Pages

| URL | Page |
|---|---|
| `/` | Main SOC alert dashboard with severity chart and MITRE tactic breakdown |
| `/investigate/<id>` | Deep-dive investigation: IOCs, timeline, analyst tools |
| `/iocs` | Aggregated IOC table with VirusTotal/AbuseIPDB integration |
| `/api/alerts` | REST API returning all alerts as JSON |

---

## 🗺 MITRE ATT&CK Coverage

| Alert | Technique ID | Tactic |
|---|---|---|
| Brute Force Attack | T1110 | Credential Access |
| DNS Tunneling | T1071.004 | Command and Control |
| Port Scan | T1046 | Discovery |
| SQL Injection | T1190 | Initial Access |
| XSS | T1059.007 | Execution |
| Privilege Escalation | T1078 | Privilege Escalation |
| Data Exfiltration | T1041 | Exfiltration |
| C2 Beaconing | T1071.001 | Command and Control |

---

## 🛠 Tech Stack

- **Python 3** — detection engine, log generators, incident management
- **Flask** — web application framework
- **Jinja2** — HTML templating
- **Chart.js** — severity donut chart
- **JSON** — log format and API output

---

## 💡 Skills Demonstrated

`Python` `Flask` `JSON Log Analysis` `SIEM Concepts` `Threat Detection` `SOC Monitoring` `Incident Response` `MITRE ATT&CK` `Detection Engineering` `Rule-Based Correlation` `IOC Extraction` `Security Dashboards` `REST API Design`

---

## 📌 Resume Line

> Built BlueEye SOC Simulator v2: a Python/Flask platform that simulates 8 attack types across 6 log sources, detects threats using custom detection rules, maps every alert to MITRE ATT&CK, and presents a professional SOC dashboard with incident management, investigation workflows, and IOC extraction.
