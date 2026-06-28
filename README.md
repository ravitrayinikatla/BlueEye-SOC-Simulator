```markdown
<div align="center">

# 👁 BlueEye SOC Simulator

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.x-black?style=flat-square&logo=flask)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

A beginner-friendly SOC simulator that generates cyberattack logs, detects threats, and displays them in a professional security dashboard — built with Python and Flask.

</div>

---

## What is this?

This project simulates what a **Security Operations Center (SOC) analyst** does every day.

It generates fake cyberattack logs, detects the attacks using Python rules, maps them to **MITRE ATT&CK**, and shows everything in a dark SOC dashboard where you can investigate and resolve incidents — just like real tools such as Splunk or IBM QRadar.

---

## Attacks Simulated

| Attack | Severity |
|--------|----------|
| Brute Force → Account Compromise | 🔴 Critical |
| Privilege Escalation | 🔴 Critical |
| Data Exfiltration | 🔴 Critical |
| C2 Beaconing | 🔴 Critical |
| DNS Tunneling | 🟠 High |
| SQL Injection | 🟠 High |
| Port Scan | 🟠 High |
| Cross-Site Scripting (XSS) | 🟡 Medium |

---

## Dashboard Pages

| Page | URL | What you can do |
|------|-----|-----------------|
| Alert Dashboard | `/` | See all detected threats |
| Investigation | `/investigate/<id>` | Deep dive into any alert |
| IOC Viewer | `/iocs` | View attacker IPs and domains |
| API | `/api/alerts` | Get all alerts as JSON |

---

## Installation

### Requirements
- Python 3.10 or above
- pip

### Steps

**1. Clone the repository**
```bash
git clone https://github.com/ravitrayinikatla/BlueEye-SOC-Simulator.git
cd BlueEye-SOC-Simulator
```

**2. Install Flask**
```bash
pip install flask
```

**3. Generate attack logs**
```bash
python generators/generate_all.py
```

**4. Start the dashboard**
```bash
python app.py
```

**5. Open your browser**
```
http://127.0.0.1:5000
```

That's it. The dashboard will show all detected attacks.

---

## How it works

```
Step 1 — generate_all.py creates fake attack logs
Step 2 — detection/engine.py reads the logs and detects attacks
Step 3 — Every alert is mapped to a MITRE ATT&CK technique
Step 4 — Flask dashboard displays all alerts
Step 5 — You investigate, add notes, and resolve incidents
```

---

## Tech Used

- **Python** — detection engine and log generation
- **Flask** — web dashboard
- **Chart.js** — severity chart
- **MITRE ATT&CK** — threat classification

---

## MITRE ATT&CK Techniques Covered

| Technique ID | Technique | Tactic |
|---|---|---|
| T1110 | Brute Force | Credential Access |
| T1078 | Valid Accounts | Privilege Escalation |
| T1041 | Exfiltration Over C2 | Exfiltration |
| T1071.001 | Web Protocols | Command & Control |
| T1071.004 | DNS | Command & Control |
| T1190 | Exploit Public-Facing App | Initial Access |
| T1046 | Network Service Discovery | Discovery |
| T1059.007 | JavaScript | Execution |

---

<div align="center">

Made by **Ravi Trayini Katla**

[![GitHub](https://img.shields.io/badge/GitHub-ravitrayinikatla-black?style=flat-square&logo=github)](https://github.com/ravitrayinikatla)


</div>
