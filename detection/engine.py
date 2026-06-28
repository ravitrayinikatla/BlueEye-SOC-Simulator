"""
BlueEye SOC v2 - Master Detection Engine
Detects 7 attack types with MITRE ATT&CK mapping and severity scoring
"""
import json
from collections import defaultdict

MITRE = {
    "brute_force":         {"id": "T1110",     "technique": "Brute Force",                      "tactic": "Credential Access"},
    "credential_stuffing": {"id": "T1110.004", "technique": "Credential Stuffing",              "tactic": "Credential Access"},
    "dns_tunneling":       {"id": "T1071.004", "technique": "Application Layer Protocol: DNS",  "tactic": "Command and Control"},
    "port_scan":           {"id": "T1046",     "technique": "Network Service Discovery",        "tactic": "Discovery"},
    "sql_injection":       {"id": "T1190",     "technique": "Exploit Public-Facing Application","tactic": "Initial Access"},
    "xss":                 {"id": "T1059.007", "technique": "JavaScript",                       "tactic": "Execution"},
    "privilege_escalation":{"id": "T1078",     "technique": "Valid Accounts",                   "tactic": "Privilege Escalation"},
    "data_exfiltration":   {"id": "T1041",     "technique": "Exfiltration Over C2 Channel",     "tactic": "Exfiltration"},
    "c2_beaconing":        {"id": "T1071.001", "technique": "Web Protocols",                    "tactic": "Command and Control"},
    "lateral_movement":    {"id": "T1021",     "technique": "Remote Services",                  "tactic": "Lateral Movement"},
}

def _load(filename):
    try:
        with open(f"logs/{filename}") as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def _alert(name, mitre_key, severity, score, extra):
    m = MITRE.get(mitre_key, {})
    rec_map = {
        "brute_force":         "Block source IP. Enforce account lockout policy. Enable MFA.",
        "dns_tunneling":       "Block DNS queries with subdomains >40 chars. Deploy DNS RPZ filtering.",
        "port_scan":           "Block scanner IP. Review exposed services. Harden firewall rules.",
        "sql_injection":       "Patch web application. Deploy WAF rules. Parameterize queries.",
        "xss":                 "Implement Content Security Policy. Sanitize all user inputs.",
        "privilege_escalation":"Isolate host. Review privileged accounts. Check scheduled tasks.",
        "data_exfiltration":   "Block outbound traffic from host. Preserve disk image for forensics.",
        "c2_beaconing":        "Isolate beaconing host. Block C2 IPs. Perform malware analysis.",
        "lateral_movement":    "Reset compromised credentials. Segment network. Review RDP exposure.",
    }
    return {
        "alert": name,
        "mitre_id": m.get("id", ""),
        "mitre_technique": m.get("technique", ""),
        "mitre_tactic": m.get("tactic", ""),
        "severity": severity,
        "score": score,
        "recommendation": rec_map.get(mitre_key, "Investigate and escalate."),
        **extra
    }

# ── 1. Brute Force ──────────────────────────────────────────────────────────
def detect_brute_force():
    logs = _load("auth_logs.json")
    ip_fail = defaultdict(int)
    ip_users = defaultdict(set)
    ip_times = defaultdict(list)

    for l in logs:
        if l.get("event_type") == "failed_login":
            ip = l["ip"]
            ip_fail[ip] += 1
            ip_users[ip].add(l.get("user", "?"))
            ip_times[ip].append(l["timestamp"])

    # Bonus: flag IPs that succeeded AFTER many failures
    ip_success = {l["ip"] for l in logs if l.get("event_type") == "successful_login"}

    alerts = []
    for ip, count in ip_fail.items():
        if count >= 5:
            compromised = ip in ip_success
            severity = "CRITICAL" if compromised else ("HIGH" if count >= 20 else "HIGH")
            score = min(100, count * 3 + (30 if compromised else 0))
            name = "Brute Force → Account Compromise" if compromised else "Brute Force Attack"
            alerts.append(_alert(name, "brute_force", severity, score, {
                "ip": ip,
                "count": count,
                "users_targeted": list(ip_users[ip]),
                "compromised": compromised,
                "first_seen": ip_times[ip][0],
                "last_seen": ip_times[ip][-1],
                "iocs": [ip],
                "log_source": "linux_auth"
            }))
    return alerts

# ── 2. DNS Tunneling ─────────────────────────────────────────────────────────
def detect_dns_tunneling():
    logs = _load("dns_logs.json")
    ip_suspicious = defaultdict(list)

    for l in logs:
        domain = l.get("domain", "")
        sub = domain.split(".")[0]
        if len(sub) > 40 or l.get("query_type") in ["TXT", "NULL"]:
            ip_suspicious[l["ip"]].append(l)

    alerts = []
    for ip, entries in ip_suspicious.items():
        if len(entries) >= 5:
            score = min(100, len(entries) * 1.5 + 20)
            alerts.append(_alert("DNS Tunneling Detected", "dns_tunneling", "HIGH", int(score), {
                "ip": ip,
                "count": len(entries),
                "sample_domain": entries[0]["domain"],
                "first_seen": entries[0]["timestamp"],
                "last_seen": entries[-1]["timestamp"],
                "iocs": list({e["domain"].split(".")[-2] + "." + e["domain"].split(".")[-1] for e in entries[:3]}),
                "log_source": "dns"
            }))
    return alerts

# ── 3. Port Scan ─────────────────────────────────────────────────────────────
def detect_port_scan():
    logs = _load("network_logs.json")
    src_ports = defaultdict(set)
    src_targets = defaultdict(set)
    src_times = defaultdict(list)

    for l in logs:
        if l.get("event_type") == "port_scan":
            src = l["src_ip"]
            src_ports[src].add(l["port"])
            src_targets[src].add(l["dst_ip"])
            src_times[src].append(l["timestamp"])

    alerts = []
    for src, ports in src_ports.items():
        if len(ports) >= 5:
            severity = "HIGH" if len(ports) >= 10 else "MEDIUM"
            score = min(100, len(ports) * 5)
            alerts.append(_alert("Port Scan Detected", "port_scan", severity, score, {
                "ip": src,
                "ports_scanned": len(ports),
                "targets": list(src_targets[src])[:5],
                "first_seen": src_times[src][0],
                "last_seen": src_times[src][-1],
                "iocs": [src],
                "log_source": "firewall"
            }))
    return alerts

# ── 4. SQL Injection ─────────────────────────────────────────────────────────
def detect_sql_injection():
    logs = _load("web_logs.json")
    ip_count = defaultdict(int)
    ip_payloads = defaultdict(list)
    ip_times = defaultdict(list)

    for l in logs:
        if l.get("event_type") == "sql_injection":
            ip = l["ip"]
            ip_count[ip] += 1
            ip_payloads[ip].append(l.get("payload", ""))
            ip_times[ip].append(l["timestamp"])

    alerts = []
    for ip, count in ip_count.items():
        if count >= 2:
            score = min(100, count * 8 + 20)
            alerts.append(_alert("SQL Injection Attempt", "sql_injection", "HIGH", score, {
                "ip": ip,
                "count": count,
                "sample_payload": ip_payloads[ip][0],
                "target_uri": "/login",
                "first_seen": ip_times[ip][0],
                "last_seen": ip_times[ip][-1],
                "iocs": [ip],
                "log_source": "web_server"
            }))
    return alerts

# ── 5. XSS ──────────────────────────────────────────────────────────────────
def detect_xss():
    logs = _load("web_logs.json")
    ip_count = defaultdict(int)
    ip_times = defaultdict(list)

    for l in logs:
        if l.get("event_type") == "xss_attempt":
            ip_count[l["ip"]] += 1
            ip_times[l["ip"]].append(l["timestamp"])

    alerts = []
    for ip, count in ip_count.items():
        if count >= 2:
            alerts.append(_alert("Cross-Site Scripting (XSS)", "xss", "MEDIUM", min(100, count * 10), {
                "ip": ip,
                "count": count,
                "first_seen": ip_times[ip][0],
                "last_seen": ip_times[ip][-1],
                "iocs": [ip],
                "log_source": "web_server"
            }))
    return alerts

# ── 6. Privilege Escalation ───────────────────────────────────────────────────
def detect_privilege_escalation():
    logs = _load("windows_logs.json")
    host_events = defaultdict(list)

    for l in logs:
        if l.get("event_type") == "privilege_escalation":
            host_events[l["host"]].append(l)

    alerts = []
    for host, events in host_events.items():
        score = min(100, len(events) * 12)
        severity = "CRITICAL" if len(events) >= 5 else "HIGH"
        alerts.append(_alert("Privilege Escalation Detected", "privilege_escalation", severity, score, {
            "ip": events[0].get("ip", ""),
            "host": host,
            "count": len(events),
            "event_ids": list({e["event_id"] for e in events}),
            "processes": list({e["process"] for e in events}),
            "first_seen": events[0]["timestamp"],
            "last_seen": events[-1]["timestamp"],
            "iocs": [events[0].get("ip", ""), host],
            "log_source": "windows_security"
        }))
    return alerts

# ── 7. Data Exfiltration ─────────────────────────────────────────────────────
def detect_data_exfiltration():
    logs = _load("linux_logs.json")
    ip_cmds = defaultdict(list)

    for l in logs:
        if l.get("event_type") == "data_exfiltration":
            ip_cmds[l["ip"]].append(l)

    alerts = []
    for ip, entries in ip_cmds.items():
        alerts.append(_alert("Data Exfiltration Detected", "data_exfiltration", "CRITICAL", 95, {
            "ip": ip,
            "host": entries[0].get("host", ""),
            "count": len(entries),
            "sample_command": entries[0]["command"][:80] + "...",
            "first_seen": entries[0]["timestamp"],
            "last_seen": entries[-1]["timestamp"],
            "iocs": [ip, "45.33.32.156", "evil.com"],
            "log_source": "linux_bash"
        }))
    return alerts

# ── 8. C2 Beaconing ───────────────────────────────────────────────────────────
def detect_c2_beaconing():
    logs = _load("firewall_logs.json")
    src_events = defaultdict(list)

    for l in logs:
        if l.get("event_type") == "c2_beaconing":
            src_events[l["src_ip"]].append(l)

    alerts = []
    for src, events in src_events.items():
        if len(events) >= 5:
            dst_ips = list({e["dst_ip"] for e in events})
            alerts.append(_alert("C2 Beaconing Activity", "c2_beaconing", "CRITICAL", 90, {
                "ip": src,
                "host": events[0].get("host", ""),
                "count": len(events),
                "c2_servers": dst_ips,
                "first_seen": events[0]["timestamp"],
                "last_seen": events[-1]["timestamp"],
                "iocs": [src] + dst_ips,
                "log_source": "firewall"
            }))
    return alerts

# ── Master Runner ─────────────────────────────────────────────────────────────
def run_all_detectors():
    all_alerts = []
    all_alerts.extend(detect_brute_force())
    all_alerts.extend(detect_dns_tunneling())
    all_alerts.extend(detect_port_scan())
    all_alerts.extend(detect_sql_injection())
    all_alerts.extend(detect_xss())
    all_alerts.extend(detect_privilege_escalation())
    all_alerts.extend(detect_data_exfiltration())
    all_alerts.extend(detect_c2_beaconing())

    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    all_alerts.sort(key=lambda a: (order.get(a.get("severity"), 0), a.get("score", 0)), reverse=True)
    return all_alerts

def get_stats(alerts):
    return {
        "total":    len(alerts),
        "critical": sum(1 for a in alerts if a.get("severity") == "CRITICAL"),
        "high":     sum(1 for a in alerts if a.get("severity") == "HIGH"),
        "medium":   sum(1 for a in alerts if a.get("severity") == "MEDIUM"),
        "low":      sum(1 for a in alerts if a.get("severity") == "LOW"),
    }
