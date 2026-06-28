import json
from collections import defaultdict

MITRE_MAPPING = {
    "Port Scan": {
        "technique_id": "T1046",
        "technique": "Network Service Discovery",
        "tactic": "Discovery"
    }
}

def detect_port_scan():
    try:
        with open("logs/network_logs.json") as f:
            logs = json.load(f)
    except FileNotFoundError:
        return []

    src_ports = defaultdict(set)
    src_targets = defaultdict(set)
    src_times = defaultdict(list)

    for log in logs:
        if log["event_type"] == "port_scan":
            src = log["src_ip"]
            src_ports[src].add(log["port"])
            src_targets[src].add(log["dst_ip"])
            src_times[src].append(log["timestamp"])

    alerts = []
    for src_ip, ports in src_ports.items():
        if len(ports) >= 5:
            severity = "HIGH" if len(ports) >= 10 else "MEDIUM"
            score = min(100, len(ports) * 5)
            mitre = MITRE_MAPPING["Port Scan"]
            alerts.append({
                "alert": "Port Scan Detected",
                "ip": src_ip,
                "ports_scanned": len(ports),
                "targets": list(src_targets[src_ip]),
                "severity": severity,
                "score": score,
                "first_seen": src_times[src_ip][0],
                "last_seen": src_times[src_ip][-1],
                "mitre_id": mitre["technique_id"],
                "mitre_technique": mitre["technique"],
                "mitre_tactic": mitre["tactic"],
                "recommendation": "Isolate source IP. Review firewall rules for exposed ports."
            })

    return alerts
