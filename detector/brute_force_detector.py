import json
from collections import defaultdict

MITRE_MAPPING = {
    "Brute Force Attack": {
        "technique_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access"
    }
}

def detect():
    try:
        with open("logs/auth_logs.json") as f:
            logs = json.load(f)
    except FileNotFoundError:
        return []

    ip_count = defaultdict(int)
    ip_users = defaultdict(set)
    ip_times = defaultdict(list)

    for log in logs:
        if log["event_type"] == "failed_login":
            ip = log["ip"]
            ip_count[ip] += 1
            ip_users[ip].add(log.get("user", "unknown"))
            ip_times[ip].append(log["timestamp"])

    alerts = []
    for ip, count in ip_count.items():
        if count >= 5:
            severity = "CRITICAL" if count >= 20 else "HIGH"
            score = min(100, count * 4)
            mitre = MITRE_MAPPING["Brute Force Attack"]
            alerts.append({
                "alert": "Brute Force Attack",
                "ip": ip,
                "count": count,
                "severity": severity,
                "score": score,
                "users_targeted": list(ip_users[ip]),
                "first_seen": ip_times[ip][0],
                "last_seen": ip_times[ip][-1],
                "mitre_id": mitre["technique_id"],
                "mitre_technique": mitre["technique"],
                "mitre_tactic": mitre["tactic"],
                "recommendation": "Block IP immediately. Review account lockout policies."
            })

    return alerts
