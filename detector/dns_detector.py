import json
from collections import defaultdict

MITRE_MAPPING = {
    "DNS Tunneling": {
        "technique_id": "T1071.004",
        "technique": "Application Layer Protocol: DNS",
        "tactic": "Command and Control"
    }
}

def detect_dns():
    try:
        with open("logs/dns_logs.json") as f:
            logs = json.load(f)
    except FileNotFoundError:
        return []

    alerts = []
    ip_query_count = defaultdict(int)

    for log in logs:
        domain = log.get("domain", "")
        subdomain = domain.split(".")[0] if "." in domain else domain
        ip = log.get("ip", "unknown")
        ip_query_count[ip] += 1

        if len(subdomain) > 50:
            score = min(100, len(subdomain) * 1.2)
            mitre = MITRE_MAPPING["DNS Tunneling"]
            alerts.append({
                "alert": "DNS Tunneling Suspected",
                "domain": domain,
                "ip": ip,
                "severity": "MEDIUM",
                "score": int(score),
                "subdomain_length": len(subdomain),
                "timestamp": log.get("timestamp", ""),
                "mitre_id": mitre["technique_id"],
                "mitre_technique": mitre["technique"],
                "mitre_tactic": mitre["tactic"],
                "recommendation": "Inspect DNS traffic. Consider DNS filtering or RPZ policy."
            })

    return alerts
