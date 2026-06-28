import json
import random
from datetime import datetime, timedelta

logs = []

attacker_ips = ["10.10.10.99", "45.33.32.156"]
target_ip = "192.168.1.100"
common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]

base_time = datetime.now() - timedelta(minutes=5)

for i, port in enumerate(common_ports * 2):
    log = {
        "timestamp": str(base_time + timedelta(seconds=i * 3)),
        "event_type": "port_scan",
        "src_ip": random.choice(attacker_ips),
        "dst_ip": target_ip,
        "port": port,
        "protocol": "TCP",
        "details": f"SYN probe on port {port}"
    }
    logs.append(log)

import os
os.makedirs("logs", exist_ok=True)
with open("logs/network_logs.json", "w") as f:
    json.dump(logs, f, indent=4)

print(f"[+] Generated {len(logs)} port scan log entries → logs/network_logs.json")
