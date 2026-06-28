import json
import random
from datetime import datetime, timedelta

logs = []

ips = ["192.168.1.10", "10.0.0.5", "172.16.0.8", "203.0.113.42"]
users = ["admin", "root", "administrator", "sysadmin", "user"]

base_time = datetime.now() - timedelta(minutes=10)

for i in range(30):
    log = {
        "timestamp": str(base_time + timedelta(seconds=i * 20)),
        "event_type": "failed_login",
        "ip": random.choice(ips),
        "user": random.choice(users),
        "details": "Invalid password",
        "source": "auth"
    }
    logs.append(log)

import os
os.makedirs("logs", exist_ok=True)
with open("logs/auth_logs.json", "w") as f:
    json.dump(logs, f, indent=4)

print(f"[+] Generated {len(logs)} brute force log entries → logs/auth_logs.json")
