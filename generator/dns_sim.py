import json
import random
import string
from datetime import datetime, timedelta

logs = []

base_time = datetime.now() - timedelta(minutes=8)

for i in range(40):
    # Simulate DNS tunneling: long, random-looking subdomains
    subdomain_len = random.randint(20, 80)
    subdomain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=subdomain_len))
    domain = f"{subdomain}.example.com"

    log = {
        "timestamp": str(base_time + timedelta(seconds=i * 12)),
        "event_type": "dns_query",
        "domain": domain,
        "ip": "192.168.1.20",
        "query_type": "TXT",
        "details": f"Unusual subdomain length: {len(subdomain)}"
    }
    logs.append(log)

import os
os.makedirs("logs", exist_ok=True)
with open("logs/dns_logs.json", "w") as f:
    json.dump(logs, f, indent=4)

print(f"[+] Generated {len(logs)} DNS tunneling log entries → logs/dns_logs.json")
