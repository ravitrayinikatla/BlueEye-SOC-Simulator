import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detector.brute_force_detector import detect
from detector.dns_detector import detect_dns
from detector.port_scan_detector import detect_port_scan

def run_correlation():
    alerts = []
    alerts.extend(detect())
    alerts.extend(detect_dns())
    alerts.extend(detect_port_scan())

    # Sort by severity score descending
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    alerts.sort(key=lambda a: severity_order.get(a.get("severity", "LOW"), 0), reverse=True)

    return alerts

def get_stats(alerts):
    stats = {
        "total": len(alerts),
        "critical": sum(1 for a in alerts if a.get("severity") == "CRITICAL"),
        "high": sum(1 for a in alerts if a.get("severity") == "HIGH"),
        "medium": sum(1 for a in alerts if a.get("severity") == "MEDIUM"),
        "low": sum(1 for a in alerts if a.get("severity") == "LOW"),
    }
    return stats
