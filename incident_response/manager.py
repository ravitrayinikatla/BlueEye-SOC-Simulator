"""
BlueEye SOC v2 - Incident Response Manager
Tracks alert status, analyst assignment, and investigation notes
"""
import json
import os
import hashlib
from datetime import datetime

INCIDENT_FILE = "logs/incidents.json"

def _load_incidents():
    if os.path.exists(INCIDENT_FILE):
        with open(INCIDENT_FILE) as f:
            return json.load(f)
    return {}

def _save_incidents(data):
    os.makedirs("logs", exist_ok=True)
    with open(INCIDENT_FILE, "w") as f:
        json.dump(data, f, indent=2)

def alert_id(alert):
    """Stable ID for an alert based on its core fields."""
    key = f"{alert.get('alert')}-{alert.get('ip')}-{alert.get('mitre_id')}"
    return hashlib.md5(key.encode()).hexdigest()[:10].upper()

def enrich_alerts(alerts):
    """Attach incident metadata (status, analyst, notes) to each alert."""
    incidents = _load_incidents()
    enriched = []
    for a in alerts:
        aid = alert_id(a)
        inc = incidents.get(aid, {
            "status": "NEW",
            "analyst": "Unassigned",
            "notes": "",
            "created_at": a.get("first_seen", str(datetime.now())),
            "updated_at": ""
        })
        enriched.append({**a, "incident_id": aid, **inc})
    return enriched

def update_incident(incident_id, status=None, analyst=None, notes=None):
    incidents = _load_incidents()
    if incident_id not in incidents:
        incidents[incident_id] = {}
    if status:
        incidents[incident_id]["status"] = status
    if analyst:
        incidents[incident_id]["analyst"] = analyst
    if notes is not None:
        incidents[incident_id]["notes"] = notes
    incidents[incident_id]["updated_at"] = str(datetime.now())
    _save_incidents(incidents)
    return incidents[incident_id]
