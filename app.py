"""
BlueEye SOC Simulator v2 - Flask Application
Routes: /, /investigate/<id>, /iocs, /api/alerts, /api/update/<id>
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, jsonify, request, redirect, url_for
from detection.engine import run_all_detectors, get_stats
from incident_response.manager import enrich_alerts, update_incident, alert_id

app = Flask(__name__, template_folder="dashboard/templates", static_folder="dashboard/static")

def get_alerts():
    alerts = run_all_detectors()
    return enrich_alerts(alerts)

@app.route("/")
def dashboard():
    alerts = get_alerts()
    stats = get_stats(alerts)
    return render_template("dashboard.html", alerts=alerts, stats=stats)

@app.route("/investigate/<incident_id>")
def investigate(incident_id):
    alerts = get_alerts()
    alert = next((a for a in alerts if a.get("incident_id") == incident_id), None)
    if not alert:
        return redirect(url_for("dashboard"))
    return render_template("investigate.html", alert=alert)

@app.route("/iocs")
def iocs():
    alerts = get_alerts()
    # Aggregate all IOCs across alerts
    ioc_map = {}
    for a in alerts:
        for ioc in a.get("iocs", []):
            if ioc not in ioc_map:
                ioc_map[ioc] = {"ioc": ioc, "alerts": [], "severity": a["severity"], "type": _ioc_type(ioc)}
            ioc_map[ioc]["alerts"].append(a["alert"])
    iocs_list = sorted(ioc_map.values(), key=lambda x: len(x["alerts"]), reverse=True)
    return render_template("iocs.html", iocs=iocs_list)

@app.route("/api/alerts")
def api_alerts():
    alerts = get_alerts()
    return jsonify({"alerts": alerts, "stats": get_stats(alerts)})

@app.route("/api/update/<incident_id>", methods=["POST"])
def api_update(incident_id):
    data = request.json or {}
    result = update_incident(
        incident_id,
        status=data.get("status"),
        analyst=data.get("analyst"),
        notes=data.get("notes")
    )
    return jsonify({"ok": True, "incident": result})

def _ioc_type(ioc):
    import re
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ioc):
        return "IP Address"
    if re.match(r"^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$", ioc):
        return "Domain"
    return "Indicator"

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
