import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, jsonify
from core.correlation import run_correlation, get_stats

app = Flask(__name__)

@app.route("/")
def home():
    alerts = run_correlation()
    stats = get_stats(alerts)
    return render_template("dashboard.html", alerts=alerts, stats=stats)

@app.route("/api/alerts")
def api_alerts():
    alerts = run_correlation()
    stats = get_stats(alerts)
    return jsonify({"alerts": alerts, "stats": stats})

if __name__ == "__main__":
    app.run(debug=True)
