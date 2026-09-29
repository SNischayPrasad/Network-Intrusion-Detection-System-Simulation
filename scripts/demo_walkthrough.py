"""
Automated "virtual simulation" walkthrough (Steps 5–12 of the project guide).

Requires the backend to be running locally:
    uvicorn backend.app:app --port 8000

Then:
    python scripts/demo_walkthrough.py

It sends synthetic flows to YOUR LOCAL API, then plays the role of a SOC
analyst: opens the alert, starts an investigation, adds a note, resolves it,
and downloads the incident report. Only loopback URLs are accepted.
"""

import argparse
import json
import os
import random
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ids.validation import format_timestamp  # noqa: E402
from simulator.traffic_simulator import is_loopback_url  # noqa: E402

SENSOR_KEY = os.getenv("IDS_SENSOR_KEY", "sensor-dev-key-change-me")
ANALYST_KEY = os.getenv("IDS_ANALYST_KEY", "analyst-dev-key-change-me")


class Api:
    def __init__(self, base):
        self.base = base.rstrip("/")

    def call(self, method, path, key, body=None, raw=False):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "X-API-Key": key, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 (loopback only)
                text = resp.read().decode("utf-8")
                return text if raw else json.loads(text)
        except urllib.error.HTTPError as exc:
            raise SystemExit(f"HTTP {exc.code} on {method} {path}: {exc.read().decode()[:300]}")
        except urllib.error.URLError as exc:
            raise SystemExit(f"Backend unreachable at {self.base} ({exc.reason}). "
                             "Start it with: uvicorn backend.app:app --port 8000")


def step(n, title):
    print(f"\n{'=' * 70}\nSTEP {n}: {title}\n{'=' * 70}")


def show(result):
    alert = result.get("alert")
    print(f"  classification : {result['classification']}")
    print(f"  risk score     : {result['risk_score']} ({result['risk_band']})")
    print(f"  signature/anom/ML : {result['signature_score']} / {result['anomaly_score']} / "
          f"{result['ml_score']}")
    for m in result["rule_matches"]:
        print(f"  rule matched   : {m['rule_id']} {m['name']} [{m['severity']}] - {m['evidence']}")
    print(f"  alert          : {alert['alert_id'] + ' ' + alert['severity'] if alert else 'none'}")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--resolution", choices=["RESOLVED", "FALSE_POSITIVE"], default="RESOLVED")
    args = parser.parse_args(argv)
    if not is_loopback_url(args.api):
        parser.error("For safety the demo only talks to a local backend (localhost / 127.0.0.1).")
    api = Api(args.api)
    now = datetime.now(timezone.utc)
    run = random.randint(100, 250)           # vary IPs so the demo can be re-run
    suspect = f"203.0.113.{run}"

    step(5, "Normal HTTPS flow (port 443, normal connection rate, no failures)")
    normal = api.call("POST", "/api/flows", SENSOR_KEY, {
        "timestamp": format_timestamp(now), "source_ip": "192.0.2.15",
        "destination_ip": "198.51.100.20", "source_port": 49152, "destination_port": 443,
        "protocol": "TCP", "packet_count": 18, "byte_count": 12400, "duration_seconds": 2.8,
        "connection_count": 3, "failed_connection_count": 0, "syn_count": 2, "rst_count": 0,
        "label": "NORMAL", "scenario_type": "NORMAL_WEB"})
    show(normal)

    step(6, "Synthetic abnormal record: very high connections + many failures")
    abnormal = api.call("POST", "/api/flows", SENSOR_KEY, {
        "timestamp": format_timestamp(now + timedelta(seconds=1)), "source_ip": suspect,
        "destination_ip": "198.51.100.22", "source_port": 51515, "destination_port": 22,
        "protocol": "TCP", "packet_count": 1600, "byte_count": 128000, "duration_seconds": 20,
        "connection_count": 400, "failed_connection_count": 360, "syn_count": 400,
        "rst_count": 360, "label": "SUSPICIOUS", "scenario_type": "REPEATED_FAILED_CONNECTIONS"})
    show(abnormal)

    step(7, "Multi-port synthetic pattern (one source -> 20 different ports in ~20 s)")
    prober = f"203.0.113.{run + 1}"
    last = None
    for k, port in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993,
                              1433, 3306, 3389, 5432, 5900, 8080, 8443]):
        last = api.call("POST", "/api/flows", SENSOR_KEY, {
            "timestamp": format_timestamp(now + timedelta(seconds=2 + k)), "source_ip": prober,
            "destination_ip": "198.51.100.41", "source_port": 40000 + k, "destination_port": port,
            "protocol": "TCP", "packet_count": 1, "byte_count": 60, "duration_seconds": 0.01,
            "connection_count": 1, "failed_connection_count": 1, "syn_count": 1, "rst_count": 1,
            "label": "SUSPICIOUS", "scenario_type": "MULTI_PORT_PROBING_PATTERN"})
    print("  (showing the result for the 20th record)")
    show(last)

    step(8, "Alert appears in the SOC queue (GET /api/alerts)")
    queue = api.call("GET", "/api/alerts?limit=5", ANALYST_KEY)
    for a in queue["items"]:
        print(f"  {a['created_at']}  {a['alert_id']}  {a['severity']:<8} {a['alert_type']:<32} "
              f"{a['source_ip']:<15} risk={a['risk_score']}  {a['status']}")

    alert_id = abnormal["alert"]["alert_id"]
    step(9, f"Analyst opens alert {alert_id}")
    detail = api.call("GET", f"/api/alerts/{alert_id}", ANALYST_KEY)
    print(f"  type={detail['alert_type']} severity={detail['severity']} risk={detail['risk_score']}")
    print(f"  reason: {detail['reason']}")
    print(f"  candidate ATT&CK (unconfirmed): {detail['mitre_hint']}")
    print("  recommended steps:")
    for s in detail["recommended_steps"][:4]:
        print(f"    - {s}")

    step(10, "Status NEW -> INVESTIGATING")
    upd = api.call("PUT", f"/api/alerts/{alert_id}/status", ANALYST_KEY, {"status": "INVESTIGATING"})
    print(f"  status={upd['status']} investigation_started_at={upd['investigation_started_at']}")

    step(11, "Add analyst note")
    note = api.call("POST", f"/api/alerts/{alert_id}/notes", ANALYST_KEY, {
        "note": "Reviewed synthetic auth logs: 360 failed SSH attempts from an unknown external "
                "source, no successful login. Source not in asset inventory."})
    print(f"  note #{note['note_id']} by {note['analyst']} at {note['created_at']}")

    step(12, f"Close alert as {args.resolution}")
    closed = api.call("PUT", f"/api/alerts/{alert_id}/status", ANALYST_KEY, {
        "status": args.resolution,
        "note": "Confirmed password-guessing pattern (simulated). Recommend blocking source at "
                "perimeter and enforcing key-based SSH. Closing." if args.resolution == "RESOLVED"
        else "Traffic traced to an approved internal load test. Tuning rule scope."})
    print(f"  status={closed['status']} resolved_at={closed['resolved_at']}")
    print("  timeline:")
    for t in closed["timeline"]:
        print(f"    {t['timestamp']}  {t['action']:<15} {t['actor']:<14} {t['details'][:70]}")

    report = api.call("GET", f"/api/alerts/{alert_id}/report", ANALYST_KEY, raw=True)
    out = PROJECT_ROOT / "reports" / "sample_incident_report.md"
    out.write_text(report, encoding="utf-8")
    print(f"\n[+] Incident report saved to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
