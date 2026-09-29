"""
Capture proof screenshots from the REAL running application and REAL command output.

Prerequisites (both running locally):
    uvicorn backend.app:app --port 8000
    cd frontend && npm run dev
    pip install -r requirements-dev.txt        # playwright (uses your installed Edge / Chrome)

Run:
    python scripts/capture_screenshots.py

Terminal-style images are rendered from the actual stdout of the project's
commands (nothing is typed by hand). The script also drives one alert through
NEW -> INVESTIGATING -> RESOLVED in the UI, exactly as an analyst would.
Only localhost URLs are used.
"""

import argparse
import html
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from simulator.traffic_simulator import is_loopback_url  # noqa: E402

OUT = PROJECT_ROOT / "screenshots"
ANALYST_KEY = os.getenv("IDS_ANALYST_KEY", "analyst-dev-key-change-me")
SENSOR_KEY = os.getenv("IDS_SENSOR_KEY", "sensor-dev-key-change-me")
PY = sys.executable
ENV = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}

TERMINAL_CSS = """
body { margin: 0; background: #1f1f1d; padding: 24px; font-family: 'Segoe UI', sans-serif; }
.term { width: 1180px; background: #0c0c0c; border-radius: 10px; overflow: hidden;
        box-shadow: 0 10px 30px rgba(0,0,0,.5); border: 1px solid #333; }
.bar { background: #2b2b29; padding: 9px 14px; display: flex; gap: 8px; align-items: center; }
.dot { width: 12px; height: 12px; border-radius: 50%; display: inline-block; }
.title { color: #c3c2b7; font-size: 13px; margin-left: 10px; }
pre { margin: 0; padding: 16px 18px; color: #e6e6e6; font: 12.5px/1.5 'Cascadia Mono', Consolas, monospace;
      white-space: pre-wrap; word-break: break-all; }
.cmd { color: #6da7ec; } .ok { color: #5fd35f; } .warn { color: #fab219; } .bad { color: #f07b7b; }
table { border-collapse: collapse; margin: 14px 18px 18px; font: 12px 'Cascadia Mono', Consolas, monospace; }
th, td { border: 1px solid #333; padding: 4px 8px; color: #e6e6e6; text-align: left; white-space: nowrap; }
th { color: #86b6ef; background: #161616; }
"""


def run(cmd, timeout=300):
    proc = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True, env=ENV,
                          timeout=timeout, encoding="utf-8", errors="replace")
    return (proc.stdout + proc.stderr).strip()


def colorize(text):
    out = html.escape(text)
    for word, cls in (("PASSED", "ok"), ("passed", "ok"), ("NORMAL ", "ok"), ("SUSPICIOUS", "warn"),
                      ("POTENTIAL_INTRUSION", "bad"), ("CRITICAL", "bad"), ("FAILED", "bad")):
        out = out.replace(word, f'<span class="{cls}">{word}</span>')
    return out


def terminal(page, title, command, body_html, path):
    page.set_content(f"""<html><head><style>{TERMINAL_CSS}</style></head><body>
      <div class="term"><div class="bar"><span class="dot" style="background:#ff5f57"></span>
      <span class="dot" style="background:#febc2e"></span><span class="dot" style="background:#28c840"></span>
      <span class="title">{html.escape(title)}</span></div>
      <pre><span class="cmd">PS Network-IDS-Simulation&gt; {html.escape(command)}</span>\n{body_html}</pre></div>
      </body></html>""")
    page.locator(".term").screenshot(path=str(path))
    print(f"  [+] {path.name}")


def table_terminal(page, title, command, headers, rows, path, note=""):
    head = "".join(f"<th>{html.escape(str(h))}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in r) + "</tr>" for r in rows)
    page.set_content(f"""<html><head><style>{TERMINAL_CSS}</style></head><body>
      <div class="term"><div class="bar"><span class="dot" style="background:#ff5f57"></span>
      <span class="dot" style="background:#febc2e"></span><span class="dot" style="background:#28c840"></span>
      <span class="title">{html.escape(title)}</span></div>
      <pre><span class="cmd">PS Network-IDS-Simulation&gt; {html.escape(command)}</span>{html.escape(note)}</pre>
      <table><tr>{head}</tr>{body}</table></div></body></html>""")
    page.locator(".term").screenshot(path=str(path))
    print(f"  [+] {path.name}")


def api(method, url, key, body=None):
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body else None,
                                 headers={"X-API-Key": key, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310 (loopback only)
        return json.loads(r.read().decode())


def tree_listing():
    skip = {".venv", "node_modules", "__pycache__", ".pytest_cache", "dist", ".git", ".claude"}
    lines = ["Network-IDS-Simulation/"]
    for top in sorted(PROJECT_ROOT.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
        if top.name in skip or top.name.startswith(".") and top.name not in (".env.example", ".gitignore"):
            continue
        if top.is_dir():
            lines.append(f"├── {top.name}/")
            children = [c for c in sorted(top.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
                        if c.name not in skip and not c.name.endswith((".db", ".db-wal", ".db-shm", ".joblib"))
                        and c.name != ".gitkeep"]
            if top.name in ("screenshots", "reports"):
                children = [c for c in children if c.is_dir() or c.suffix == ".md"]
            for c in children[:14]:
                lines.append(f"│   ├── {c.name}{'/' if c.is_dir() else ''}")
            if len(children) > 14:
                lines.append(f"│   └── … {len(children) - 14} more")
        else:
            lines.append(f"├── {top.name}")
    return "\n".join(lines)


ARCH_HTML = """<html><head><style>
body{margin:0;background:#111110;font-family:'Segoe UI',sans-serif;color:#fff;padding:28px}
.wrap{width:1080px;display:flex;flex-direction:column;align-items:center;gap:10px}
h1{font-size:22px;margin:0 0 4px} p{color:#8a8983;margin:0 0 12px;font-size:13px}
.box{background:#1a1a19;border:1px solid #2e2e2b;border-left:4px solid #3987e5;border-radius:10px;
     padding:10px 16px;width:520px;text-align:center}
.box b{display:block;font-size:15px}.box span{color:#8a8983;font-size:12px}
.row{display:flex;gap:14px}.row .box{width:250px;border-left-color:#d95926}
.arrow{color:#5598e7;font-size:20px;line-height:1}
.analyst{border-left-color:#0ca30c}.db{border-left-color:#c98500}
</style></head><body><div class="wrap">
<h1>Network IDS Simulation — Hybrid Detection Architecture</h1>
<p>Synthetic data only · RFC 5737 addresses · defensive education</p>
<div class="box"><b>Synthetic Traffic Generator / Real-time Simulator</b><span>simulator/ · JSON flow records, never packets · loopback-only POST</span></div>
<div class="arrow">▼</div>
<div class="box"><b>Flow Collector + Validation</b><span>POST /api/flows · sensor key · IP / port / protocol checks · duplicate protection</span></div>
<div class="arrow">▼</div>
<div class="box"><b>Feature Extractor</b><span>15 features · rates, ratios · 60 s per-source port/IP window</span></div>
<div class="arrow">▼</div>
<div class="row">
 <div class="box"><b>Rule Engine</b><span>IDS-001 … IDS-006<br>configurable thresholds</span></div>
 <div class="box"><b>Anomaly Detector</b><span>log-scale Z-score + IQR<br>normal baseline</span></div>
 <div class="box"><b>ML Model (optional)</b><span>Random Forest probability<br>LR / Isolation Forest compared</span></div>
</div>
<div class="arrow">▼</div>
<div class="box"><b>Risk Engine</b><span>0.4 rules + 0.3 anomaly + 0.3 ML (0.6 / 0.4 without ML) + evidence floors → 0–100</span></div>
<div class="arrow">▼</div>
<div class="box"><b>Alert Engine + Correlation</b><span>severity · reason · playbook · ATT&amp;CK candidate · incidents (source + type + 60 s)</span></div>
<div class="arrow">▼</div>
<div class="box db"><b>Security Database (SQLite) → SIEM JSONL</b><span>flows · alerts · incidents · rules · notes · model results · audit log</span></div>
<div class="arrow">▼</div>
<div class="box"><b>REST API + SOC Dashboard</b><span>FastAPI (RBAC, rate limit) · React console, 5 s polling</span></div>
<div class="arrow">▼</div>
<div class="box analyst"><b>SOC Analyst</b><span>triage → investigate → notes → resolve / false positive → report</span></div>
</div></body></html>"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ui", default="http://localhost:5173")
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--browser-channel", default="msedge", help="msedge or chrome")
    args = parser.parse_args()
    if not (is_loopback_url(args.ui) and is_loopback_url(args.api)):
        parser.error("Only localhost URLs are allowed.")

    from playwright.sync_api import sync_playwright

    OUT.mkdir(exist_ok=True)
    print("[*] Collecting command output ...")
    sim_out = run([PY, "-m", "simulator.traffic_simulator", "--mode", "mixed", "--count", "14",
                   "--interval", "0", "--seed", "11", "--suspicious-ratio", "0.3"])
    demo_out = run([PY, "scripts/demo_walkthrough.py"])
    feat_out = run([PY, "-c", (
        "import json; from ids.feature_extractor import extract_network_features as f;"
        "flow={'source_ip':'203.0.113.160','destination_ip':'198.51.100.22','source_port':50000,"
        "'destination_port':22,'protocol':'TCP','packet_count':300,'byte_count':24000,"
        "'duration_seconds':60,'connection_count':70,'failed_connection_count':60,'syn_count':70,'rst_count':60};"
        "print(json.dumps(f(flow), indent=2))")])
    test_out = run([PY, "-m", "pytest", "-v", "-p", "no:warnings", "-p", "no:cacheprovider"])
    api_resp = api("POST", f"{args.api}/api/flows", SENSOR_KEY, {
        "source_ip": "203.0.113.199", "destination_ip": "198.51.100.12", "source_port": 51000,
        "destination_port": 443, "protocol": "TCP", "packet_count": 2600, "byte_count": 210000,
        "duration_seconds": 12, "connection_count": 520, "failed_connection_count": 30,
        "syn_count": 520, "rst_count": 30, "label": "SUSPICIOUS", "scenario_type": "HIGH_CONNECTION_RATE"})

    with sync_playwright() as p:
        browser = p.chromium.launch(channel=args.browser_channel, headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 900})

        print("[*] Rendering terminal / document captures ...")
        terminal(page, "Project structure", "tree /F (filtered)", html.escape(tree_listing()),
                 OUT / "01_project_folder_structure.png")
        page.set_content(ARCH_HTML)
        page.locator(".wrap").screenshot(path=str(OUT / "02_ids_architecture_diagram.png"))
        print("  [+] 02_ids_architecture_diagram.png")
        csv_lines = (PROJECT_ROOT / "data" / "network_traffic.csv").read_text(encoding="utf-8").splitlines()
        header = csv_lines[0].split(",")
        rows = [ln.split(",") for ln in csv_lines[1:]]
        pick = rows[:6] + [r for r in rows if r[-2] == "SUSPICIOUS"][:6]
        table_terminal(page, "Synthetic dataset — data/network_traffic.csv",
                       "python -m simulator.generate_dataset", header, pick,
                       OUT / "03_synthetic_dataset_preview.png",
                       note=f"\n[+] {len(rows)} synthetic flow records (6 normal rows + 6 suspicious rows shown)")
        terminal(page, "Traffic simulator (synthetic JSON only)",
                 "python -m simulator.traffic_simulator --mode mixed --count 14", colorize(sim_out),
                 OUT / "04_traffic_simulator_terminal.png")
        steps = demo_out.split("=" * 70)
        step5 = "".join(steps[1:3])
        step67 = "".join(steps[3:7])
        terminal(page, "Walkthrough step 5 — normal HTTPS flow", "python scripts/demo_walkthrough.py",
                 colorize(step5), OUT / "05_normal_traffic_detection.png")
        terminal(page, "Walkthrough steps 6–7 — suspicious synthetic patterns",
                 "python scripts/demo_walkthrough.py", colorize(step67),
                 OUT / "06_suspicious_traffic_detection.png")
        terminal(page, "Feature extraction", "python -c \"extract_network_features(flow)\"",
                 html.escape(feat_out), OUT / "07_feature_extraction_output.png")
        terminal(page, "Automated tests", "python -m pytest -v", colorize(test_out),
                 OUT / "22_automated_tests_passing.png")
        terminal(page, "REST API response", "POST /api/flows  (X-API-Key: sensor)",
                 colorize(json.dumps(api_resp, indent=2)), OUT / "23_api_response.png")
        conn = sqlite3.connect(PROJECT_ROOT / "data" / "ids.db")
        counts = {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in (
            "network_flows", "alerts", "incidents", "rules", "incident_notes", "model_results", "audit_log")}
        db_rows = conn.execute(
            "SELECT alert_id, flow_id, incident_id, rule_id, severity, risk_score, status, source_ip, "
            "created_at FROM alerts ORDER BY created_at DESC LIMIT 12").fetchall()
        conn.close()
        table_terminal(page, "SQLite security database — data/ids.db",
                       "SELECT … FROM alerts ORDER BY created_at DESC LIMIT 12",
                       ["alert_id", "flow_id", "incident_id", "rule_id", "severity", "risk", "status",
                        "source_ip", "created_at"], db_rows, OUT / "24_database_records.png",
                       note="\n" + "  ".join(f"{k}={v:,}" for k, v in counts.items()))
        shutil.copy(PROJECT_ROOT / "reports" / "figures" / "detector_comparison.png",
                    OUT / "20_ml_model_evaluation.png")
        shutil.copy(PROJECT_ROOT / "reports" / "figures" / "confusion_matrix_random_forest.png",
                    OUT / "21_confusion_matrix.png")
        print("  [+] 20_ml_model_evaluation.png, 21_confusion_matrix.png")

        print("[*] Capturing the live dashboard ...")
        page.goto(args.ui)
        page.fill("#apikey", ANALYST_KEY)
        page.click("button[type=submit]")
        page.wait_for_selector("text=Security Overview")
        page.wait_for_function("document.querySelectorAll('.recharts-surface').length >= 8", timeout=20000)
        page.wait_for_timeout(1500)
        page.screenshot(path=str(OUT / "12_soc_dashboard_overview.png"), full_page=True)
        print("  [+] 12_soc_dashboard_overview.png")

        def card(title, name):
            page.locator("section.card").filter(has=page.locator("h3", has_text=title)).first \
                .screenshot(path=str(OUT / name))
            print(f"  [+] {name}")

        card("Traffic over time", "13_traffic_over_time_chart.png")
        card("Protocol distribution", "14_protocol_distribution_chart.png")
        card("Alerts by severity", "15_alerts_by_severity_chart.png")
        card("Top alert types", "16_top_alert_types_chart.png")

        page.goto(f"{args.ui}/alerts")
        page.wait_for_selector("table tbody tr")
        page.wait_for_timeout(800)
        page.screenshot(path=str(OUT / "11_alert_queue_generated_alerts.png"))
        print("  [+] 11_alert_queue_generated_alerts.png")

        page.goto(f"{args.ui}/traffic")
        page.wait_for_function("document.querySelectorAll('.recharts-surface').length >= 8", timeout=20000)
        page.wait_for_timeout(1200)
        page.screenshot(path=str(OUT / "28_traffic_analytics_page.png"), full_page=True)
        print("  [+] 28_traffic_analytics_page.png")

        page.goto(f"{args.ui}/incidents")
        page.wait_for_selector("table tbody tr")
        page.locator("table tbody tr.clickable").nth(0).click()
        page.wait_for_timeout(1200)
        page.screenshot(path=str(OUT / "29_correlated_incidents.png"))
        print("  [+] 29_correlated_incidents.png")

        print("[*] Driving an alert through the analyst workflow ...")
        alerts = api("GET", f"{args.api}/api/alerts?severity=CRITICAL&status=NEW&limit=100", ANALYST_KEY)["items"]
        target = next((a for a in alerts if a["alert_type"] == "Repeated Failed Connections"), alerts[0])
        page.goto(f"{args.ui}/alerts/{target['alert_id']}")
        page.wait_for_selector("text=Why this alert fired")
        page.wait_for_timeout(600)
        page.screenshot(path=str(OUT / "17_alert_investigation_page.png"), full_page=True)
        print("  [+] 17_alert_investigation_page.png")
        card("Why this alert fired", "08_signature_rule_triggered.png")
        card("Anomaly analysis", "09_anomaly_score_breakdown.png")
        card("Hybrid risk breakdown", "10_hybrid_risk_score.png")

        page.get_by_role("button", name="Start investigation").click()
        page.wait_for_selector(".status-investigating")
        page.get_by_placeholder("Add an investigation note").fill(
            "Checked asset inventory: source is not a known asset or approved scanner. Reviewing "
            "synthetic auth logs for any successful login after the failures.")
        page.get_by_role("button", name="Add note").click()
        page.wait_for_selector(".notes li")
        card("Analyst notes", "18_analyst_notes.png")
        page.get_by_role("button", name="Resolve").click()
        page.get_by_placeholder("What was found").fill(
            "No successful login found. Pattern consistent with password guessing (simulated). "
            "Recommend perimeter block and key-only SSH. Closing.")
        page.get_by_role("button", name="Confirm").click()
        page.wait_for_selector(".status-resolved")
        page.wait_for_timeout(500)
        card("Incident timeline", "19_incident_status_workflow.png")

        page.goto(f"{args.api}/docs")
        page.wait_for_selector(".swagger-ui .opblock", timeout=20000)
        page.wait_for_timeout(800)
        page.screenshot(path=str(OUT / "30_api_docs_swagger.png"))
        print("  [+] 30_api_docs_swagger.png")
        browser.close()

    print(f"\n[+] Screenshots written to {OUT}")
    print("    Still manual after pushing to GitHub: 25_github_commit_history.png, "
          "26_github_repository_page.png, 27_readme_preview.png")


if __name__ == "__main__":
    main()
