"""
Build social-media carousel slides (1080x1350, 4:5 portrait) from the REAL app.

The script logs in to the locally running dashboard, captures crisp 2x
element screenshots, and composes 10 slides that work for both an Instagram
carousel and a LinkedIn document (PDF) carousel.

Prerequisites: backend on :8000, dashboard on :5173, `pip install -r requirements-dev.txt`
Run:           python scripts/make_social_posts.py
Output:        social/slides/slide_01.png … slide_10.png, social/linkedin_carousel.pdf
"""

import base64
import json
import os
import sys
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUT = PROJECT_ROOT / "social"
ASSETS = OUT / "assets"
SLIDES = OUT / "slides"
UI, API = "http://localhost:5173", "http://127.0.0.1:8000"
ANALYST_KEY = os.getenv("IDS_ANALYST_KEY", "analyst-dev-key-change-me")
TOTAL = 10


def api(path):
    req = urllib.request.Request(API + path, headers={"X-API-Key": ANALYST_KEY})
    with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310 (localhost only)
        return json.loads(r.read().decode())


def data_uri(path):
    return "data:image/png;base64," + base64.b64encode(Path(path).read_bytes()).decode()


# --------------------------------------------------------------------------- capture
def capture_assets(p):
    ASSETS.mkdir(parents=True, exist_ok=True)
    browser = p.chromium.launch(channel="msedge", headless=True)
    page = browser.new_page(viewport={"width": 1440, "height": 900}, device_scale_factor=2)
    page.goto(UI)
    page.fill("#apikey", ANALYST_KEY)
    page.click("button[type=submit]")
    page.wait_for_selector("text=Security Overview")
    page.wait_for_function("document.querySelectorAll('.recharts-surface').length >= 8", timeout=20000)
    page.wait_for_timeout(1500)
    page.screenshot(path=str(ASSETS / "dashboard_top.png"), clip={"x": 0, "y": 0, "width": 1440, "height": 900})
    page.locator(".stat-grid").screenshot(path=str(ASSETS / "kpis.png"))

    def card(title, name):
        page.locator("section.card").filter(has=page.locator("h3", has_text=title)).first \
            .screenshot(path=str(ASSETS / name))

    card("Traffic over time", "traffic_chart.png")
    card("Alerts by severity", "severity_chart.png")

    resolved = api("/api/alerts?status=RESOLVED&limit=20")["items"]
    target = next((a for a in resolved if a["alert_type"] == "Repeated Failed Connections"), resolved[0])
    page.goto(f"{UI}/alerts/{target['alert_id']}")
    page.wait_for_selector("text=Why this alert fired")
    page.wait_for_timeout(800)
    page.screenshot(path=str(ASSETS / "investigation_top.png"), clip={"x": 232, "y": 60, "width": 1208, "height": 780})
    card("Why this alert fired", "why_fired.png")
    card("Anomaly analysis", "anomaly.png")
    card("Hybrid risk breakdown", "risk.png")
    card("Incident timeline", "timeline.png")

    page.goto(f"{UI}/incidents")
    page.wait_for_selector("table tbody tr")
    page.wait_for_timeout(800)
    page.screenshot(path=str(ASSETS / "incidents.png"), clip={"x": 232, "y": 60, "width": 1208, "height": 620})
    browser.close()


# --------------------------------------------------------------------------- slides
CSS = """
*{box-sizing:border-box} html,body{margin:0}
body{width:1080px;height:1350px;background:#111110;color:#fff;font-family:'Segoe UI',Inter,sans-serif;
  position:relative;overflow:hidden}
body::before{content:"";position:absolute;inset:0;background:radial-gradient(ellipse 900px 600px at 85% -10%,
  rgba(57,135,229,.22),transparent 70%)}
.s{position:relative;height:100%;padding:64px 68px 56px;display:flex;flex-direction:column;gap:26px}
.s>*{flex:none}
.top{display:flex;justify-content:space-between;align-items:center;color:#8a8983;font-size:22px;font-weight:600}
.brand{display:flex;align-items:center;gap:12px;color:#c3c2b7}
.kicker{color:#5598e7;font-size:24px;font-weight:700;letter-spacing:.12em;text-transform:uppercase}
h1{font-size:74px;line-height:1.04;margin:0;font-weight:800;letter-spacing:-.02em}
h2{font-size:60px;line-height:1.08;margin:0;font-weight:800;letter-spacing:-.015em}
.hl{color:#6da7ec}.or{color:#ec835a}.gr{color:#5fd35f}
p.lead{font-size:30px;line-height:1.4;color:#c3c2b7;margin:0}
.shot{border-radius:18px;overflow:hidden;border:1px solid #2e2e2b;box-shadow:0 24px 60px rgba(0,0,0,.55);background:#1a1a19}
.shot img{display:block;width:100%}
.chips{display:flex;flex-wrap:wrap;gap:12px}
.chip{border:1.5px solid #3a3a36;border-radius:999px;padding:9px 20px;font-size:23px;color:#e6e6e6;background:#1a1a19}
.foot{margin-top:auto;display:flex;justify-content:space-between;align-items:center;color:#8a8983;font-size:22px}
.swipe{color:#fff;font-weight:700}
.cards{display:grid;gap:18px}
.card{background:#1a1a19;border:1px solid #2e2e2b;border-radius:18px;padding:26px 30px}
.card h3{margin:0 0 8px;font-size:32px}.card p{margin:0;font-size:25px;line-height:1.4;color:#c3c2b7}
.bar{border-left:6px solid #3987e5}.bar.o{border-left-color:#d95926}.bar.a{border-left-color:#199e70}
.bar.r{border-left-color:#d03b3b}.bar.y{border-left-color:#fab219}.bar.g{border-left-color:#0ca30c}
.flow{display:flex;flex-direction:column;gap:12px}
.step{display:flex;gap:22px;align-items:center;background:#1a1a19;border:1px solid #2e2e2b;border-radius:16px;padding:18px 24px}
.num{flex:none;width:54px;height:54px;border-radius:50%;background:#2a78d6;display:grid;place-items:center;font-size:26px;font-weight:800}
.step b{font-size:29px;display:block}.step span{font-size:23px;color:#a9a89f}
.arrow{color:#5598e7;text-align:center;font-size:22px;line-height:.6}
.metric{display:grid;grid-template-columns:330px 1fr 120px;align-items:center;gap:18px;font-size:27px;margin:14px 0}
.track{height:34px;background:#262624;border-radius:8px;overflow:hidden}.track i{display:block;height:100%;border-radius:8px}
.big{font-size:120px;font-weight:800;line-height:1;letter-spacing:-.03em}
.row{display:flex;gap:18px}.row>*{flex:1}
ul.clean{margin:0;padding:0;list-style:none;display:flex;flex-direction:column;gap:14px}
ul.clean li{font-size:27px;color:#d6d5cc;padding-left:40px;position:relative;line-height:1.35}
ul.clean li::before{content:"✓";position:absolute;left:0;color:#5fd35f;font-weight:800}
.flowchips{display:flex;align-items:center;gap:14px;font-size:26px;font-weight:700}
.st{padding:10px 20px;border-radius:12px}
"""

LOGO = """<svg viewBox="0 0 32 32" width="34" height="34"><path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15
6.9-1.6 12-7.5 12-15V7z" fill="#3987e5"/><path d="M10 16h3l2-4 3 8 2-4h2" stroke="#fff" stroke-width="2"
fill="none" stroke-linecap="round"/></svg>"""


def frame(n, body, foot_left="Synthetic data only · defensive education"):
    swipe = '<span class="swipe">Swipe →</span>' if n < TOTAL else '<span class="swipe">Link in comments ↓</span>'
    return f"""<html><head><style>{CSS}</style></head><body><div class="s">
      <div class="top"><div class="brand">{LOGO} Network IDS Simulation</div><div>{n:02d} / {TOTAL}</div></div>
      {body}
      <div class="foot"><span>{foot_left}</span>{swipe}</div></div></body></html>"""


def slides(img):
    return [
        # 1 — cover
        f"""<div class="kicker">Cybersecurity project</div>
        <h1>I built a <span class="hl">Network Intrusion Detection System</span> simulation</h1>
        <p class="lead">Hybrid detection · live SOC dashboard · full incident workflow</p>
        <div class="shot"><img src="{img('dashboard_top')}"></div>
        <div class="chips"><span class="chip">Python</span><span class="chip">FastAPI</span>
        <span class="chip">React</span><span class="chip">scikit-learn</span><span class="chip">SQLite</span>
        <span class="chip">37 tests ✓</span></div>""",
        # 2 — pipeline
        """<div class="kicker">How it works</div><h2>From raw traffic to a <span class="hl">closed incident</span></h2>
        <div class="flow">
          <div class="step"><div class="num">1</div><div><b>Synthetic traffic</b><span>6,019 labelled flows · documentation-only IPs · no real packets</span></div></div>
          <div class="step"><div class="num">2</div><div><b>Feature engineering</b><span>15 features: rates, failure &amp; SYN ratios, 60 s port diversity</span></div></div>
          <div class="step"><div class="num">3</div><div><b>3 detection layers</b><span>6 signature rules · statistical anomaly · Random Forest</span></div></div>
          <div class="step"><div class="num">4</div><div><b>Hybrid risk score 0–100</b><span>weighted fusion → NORMAL / SUSPICIOUS / POTENTIAL INTRUSION</span></div></div>
          <div class="step"><div class="num">5</div><div><b>Alerts → incidents</b><span>evidence, playbooks, correlation by source + type + 60 s</span></div></div>
          <div class="step"><div class="num">6</div><div><b>SOC analyst workflow</b><span>triage → investigate → notes → resolve / false positive</span></div></div>
        </div>""",
        # 3 — dashboard
        f"""<div class="kicker">The SOC console</div><h2>24 hours of traffic, <span class="hl">at a glance</span></h2>
        <div class="shot"><img src="{img('kpis')}"></div>
        <div class="shot"><img src="{img('traffic_chart')}"></div>
        <div class="card bar o"><p>Normal (blue) vs suspicious (orange) flows over a simulated business day.
        KPIs, 8 charts and the alert queue refresh every 5 seconds.</p></div>""",
        # 4 — detection layers
        """<div class="kicker">Detection engine</div><h2>Three layers, <span class="hl">one risk score</span></h2>
        <div class="cards">
          <div class="card bar"><h3>① Signature rules</h3><p>High connection rate · repeated failed connections · multi-port probing ·
          SYN-heavy behaviour · watch-listed ports · abnormal volume. Thresholds are tunable and every change is audited.</p></div>
          <div class="card bar o"><h3>② Statistical anomaly detection</h3><p>Learns “normal” from clean traffic, then scores deviation with
          log-scale Z-scores confirmed by the IQR rule.</p></div>
          <div class="card bar a"><h3>③ Machine learning (optional)</h3><p>Random Forest vs Logistic Regression vs Isolation Forest,
          evaluated on a held-out test set.</p></div>
          <div class="card bar y"><h3>= Hybrid risk (0–100)</h3><p>40% rules · 30% anomaly · 30% ML, with safety floors so strong evidence is never averaged away.</p></div>
        </div>""",
        # 5 — explainability
        f"""<div class="kicker">Explainable alerts</div><h2>Every alert says <span class="hl">why</span> it fired</h2>
        <div class="shot" style="width:840px;align-self:center"><img src="{img('why_fired')}"></div>
        <div class="shot" style="width:840px;align-self:center"><img src="{img('anomaly')}"></div>""",
        # 6 — results
        """<div class="kicker">Results · measured, not guessed</div><h2>Hybrid detection <span class="gr">caught 99.6%</span></h2>
        <p class="lead">Recall on a 1,505-flow held-out test set (275 suspicious flows)</p>
        <div class="card">
          <div class="metric"><span>Rules only</span><div class="track"><i style="width:85.5%;background:#3987e5"></i></div><b>0.855</b></div>
          <div class="metric"><span>Anomaly only</span><div class="track"><i style="width:67.6%;background:#3987e5"></i></div><b>0.676</b></div>
          <div class="metric"><span>Rules + anomaly</span><div class="track"><i style="width:97.1%;background:#3987e5"></i></div><b>0.971</b></div>
          <div class="metric"><span><b>+ ML (full hybrid)</b></span><div class="track"><i style="width:99.6%;background:#5fd35f"></i></div><b>0.996</b></div>
        </div>
        <div class="row">
          <div class="card"><div class="big">40 → 1</div><p>missed suspicious flows (rules only → full hybrid)</p></div>
          <div class="card"><div class="big or">4.0%</div><p>false-positive rate: the price of higher recall (rules only: 1.8%)</p></div>
        </div>
        <div class="card bar a"><h3>Best ML model: Random Forest</h3><p>Precision 0.865 · Recall 0.975 · F1 0.916 · ROC-AUC 0.996</p></div>
        <p class="lead" style="font-size:24px;color:#8a8983">Synthetic data makes absolute scores optimistic. The comparison between
        layers is the real result.</p>""",
        # 7 — lessons
        """<div class="kicker">What surprised me</div><h2>The best lessons came from <span class="or">what went wrong</span></h2>
        <div class="cards">
          <div class="card bar r"><h3>My first formula made the hybrid worse</h3><p>Averaging diluted rule matches:
          recall dropped to 0.676, below rules alone (0.855). Measuring it exposed the bug, and evidence-based risk floors fixed it.</p></div>
          <div class="card bar y"><h3>Backups look like data theft</h3><p>81.5% of legitimate nightly backups were flagged by the
          high-volume rule. Detection needs <b>context</b> (asset lists, schedules), not just lower thresholds.</p></div>
          <div class="card bar"><h3>Accuracy lies</h3><p>Always answering “normal” scores 81.7% accuracy and catches nothing.
          Precision, recall and false-positive rate tell the real story.</p></div>
        </div>""",
        # 8 — workflow
        f"""<div class="kicker">Incident response</div><h2>Built for the <span class="hl">analyst</span></h2>
        <div class="flowchips"><span class="st" style="background:rgba(57,135,229,.2);color:#86b6ef">NEW</span>→
        <span class="st" style="background:rgba(250,178,25,.18);color:#fab219">INVESTIGATING</span>→
        <span class="st" style="background:rgba(12,163,12,.2);color:#5fd35f">RESOLVED</span>/
        <span class="st" style="background:rgba(138,137,131,.2);color:#c3c2b7">FALSE POSITIVE</span></div>
        <div class="shot"><img src="{img('timeline')}"></div>
        <div class="row">
          <div class="card"><div class="big" style="font-size:88px">64%</div><p>fewer items to triage: correlation grouped 562 alerts into 200 incidents</p></div>
          <div class="card"><h3>Every action is audited</h3><p>Closing an alert requires a written reason, and a Markdown incident report is one click away.</p></div>
        </div>""",
        # 9 — engineering
        f"""<div class="kicker">Engineered like a real tool</div><h2>Secure, tested, <span class="hl">reproducible</span></h2>
        <div class="row">
          <div class="card"><ul class="clean"><li>Role-based access (sensor / analyst / admin)</li><li>Input validation + parameterised SQL</li>
          <li>Rate limiting + security headers</li><li>Append-only audit log</li><li>Secrets in .env, never in code</li></ul></div>
          <div class="card"><div class="big gr">37/37</div><p>automated tests passing: detection, API, workflow, security</p>
          <div class="big" style="font-size:84px;margin-top:22px">~840/s</div><p>flows through the full pipeline incl. database</p></div>
        </div>
        <div class="card bar"><h3>Detection-as-code</h3><p>Every threshold is data: editable by admins, validated, hot-reloaded and written to the audit log.</p></div>
        <div class="chips"><span class="chip">Python</span><span class="chip">FastAPI</span><span class="chip">SQLite</span>
        <span class="chip">React</span><span class="chip">Recharts</span><span class="chip">scikit-learn</span><span class="chip">pytest</span></div>""",
        # 10 — ethics + CTA
        """<div class="kicker">Safe by design</div><h2>Defensive only: <span class="hl">zero real attack traffic</span></h2>
        <div class="card"><ul class="clean"><li>100% synthetic flow records, no real networks touched</li>
          <li>Only RFC 5737 documentation IP ranges</li><li>No scanning, exploits or packet generation</li>
          <li>The simulator refuses to send data anywhere except localhost</li><li>IDS (alert), not IPS (block): humans decide</li></ul></div>
        <div class="card bar"><h3>Full source code, docs &amp; project report</h3><p>README · architecture · API reference · test results ·
          model evaluation · interview notes. Link in the comments.</p></div>
        <div class="chips"><span class="chip">#cybersecurity</span><span class="chip">#SOC</span><span class="chip">#blueteam</span>
        <span class="chip">#intrusiondetection</span><span class="chip">#python</span></div>""",
    ]


def main():
    from PIL import Image
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        print("[*] Capturing 2x assets from the running app ...")
        capture_assets(p)
        cache = {}

        def img(name):
            if name not in cache:
                cache[name] = data_uri(ASSETS / f"{name}.png")
            return cache[name]

        SLIDES.mkdir(parents=True, exist_ok=True)
        browser = p.chromium.launch(channel="msedge", headless=True)
        page = browser.new_page(viewport={"width": 1080, "height": 1350}, device_scale_factor=1)
        paths = []
        for n, body in enumerate(slides(img), start=1):
            page.set_content(frame(n, body))
            page.wait_for_timeout(300)
            path = SLIDES / f"slide_{n:02d}.png"
            page.screenshot(path=str(path))
            paths.append(path)
            print(f"  [+] {path.relative_to(PROJECT_ROOT)}")
        browser.close()

    images = [Image.open(pth).convert("RGB") for pth in paths]
    pdf = OUT / "linkedin_carousel.pdf"
    images[0].save(pdf, save_all=True, append_images=images[1:], resolution=150)
    print(f"  [+] {pdf.relative_to(PROJECT_ROOT)}  (upload as a LinkedIn 'Document' post)")


if __name__ == "__main__":
    sys.exit(main())
