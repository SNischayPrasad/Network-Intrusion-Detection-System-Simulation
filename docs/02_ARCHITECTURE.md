# 02 · System Architecture & Design

This guide covers project-brief sections **4–18, 21 and 22**. For the theory behind each part, see [01_IDS_CONCEPTS.md](01_IDS_CONCEPTS.md).

## 21. System architecture

```
          Synthetic Traffic Generator  (simulator/generate_dataset.py, traffic_simulator.py)
                        │   JSON flow records only — never packets
                        ▼
                  Flow Collector       (POST /api/flows · backend/routes/flows.py)
                        │   Pydantic schema + ids/validation.py
                        ▼
                 Feature Extractor     (ids/feature_extractor.py + SourceWindowTracker)
          ┌─────────────┼──────────────┐
          ▼             ▼              ▼
     Rules Engine   Anomaly        ML Model
     rule_engine.py Detector       ml/predict.py (Random Forest, optional)
                    anomaly_detector.py
          └─────────────┼──────────────┘
                        ▼
                   Risk Engine         (ids/risk_engine.py — weights + floors + bands)
                        ▼
                  Alert Engine         (ids/alert_engine.py → correlation into incidents)
                        ▼
                Security Database      (SQLite · backend/models/database.py) ──► SIEM JSONL
                        ▼
                  SOC Dashboard        (React · frontend/, polls REST API every 5 s)
                        ▼
                     Analyst           (triage → investigate → notes → resolve / FP)
```

| Component | Responsibility | Key design decisions |
|---|---|---|
| **Synthetic Traffic Generator** | Produces labelled flow records for normal and suspicious scenarios | RFC 5737 IPs only; deliberate look-alikes (backups, busy pages) for honest FP/FN |
| **Flow Collector** | Receives flows over HTTP, authenticates the sensor, rejects bad input | `extra="forbid"` (no payload fields), duplicate `flow_id` returns 409 (idempotent ingestion) |
| **Feature Extractor** | Converts raw counters into behaviour features | 1 s rate floor, safe division, 60 s per-source sliding window keyed on *event time* |
| **Rules Engine** | Evaluates 6 detection rules with configurable thresholds | Rules are data (DB rows); a bad threshold never crashes the engine; hot reload |
| **Anomaly Detector** | Scores deviation from a learned normal baseline | log1p transform, Z-score + IQR, std floors, explainable per-metric output |
| **ML Model** | Probability that a flow is suspicious | Trained offline; loaded only from local `models/`; batch scoring for bulk loads |
| **Risk Engine** | Fuses the three scores into a 0–100 risk and a class | Configurable weights; rule and single-detector floors (evidence is never diluted) |
| **Alert Engine** | Builds analyst-ready alerts | Primary rule by severity, human-readable evidence, playbooks, ATT&CK *candidates* |
| **Correlation** | Groups alerts into incidents | Source IP + alert type + sliding 60 s window |
| **Security Database** | Persists flows, alerts, incidents, notes, rules, audit trail | Parameterised SQL, WAL mode, indexes on every filter column |
| **SOC Dashboard** | Visualises, filters, drives the analyst workflow | Polling, RBAC-aware UI, severity always shown with an icon and a label |
| **Analyst** | The human decision-maker | Closure requires a note, and every action is audited |

---

## 22. Project folder structure

```
Network-IDS-Simulation/
├── simulator/                 SYNTHETIC DATA (never packets)
│   ├── scenarios.py           12 scenario generators + address plan
│   ├── generate_dataset.py    → data/network_traffic.csv
│   └── traffic_simulator.py   live generator (stdout or local API)
├── ids/                       DETECTION ENGINE (framework-independent, pure Python)
│   ├── config.py              every threshold, weight, band, and the rule set
│   ├── validation.py          IP / port / protocol / number validation
│   ├── feature_extractor.py   15 features + SourceWindowTracker
│   ├── rule_engine.py         IDS-001…IDS-006
│   ├── anomaly_detector.py    baseline, Z-score, IQR, EWMA, moving average
│   ├── risk_engine.py         hybrid score, bands, classification
│   ├── alert_engine.py        alerts + defensive playbooks
│   ├── correlation.py         alert → incident grouping
│   ├── engine.py              HybridIDSEngine pipeline
│   └── siem_export.py         ECS-style JSON events
├── ml/                        OPTIONAL ML LAYER
│   ├── data_prep.py           shared loading / features / split
│   ├── train_model.py         trains LR, RF, IF + evaluates every layer
│   ├── evaluate.py            metrics, confusion-matrix plots, CLI re-evaluation
│   └── predict.py             MLDetector used by the engine
├── backend/                   REST API (FastAPI)
│   ├── app.py                 app factory, middleware, routers
│   ├── config.py              settings from environment (.env)
│   ├── routes/                flows, alerts, incidents, dashboard, rules, system
│   ├── models/                database.py (schema + access), schemas.py (Pydantic)
│   ├── services/              ids_service, alert_service, dashboard_service,
│   │                          rule_service, report_service, audit
│   └── utils/                 security.py (auth, RBAC, rate limit, headers), time_utils.py
├── frontend/                  SOC DASHBOARD (React + Vite + Recharts)
│   ├── package.json, vite.config.js, index.html
│   └── src/
│       ├── components/        Charts, AlertsTable, AlertFilters, Layout, ui
│       ├── pages/             Login, Dashboard, Traffic, Alerts, AlertDetail, Incidents, Rules
│       ├── services/          api.js (HTTP client), format.js
│       └── hooks/             usePolling.js
├── scripts/                   seed_database.py, demo_walkthrough.py, run_scenarios.py,
│                              capture_screenshots.py
├── data/                      network_traffic.csv (committed), ids.db (git-ignored)
├── models/                    baseline.json, model_metadata.json (*.joblib git-ignored)
├── tests/                     37 pytest tests + auto-generated results table
├── screenshots/               proof screenshots for GitHub/LinkedIn
├── docs/                      these guides
├── reports/                   model evaluation, scenario results, test results, project report
├── logs/                      runtime logs + SIEM JSONL (git-ignored)
├── README.md, requirements.txt, .env.example, .gitignore, LICENSE
```

Why `components/`, `pages/` and `services/` sit inside `frontend/src/`: that is the Vite/React convention, and the build tool only compiles files under `src/`.

---

## 4–5. Synthetic data and simulator design

- **Scenarios** are functions `scenario(rng, start) -> list[dict]`. Probing-like patterns return a *burst* of tiny records, because that is how probing appears in real flow logs. The pattern is only visible in aggregate.
- **Episodes:** most suspicious scenarios repeat 1–6 times from the same source within seconds. This produces realistic alert clusters for correlation.
- **Diurnal curve:** normal traffic peaks around 14:00, so the traffic chart looks like a real business day.
- **Reproducibility:** fixed seeds, so the same dataset and the same metrics every time.
- **Simulator safety:** it produces JSON only, and `--post` is restricted to loopback addresses by `is_loopback_url()` (unit-tested).

## 6. Feature engineering details
- `rate_duration_floor_seconds = 1.0`: a 5 ms DNS flow of 150 bytes gives 150 B/s, not 30,000 B/s.
- `SourceWindowTracker` keeps `(time, dst_ip, dst_port)` per source for 60 s of **event time**. Replaying a dataset therefore gives the same answers as live ingestion. The tracker is thread-safe.
- Input problems fall into two classes:
  - **Errors** (malformed IP, invalid port, unsupported protocol, absurd values): the record is **rejected** (HTTP 422).
  - **Warnings** (missing or negative counters, failures > connections, bad timestamp): the value is **repaired and recorded** in `data_quality_warnings`, which is shown on the flow.

## 7. Rule engine details
- Each rule is a small pure function that returns an *evidence string* or `None`. This keeps rules easy to test and makes alerts self-explanatory.
- Rules and thresholds are stored in the `rules` table. `PUT /api/rules/{id}` validates keys, types and ratio ranges, writes an audit entry, and hot-reloads the running engine.
- Signature score = the highest matched severity score (MEDIUM 50 / HIGH 75 / CRITICAL 90) + 5 per additional rule, capped at 100.

## 8. Anomaly detection details
- Baseline statistics are computed on **log1p-transformed** values from NORMAL training flows only.
- `min_std` floors stop near-constant metrics (for example destination-port diversity, which is almost always 1) from turning tiny changes into huge Z-scores.
- The IQR check uses Tukey's outer fence (Q3 + 3·IQR). It is skipped when the IQR is 0, which is degenerate.
- Output: the score, `is_anomalous`, per-metric `{value, z_score, iqr_outlier, metric_score}` and the top contributors. The investigation page renders these as a table.

## 9. Optional ML layer
See the README "Machine Learning" section and [reports/model_evaluation.md](../reports/model_evaluation.md). The pipeline is `log1p → (StandardScaler) → model`, with `class_weight="balanced"` for the imbalanced classes. Isolation Forest is fitted on normal flows only.

## 10–11. Hybrid risk engine
`calculate_risk_score(signature, anomaly, ml_probability=None, weights=None, top_rule_severity=None)` works in three steps:
1. Weighted sum (40/30/30, or 60/40 without ML). Custom weights are normalised.
2. Floors:
   - **Rule floor:** MEDIUM → 41, HIGH or CRITICAL → 61.
   - **Single-detector floor:** anomaly ≥ 75 or ML ≥ 85% → 41.
3. Band mapping gives the band label, alert severity and classification.

Both floors were added **because the evaluation showed specific failure modes**. That story is written up in the README and makes a good interview answer.

## 12–13. Alerts & correlation
- **One alert per risky flow.** The primary rule is the most severe match, and the other matches are listed in the description. The alternative, one alert per rule, would multiply analyst work for the same event.
- **Alert types without a rule:** `ANOMALY` (Statistical Anomaly) and `ML` (ML-Detected Suspicious Flow), chosen by whichever score is larger.
- **Correlation in the backend:** `IDSService._correlate()` looks for an incident with the same source and alert type whose `last_seen` is within the window, and extends it. Otherwise it creates `INC-xxxxxxxx`.

## 14–16. Dashboard & real-time design

### 15. Real-time simulation
```
Traffic Simulator ─POST─► Backend ─► IDS Engine ─► Alert Engine ─► SQLite ◄─poll every 5 s─ Dashboard
```
| Option | How it works | Verdict for this project |
|---|---|---|
| **A. Polling** | The browser re-requests `/api/dashboard/*` every N seconds | **Recommended.** Simplest, works through any proxy, easy to debug in DevTools, stateless server. Our dashboard needs "seconds-fresh", not "milliseconds-fresh". |
| B. Server-Sent Events | The server pushes a one-way event stream over HTTP | A good next step for a live alert ticker. Needs a long-lived connection per client. |
| C. WebSockets | Full-duplex socket | Overkill here. More complex (reconnects, auth on upgrade, scaling). |

The `usePolling` hook pauses while the browser tab is hidden (to save work), and the **Live/Paused** toggle stops refreshing during an investigation.

### 16. Charts and what they tell an analyst
| Chart | What it helps an analyst understand |
|---|---|
| Packets per second | Floods and bursts, and whether a spike is packets (many small) or bytes (few large) |
| Bytes per second | Bulk transfers: exfiltration-like surges **or** backups (check the schedule) |
| Connections per minute | Automation, DoS-like connection storms, a misbehaving client |
| Failed connections | Password guessing and probing of closed ports |
| Protocol distribution | Unexpected protocol mix (e.g. a UDP surge) |
| Port distribution | Rare or watch-listed services, shadow IT |
| Alert timeline (by severity) | When attacks cluster, and whether an incident is ongoing |
| Risk timeline (avg vs max) | A rising average means environment-wide change. A spike in max means a single high-risk event. |
| Traffic over time (normal vs suspicious) | The overall shape of the day and when suspicious activity occurs |
| Top source IPs by alerts | Who to investigate first |
| Risk-score distribution | Whether thresholds are sensible (most flows should sit in 0–10) |

## 17–18. Investigation & incident management
- The investigation page shows every item from brief section 17. Actions available depend on `allowed_transitions`, which the server computes from `STATUS_TRANSITIONS`.
- **Workflow:** `NEW → INVESTIGATING → RESOLVED | FALSE_POSITIVE`. Closed alerts can be re-opened.
- **Timestamps** are recorded automatically:
  - `investigation_started_at` on the first move to INVESTIGATING
  - `resolved_at` on closure
  - `updated_at` and `assigned_to` on every change
- **Timeline** = `audit_log` rows for the alert: ALERT_CREATED, STATUS_CHANGED, NOTE_ADDED.
- **Notes:**
  - Free-text notes are stored as `NOTE`.
  - The mandatory closing note is stored as `RESOLUTION`.
  - Control characters are stripped, and React renders all text escaped.
