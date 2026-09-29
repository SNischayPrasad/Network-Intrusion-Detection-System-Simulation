# 05 · Complete Virtual Simulation (no network lab required)

This guide covers project-brief sections **24 and 25**. Everything runs on one laptop. No packets are sent anywhere, and all traffic is synthetic JSON sent to `127.0.0.1`.

You will need **four terminals**, all opened in the project root (Windows: PowerShell; macOS/Linux: bash).

## STEP 0 — One-time setup
```bash
python -m venv .venv
.venv\Scripts\activate            # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env            # macOS/Linux: cp .env.example .env
cd frontend
npm install
cd ..
```

## STEP 1 — Generate the synthetic dataset
```bash
python -m simulator.generate_dataset
python -m ml.train_model                    # anomaly baseline + ML models + evaluation report
python scripts/seed_database.py --reset     # optional: 24 h of history for the dashboard (~7 s)
```
Expected: `Wrote 6019 synthetic flow records`, then a metrics table, then `Seeded 6019 flows`.

## STEP 2 — Start the backend (Terminal 1)
```bash
uvicorn backend.app:app --port 8000
```
Expected: `IDS engine ready | ML ENABLED | 6 rules`. Open http://127.0.0.1:8000/docs to see the API.

## STEP 3 — Start the frontend (Terminal 2)
```bash
cd frontend
npm run dev
```
Open http://localhost:5173 and sign in with `IDS_ANALYST_KEY` from your `.env`.

## STEP 4 — Start the traffic simulator (Terminal 3)
```bash
python -m simulator.traffic_simulator --mode mixed --speed fast --post http://127.0.0.1:8000/api/flows
```
Each line shows a synthetic flow and the IDS verdict. The dashboard refreshes every 5 s.

## STEPS 5–12 — Automated analyst walkthrough (Terminal 4)
```bash
python scripts/demo_walkthrough.py                         # resolves as RESOLVED
python scripts/demo_walkthrough.py --resolution FALSE_POSITIVE
```
The script performs every step below through the real API and prints the results. These are the **actual outputs** recorded during development:

| Step | Action | Actual result |
|---|---|---|
| 5 | Normal HTTPS flow (443, 3 conns, 0 failures) | `NORMAL`, risk **0.0**, no alert |
| 6 | Abnormal record: 400 connections, 360 failed in 20 s | `POTENTIAL_INTRUSION`, risk **87.9**; IDS-001 + IDS-002; alert **CRITICAL** (a stronger outcome than the minimum expectation of "SUSPICIOUS") |
| 7 | Multi-port pattern: 1 source → 20 ports in ~20 s | **IDS-003 Multi-Port Probing Pattern** fires (unique ports = 20 ≥ 12); risk 83.3 |
| 8 | `GET /api/alerts` | the new alerts appear at the top of the queue (and on the dashboard) |
| 9 | Analyst opens the alert | reason, evidence, candidate ATT&CK hint, playbook |
| 10 | NEW → INVESTIGATING | `investigation_started_at` stamped |
| 11 | Add analyst note | note saved, and a `NOTE_ADDED` timeline entry |
| 12 | Close as RESOLVED or FALSE_POSITIVE (note required) | `resolved_at` stamped; `reports/sample_incident_report.md` written |

### Doing steps 8–12 by hand in the dashboard
1. **Dashboard → Recent alerts** (or **Alert Queue**, filter *Status = New*) → click the alert row.
2. Click **Start investigation**.
3. Type a note in **Analyst notes** → **Add note**.
4. Click **Resolve** or **Mark false positive** → type the resolution → **Confirm**.
5. Click **Download report** for the Markdown incident report.

### Injecting single scenarios by hand
```bash
python -m simulator.traffic_simulator --scenario https      --post http://127.0.0.1:8000/api/flows
python -m simulator.traffic_simulator --scenario failed     --post http://127.0.0.1:8000/api/flows
python -m simulator.traffic_simulator --scenario multi_port --post http://127.0.0.1:8000/api/flows
python -m simulator.traffic_simulator --scenario syn        --post http://127.0.0.1:8000/api/flows
python -m simulator.traffic_simulator --scenario volume     --post http://127.0.0.1:8000/api/flows
python -m simulator.traffic_simulator --scenario backup     --post http://127.0.0.1:8000/api/flows   # false-positive demo
```

---

## 25. Sample safe detection scenarios

All inputs are **flow records**; none of these scenarios generates packets. Run `python scripts/run_scenarios.py` to reproduce this table. The numbers below are its real output (ML enabled).

| # | Scenario | Input | Key features | Rule triggered | Sig / Anom / ML | Risk | Classification | Expected alert |
|---|---|---|---|---|---|---|---|---|
| A | Normal HTTPS browsing | TCP/443, 18 pkts, 12.4 KB, 2.8 s, 3 conns | conn_rate 1.1/s, fail 0.00 | none | 0 / 0 / 0 | **0.0** | NORMAL | none |
| B | Normal DNS query pattern | UDP/53, 2 pkts, 150 B, 0.02 s | rate floor → 150 B/s | none | 0 / 0 / 1 | **0.3** | NORMAL | none |
| C | Repeated failed connections | TCP/22, 70 conns, 60 failed, 60 s | failure_ratio 0.86 | IDS-002 | 75 / 75 / 100 | **82.5** | POTENTIAL_INTRUSION | CRITICAL — Repeated Failed Connections |
| D | High connection rate | TCP/443, 500 conns in 10 s | conn_rate 50/s | IDS-001 | 75 / 81 / 100 | **84.4** | POTENTIAL_INTRUSION | CRITICAL — High Connection Rate |
| E | Multi-port probing-like pattern | 1 source → 20 ports, 1 pkt each, 20 s | unique_dst_ports 20 | IDS-003 (from record 12) | 75 / 82 / 96 | **83.3** | POTENTIAL_INTRUSION | CRITICAL — Multi-Port Probing Pattern; records 1–11 alerted as ML-detected |
| F | SYN-heavy statistical pattern | 2000 pkts, 1800 SYN, 1200 conns (1100 failed), 10 s | syn_ratio 0.90, conn_rate 120/s | IDS-004 + 001 + 002 | 100 / 87 / 100 | **96.1** | POTENTIAL_INTRUSION | CRITICAL — SYN-Heavy Connection Behavior |
| G | Abnormally high traffic volume | 2 GB outbound in 300 s | 6.7 MB/s | IDS-006 | 50 / 46 / 68 | **54.4** | SUSPICIOUS | MEDIUM — Abnormally High Traffic Volume |

**Reading the results**
- A and B: all three layers agree the traffic is normal.
- C, D and F: rule, anomaly and ML all agree, so risk goes above 80 → *critical investigation*.
- E: the rule needs 12 distinct ports before it fires, so the ML model covers records 1–11. This is hybrid detection in action.
- G: only the volume rule is confident, and the anomaly detector and ML are moderate, so the result is MEDIUM severity. That is appropriate, because a large transfer is often a backup (see `--scenario backup`, a known false-positive source).
