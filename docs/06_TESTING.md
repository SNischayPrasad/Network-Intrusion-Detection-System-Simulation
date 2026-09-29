# 06 · Testing Strategy

```bash
python -m pytest -v                 # 37 tests, about 8 s
```
Every run regenerates **[reports/test_results.md](../reports/test_results.md)**: a table with *Test ID · Scenario · Input · Expected · Actual · Pass/Fail*. The "Actual" column is recorded by each test from what it really observed (via pytest's `record_property`). It is never typed by hand.

## Test design
| File | Level | What it covers |
|---|---|---|
| `tests/test_detection.py` | Unit | validation, features, rules, anomaly, risk, alerts, correlation (pure `ids/` code, deterministic engine with ML off) |
| `tests/test_api.py` | Integration | FastAPI + SQLite in a temp directory: workflow, notes, storage, dashboard, validation, auth, rule reload, reports, ML model |
| `tests/test_simulator.py` | Unit / safety | dataset columns, labels, RFC 5737-only IPs; simulator loopback guard |

Each API test gets a **fresh temporary database** (`tmp_path`), so tests never touch `data/ids.db` and can run in any order.

## Test catalogue
| ID | Scenario | Input | Expected result |
|---|---|---|---|
| TC-01 | Normal TCP flow | SSH session, 1 conn, 0 failures | NORMAL, no alert |
| TC-02 | Normal UDP flow | NTP-style exchange | NORMAL |
| TC-03 | Normal DNS flow | UDP/53, 2 packets | NORMAL, no rules |
| TC-04 | Normal HTTPS flow | Scenario A | NORMAL, risk ≤ 20 |
| TC-05 | High connection rate | 500 conns / 10 s | IDS-001, alert |
| TC-06 | Repeated failed connections | 60/70 failed | IDS-002, not NORMAL |
| TC-07 | Multi-port pattern | 15 ports / 15 s | IDS-003 fires on later records only |
| TC-08 | SYN-heavy pattern | 1800 SYN / 2000 pkts | IDS-004, risk ≥ 61 |
| TC-09 | High traffic volume | 2 GB / 5 min | IDS-006 |
| TC-10 | Invalid source IP | `999.1.1.1` | rejected |
| TC-11 | Invalid destination IP | `not-an-ip` | rejected |
| TC-12 | Invalid source port | 70000 | rejected |
| TC-13 | Invalid destination port | −1 | rejected |
| TC-14 | Unsupported protocol | GRE | rejected |
| TC-15 | Missing packet count | field omitted | imputed 0 + data-quality warning |
| TC-16 | Zero duration | duration 0 | no ZeroDivisionError; 1 s floor |
| TC-17 | Feature extraction | known counters | exact ratios/rates |
| TC-18 | Rule detection & config | default, raised, disabled thresholds | fires / silent / silent |
| TC-19 | Anomaly score | normal vs abnormal | < 20 vs ≥ 75 |
| TC-20 | Risk score | 70/60/0.78 and 70/60 | 69.4 and 66.0; floor = 61 |
| TC-21 | Alert creation | suspicious result | ALT-id, NEW, reason, playbook |
| TC-22 | Alert correlation | 100 alerts / 50 s + 2 others | 3 incidents |
| TC-23 | Alert status update | legal and illegal transitions | 200s; 409 illegal; 409 without note |
| TC-24 | Analyst note | note with control chars | 201, cleaned, on timeline |
| TC-25 | Database storage | suspicious flow | linked flow/alert/incident/audit rows |
| TC-26 | Dashboard statistics | 3 normal + 1 suspicious | 4 / 3 / 1, 1 open alert |
| TC-27 | ML prediction | normal vs SYN-heavy features | valid probabilities, suspicious > normal |
| TC-28 | API validation | bad IP, port, unknown field, missing field, bad ID | 422 each |
| TC-29 | Empty dataset | fresh DB | zeros, empty lists, no errors |
| TC-30 | Duplicate event handling | same flow_id twice | 201 then 409, stored once |
| TC-31 | Unusual service port | TCP/4444 | IDS-005 |
| TC-32 | Baseline fit / empty data | 50 flows; [] | fitted; ValueError |
| TC-33 | AuthN / AuthZ | no key, bad key, wrong roles | 401, 401, 403, 403, 200 |
| TC-34 | Rule tuning | bad key/value; disable IDS-005 | 422s; rule stops firing |
| TC-35 | Report + headers | GET report | Markdown, nosniff, DENY |
| TC-36 | Dataset generator | 5,000 rows | columns, both labels, doc-range IPs |
| TC-37 | Simulator safety | normal mode; external URLs | only NORMAL; non-loopback refused |

(TC-10 to TC-13 are one parametrised test, so pytest reports 37 test cases.)

## Latest run
See [reports/test_results.md](../reports/test_results.md). At the time of writing: **37 / 37 passed**.

## Beyond unit tests
- **End-to-end:** `scripts/demo_walkthrough.py` exercises the running API (steps 5–12).
- **Model quality:** `python -m ml.train_model` and `python -m ml.evaluate` produce measured metrics on a held-out split.
- **Manual UI test:** sign in, run the simulator, and work an alert from NEW to FALSE_POSITIVE in the dashboard.
