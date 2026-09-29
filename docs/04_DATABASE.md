# 04 · Database Design

The database is SQLite (`data/ids.db`) with WAL journaling. The full DDL is in [backend/models/database.py](../backend/models/database.py). Every query uses `?` placeholders (no SQL injection), and foreign keys are enforced.

## Entity-relationship diagram
```
┌──────────────────┐ 1      0..1 ┌──────────────────┐ *        1 ┌──────────────┐
│  NETWORK_FLOWS   │─────────────│      ALERTS      │────────────│  INCIDENTS   │
│ PK flow_id       │             │ PK alert_id      │            │ PK incident_id│
└──────────────────┘             │ FK flow_id UNIQUE│            └──────────────┘
        │ 1                      │ FK incident_id   │
        │                        │    rule_id ──────┼──► RULES.rule_id (or ANOMALY / ML)
        │ 0..*                   └──────────────────┘
┌──────────────────┐                     │ 1
│  MODEL_RESULTS   │                     │ 0..*
│ FK flow_id       │             ┌──────────────────┐        ┌──────────────┐
└──────────────────┘             │  INCIDENT_NOTES  │        │  AUDIT_LOG   │ (append-only,
                                 │ FK alert_id      │        │ target_type, │  references any
                                 └──────────────────┘        │ target_id)   │  object by id)
                                                             └──────────────┘
```

## Tables
### NETWORK_FLOWS: one row per analysed flow
| Column | Type | Notes |
|---|---|---|
| flow_id | TEXT PK | client-supplied or generated. The PK guarantees duplicate protection. |
| timestamp | TEXT | ISO-8601 UTC, fixed width (`2026-09-28T10:15:00.123Z`), so string comparison equals time comparison |
| source_ip, destination_ip | TEXT | validated IPs |
| source_port, destination_port | INTEGER | 0–65535 |
| protocol | TEXT | CHECK in (TCP, UDP, ICMP) |
| packet_count, byte_count, duration | INTEGER / REAL | |
| connection_count, failed_connection_count, syn_count, rst_count, average_packet_size | | |
| signature_score, anomaly_score, ml_score | REAL | per-layer scores (ml_score is NULL when ML is disabled) |
| risk_score, risk_band, classification | | hybrid output |
| detection_json | TEXT | features, anomaly details, rule matches and warnings, kept for investigation |
| label, scenario_type | TEXT | optional synthetic ground truth |
| ingested_at | TEXT | wall-clock ingestion time |

### ALERTS: one row per alerting flow
Columns: `alert_id` PK, `flow_id` FK UNIQUE, `incident_id` FK, `rule_id`, `alert_type`, `severity` (CHECK), `description`, `reason`, `risk_score`, `signature_score`, `anomaly_score`, `ml_score`, `status` (CHECK NEW / INVESTIGATING / RESOLVED / FALSE_POSITIVE), a denormalised network context (`source_ip`, `destination_ip`, ports, `protocol`, so the queue loads without joins), `matched_rules_json`, `mitre_hint`, `created_at` (event time), `detected_at`, `updated_at`, `assigned_to`, `investigation_started_at`, `resolved_at`.

### RULES
`rule_id` PK, `rule_name`, `description`, `severity`, `threshold` (a JSON object, so each rule can have different tunables), `enabled`, `mitre_hint`, `updated_at`.

### INCIDENT_NOTES
`note_id` INTEGER PK AUTOINCREMENT, `alert_id` FK (ON DELETE CASCADE), `note`, `note_type` (NOTE / RESOLUTION), `analyst`, `created_at`.

### MODEL_RESULTS (optional ML)
`result_id` PK, `flow_id` FK, `model_name`, `prediction` (NORMAL / SUSPICIOUS), `score` (probability), `created_at`. Keeping predictions per model allows later A/B comparison and drift analysis.

### INCIDENTS (correlation)
`incident_id` PK, `source_ip`, `alert_type`, `first_seen`, `last_seen`, `alert_count`, `max_severity`, `max_risk_score`.

### AUDIT_LOG
`id`, `timestamp`, `actor`, `role`, `action` (ALERT_CREATED, STATUS_CHANGED, NOTE_ADDED, RULE_UPDATED), `target_type`, `target_id`, `details`. The application only ever INSERTs into this table.

## Relationships
- **Flow → Alert (1 : 0..1):** only risky flows raise an alert. `UNIQUE(flow_id)` prevents double alerts for one flow.
- **Incident → Alerts (1 : many):** correlation assigns `incident_id`.
- **Alert → Notes (1 : many)** and **Flow → Model results (1 : many)**.
- **Rules → Alerts (logical):** `rule_id` refers to a rule, or to the virtual detectors `ANOMALY` and `ML`, which is why this is not a hard foreign key.

## Indexes and why
| Index | Serves |
|---|---|
| `network_flows(timestamp)` | every time-range dashboard query |
| `network_flows(source_ip)`, `(classification)` | flow filters |
| `alerts(created_at)`, `(status)`, `(severity)`, `(source_ip)` | alert queue filters and KPIs |
| `alerts(incident_id)` | incident drill-down |
| `incidents(source_ip, alert_type, last_seen)` | correlation lookup on every new alert |
| `incident_notes(alert_id)`, `model_results(flow_id)`, `audit_log(target_type, target_id)` | investigation page joins |

## Inspecting the data
```bash
python -c "import sqlite3; c=sqlite3.connect('data/ids.db'); print(c.execute('select classification, count(*) from network_flows group by 1').fetchall())"
```
Or open `data/ids.db` in *DB Browser for SQLite* and screenshot the tables (checklist item 24).
