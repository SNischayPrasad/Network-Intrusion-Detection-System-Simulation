# 03 · REST API Reference

Base URL: `http://127.0.0.1:8000` · Interactive docs (Swagger UI): `/docs` · OpenAPI JSON: `/openapi.json`

## Cross-cutting rules
| Topic | Behaviour |
|---|---|
| **Authentication** | Header `X-API-Key: <key>`. Keys come from `.env`. A missing or invalid key returns **401**. `/api/health` is public. |
| **Authorisation (RBAC)** | `sensor` can only `POST /api/flows`. `analyst` can read everything and work alerts. `admin` has analyst rights plus rule edits and the audit log. A wrong role returns **403**. |
| **Validation** | Pydantic schemas with `extra="forbid"` (unknown fields are rejected), string length limits, regex-checked path IDs, and semantic checks in `ids/validation.py`. A failure returns **422**. |
| **Rate limiting** | `IDS_RATE_LIMIT_PER_MINUTE` per client + key. Exceeding it returns **429** with a `Retry-After` header. |
| **Errors** | JSON `{"detail": ...}`. Unexpected errors return **500** `{"detail":"Internal server error"}`. Stack traces are logged server-side only, never returned. |
| **Headers** | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `Content-Security-Policy: default-src 'none'` |
| **Time ranges** | `range` = `15m`, `1h`, `6h`, `24h`, `7d`, `30d` or `all` |

---

### POST /api/flows — submit a flow for analysis
- **Auth:** sensor, admin
- **Request**
```json
{
  "flow_id": "SIM-0001",                      // optional; generated if omitted; ^[A-Za-z0-9_.:-]{1,64}$
  "timestamp": "2026-09-28T10:15:00.000Z",    // optional; defaults to now (UTC)
  "source_ip": "192.0.2.15", "destination_ip": "198.51.100.20",
  "source_port": 49152, "destination_port": 443, "protocol": "TCP",
  "packet_count": 18, "byte_count": 12400, "duration_seconds": 2.8,
  "connection_count": 3, "failed_connection_count": 0, "syn_count": 2, "rst_count": 0,
  "label": "NORMAL", "scenario_type": "NORMAL_WEB"   // optional synthetic ground truth
}
```
- **Validation:**
  - IPv4 or IPv6 addresses.
  - Ports 0–65535 (they may be omitted only for ICMP).
  - Protocol must be TCP, UDP or ICMP.
  - Counters must be ≥ 0; `packet_count` and `byte_count` are required.
  - Unknown fields are rejected (for example a `payload` field).
- **Response 201**
```json
{ "flow_id": "SIM-0001", "classification": "NORMAL", "risk_score": 0.0, "risk_band": "NORMAL",
  "severity": "INFO", "signature_score": 0.0, "anomaly_score": 0.0, "ml_score": 0.1,
  "rule_matches": [], "features": { "bytes_per_second": 4428.57, "...": "..." },
  "data_quality_warnings": [], "alert": null }
```
When risky, `alert` = `{alert_id, alert_type, rule_id, severity, risk_score, status, incident_id}`.
- **Status codes:** 201 created · 401 · 403 · **409 duplicate flow_id** · 422 invalid · 429

### GET /api/flows — list flows
- **Auth:** analyst, admin
- **Query:** `classification` (NORMAL/SUSPICIOUS/POTENTIAL_INTRUSION), `protocol`, `source_ip`, `range`, `limit` ≤ 500, `offset`
- **Response 200:** `{items:[{flow_id, timestamp, source_ip, destination_ip, ports, protocol, packet_count, byte_count, duration, connection_count, failed_connection_count, risk_score, risk_band, classification, scenario_type}], total, limit, offset}`

### GET /api/flows/{id} — flow detail
- **Response 200:** every stored column, plus `detection` (features, anomaly details, rule matches, ML probability, warnings) and `alert_id`
- **Status codes:** 404 if unknown

### GET /api/alerts — alert queue
- **Query:** `severity` (comma list, e.g. `HIGH,CRITICAL`), `protocol`, `alert_type`, `status` (comma list, e.g. `NEW,INVESTIGATING`), `source_ip`, `incident_id`, `range`, `limit`, `offset`
- **Response 200:** `{items:[{alert_id, flow_id, incident_id, rule_id, alert_type, severity, risk_score, status, source_ip, destination_ip, source_port, destination_port, protocol, created_at, detected_at, updated_at, reason}], total, limit, offset}`, newest first

### GET /api/alerts/{id} — investigation view
- **Path:** `ALT-[A-F0-9]{8}`. Anything else returns 422, so the path cannot carry an injection attempt.
- **Response 200:** the alert, plus:
  - `flow`, `features`, `anomaly_details` and `matched_rules`
  - `notes`, `timeline` and `incident`
  - `recommended_steps`, `mitre_hint` and `allowed_transitions`

### PUT /api/alerts/{id}/status — incident workflow
- **Request:** `{"status": "INVESTIGATING"}` or `{"status": "RESOLVED", "note": "What was found / done"}`
- **Rules:**
  - Allowed transitions are NEW→INVESTIGATING|FALSE_POSITIVE, INVESTIGATING→RESOLVED|FALSE_POSITIVE, and RESOLVED|FALSE_POSITIVE→INVESTIGATING.
  - Closing requires a note of at least 5 characters.
- **Response 200:** the updated investigation view
- **Status codes:** 404 · **409** for an illegal transition or a missing resolution note · 422 for an unknown status

### POST /api/alerts/{id}/notes — analyst note
- **Request:** `{"note": "Checked firewall logs; source not in inventory."}` (1–2000 chars; control characters stripped)
- **Response 201:** `{note_id, alert_id, note, note_type:"NOTE", analyst, created_at}`

### GET /api/alerts/{id}/report — incident report
- **Response 200:** `text/markdown` attachment `incident_report_<id>.md` containing the summary, network context, evidence, timeline, notes and steps

### GET /api/alerts/{id}/siem — SIEM event
- **Response 200:** ECS-style JSON (see [08_SOC_MITRE_SIEM.md](08_SOC_MITRE_SIEM.md))

### GET /api/incidents · GET /api/incidents/{id}
- **List:** `{items:[{incident_id, source_ip, alert_type, first_seen, last_seen, alert_count, max_severity, max_risk_score, open_alerts}], total}`
- **Detail:** the incident plus its `alerts`
- **Path:** `INC-[A-F0-9]{8}`

### GET /api/dashboard/stats?range=24h
```json
{ "total_flows": 6018, "normal_flows": 4727, "suspicious_flows": 1291, "potential_intrusions": 470,
  "average_risk_score": 14.8, "total_alerts": 1290, "open_alerts": 1290, "new_alerts": 1290,
  "critical_alerts": 486, "critical_open_alerts": 485, "incidents": 464, "ml_enabled": true,
  "last_flow_at": "...", "range": "24h" }
```

### GET /api/dashboard/traffic?range=24h
`{bucket_seconds, series:[{time, flows, normal, suspicious, packets, bytes, packets_per_second, bytes_per_second, connections_per_minute, failed_connections, avg_risk, max_risk, flows_moving_avg}], protocols:[{protocol,count}], top_ports:[{port,service,count}], classification:[{name,count}]}`

Empty time buckets are filled with zeros, so charts show quiet periods honestly.

### GET /api/dashboard/alerts?range=24h
`{by_severity, by_type, by_status, top_sources:[{source_ip,count,max_risk}], risk_distribution:[{range:"0-9",count}], timeline:[{time, INFO, LOW, MEDIUM, HIGH, CRITICAL}]}`

### GET /api/rules · PUT /api/rules/{id}
- **GET:** analyst or admin. Returns `{items:[{rule_id, rule_name, description, severity, threshold:{...}, enabled, mitre_hint, updated_at}]}`.
- **PUT:** **admin only**. Request `{"enabled": true, "severity": "HIGH", "threshold": {"connection_count": 200}}`.
- **Validation:**
  - Only existing threshold keys may be set.
  - Numbers must be > 0.
  - `*_ratio` values must be ≤ 1.
  - Watch-lists must be lists of valid ports.
- **Response 200:** the updated rule, audited and **hot-reloaded** into the engine
- **Status codes:** 403 non-admin · 404 · 422 invalid threshold

### GET /api/audit-log (admin) · GET /api/auth/whoami · GET /api/health
- **Audit log:** `{items:[{timestamp, actor, role, action, target_type, target_id, details}]}`
- **whoami:** `{name, role}`. Used by the dashboard sign-in.
- **health:** `{status:"ok", ml_enabled}`. No authentication and no sensitive data.

## Try it with curl
```bash
curl -s -X POST http://127.0.0.1:8000/api/flows -H "X-API-Key: <IDS_SENSOR_KEY from .env>" \
     -H "Content-Type: application/json" \
     -d '{"source_ip":"203.0.113.9","destination_ip":"198.51.100.22","source_port":50000,"destination_port":22,"protocol":"TCP","packet_count":1600,"byte_count":128000,"duration_seconds":20,"connection_count":400,"failed_connection_count":360,"syn_count":400,"rst_count":360}'
curl -s "http://127.0.0.1:8000/api/alerts?severity=HIGH,CRITICAL&status=NEW&limit=5" -H "X-API-Key: <IDS_ANALYST_KEY from .env>"
```
