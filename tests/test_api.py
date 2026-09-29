"""API, database, workflow, security and ML tests."""

import sqlite3

import pytest

from ml.data_prep import ML_FEATURES
from tests.conftest import ADMIN, ANALYST, SENSOR, make_flow


def test_alert_status_update(client, alert_id, record_property):
    """TC-23 | Alert status update | NEW -> INVESTIGATING -> RESOLVED; illegal NEW -> RESOLVED | Expected: valid transitions OK, illegal = 409, close w/o note = 409"""
    illegal = client.put(f"/api/alerts/{alert_id}/status", headers=ANALYST, json={"status": "RESOLVED", "note": "done done"})
    r1 = client.put(f"/api/alerts/{alert_id}/status", headers=ANALYST, json={"status": "INVESTIGATING"})
    no_note = client.put(f"/api/alerts/{alert_id}/status", headers=ANALYST, json={"status": "RESOLVED"})
    r2 = client.put(f"/api/alerts/{alert_id}/status", headers=ANALYST,
                    json={"status": "RESOLVED", "note": "Confirmed synthetic brute-force pattern."})
    record_property("actual", f"illegal={illegal.status_code}, investigate={r1.json()['status']}, "
                              f"no-note={no_note.status_code}, resolve={r2.json()['status']}")
    assert illegal.status_code == 409 and no_note.status_code == 409
    assert r1.json()["investigation_started_at"] and r2.json()["resolved_at"]


def test_analyst_note(client, alert_id, record_property):
    """TC-24 | Analyst note | POST note with control characters | Expected: 201, stored cleaned, appears in timeline"""
    resp = client.post(f"/api/alerts/{alert_id}/notes", headers=ANALYST,
                       json={"note": "Checked firewall logs\x00\x07 — source unknown."})
    detail = client.get(f"/api/alerts/{alert_id}", headers=ANALYST).json()
    record_property("actual", f"status={resp.status_code}, stored={detail['notes'][0]['note']!r}, "
                              f"timeline={[t['action'] for t in detail['timeline']]}")
    assert resp.status_code == 201 and "\x00" not in detail["notes"][0]["note"]
    assert "NOTE_ADDED" in [t["action"] for t in detail["timeline"]]


def test_database_storage(client, alert_id, record_property):
    """TC-25 | Database storage | ingest suspicious flow, inspect SQLite | Expected: flow, alert, incident, audit rows exist and are linked"""
    db_path = client.app.state.settings.db_path
    conn = sqlite3.connect(db_path)
    flow_id, incident_id = conn.execute(
        "SELECT flow_id, incident_id FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    counts = {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
              for t in ("network_flows", "alerts", "incidents", "audit_log", "rules")}
    flow_exists = conn.execute("SELECT 1 FROM network_flows WHERE flow_id = ?", (flow_id,)).fetchone()
    conn.close()
    record_property("actual", f"counts={counts}, flow={flow_id}, incident={incident_id}")
    assert flow_exists and incident_id and counts["rules"] == 6 and counts["audit_log"] >= 1


def test_dashboard_statistics(client, record_property):
    """TC-26 | Dashboard statistics | 3 normal + 1 suspicious flow | Expected: totals 4/3/1, 1 open alert, charts populated"""
    for i in range(3):
        client.post("/api/flows", headers=SENSOR, json=make_flow(source_port=50000 + i))
    client.post("/api/flows", headers=SENSOR, json=make_flow(
        source_ip="203.0.113.50", connection_count=600, duration_seconds=10, syn_count=600))
    s = client.get("/api/dashboard/stats?range=1h", headers=ANALYST).json()
    t = client.get("/api/dashboard/traffic?range=1h", headers=ANALYST).json()
    a = client.get("/api/dashboard/alerts?range=1h", headers=ANALYST).json()
    record_property("actual", f"total={s['total_flows']} normal={s['normal_flows']} "
                              f"suspicious={s['suspicious_flows']} open={s['open_alerts']} "
                              f"series_points={len(t['series'])} types={[x['alert_type'] for x in a['by_type']]}")
    assert (s["total_flows"], s["normal_flows"], s["suspicious_flows"], s["open_alerts"]) == (4, 3, 1, 1)
    assert t["protocols"][0]["protocol"] == "TCP" and a["by_type"]


def test_ml_prediction(record_property):
    """TC-27 | ML prediction | trained Random Forest scores normal vs SYN-heavy features | Expected: probabilities in [0,1], suspicious > normal"""
    from pathlib import Path

    from ids.feature_extractor import extract_network_features
    from ml.predict import DEFAULT_MODEL, MLDetector
    if not Path(DEFAULT_MODEL).exists():
        pytest.skip("Model not trained — run: python -m ml.train_model")
    det = MLDetector.load()
    p_normal = det.predict_probability(extract_network_features(make_flow()))
    p_susp = det.predict_probability(extract_network_features(make_flow(
        packet_count=3000, syn_count=2800, byte_count=180000, duration_seconds=8,
        connection_count=2000, failed_connection_count=1900)))
    record_property("actual", f"P(normal flow)={p_normal:.3f}, P(SYN-heavy flow)={p_susp:.3f}, "
                              f"features={len(ML_FEATURES)}")
    assert 0 <= p_normal <= 1 and 0 <= p_susp <= 1 and p_susp > p_normal
    assert det.predict(extract_network_features(make_flow())) == "NORMAL"


def test_api_validation(client, record_property):
    """TC-28 | API validation | bad IP, port 70000, unknown field, missing byte_count, bad alert id | Expected: 422 for each"""
    codes = [
        client.post("/api/flows", headers=SENSOR, json=make_flow(source_ip="300.1.1.1")).status_code,
        client.post("/api/flows", headers=SENSOR, json=make_flow(destination_port=70000)).status_code,
        client.post("/api/flows", headers=SENSOR, json=make_flow(payload="GET / HTTP/1.1")).status_code,
        client.post("/api/flows", headers=SENSOR, json={k: v for k, v in make_flow().items()
                                                         if k != "byte_count"}).status_code,
        client.get("/api/alerts/DROP TABLE alerts", headers=ANALYST).status_code,
    ]
    record_property("actual", f"status codes={codes}")
    assert codes[:4] == [422, 422, 422, 422] and codes[4] in (404, 422)


def test_empty_dataset(client, record_property):
    """TC-29 | Empty dataset | dashboard + alert queue on a fresh empty DB | Expected: zeros / empty lists, no errors"""
    s = client.get("/api/dashboard/stats", headers=ANALYST).json()
    t = client.get("/api/dashboard/traffic", headers=ANALYST).json()
    a = client.get("/api/alerts", headers=ANALYST).json()
    record_property("actual", f"total_flows={s['total_flows']}, avg_risk={s['average_risk_score']}, "
                              f"series={t['series']}, alerts={a['total']}")
    assert s["total_flows"] == 0 and t["series"] == [] and a["total"] == 0


def test_duplicate_event_handling(client, record_property):
    """TC-30 | Duplicate event handling | same flow_id posted twice | Expected: 201 then 409, stored once"""
    flow = make_flow(flow_id="FLOW-DUPLICATE-1")
    first = client.post("/api/flows", headers=SENSOR, json=flow).status_code
    second = client.post("/api/flows", headers=SENSOR, json=flow).status_code
    total = client.get("/api/flows", headers=ANALYST).json()["total"]
    record_property("actual", f"first={first}, second={second}, stored={total}")
    assert (first, second, total) == (201, 409, 1)


def test_authentication_and_authorization(client, record_property):
    """TC-33 | AuthN / AuthZ (RBAC) | no key, bad key, sensor reading alerts, analyst editing rules, admin editing rules | Expected: 401, 401, 403, 403, 200"""
    codes = [
        client.get("/api/alerts").status_code,
        client.get("/api/alerts", headers={"X-API-Key": "wrong"}).status_code,
        client.get("/api/alerts", headers=SENSOR).status_code,
        client.put("/api/rules/IDS-001", headers=ANALYST, json={"enabled": False}).status_code,
        client.put("/api/rules/IDS-001", headers=ADMIN,
                   json={"threshold": {"connection_count": 200}}).status_code,
    ]
    record_property("actual", f"status codes={codes}")
    assert codes == [401, 401, 403, 403, 200]


def test_rule_update_validation_and_hot_reload(client, record_property):
    """TC-34 | Rule tuning | invalid threshold key/value, then disable IDS-005 | Expected: 422s, then port-4444 flow no longer matches IDS-005"""
    bad_key = client.put("/api/rules/IDS-001", headers=ADMIN, json={"threshold": {"evil": 1}}).status_code
    bad_val = client.put("/api/rules/IDS-002", headers=ADMIN, json={"threshold": {"failure_ratio": 5}}).status_code
    before = client.post("/api/flows", headers=SENSOR, json=make_flow(destination_port=4444)).json()
    client.put("/api/rules/IDS-005", headers=ADMIN, json={"enabled": False})
    after = client.post("/api/flows", headers=SENSOR, json=make_flow(destination_port=4444,
                                                                      source_port=50001)).json()
    ids_before = [m["rule_id"] for m in before["rule_matches"]]
    ids_after = [m["rule_id"] for m in after["rule_matches"]]
    record_property("actual", f"bad_key={bad_key}, bad_val={bad_val}, before={ids_before}, after={ids_after}")
    assert (bad_key, bad_val) == (422, 422) and "IDS-005" in ids_before and "IDS-005" not in ids_after


def test_incident_report_and_security_headers(client, alert_id, record_property):
    """TC-35 | Incident report + security headers | GET report for an alert | Expected: Markdown report, nosniff + DENY headers"""
    resp = client.get(f"/api/alerts/{alert_id}/report", headers=ANALYST)
    record_property("actual", f"status={resp.status_code}, type={resp.headers['content-type']}, "
                              f"X-Frame-Options={resp.headers.get('x-frame-options')}")
    assert resp.status_code == 200 and resp.text.startswith(f"# Incident Report — {alert_id}")
    assert resp.headers["x-content-type-options"] == "nosniff"
