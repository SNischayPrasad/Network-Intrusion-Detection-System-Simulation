"""
Detection-engine tests: normal traffic, suspicious patterns, validation,
feature extraction, anomaly scoring, risk scoring, alerts and correlation.
"""

from datetime import datetime, timedelta, timezone

import pytest

from ids.alert_engine import generate_alert
from ids.anomaly_detector import AnomalyDetector, calculate_anomaly_score
from ids.correlation import correlate_alerts, reduction_ratio
from ids.feature_extractor import extract_network_features
from ids.risk_engine import calculate_risk_score, classify, risk_band
from ids.rule_engine import analyze_flow
from ids.validation import FlowValidationError, format_timestamp, validate_flow
from tests.conftest import make_flow


def _rule_ids(result):
    return [m["rule_id"] for m in result["rule_matches"]]


# ---------------------------------------------------------------- normal traffic
def test_normal_tcp_flow(engine, record_property):
    """TC-01 | Normal TCP flow | SSH admin session, 1 connection, 0 failures | Expected: NORMAL, no alert"""
    r = engine.analyze(make_flow(destination_port=22, packet_count=400, byte_count=60000,
                                 duration_seconds=300, connection_count=1, syn_count=1))
    record_property("actual", f"{r['classification']}, risk={r['risk_score']}, alert={r['alert'] is not None}")
    assert r["classification"] == "NORMAL" and r["alert"] is None


def test_normal_udp_flow(engine, record_property):
    """TC-02 | Normal UDP flow | NTP-style UDP exchange | Expected: NORMAL, no alert"""
    r = engine.analyze(make_flow(protocol="UDP", destination_port=123, packet_count=2,
                                 byte_count=180, duration_seconds=0.05, connection_count=1,
                                 syn_count=0))
    record_property("actual", f"{r['classification']}, risk={r['risk_score']}")
    assert r["classification"] == "NORMAL" and r["alert"] is None


def test_normal_dns_flow(engine, record_property):
    """TC-03 | Normal DNS flow | UDP/53, 2 packets, 150 bytes | Expected: NORMAL, no alert"""
    r = engine.analyze(make_flow(protocol="UDP", destination_ip="198.51.100.53",
                                 destination_port=53, packet_count=2, byte_count=150,
                                 duration_seconds=0.02, connection_count=1, syn_count=0))
    record_property("actual", f"{r['classification']}, risk={r['risk_score']}")
    assert r["classification"] == "NORMAL" and not r["rule_matches"]


def test_normal_https_flow(engine, record_property):
    """TC-04 | Normal HTTPS flow | TCP/443, 3 connections, 0 failures (Scenario A) | Expected: NORMAL, risk <= 20"""
    r = engine.analyze(make_flow())
    record_property("actual", f"{r['classification']}, risk={r['risk_score']}, band={r['risk_band']}")
    assert r["classification"] == "NORMAL" and r["risk_score"] <= 20


# ------------------------------------------------------------ suspicious patterns
def test_high_connection_rate(engine, record_property):
    """TC-05 | High connection rate | 500 connections in 10 s | Expected: IDS-001 fires, alert raised"""
    r = engine.analyze(make_flow(source_ip="203.0.113.10", connection_count=500,
                                 packet_count=2500, byte_count=200000, duration_seconds=10,
                                 syn_count=500))
    record_property("actual", f"rules={_rule_ids(r)}, {r['classification']}, risk={r['risk_score']}")
    assert "IDS-001" in _rule_ids(r) and r["alert"] is not None


def test_repeated_failed_connections(engine, record_property):
    """TC-06 | Repeated failed connections | 60 of 70 SSH connections failed | Expected: IDS-002 fires, not NORMAL"""
    r = engine.analyze(make_flow(source_ip="203.0.113.11", destination_port=22,
                                 connection_count=70, failed_connection_count=60,
                                 packet_count=300, byte_count=24000, duration_seconds=60,
                                 syn_count=70, rst_count=60))
    record_property("actual", f"rules={_rule_ids(r)}, {r['classification']}, risk={r['risk_score']}")
    assert "IDS-002" in _rule_ids(r) and r["classification"] != "NORMAL"


def test_multi_port_pattern(engine, record_property):
    """TC-07 | Multi-port pattern | one source -> 15 ports within 15 s | Expected: IDS-003 fires on later records"""
    start = datetime.now(timezone.utc)
    results = [engine.analyze(make_flow(
        source_ip="203.0.113.12", destination_port=p, packet_count=1, byte_count=60,
        duration_seconds=0.01, connection_count=1, failed_connection_count=1, syn_count=1,
        rst_count=1, timestamp=format_timestamp(start + timedelta(seconds=i))))
        for i, p in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 3306, 3389])]
    first_hit = next(i for i, r in enumerate(results) if "IDS-003" in _rule_ids(r))
    record_property("actual", f"IDS-003 first fired on record #{first_hit + 1} of 15 "
                              f"(unique ports={results[-1]['features']['unique_destination_ports']:.0f})")
    assert "IDS-003" not in _rule_ids(results[0]) and "IDS-003" in _rule_ids(results[-1])


def test_syn_heavy_pattern(engine, record_property):
    """TC-08 | SYN-heavy pattern | 2000 packets, 1800 SYN | Expected: IDS-004 (CRITICAL rule) fires"""
    r = engine.analyze(make_flow(source_ip="203.0.113.13", packet_count=2000, syn_count=1800,
                                 byte_count=120000, duration_seconds=10, connection_count=1200,
                                 failed_connection_count=1100))
    record_property("actual", f"rules={_rule_ids(r)}, severity={r['severity']}, risk={r['risk_score']}")
    assert "IDS-004" in _rule_ids(r) and r["risk_score"] >= 61


def test_high_traffic_volume(engine, record_property):
    """TC-09 | High traffic volume | 2 GB in 5 min | Expected: IDS-006 fires"""
    r = engine.analyze(make_flow(byte_count=2_000_000_000, packet_count=1_400_000,
                                 duration_seconds=300, connection_count=1, syn_count=1))
    record_property("actual", f"rules={_rule_ids(r)}, {r['classification']}, risk={r['risk_score']}")
    assert "IDS-006" in _rule_ids(r) and r["classification"] != "NORMAL"


def test_unusual_port_activity(engine, record_property):
    """TC-31 | Unusual service port | internal host -> external TCP/4444 | Expected: IDS-005 fires"""
    r = engine.analyze(make_flow(destination_ip="203.0.113.200", destination_port=4444))
    record_property("actual", f"rules={_rule_ids(r)}, risk={r['risk_score']}")
    assert "IDS-005" in _rule_ids(r)


# ------------------------------------------------------------------- validation
@pytest.mark.parametrize("tc, field, value", [
    ("TC-10", "source_ip", "999.1.1.1"),
    ("TC-11", "destination_ip", "not-an-ip"),
    ("TC-12", "source_port", 70000),
    ("TC-13", "destination_port", -1),
])
def test_invalid_fields_rejected(tc, field, value, record_property):
    """TC-10..13 | Invalid IP / port | malformed source/destination IP or port | Expected: FlowValidationError"""
    with pytest.raises(FlowValidationError) as exc:
        validate_flow(make_flow(**{field: value}))
    record_property("actual", f"{tc}: rejected — {exc.value.errors[0][:80]}")


def test_unsupported_protocol(record_property):
    """TC-14 | Unsupported protocol | protocol='GRE' | Expected: FlowValidationError"""
    with pytest.raises(FlowValidationError) as exc:
        validate_flow(make_flow(protocol="GRE"))
    record_property("actual", f"rejected — {exc.value.errors[0][:80]}")


def test_missing_packet_count_imputed(record_property):
    """TC-15 | Missing packet count | packet_count omitted | Expected: imputed to 0 + data-quality warning"""
    flow = make_flow()
    del flow["packet_count"]
    clean, warnings = validate_flow(flow)
    record_property("actual", f"packet_count={clean['packet_count']}, warnings={warnings}")
    assert clean["packet_count"] == 0 and any("packet_count" in w for w in warnings)


def test_zero_duration_no_crash(record_property):
    """TC-16 | Zero duration | duration=0 with 1000 bytes | Expected: no ZeroDivisionError, rates use 1 s floor"""
    f = extract_network_features(make_flow(duration_seconds=0, byte_count=1000, packet_count=10))
    record_property("actual", f"bytes_per_second={f['bytes_per_second']}, packets_per_second={f['packets_per_second']}")
    assert f["bytes_per_second"] == 1000 and f["packets_per_second"] == 10


# ---------------------------------------------------------- features / rules / scores
def test_feature_extraction(record_property):
    """TC-17 | Feature extraction | 100 conns, 40 failed, 50 SYN of 200 pkts, 10 s | Expected: failure_ratio=0.4, syn_ratio=0.25, connection_rate=10"""
    f = extract_network_features(make_flow(connection_count=100, failed_connection_count=40,
                                           syn_count=50, packet_count=200, byte_count=20000,
                                           duration_seconds=10))
    record_property("actual", f"failure_ratio={f['failure_ratio']}, syn_ratio={f['syn_ratio']}, "
                              f"connection_rate={f['connection_rate']}, avg_pkt={f['average_packet_size']}")
    assert (f["failure_ratio"], f["syn_ratio"], f["connection_rate"], f["average_packet_size"]) == \
        (0.4, 0.25, 10.0, 100.0)


def test_rule_detection_respects_config(record_property):
    """TC-18 | Rule detection + configurable thresholds | 150-conn flow vs default and raised threshold | Expected: fires by default, silent when threshold raised / rule disabled"""
    flow, _ = validate_flow(make_flow(connection_count=150, duration_seconds=30))
    feats = extract_network_features(flow, validate=False)
    default_hit = [m.rule_id for m in analyze_flow(feats, flow)]
    tuned = [{"rule_id": "IDS-001", "rule_name": "High Connection Rate", "severity": "HIGH",
              "description": "", "enabled": True,
              "threshold": {"connection_rate_per_sec": 50, "connection_count": 1000}}]
    tuned_hit = [m.rule_id for m in analyze_flow(feats, flow, tuned)]
    disabled = [dict(tuned[0], enabled=False, threshold={"connection_rate_per_sec": 1, "connection_count": 1})]
    disabled_hit = [m.rule_id for m in analyze_flow(feats, flow, disabled)]
    record_property("actual", f"default={default_hit}, tuned={tuned_hit}, disabled={disabled_hit}")
    assert "IDS-001" in default_hit and tuned_hit == [] and disabled_hit == []


def test_anomaly_score(record_property):
    """TC-19 | Anomaly score | normal flow vs flow with 90% failures + 50 conns/s | Expected: normal < 20, abnormal >= 75"""
    normal = calculate_anomaly_score(extract_network_features(make_flow()))
    detector = AnomalyDetector()
    abnormal = detector.calculate_anomaly_score(extract_network_features(make_flow(
        connection_count=500, failed_connection_count=450, duration_seconds=10,
        packet_count=2000, byte_count=100000)))
    record_property("actual", f"normal={normal}, abnormal={abnormal['score']} "
                              f"(top={abnormal['top_contributors']})")
    assert normal < 20 and abnormal["score"] >= 75 and 0 <= abnormal["score"] <= 100


def test_anomaly_baseline_fit(record_property):
    """TC-32 | Anomaly baseline fit + empty dataset | fit on 50 normal flows; fit on [] | Expected: baseline built; empty raises ValueError"""
    feats = [extract_network_features(make_flow(byte_count=10000 + i * 100)) for i in range(50)]
    det = AnomalyDetector.fit(feats)
    with pytest.raises(ValueError):
        AnomalyDetector.fit([])
    record_property("actual", f"samples={det.sample_size}, bytes/s mean(log)={det.baseline['bytes_per_second']['mean']:.2f}; empty -> ValueError")
    assert det.sample_size == 50


def test_risk_score(record_property):
    """TC-20 | Risk score | sig=70, anomaly=60, ML=0.78 (40/30/30) ; same without ML (60/40) | Expected: 69.4 and 66.0"""
    with_ml = calculate_risk_score(70, 60, 0.78)
    without_ml = calculate_risk_score(70, 60, None)
    floored = calculate_risk_score(0, 0, None, top_rule_severity="HIGH")
    record_property("actual", f"with_ml={with_ml} ({risk_band(with_ml)[0]}), without_ml={without_ml}, "
                              f"HIGH-rule floor={floored}")
    assert with_ml == 69.4 and without_ml == 66.0 and floored == 61
    assert classify(10) == "NORMAL" and classify(50) == "SUSPICIOUS" and classify(90) == "POTENTIAL_INTRUSION"


def test_alert_creation(engine, record_property):
    """TC-21 | Alert creation | suspicious flow result -> generate_alert() | Expected: ALT-id, status NEW, reason + playbook present"""
    r = engine.analyze(make_flow(source_ip="203.0.113.9", connection_count=400, duration_seconds=10))
    alert = generate_alert(r["flow"], r)
    record_property("actual", f"{alert['alert_id']} {alert['alert_type']} {alert['severity']} "
                              f"status={alert['status']} steps={len(alert['recommended_steps'])}")
    assert alert["alert_id"].startswith("ALT-") and alert["status"] == "NEW"
    assert alert["reason"] and alert["recommended_steps"]


def test_alert_correlation(record_property):
    """TC-22 | Alert correlation | 100 alerts from one source in 50 s + 1 alert 5 min later + other source | Expected: 3 incidents"""
    base = datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc)
    alerts = [{"alert_id": f"ALT-{i:08X}", "source_ip": "203.0.113.5", "alert_type": "High Connection Rate",
               "timestamp": format_timestamp(base + timedelta(seconds=i * 0.5)),
               "severity": "HIGH", "risk_score": 70 + i % 5} for i in range(100)]
    alerts.append({"alert_id": "ALT-LATE0001", "source_ip": "203.0.113.5",
                   "alert_type": "High Connection Rate",
                   "timestamp": format_timestamp(base + timedelta(minutes=6)),
                   "severity": "MEDIUM", "risk_score": 50})
    alerts.append({"alert_id": "ALT-OTHER001", "source_ip": "203.0.113.6",
                   "alert_type": "High Connection Rate", "timestamp": format_timestamp(base),
                   "severity": "HIGH", "risk_score": 70})
    incidents = correlate_alerts(alerts, window_seconds=60)
    biggest = max(incidents, key=lambda i: i["alert_count"])
    record_property("actual", f"{len(alerts)} alerts -> {len(incidents)} incidents "
                              f"(largest={biggest['alert_count']}, reduction={reduction_ratio(len(alerts), len(incidents)):.0%})")
    assert len(incidents) == 3 and biggest["alert_count"] == 100 and biggest["max_risk_score"] == 74
