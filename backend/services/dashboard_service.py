"""
Dashboard analytics: KPI cards, traffic time-series and alert breakdowns.

Aggregation happens in SQL where it is simple (counts, averages) and in
Python for time bucketing (easy to read and explain). For a student-scale
dataset (tens of thousands of flows) this is fast; a production system would
use a time-series database or pre-aggregated rollups.
"""

from collections import Counter, defaultdict

from ids.anomaly_detector import MovingAverage
from ids.config import KNOWN_SERVICE_PORTS, SEVERITIES, WATCHLIST_PORTS
from backend.utils.time_utils import (
    bucket_seconds_for,
    bucket_start,
    epoch_to_iso,
    since_for_range,
)


def _range_clause(column, time_range):
    since = since_for_range(time_range)
    return (f" WHERE {column} >= ?", [since]) if since else ("", [])


def get_stats(db, time_range=None, ml_enabled=False):
    fclause, fparams = _range_clause("timestamp", time_range)
    aclause, aparams = _range_clause("created_at", time_range)
    with db.connect() as conn:
        f = conn.execute(
            f"""SELECT COUNT(*) AS total,
                   SUM(classification = 'NORMAL') AS normal,
                   SUM(classification = 'SUSPICIOUS') AS suspicious,
                   SUM(classification = 'POTENTIAL_INTRUSION') AS intrusion,
                   ROUND(AVG(risk_score), 1) AS avg_risk,
                   MAX(timestamp) AS last_flow_at
                FROM network_flows{fclause}""", fparams).fetchone()
        a = conn.execute(
            f"""SELECT COUNT(*) AS total,
                   SUM(status IN ('NEW','INVESTIGATING')) AS open,
                   SUM(status = 'NEW') AS new,
                   SUM(severity = 'CRITICAL') AS critical,
                   SUM(severity = 'CRITICAL' AND status IN ('NEW','INVESTIGATING')) AS critical_open,
                   COUNT(DISTINCT incident_id) AS incidents
                FROM alerts{aclause}""", aparams).fetchone()
    return {
        "total_flows": f["total"] or 0,
        "normal_flows": f["normal"] or 0,
        "suspicious_flows": (f["suspicious"] or 0) + (f["intrusion"] or 0),
        "potential_intrusions": f["intrusion"] or 0,
        "average_risk_score": f["avg_risk"] or 0.0,
        "last_flow_at": f["last_flow_at"],
        "total_alerts": a["total"] or 0,
        "open_alerts": a["open"] or 0,
        "new_alerts": a["new"] or 0,
        "critical_alerts": a["critical"] or 0,
        "critical_open_alerts": a["critical_open"] or 0,
        "incidents": a["incidents"] or 0,
        "ml_enabled": ml_enabled,
        "range": time_range or "all",
    }


def get_traffic(db, time_range="24h"):
    clause, params = _range_clause("timestamp", time_range)
    with db.connect() as conn:
        rows = conn.execute(
            f"""SELECT timestamp, protocol, destination_port, packet_count, byte_count,
                       connection_count, failed_connection_count, classification, risk_score
                FROM network_flows{clause} ORDER BY timestamp""", params).fetchall()

    if not rows:
        return {"bucket_seconds": bucket_seconds_for(time_range), "series": [],
                "protocols": [], "top_ports": [], "classification": []}

    bucket = bucket_seconds_for(time_range, rows[0]["timestamp"], rows[-1]["timestamp"])
    agg = defaultdict(lambda: defaultdict(float))
    protocols, ports, classes = Counter(), Counter(), Counter()
    for r in rows:
        b = agg[bucket_start(r["timestamp"], bucket)]
        b["flows"] += 1
        b["packets"] += r["packet_count"]
        b["bytes"] += r["byte_count"]
        b["connections"] += r["connection_count"]
        b["failed_connections"] += r["failed_connection_count"]
        b["suspicious"] += r["classification"] != "NORMAL"
        b["risk_sum"] += r["risk_score"]
        b["max_risk"] = max(b["max_risk"], r["risk_score"])
        protocols[r["protocol"]] += 1
        ports[r["destination_port"]] += 1
        classes[r["classification"]] += 1

    # Fill gaps with zero buckets so charts show quiet periods honestly.
    start, end = min(agg), max(agg)
    series = []
    for epoch in range(start, end + bucket, bucket):
        b = agg.get(epoch, {})
        flows = b.get("flows", 0)
        series.append({
            "time": epoch_to_iso(epoch),
            "flows": int(flows),
            "normal": int(flows - b.get("suspicious", 0)),
            "suspicious": int(b.get("suspicious", 0)),
            "packets": int(b.get("packets", 0)),
            "bytes": int(b.get("bytes", 0)),
            "packets_per_second": round(b.get("packets", 0) / bucket, 2),
            "bytes_per_second": round(b.get("bytes", 0) / bucket, 1),
            "connections_per_minute": round(b.get("connections", 0) / (bucket / 60), 2),
            "failed_connections": int(b.get("failed_connections", 0)),
            "avg_risk": round(b["risk_sum"] / flows, 1) if flows else 0,
            "max_risk": round(b.get("max_risk", 0), 1),
        })
    smoothed = MovingAverage(window=5).smooth([s["flows"] for s in series])
    for s, ma in zip(series, smoothed):
        s["flows_moving_avg"] = ma

    def port_name(p):
        return KNOWN_SERVICE_PORTS.get(p) or ("WATCHLIST" if p in WATCHLIST_PORTS else "other")

    return {
        "bucket_seconds": bucket,
        "series": series,
        "protocols": [{"protocol": k, "count": v} for k, v in protocols.most_common()],
        "top_ports": [{"port": p, "service": port_name(p), "count": c}
                      for p, c in ports.most_common(10)],
        "classification": [{"name": k, "count": classes.get(k, 0)}
                           for k in ("NORMAL", "SUSPICIOUS", "POTENTIAL_INTRUSION")],
    }


def get_alert_analytics(db, time_range="24h"):
    aclause, aparams = _range_clause("created_at", time_range)
    fclause, fparams = _range_clause("timestamp", time_range)
    with db.connect() as conn:
        alerts = conn.execute(
            f"SELECT created_at, severity, alert_type, source_ip, status, risk_score "
            f"FROM alerts{aclause} ORDER BY created_at", aparams).fetchall()
        risk_hist = conn.execute(
            f"""SELECT MIN(CAST(risk_score / 10 AS INTEGER), 9) AS bin, COUNT(*) AS n
                FROM network_flows{fclause} GROUP BY bin ORDER BY bin""", fparams).fetchall()

    by_sev, by_type, by_status = Counter(), Counter(), Counter()
    sources = defaultdict(lambda: {"count": 0, "max_risk": 0})
    for a in alerts:
        by_sev[a["severity"]] += 1
        by_type[a["alert_type"]] += 1
        by_status[a["status"]] += 1
        s = sources[a["source_ip"]]
        s["count"] += 1
        s["max_risk"] = max(s["max_risk"], a["risk_score"])

    timeline = []
    if alerts:
        bucket = bucket_seconds_for(time_range, alerts[0]["created_at"], alerts[-1]["created_at"])
        agg = defaultdict(Counter)
        for a in alerts:
            agg[bucket_start(a["created_at"], bucket)][a["severity"]] += 1
        for epoch in range(min(agg), max(agg) + bucket, bucket):
            c = agg.get(epoch, Counter())
            timeline.append({"time": epoch_to_iso(epoch), **{s: c.get(s, 0) for s in SEVERITIES}})

    hist = {r["bin"]: r["n"] for r in risk_hist}
    return {
        "by_severity": [{"severity": s, "count": by_sev.get(s, 0)} for s in SEVERITIES],
        "by_type": [{"alert_type": t, "count": c} for t, c in by_type.most_common(10)],
        "by_status": [{"status": s, "count": c} for s, c in by_status.most_common()],
        "top_sources": sorted(
            ({"source_ip": ip, **v} for ip, v in sources.items()),
            key=lambda x: (-x["count"], -x["max_risk"]))[:10],
        "risk_distribution": [{"range": f"{b * 10}-{b * 10 + 9 if b < 9 else 100}",
                               "count": hist.get(b, 0)} for b in range(10)],
        "timeline": timeline,
    }
