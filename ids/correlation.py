"""
Alert correlation.

Problem: a single noisy source can produce hundreds of near-identical alerts
in a minute. Showing all of them separately buries analysts ("alert fatigue").

Solution: group alerts that share
    * the same source IP
    * the same alert type
    * and occur within a sliding time window (default 60 s)
into one INCIDENT. The analyst then investigates one incident with an
alert count, first/last seen times and the maximum risk observed.

The window is *sliding*: each new alert extends the incident if it arrives
within `window_seconds` of the incident's most recent alert.
"""

from ids.config import CORRELATION_WINDOW_SECONDS, SEVERITIES
from ids.validation import parse_timestamp


def correlation_key(alert: dict):
    """Alerts with the same key are candidates for the same incident."""
    return (alert["source_ip"], alert["alert_type"])


def correlate_alerts(alerts, window_seconds: int = CORRELATION_WINDOW_SECONDS):
    """
    Group alerts into incidents.

    Parameters
    ----------
    alerts         : iterable of alert dicts (needs source_ip, alert_type,
                     timestamp, severity, risk_score, alert_id)
    window_seconds : max gap between consecutive alerts in one incident

    Returns
    -------
    list of incident dicts sorted by first_seen:
      {incident_id, source_ip, alert_type, first_seen, last_seen,
       alert_count, alert_ids, max_severity, max_risk_score}
    """
    ordered = sorted(alerts, key=lambda a: parse_timestamp(a["timestamp"]))
    open_incidents = {}   # key -> incident currently accepting alerts
    incidents = []

    for alert in ordered:
        key = correlation_key(alert)
        ts = parse_timestamp(alert["timestamp"])
        current = open_incidents.get(key)

        if current is not None and (ts - current["_last_dt"]).total_seconds() <= window_seconds:
            current["alert_ids"].append(alert["alert_id"])
            current["alert_count"] += 1
            current["last_seen"] = alert["timestamp"]
            current["_last_dt"] = ts
            current["max_risk_score"] = max(current["max_risk_score"], alert["risk_score"])
            if SEVERITIES.index(alert["severity"]) > SEVERITIES.index(current["max_severity"]):
                current["max_severity"] = alert["severity"]
        else:
            current = {
                "incident_id": f"INC-{len(incidents) + 1:05d}",
                "source_ip": alert["source_ip"],
                "alert_type": alert["alert_type"],
                "first_seen": alert["timestamp"],
                "last_seen": alert["timestamp"],
                "_last_dt": ts,
                "alert_count": 1,
                "alert_ids": [alert["alert_id"]],
                "max_severity": alert["severity"],
                "max_risk_score": alert["risk_score"],
            }
            open_incidents[key] = current
            incidents.append(current)

    for inc in incidents:
        inc.pop("_last_dt", None)
    return incidents


def reduction_ratio(alert_count: int, incident_count: int) -> float:
    """How much correlation reduced analyst workload (0.0–1.0)."""
    if alert_count == 0:
        return 0.0
    return round(1 - incident_count / alert_count, 3)
