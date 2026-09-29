"""
Alert generation.

EVENT    -> an individual observation (one flow record).
ALERT    -> an event (or detection) that needs a human to look at it.
INCIDENT -> a group of related alerts that together need investigation
            (see ids.correlation).

generate_alert() turns a detection result into an analyst-ready alert:
who talked to whom, what fired, how risky it is, WHY it fired, and what a
Tier-1 analyst should check next. All recommendations are defensive.
"""

import uuid
from datetime import datetime, timezone

from ids.validation import format_timestamp

# Defensive investigation playbooks per detection type.
COMMON_STEPS = [
    "Check whether the source IP is a known asset (CMDB / asset inventory) or an "
    "approved scanner / monitoring system.",
    "Compare this activity with the source's historical baseline on the dashboard.",
    "Review firewall and proxy records for the same source and time window.",
    "Determine whether the activity is expected (change ticket, maintenance, new app).",
]

PLAYBOOKS = {
    "IDS-001": [
        "Check whether the destination service experienced degraded performance.",
        "Identify whether many sources are involved (distributed) or a single one.",
        "Confirm with the service owner whether a load test or batch job was scheduled.",
    ],
    "IDS-002": [
        "Review authentication logs on the destination for failed logins from this source.",
        "Check for any SUCCESSFUL login after the failures (possible compromise).",
        "Verify whether the source is a misconfigured client or expired credential.",
    ],
    "IDS-003": [
        "List all destination ports contacted by the source in the time window.",
        "Check whether the source is an authorised vulnerability scanner.",
        "Look for follow-up connections to any port that responded.",
    ],
    "IDS-004": [
        "Check destination for half-open connection build-up / SYN backlog.",
        "Review upstream network device telemetry where authorised.",
        "Coordinate with network team on rate-limiting only after confirmation.",
    ],
    "IDS-005": [
        "Identify the process / application using this port on the host "
        "(review endpoint telemetry where authorised).",
        "Check whether the service is documented and approved.",
        "Search threat-intelligence sources for the destination IP.",
    ],
    "IDS-006": [
        "Identify the data transferred and whether a backup / sync job was scheduled.",
        "Check data-loss-prevention (DLP) logs if available.",
        "Confirm the destination is an approved storage or backup target.",
    ],
    "ANOMALY": [
        "Review which metrics deviated most from baseline (see anomaly details).",
        "Check for recent changes (deployments, new applications) explaining the shift.",
    ],
    "ML": [
        "Review the model features that made this flow look suspicious.",
        "Treat ML-only detections as lower confidence until corroborated.",
    ],
}


def recommended_investigation_steps(rule_id: str):
    """Return a de-duplicated list of defensive investigation steps."""
    specific = PLAYBOOKS.get(rule_id, PLAYBOOKS["ANOMALY"])
    return list(dict.fromkeys(specific + COMMON_STEPS))


def new_alert_id() -> str:
    return f"ALT-{uuid.uuid4().hex[:8].upper()}"


def generate_alert(flow: dict, detection: dict, alert_id: str | None = None) -> dict:
    """
    Build an alert from a validated flow + detection result.

    `detection` is the dict produced by HybridIDSEngine.analyze() and must
    contain: rule_matches, risk_score, severity, anomaly, ml_probability.
    """
    matches = detection.get("rule_matches", [])
    anomaly = detection.get("anomaly", {})
    ml_prob = detection.get("ml_probability")

    if matches:
        primary = matches[0]
        rule_id, alert_type = primary["rule_id"], primary["name"]
        reason = primary["evidence"]
        description = primary["description"]
        if len(matches) > 1:
            others = ", ".join(m["name"] for m in matches[1:])
            description += f" Also matched: {others}."
    elif anomaly.get("score", 0) >= (ml_prob or 0) * 100:
        rule_id, alert_type = "ANOMALY", "Statistical Anomaly"
        top = ", ".join(anomaly.get("top_contributors", [])) or "multiple metrics"
        reason = f"Flow deviated from the normal baseline on: {top}."
        description = "Behaviour significantly different from learned normal traffic."
    else:
        rule_id, alert_type = "ML", "ML-Detected Suspicious Flow"
        reason = f"Machine-learning model probability of suspicious = {ml_prob:.0%}."
        description = "The ML model classified this flow as suspicious."

    return {
        "alert_id": alert_id or new_alert_id(),
        "timestamp": flow["timestamp"],
        "detected_at": format_timestamp(datetime.now(timezone.utc)),
        "flow_id": flow.get("flow_id"),
        "source_ip": flow["source_ip"],
        "destination_ip": flow["destination_ip"],
        "protocol": flow["protocol"],
        "source_port": flow["source_port"],
        "destination_port": flow["destination_port"],
        "rule_id": rule_id,
        "alert_type": alert_type,
        "severity": detection["severity"],
        "risk_score": detection["risk_score"],
        "signature_score": detection.get("signature_score", 0),
        "anomaly_score": anomaly.get("score", 0),
        "ml_score": None if ml_prob is None else round(ml_prob * 100, 1),
        "description": description,
        "reason": reason,
        "matched_rules": matches,
        "mitre_hint": matches[0].get("mitre_hint", "") if matches else "",
        "recommended_steps": recommended_investigation_steps(rule_id),
        "status": "NEW",
    }


def format_alert_text(alert: dict) -> str:
    """Console-friendly alert card (used by the CLI demo)."""
    return (
        f"ALERT ID:    {alert['alert_id']}\n"
        f"TYPE:        {alert['alert_type']} ({alert['rule_id']})\n"
        f"SEVERITY:    {alert['severity']}\n"
        f"SOURCE:      {alert['source_ip']}:{alert['source_port']}\n"
        f"DESTINATION: {alert['destination_ip']}:{alert['destination_port']} "
        f"({alert['protocol']})\n"
        f"RISK:        {alert['risk_score']}/100\n"
        f"REASON:      {alert['reason']}\n"
        f"STATUS:      {alert['status']}"
    )
