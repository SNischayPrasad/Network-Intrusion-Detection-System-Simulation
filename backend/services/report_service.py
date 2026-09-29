"""Incident report generation (Markdown) for a single alert investigation."""

from backend.utils.time_utils import now_iso


def _md_escape(text) -> str:
    """Neutralise Markdown/HTML control characters in analyst-supplied text."""
    text = str(text if text is not None else "")
    for ch in ("\\", "`", "*", "_", "|", "<", ">", "[", "]"):
        text = text.replace(ch, "\\" + ch)
    return text


def build_incident_report(alert: dict) -> str:
    flow = alert["flow"]
    feats = alert["features"]
    lines = [
        f"# Incident Report — {alert['alert_id']}",
        "",
        f"_Generated {now_iso()} by Network IDS Simulation. Synthetic data — for training only._",
        "",
        "## 1. Summary",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Alert ID | {alert['alert_id']} |",
        f"| Incident (correlated group) | {alert.get('incident_id') or '—'} |",
        f"| Detection | {alert['alert_type']} ({alert['rule_id']}) |",
        f"| Severity | **{alert['severity']}** |",
        f"| Final risk score | {alert['risk_score']}/100 |",
        f"| Status | {alert['status']} |",
        f"| Event time | {alert['created_at']} |",
        f"| Detected at | {alert['detected_at']} |",
        f"| Assigned to | {alert.get('assigned_to') or 'unassigned'} |",
        "",
        "## 2. Network context",
        "",
        f"* **Source:** {alert['source_ip']}:{alert['source_port']}",
        f"* **Destination:** {alert['destination_ip']}:{alert['destination_port']} ({alert['protocol']})",
        f"* **Packets / bytes:** {flow['packet_count']:,} / {flow['byte_count']:,}",
        f"* **Duration:** {flow['duration']} s",
        f"* **Connections (failed):** {flow['connection_count']} ({flow['failed_connection_count']})",
        f"* **SYN / RST:** {flow['syn_count']} / {flow['rst_count']}",
        f"* **Unique destination ports from source (60 s window):** "
        f"{int(feats['unique_destination_ports'])}",
        "",
        "## 3. Detection evidence",
        "",
        f"**Reason:** {_md_escape(alert['reason'])}",
        "",
        f"* Signature score: {alert['signature_score']}",
        f"* Anomaly score: {alert['anomaly_score']}",
        f"* ML score: {alert['ml_score'] if alert['ml_score'] is not None else 'ML disabled'}",
        "",
    ]
    if alert["matched_rules"]:
        lines += ["| Rule | Severity | Evidence |", "|---|---|---|"]
        for m in alert["matched_rules"]:
            lines.append(f"| {m['rule_id']} {m['name']} | {m['severity']} | "
                         f"{_md_escape(m['evidence'])} |")
        lines.append("")
    top = alert["anomaly_details"].get("top_contributors", [])
    if top:
        lines.append("**Anomaly contributors (Z-score vs. baseline):** " + ", ".join(
            f"{m} (z={alert['anomaly_details']['details'][m]['z_score']})" for m in top))
        lines.append("")
    if alert.get("mitre_hint"):
        lines += [f"**Candidate ATT&CK mapping (unconfirmed):** {alert['mitre_hint']}", ""]

    lines += ["## 4. Timeline", ""]
    for t in alert["timeline"]:
        lines.append(f"* `{t['timestamp']}` — **{t['action']}** by {t['actor']}: "
                     f"{_md_escape(t['details'])}")
    lines += ["", "## 5. Analyst notes", ""]
    if alert["notes"]:
        for n in alert["notes"]:
            lines.append(f"* `{n['created_at']}` [{n['note_type']}] {n['analyst']}: "
                         f"{_md_escape(n['note'])}")
    else:
        lines.append("_No notes recorded._")
    lines += ["", "## 6. Recommended investigation steps", ""]
    lines += [f"{i}. {s}" for i, s in enumerate(alert["recommended_steps"], 1)]
    lines += [
        "",
        "---",
        "_A detection indicates behaviour requiring investigation; it is not proof of "
        "malicious activity. This report was generated from synthetic data for defensive "
        "cybersecurity education._",
        "",
    ]
    return "\n".join(lines)
