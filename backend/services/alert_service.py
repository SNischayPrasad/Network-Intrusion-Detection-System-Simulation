"""
Alert queue, investigation and incident-management logic.

Workflow enforced here (see ids.config.STATUS_TRANSITIONS):

    NEW ──► INVESTIGATING ──► RESOLVED
     │            │
     └────────────┴────────► FALSE_POSITIVE
    (RESOLVED / FALSE_POSITIVE can be re-opened to INVESTIGATING)

Closing an alert (RESOLVED / FALSE_POSITIVE) requires a resolution note, so
every closure is documented — an important habit in real SOCs.
"""

import json

from ids.alert_engine import recommended_investigation_steps
from ids.config import STATUS_TRANSITIONS
from backend.services.audit import write_audit
from backend.utils.time_utils import now_iso, since_for_range

ALERT_LIST_COLUMNS = (
    "alert_id, flow_id, incident_id, rule_id, alert_type, severity, risk_score, status, "
    "source_ip, destination_ip, source_port, destination_port, protocol, created_at, "
    "detected_at, updated_at, reason"
)


class NotFoundError(Exception):
    pass


class WorkflowError(Exception):
    pass


def _split(value):
    return [v.strip().upper() for v in value.split(",") if v.strip()] if value else []


def list_alerts(db, severity=None, protocol=None, alert_type=None, status=None,
                source_ip=None, time_range=None, incident_id=None, limit=50, offset=0):
    where, params = [], []
    for column, values in (("severity", _split(severity)), ("status", _split(status)),
                           ("protocol", _split(protocol))):
        if values:
            where.append(f"{column} IN ({','.join('?' * len(values))})")
            params.extend(values)
    if alert_type:
        where.append("alert_type = ?")
        params.append(alert_type)
    if source_ip:
        where.append("source_ip = ?")
        params.append(source_ip)
    if incident_id:
        where.append("incident_id = ?")
        params.append(incident_id)
    since = since_for_range(time_range)
    if since:
        where.append("created_at >= ?")
        params.append(since)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    limit = min(max(1, int(limit)), 500)
    offset = max(0, int(offset))
    with db.connect() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM alerts{clause}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT {ALERT_LIST_COLUMNS} FROM alerts{clause} "
            "ORDER BY created_at DESC, alert_id LIMIT ? OFFSET ?",
            params + [limit, offset]).fetchall()
    return {"items": [dict(r) for r in rows], "total": total, "limit": limit, "offset": offset}


def get_alert_detail(db, alert_id):
    with db.connect() as conn:
        alert = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        if alert is None:
            raise NotFoundError(alert_id)
        alert = dict(alert)
        flow = dict(conn.execute("SELECT * FROM network_flows WHERE flow_id = ?",
                                 (alert["flow_id"],)).fetchone())
        notes = [dict(r) for r in conn.execute(
            "SELECT * FROM incident_notes WHERE alert_id = ? ORDER BY note_id", (alert_id,))]
        timeline = [dict(r) for r in conn.execute(
            "SELECT timestamp, actor, role, action, details FROM audit_log "
            "WHERE target_type = 'alert' AND target_id = ? ORDER BY id", (alert_id,))]
        incident = None
        if alert["incident_id"]:
            row = conn.execute("SELECT * FROM incidents WHERE incident_id = ?",
                               (alert["incident_id"],)).fetchone()
            incident = dict(row) if row else None

    detection = json.loads(flow.pop("detection_json"))
    alert["matched_rules"] = json.loads(alert.pop("matched_rules_json"))
    alert["flow"] = flow
    alert["features"] = detection["features"]
    alert["anomaly_details"] = detection["anomaly"]
    alert["data_quality_warnings"] = detection.get("data_quality_warnings", [])
    alert["notes"] = notes
    alert["timeline"] = timeline
    alert["incident"] = incident
    alert["recommended_steps"] = recommended_investigation_steps(alert["rule_id"])
    alert["allowed_transitions"] = list(STATUS_TRANSITIONS.get(alert["status"], ()))
    return alert


def update_status(db, alert_id, new_status, note, principal):
    with db.write_lock, db.connect() as conn:
        row = conn.execute("SELECT status, investigation_started_at FROM alerts "
                           "WHERE alert_id = ?", (alert_id,)).fetchone()
        if row is None:
            raise NotFoundError(alert_id)
        current = row["status"]
        if new_status not in STATUS_TRANSITIONS.get(current, ()):
            raise WorkflowError(
                f"Cannot change status from {current} to {new_status}. Allowed: "
                f"{', '.join(STATUS_TRANSITIONS.get(current, ())) or 'none'}")
        closing = new_status in ("RESOLVED", "FALSE_POSITIVE")
        if closing and (not note or len(note) < 5):
            raise WorkflowError("A resolution note (at least 5 characters) is required "
                                "when closing an alert.")

        now = now_iso()
        started = row["investigation_started_at"]
        if new_status == "INVESTIGATING" and not started:
            started = now
        conn.execute(
            "UPDATE alerts SET status = ?, updated_at = ?, assigned_to = ?, "
            "investigation_started_at = ?, resolved_at = ? WHERE alert_id = ?",
            (new_status, now, principal.name, started, now if closing else None, alert_id))
        if note:
            conn.execute(
                "INSERT INTO incident_notes (alert_id, note, note_type, analyst, created_at) "
                "VALUES (?,?,?,?,?)",
                (alert_id, note, "RESOLUTION" if closing else "NOTE", principal.name, now))
        write_audit(conn, principal.name, principal.role, "STATUS_CHANGED", "alert", alert_id,
                    f"{current} -> {new_status}" + (f" | {note}" if note else ""), now)
    return get_alert_detail(db, alert_id)


def add_note(db, alert_id, note, principal):
    with db.write_lock, db.connect() as conn:
        if conn.execute("SELECT 1 FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone() is None:
            raise NotFoundError(alert_id)
        now = now_iso()
        cur = conn.execute(
            "INSERT INTO incident_notes (alert_id, note, note_type, analyst, created_at) "
            "VALUES (?,?,?,?,?)", (alert_id, note, "NOTE", principal.name, now))
        conn.execute("UPDATE alerts SET updated_at = ? WHERE alert_id = ?", (now, alert_id))
        write_audit(conn, principal.name, principal.role, "NOTE_ADDED", "alert", alert_id,
                    note[:200], now)
        return {"note_id": cur.lastrowid, "alert_id": alert_id, "note": note,
                "note_type": "NOTE", "analyst": principal.name, "created_at": now}


# ------------------------------------------------------------------ incidents
def list_incidents(db, time_range=None, limit=50, offset=0):
    since = since_for_range(time_range)
    clause, params = ("WHERE i.last_seen >= ?", [since]) if since else ("", [])
    limit = min(max(1, int(limit)), 500)
    with db.connect() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM incidents i {clause}", params).fetchone()[0]
        rows = conn.execute(
            f"""SELECT i.*,
                   SUM(CASE WHEN a.status IN ('NEW','INVESTIGATING') THEN 1 ELSE 0 END) AS open_alerts
                FROM incidents i LEFT JOIN alerts a ON a.incident_id = i.incident_id
                {clause}
                GROUP BY i.incident_id ORDER BY i.last_seen DESC LIMIT ? OFFSET ?""",
            params + [limit, max(0, int(offset))]).fetchall()
    return {"items": [dict(r) for r in rows], "total": total}


def get_incident(db, incident_id):
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM incidents WHERE incident_id = ?",
                           (incident_id,)).fetchone()
        if row is None:
            raise NotFoundError(incident_id)
    incident = dict(row)
    incident["alerts"] = list_alerts(db, incident_id=incident_id, limit=500)["items"]
    return incident
