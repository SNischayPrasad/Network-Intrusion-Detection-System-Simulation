"""Append-only audit trail: who did what, to which object, and when."""

from backend.utils.time_utils import now_iso


def write_audit(conn, actor: str, role: str, action: str, target_type: str,
                target_id: str, details: str = "", timestamp: str | None = None):
    conn.execute(
        "INSERT INTO audit_log (timestamp, actor, role, action, target_type, target_id, details) "
        "VALUES (?,?,?,?,?,?,?)",
        (timestamp or now_iso(), actor, role, action, target_type, target_id, details[:2000]))


def list_audit(db, limit=200, target_id=None):
    sql, params = "SELECT * FROM audit_log", []
    if target_id:
        sql += " WHERE target_id = ?"
        params.append(target_id)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(min(max(1, limit), 1000))
    with db.connect() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
