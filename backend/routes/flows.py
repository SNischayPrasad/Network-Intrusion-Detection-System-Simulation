"""
/api/flows — flow ingestion and retrieval.

POST /api/flows        sensor/admin  : submit one flow for real-time analysis
GET  /api/flows        analyst/admin : list flows (filters + pagination)
GET  /api/flows/{id}   analyst/admin : one flow with full detection details
"""

import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from backend.models.schemas import FlowIn
from backend.services.ids_service import DuplicateFlowError
from backend.utils.security import INGEST_ROLES, READ_ROLES, Principal, require_roles
from backend.utils.time_utils import since_for_range
from ids.validation import FlowValidationError

router = APIRouter(prefix="/api/flows", tags=["flows"])


@router.post("", status_code=status.HTTP_201_CREATED)
def submit_flow(flow: FlowIn, request: Request,
                principal: Principal = Depends(require_roles(*INGEST_ROLES))):
    service = request.app.state.ids
    try:
        return service.process_flow(flow.model_dump(), principal.name, principal.role)
    except FlowValidationError as exc:
        raise HTTPException(422,
                            {"message": "Flow failed validation", "errors": exc.errors})
    except DuplicateFlowError:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"Flow {flow.flow_id} was already ingested (duplicate event ignored)")


@router.get("")
def list_flows(request: Request,
               classification: str | None = Query(None, pattern="^(NORMAL|SUSPICIOUS|POTENTIAL_INTRUSION)$"),
               protocol: str | None = Query(None, pattern="^(TCP|UDP|ICMP)$"),
               source_ip: str | None = Query(None, max_length=45),
               range: str | None = Query(None, alias="range", pattern="^(15m|1h|6h|24h|7d|30d|all)$"),
               limit: int = Query(50, ge=1, le=500),
               offset: int = Query(0, ge=0),
               _: Principal = Depends(require_roles(*READ_ROLES))):
    where, params = [], []
    if classification:
        where.append("classification = ?")
        params.append(classification)
    if protocol:
        where.append("protocol = ?")
        params.append(protocol)
    if source_ip:
        where.append("source_ip = ?")
        params.append(source_ip)
    since = since_for_range(range)
    if since:
        where.append("timestamp >= ?")
        params.append(since)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    db = request.app.state.db
    with db.connect() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM network_flows{clause}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT flow_id, timestamp, source_ip, destination_ip, source_port, destination_port, "
            f"protocol, packet_count, byte_count, duration, connection_count, "
            f"failed_connection_count, risk_score, risk_band, classification, scenario_type "
            f"FROM network_flows{clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [limit, offset]).fetchall()
    return {"items": [dict(r) for r in rows], "total": total, "limit": limit, "offset": offset}


@router.get("/{flow_id}")
def get_flow(flow_id: str, request: Request,
             _: Principal = Depends(require_roles(*READ_ROLES))):
    with request.app.state.db.connect() as conn:
        row = conn.execute("SELECT * FROM network_flows WHERE flow_id = ?", (flow_id,)).fetchone()
        alert = conn.execute("SELECT alert_id FROM alerts WHERE flow_id = ?", (flow_id,)).fetchone()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Flow not found")
    flow = dict(row)
    flow["detection"] = json.loads(flow.pop("detection_json"))
    flow["alert_id"] = alert["alert_id"] if alert else None
    return flow
