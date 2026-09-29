"""
/api/alerts — SOC alert queue, investigation and incident management.

GET  /api/alerts                 list/filter alerts
GET  /api/alerts/{id}            full investigation view
PUT  /api/alerts/{id}/status     NEW -> INVESTIGATING -> RESOLVED / FALSE_POSITIVE
POST /api/alerts/{id}/notes      add an analyst note
GET  /api/alerts/{id}/report     Markdown incident report
GET  /api/alerts/{id}/siem       SIEM-formatted JSON event
"""

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from fastapi.responses import PlainTextResponse

from backend.models.schemas import NoteIn, StatusUpdate
from backend.services import alert_service
from backend.services.alert_service import NotFoundError, WorkflowError
from backend.services.report_service import build_incident_report
from backend.utils.security import READ_ROLES, Principal, require_roles
from ids.siem_export import to_siem_event

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

ALERT_ID_PATTERN = r"^ALT-[A-F0-9]{8}$"
LIST_PATTERN = r"^[A-Za-z_,]{1,100}$"


@router.get("")
def list_alerts(request: Request,
                severity: str | None = Query(None, pattern=LIST_PATTERN),
                protocol: str | None = Query(None, pattern=LIST_PATTERN),
                alert_type: str | None = Query(None, max_length=80),
                status_: str | None = Query(None, alias="status", pattern=LIST_PATTERN),
                source_ip: str | None = Query(None, max_length=45),
                incident_id: str | None = Query(None, max_length=20),
                range: str | None = Query(None, pattern="^(15m|1h|6h|24h|7d|30d|all)$"),
                limit: int = Query(50, ge=1, le=500),
                offset: int = Query(0, ge=0),
                _: Principal = Depends(require_roles(*READ_ROLES))):
    return alert_service.list_alerts(request.app.state.db, severity, protocol, alert_type,
                                     status_, source_ip, range, incident_id, limit, offset)


def _detail_or_404(db, alert_id):
    try:
        return alert_service.get_alert_detail(db, alert_id)
    except NotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")


@router.get("/{alert_id}")
def get_alert(request: Request, alert_id: str = Path(pattern=ALERT_ID_PATTERN),
              _: Principal = Depends(require_roles(*READ_ROLES))):
    return _detail_or_404(request.app.state.db, alert_id)


@router.put("/{alert_id}/status")
def update_alert_status(body: StatusUpdate, request: Request,
                        alert_id: str = Path(pattern=ALERT_ID_PATTERN),
                        principal: Principal = Depends(require_roles(*READ_ROLES))):
    try:
        return alert_service.update_status(request.app.state.db, alert_id, body.status,
                                           body.note, principal)
    except NotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    except WorkflowError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc))


@router.post("/{alert_id}/notes", status_code=status.HTTP_201_CREATED)
def add_note(body: NoteIn, request: Request,
             alert_id: str = Path(pattern=ALERT_ID_PATTERN),
             principal: Principal = Depends(require_roles(*READ_ROLES))):
    try:
        return alert_service.add_note(request.app.state.db, alert_id, body.note, principal)
    except NotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")


@router.get("/{alert_id}/report", response_class=PlainTextResponse)
def incident_report(request: Request, alert_id: str = Path(pattern=ALERT_ID_PATTERN),
                    _: Principal = Depends(require_roles(*READ_ROLES))):
    report = build_incident_report(_detail_or_404(request.app.state.db, alert_id))
    return PlainTextResponse(report, media_type="text/markdown; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="incident_report_{alert_id}.md"'})


@router.get("/{alert_id}/siem")
def siem_event(request: Request, alert_id: str = Path(pattern=ALERT_ID_PATTERN),
               _: Principal = Depends(require_roles(*READ_ROLES))):
    alert = _detail_or_404(request.app.state.db, alert_id)
    alert["timestamp"] = alert["created_at"]
    return to_siem_event(alert)
