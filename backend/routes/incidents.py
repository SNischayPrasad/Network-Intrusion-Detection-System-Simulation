"""/api/incidents — correlated alert groups (same source + type + time window)."""

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status

from backend.services import alert_service
from backend.services.alert_service import NotFoundError
from backend.utils.security import READ_ROLES, Principal, require_roles

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


@router.get("")
def list_incidents(request: Request,
                   range: str | None = Query(None, pattern="^(15m|1h|6h|24h|7d|30d|all)$"),
                   limit: int = Query(50, ge=1, le=500),
                   offset: int = Query(0, ge=0),
                   _: Principal = Depends(require_roles(*READ_ROLES))):
    return alert_service.list_incidents(request.app.state.db, range, limit, offset)


@router.get("/{incident_id}")
def get_incident(request: Request, incident_id: str = Path(pattern=r"^INC-[A-F0-9]{8}$"),
                 _: Principal = Depends(require_roles(*READ_ROLES))):
    try:
        return alert_service.get_incident(request.app.state.db, incident_id)
    except NotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
