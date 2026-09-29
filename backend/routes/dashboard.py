"""/api/dashboard — aggregated data for the SOC dashboard (read-only)."""

from fastapi import APIRouter, Depends, Query, Request

from backend.services import dashboard_service
from backend.utils.security import READ_ROLES, Principal, require_roles

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])
RANGE = "^(15m|1h|6h|24h|7d|30d|all)$"


@router.get("/stats")
def stats(request: Request, range: str = Query("24h", pattern=RANGE),
          _: Principal = Depends(require_roles(*READ_ROLES))):
    return dashboard_service.get_stats(request.app.state.db, range,
                                       request.app.state.ids.engine.ml_enabled)


@router.get("/traffic")
def traffic(request: Request, range: str = Query("24h", pattern=RANGE),
            _: Principal = Depends(require_roles(*READ_ROLES))):
    return dashboard_service.get_traffic(request.app.state.db, range)


@router.get("/alerts")
def alert_analytics(request: Request, range: str = Query("24h", pattern=RANGE),
                    _: Principal = Depends(require_roles(*READ_ROLES))):
    return dashboard_service.get_alert_analytics(request.app.state.db, range)
